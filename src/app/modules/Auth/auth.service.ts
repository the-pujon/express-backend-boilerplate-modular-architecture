import { sendEmail, getEmailTemplate } from "./../../utils/sendEmail";
import httpStatus from "http-status";
import AppError from "../../errors/AppError";
import {
  ILoginUser,
  IUser,
  IPaginationParams,
  IPaginatedResponse,
  UserRole,
  ITokenPayload,
  IVerificationData,
  IResetPasswordData,
} from "./auth.interface";
import { User } from "./auth.model";
import config from "../../config";
import {
  createToken,
  removeTokens,
  checkRateLimit,
  validatePassword,
  canModifyRole,
} from "./auth.utils";
import bcrypt from "bcrypt";
import crypto from "crypto";
import {
  cacheData,
  deleteCachedData,
  getCachedData,
} from "../../utils/redis.utils";
import { JsonWebTokenError, JwtPayload, TokenExpiredError } from "jsonwebtoken";
import jwt from "jsonwebtoken";
import { AUTH_CONFIG } from "./auth.config";
import { setImmediate } from "timers";
import { th } from "zod/v4/locales";

// Constants for configuration
const VERIFICATION_TOKEN_LENGTH = 6;
const VERIFICATION_TOKEN_EXPIRY_MINUTES = 10;
const CACHE_PREFIX = "verification:";

/**
 * Generates a secure random verification code
 */
const generateVerificationCode = (): string => {
  return crypto.randomBytes(3).toString("hex").toUpperCase().slice(0, 6);
};

/**
 * Handles user signup process including verification code generation and email sending
 */
const signupUser = async (payload: IUser): Promise<{ newUser: IUser }> => {
  const { email } = payload;

  try {
    const start = Date.now();

    // Check rate limiting
    await checkRateLimit(
      `signup:${email}`,
      AUTH_CONFIG.RATE_LIMIT.SIGNUP.MAX_ATTEMPTS,
      AUTH_CONFIG.RATE_LIMIT.SIGNUP.WINDOW_MS
    );
    // console.log('Validation:', Date.now() - start);

    // Validate password strength
    if (!validatePassword(payload.password)) {
      throw new AppError(
        httpStatus.BAD_REQUEST,
        "Password does not meet security requirements"
      );
    }
    // console.log('Validation:', Date.now() - start);

    // Check if user exists
    const existingUser = await User.isUserExistsByEmail(email);
    if (existingUser) {
      throw new AppError(409, "User already exists");
    }
    // console.log('User check:', Date.now() - start);

    // Generate verification code and expiry time
    const verificationCode = generateVerificationCode();
    const expiresAt =
      Date.now() + AUTH_CONFIG.VERIFICATION_TOKEN_EXPIRY_MINUTES * 60 * 1000;

    // Create user
    const newUser = await User.create({
      ...payload,
      failedLoginAttempts: 0,
      accountLocked: false,
    });
    // console.log('DB save:', Date.now() - start);

    if (!newUser) {
      throw new AppError(httpStatus.BAD_REQUEST, "Failed to create user");
    }

    // Cache verification data
    const verificationData: IVerificationData = {
      code: verificationCode,
      expiresAt,
      attempts: 0,
    };

    await cacheData(
      `${config.redis_cache_key_prefix}:${AUTH_CONFIG.CACHE_PREFIXES.VERIFICATION}${email}`,
      verificationData,
      AUTH_CONFIG.VERIFICATION_TOKEN_EXPIRY_MINUTES * 60
    );

    // Get email template and replace placeholders
    const emailTemplate = getEmailTemplate("verification-email.html", {
      code: verificationCode,
      expiryTime: AUTH_CONFIG.VERIFICATION_TOKEN_EXPIRY_MINUTES,
      year: new Date().getFullYear(),
    });

    // Send verification email asynchronously
    setImmediate(() => {
      sendEmail({
        to: email,
        subject: "Email Verification Code",
        html: emailTemplate,
      }).catch((err) => {
        console.error("Failed to send verification email:", err);
      });
    });

    // Return response immediately
    return { newUser };
  } catch (error) {
    // Clean up cache if user creation fails
    if (
      error instanceof AppError &&
      error.statusCode === httpStatus.BAD_REQUEST
    ) {
      await deleteCachedData(
        `${AUTH_CONFIG.CACHE_PREFIXES.VERIFICATION}${email}`
      );
    }
    throw error;
  }
};

/**
 * Verifies user email using cached verification code
 */
const verifyEmail = async (
  email: string,
  code: string
): Promise<{ user: IUser }> => {
  try {
    // Get verification data from cache
    const verificationData = (await getCachedData(
      `${config.redis_cache_key_prefix}:${AUTH_CONFIG.CACHE_PREFIXES.VERIFICATION}${email}`
    )) as IVerificationData | null;

    if (!verificationData) {
      throw new AppError(
        httpStatus.BAD_REQUEST,
        "Verification code expired or not found"
      );
    }

    if (verificationData.attempts >= 3) {
      throw new AppError(
        httpStatus.TOO_MANY_REQUESTS,
        "Too many verification attempts"
      );
    }

    if (verificationData.code !== code) {
      // Increment attempts
      verificationData.attempts++;
      await cacheData(
        `${config.redis_cache_key_prefix}:${AUTH_CONFIG.CACHE_PREFIXES.VERIFICATION}${email}`,
        verificationData,
        AUTH_CONFIG.VERIFICATION_TOKEN_EXPIRY_MINUTES * 60
      );
      throw new AppError(httpStatus.BAD_REQUEST, "Invalid verification code");
    }

    if (verificationData.expiresAt < Date.now()) {
      throw new AppError(httpStatus.BAD_REQUEST, "Verification code expired");
    }

    // Update user verification status
    const user = await User.findOneAndUpdate(
      { email },
      { isVerified: true },
      { new: true }
    );

    if (!user) {
      throw new AppError(httpStatus.NOT_FOUND, "User not found");
    }

    // Clear verification data from cache
    await deleteCachedData(
      `${config.redis_cache_key_prefix}:${AUTH_CONFIG.CACHE_PREFIXES.VERIFICATION}${email}`
    );

    return { user };
  } catch (error) {
    throw error;
  }
};

/**
 * Resends verification code with rate limiting
 */
const resendVerifyEmailCode = async (email: string): Promise<void> => {
  try {
    // Check rate limiting
    await checkRateLimit(
      `resend:${email}`,
      AUTH_CONFIG.RATE_LIMIT.SIGNUP.MAX_ATTEMPTS,
      AUTH_CONFIG.RATE_LIMIT.SIGNUP.WINDOW_MS
    );

    const user = await User.isUserExistsByEmail(email);
    if (!user) {
      throw new AppError(httpStatus.NOT_FOUND, "User not found");
    }

    if (user.isVerified) {
      throw new AppError(httpStatus.BAD_REQUEST, "User is already verified");
    }

    // Generate new verification code
    const verificationCode = generateVerificationCode();
    const expiresAt =
      Date.now() + AUTH_CONFIG.VERIFICATION_TOKEN_EXPIRY_MINUTES * 60 * 1000;

    // Cache new verification data
    const verificationData: IVerificationData = {
      code: verificationCode,
      expiresAt,
      attempts: 0,
    };

    await cacheData(
      `${AUTH_CONFIG.CACHE_PREFIXES.VERIFICATION}${email}`,
      verificationData,
      AUTH_CONFIG.VERIFICATION_TOKEN_EXPIRY_MINUTES * 60
    );

    // Get email template and replace placeholders
    const emailTemplate = getEmailTemplate("verification-email.html", {
      code: verificationCode,
      expiryTime: AUTH_CONFIG.VERIFICATION_TOKEN_EXPIRY_MINUTES,
      year: new Date().getFullYear(),
    });

    // Send new verification email
    await sendEmail({
      to: email,
      subject: "New Email Verification Code",
      html: emailTemplate,
    });
  } catch (error) {
    throw error;
  }
};

/**
 * Handles user login with rate limiting and account locking
 */
const loginUser = async (
  payload: ILoginUser,
  meta: { ip: string; userAgent: string }
): Promise<{ user: IUser; accessToken: string; refreshToken: string }> => {
  const { email, password } = payload;
  const { ip, userAgent } = meta;

  try {
    // Check rate limiting
    await Promise.all([
      checkRateLimit(
        `login:email:${email}`,
        AUTH_CONFIG.RATE_LIMIT.LOGIN.MAX_ATTEMPTS,
        AUTH_CONFIG.RATE_LIMIT.LOGIN.WINDOW_MS
      ),
      checkRateLimit(
        `login:ip:${ip}`,
        AUTH_CONFIG.RATE_LIMIT.LOGIN.MAX_ATTEMPTS,
        AUTH_CONFIG.RATE_LIMIT.LOGIN.WINDOW_MS
      ),
      checkRateLimit(
        `login:ua:${userAgent}`,
        AUTH_CONFIG.RATE_LIMIT.LOGIN.MAX_ATTEMPTS,
        AUTH_CONFIG.RATE_LIMIT.LOGIN.WINDOW_MS
      ),
    ]);

    // const user = await User.isUserExistsByEmail(email);
    const user = await User.findOne({ email }).select(
      "+password +accountLocked +failedLoginAttempts"
    );
    if (!user) {
      throw new AppError(httpStatus.NOT_FOUND, "Email not found!");
    }

    // Check if account is locked
    if (user.accountLocked) {
      throw new AppError(
        httpStatus.FORBIDDEN,
        "Account is locked. Please try again later."
      );
    }

    const isMatched = await User.isPasswordMatched(password, user.password);
    if (!isMatched) {
      await user.incrementFailedLoginAttempts();
      throw new AppError(httpStatus.FORBIDDEN, "Wrong Password");
    }

    // Reset failed login attempts on successful login
    await user.resetFailedLoginAttempts().catch((err) => {
      console.error("Failed to reset login attempts:", err);
      throw err;
    });

    const sessionId = crypto.randomUUID();
    const sessionKey = `session:${sessionId}`;

    await cacheData(
      sessionKey,
      {
        userId: user._id,
        role: user.role,
        ip,
        userAgent,
        createdAt: Date.now(),
      },
      60 * 60 * 24 * 30 // 30 days
    );

    const jwtPayload: ITokenPayload = {
      sub: user._id.toString(),
      email: user.email,
      role: user.role,
      sessionId,
    };

    const accessToken = createToken(jwtPayload);
    const refreshToken = createToken(jwtPayload, { isRefresh: true });

    // await User.updateOne({ _id: user._id }, { lastLogin: new Date() });
    await User.updateOne(
      { _id: user._id },
      {
        $set: {
          failedLoginAttempts: 0,
          lastLogin: new Date(),
        },
      }
    ).catch((err) => {
      console.error("Failed to update last login:", err);
      throw err;
    });

    // Cache tokens
    // const prefix = config.redis_cache_key_prefix || "auth";
    // await Promise.all([
    //   cacheData(
    //     `${prefix}:user:${email}:accessToken`,
    //     accessToken,
    //     parseInt(config.redis_ttl_access_token as string) || 3600
    //   ),
    //   cacheData(
    //     `${prefix}:user:${email}:refreshToken`,
    //     refreshToken,
    //     parseInt(config.redis_ttl_refresh_token as string) || 604800
    //   ),
    // ]);

    return {
      user,
      accessToken,
      refreshToken,
    };
  } catch (error) {
    throw error;
  }
};

/**
 * Handles password reset request
 */
const forgotPassword = async (email: string): Promise<void> => {
  try {
    // Check rate limiting
    await checkRateLimit(
      `reset:${email}`,
      AUTH_CONFIG.RATE_LIMIT.PASSWORD_RESET.MAX_ATTEMPTS,
      AUTH_CONFIG.RATE_LIMIT.PASSWORD_RESET.WINDOW_MS
    );

    const user = await User.isUserExistsByEmail(email);
    if (!user) {
      throw new AppError(httpStatus.NOT_FOUND, "User not found!");
    }

    const resetToken = crypto
      .randomBytes(AUTH_CONFIG.PASSWORD_RESET_TOKEN_LENGTH)
      .toString("hex");

    const expiresAt =
      Date.now() + AUTH_CONFIG.RESET_TOKEN_EXPIRY_MINUTES * 60 * 1000;

    // Cache reset token data
    const resetData: IResetPasswordData = {
      token: resetToken,
      expiresAt,
      attempts: 0,
    };

    await cacheData(
      `${config.redis_cache_key_prefix}:${AUTH_CONFIG.CACHE_PREFIXES.RESET_PASSWORD}${email}`,
      resetData,
      AUTH_CONFIG.RESET_TOKEN_EXPIRY_MINUTES * 60
    );

    const resetUILink = `${config.reset_pass_ui_link}${resetToken}`;

    // Get email template and replace placeholders
    const emailTemplate = getEmailTemplate("reset-password-email.html", {
      resetLink: resetUILink,
      expiryTime: AUTH_CONFIG.RESET_TOKEN_EXPIRY_MINUTES,
      year: new Date().getFullYear(),
    });

    await sendEmail({
      to: email,
      subject: "Password Reset Request",
      html: emailTemplate,
    });
  } catch (error) {
    throw error;
  }
};

/**
 * Handles password reset with token validation
 */
const resetPassword = async (
  email: string,
  token: string,
  newPassword: string
): Promise<void> => {
  try {
    if (!validatePassword(newPassword)) {
      throw new AppError(
        httpStatus.BAD_REQUEST,
        "Password does not meet security requirements"
      );
    }

    // Get reset token data from cache
    const resetData = (await getCachedData(
      `${config.redis_cache_key_prefix}:${AUTH_CONFIG.CACHE_PREFIXES.RESET_PASSWORD}${email}`
    )) as IResetPasswordData | null;

    if (!resetData) {
      throw new AppError(
        httpStatus.BAD_REQUEST,
        "Reset token expired or not found"
      );
    }

    if (resetData.attempts >= 3) {
      throw new AppError(
        httpStatus.TOO_MANY_REQUESTS,
        "Too many reset attempts"
      );
    }

    if (resetData.token !== token) {
      // Increment attempts
      resetData.attempts++;
      await cacheData(
        `${config.redis_cache_key_prefix}:${AUTH_CONFIG.CACHE_PREFIXES.RESET_PASSWORD}${email}`,
        resetData,
        AUTH_CONFIG.RESET_TOKEN_EXPIRY_MINUTES * 60
      );
      throw new AppError(httpStatus.BAD_REQUEST, "Invalid reset token");
    }

    if (resetData.expiresAt < Date.now()) {
      throw new AppError(httpStatus.BAD_REQUEST, "Reset token expired");
    }

    const user = await User.isUserExistsByEmail(email);
    if (!user) {
      throw new AppError(httpStatus.NOT_FOUND, "User not found");
    }

    // Update password
    const newHashedPassword = await bcrypt.hash(
      newPassword,
      Number(config.bcrypt_salt_rounds)
    );

    await User.findOneAndUpdate({ email }, { password: newHashedPassword });

    // Clear reset token from cache
    await deleteCachedData(
      `${config.redis_cache_key_prefix}:${AUTH_CONFIG.CACHE_PREFIXES.RESET_PASSWORD}${email}`
    );
  } catch (error) {
    throw error;
  }
};

const getUsers = async (filters: any) => {
  const { limit = 100, page = 1, searchTerm = "" } = filters;
  const skip = (Number(page) - 1) * Number(limit);
  const total = await User.countDocuments({});
  const totalPages = Math.ceil(total / Number(limit));
  const hasNextPage = page < totalPages;
  const hasPrevPage = page > 1;

  const searchConditions = {
    $or: [
      { name: { $regex: searchTerm, $options: "i" } },
      { email: { $regex: searchTerm, $options: "i" } },
      { role: { $regex: searchTerm, $options: "i" } },
      { phone: { $regex: searchTerm, $options: "i" } },
    ],
  };

  const users = await User.find(searchConditions)
    .skip(skip)
    .limit(Number(limit))
    .sort({ createdAt: -1 });
  // .select("-password -verificationToken -verificationTokenExpiresAt -resetPasswordToken -resetPasswordExpiresAt");

  if (!users.length) {
    throw new AppError(409, "Users not found");
  }

  return {
    meta: {
      total,
      page: Number(page),
      limit: Number(limit),
      totalPages,
      hasNextPage,
      hasPrevPage,
    },
    data: users,
  };
};

const refreshTokenService = async (res: any, token?: any) => {
  console.log(!token);
  if (!token) {
    console.log("here");
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "You are not authorized. Login first"
    );
  }
  const prefix = config.redis_cache_key_prefix;

  try {
    console.log("here2");
    const decoded = jwt.verify(token, config.jwt_refresh_secret as string);

    const { email } = decoded as JwtPayload;
    console.log("here3");
    const cachedToken = await getCachedData(
      `${config.redis_cache_key_prefix}:user:${email}:refreshToken`
    );
    console.log("cachedToken", cachedToken, token);
    console.log(cachedToken === token);

    if (cachedToken !== token) {
      console.log("entered here");
      removeTokens(res, prefix as string, email);
      throw new AppError(httpStatus.UNAUTHORIZED, "Token is not valid");
    }

    const user = await User.isUserExistsByEmail(email);
    console.log("user comer here", user);
    console.log(!user);

    if (!user) {
      removeTokens(res, prefix as string, email);
      throw new AppError(httpStatus.NOT_FOUND, "This user is not found!");
    }

    const jwtPayload = {
      email: user.email,
      role: user.role as UserRole,
    };

    const accessToken = createToken(jwtPayload);

    await cacheData(
      `${config.redis_cache_key_prefix}:user:${user.email}:accessToken`,
      accessToken,
      10
    );

    return { accessToken };
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }
    if (error instanceof TokenExpiredError) {
      throw new AppError(
        httpStatus.UNAUTHORIZED,
        "Your session has expired. Please login again."
      );
    } else if (error instanceof JsonWebTokenError) {
      console.log(error);
      throw new AppError(
        httpStatus.UNAUTHORIZED,
        "Invalid token. Please login again."
      );
    }
    throw new AppError(httpStatus.UNAUTHORIZED, "Token is not valid");
  }
};

/**
 * Handles role changes with proper authorization checks
 */
const changeRole = async (
  email: string,
  newRole: UserRole,
  currentUser: JwtPayload
): Promise<IUser> => {
  try {
    const user = await User.isUserExistsByEmail(email);
    if (!user) {
      throw new AppError(httpStatus.NOT_FOUND, "User not found!");
    }

    if (!canModifyRole(currentUser.role, user.role, newRole)) {
      throw new AppError(
        httpStatus.FORBIDDEN,
        "You don't have permission to perform this action"
      );
    }

    const updatedUser = await User.findOneAndUpdate(
      { email },
      { role: newRole },
      { new: true }
    );

    if (!updatedUser) {
      throw new AppError(httpStatus.BAD_REQUEST, "Failed to update user role");
    }

    return updatedUser;
  } catch (error) {
    throw error;
  }
};

/**
 * Handles user deletion with proper authorization checks
 */
const deleteUser = async (
  id: string,
  currentUser: JwtPayload
): Promise<IUser> => {
  try {
    const user = await User.findById(id);
    if (!user) {
      throw new AppError(httpStatus.NOT_FOUND, "User not found!");
    }

    if (currentUser.role !== UserRole.SUPER_ADMIN) {
      throw new AppError(
        httpStatus.FORBIDDEN,
        "Only super admin can delete users"
      );
    }

    if (user.role === UserRole.SUPER_ADMIN) {
      throw new AppError(httpStatus.FORBIDDEN, "Cannot delete super admin");
    }

    if (user.email === currentUser.email) {
      throw new AppError(
        httpStatus.FORBIDDEN,
        "Cannot delete your own account"
      );
    }

    const deletedUser = await User.findByIdAndDelete(id);
    if (!deletedUser) {
      throw new AppError(httpStatus.BAD_REQUEST, "Failed to delete user");
    }

    // Clear user's cached data
    await Promise.all([
      deleteCachedData(
        `${config.redis_cache_key_prefix}:user:${user.email}:accessToken`
      ),
      deleteCachedData(
        `${config.redis_cache_key_prefix}:user:${user.email}:refreshToken`
      ),
      deleteCachedData(
        `${config.redis_cache_key_prefix}:${AUTH_CONFIG.CACHE_PREFIXES.VERIFICATION}${user.email}`
      ),
      deleteCachedData(
        `${config.redis_cache_key_prefix}:${AUTH_CONFIG.CACHE_PREFIXES.RESET_PASSWORD}${user.email}`
      ),
    ]);

    return deletedUser;
  } catch (error) {
    throw error;
  }
};

export const AuthServices = {
  signupUser,
  verifyEmail,
  resendVerifyEmailCode,
  loginUser,
  forgotPassword,
  resetPassword,
  getUsers,
  refreshTokenService,
  changeRole,
  deleteUser,
};
