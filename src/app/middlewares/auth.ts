// import { NextFunction, Request, Response } from "express";
// // import catchAsync from "../utils/catchAsync.";
// import AppError from "../errors/AppError";
// import httpStatus from "http-status";
// import jwt, {
//   JsonWebTokenError,
//   JwtPayload,
//   TokenExpiredError,
// } from "jsonwebtoken";
// // import config from "../config";
// // import { UserModel } from "../modules/auth/auth.model";
// import { getCachedData } from "../utils/redis.utils";
// // import UserModel from "../modules/auth/auth.model";
// import config from "../config";
// import { User } from "../modules/Auth/auth.model";
// import catchAsync from "../utils/catchAsync";

// export const auth = (...requiredRoles: ("admin" | "moderator" | "superAdmin")[]) => {
//   return catchAsync(async (req: Request, res: Response, next: NextFunction) => {
//     const token = req.cookies.accessToken

//     if (!token) {
//       throw new AppError(
//         httpStatus.UNAUTHORIZED,
//         "You are not authorized. Login first",
//       );
//     }

//     try {
//       const decoded = jwt.verify(token, config.jwt_access_secret as string);

//       const { email, role } = decoded as JwtPayload;

//       // console.log(email, role)

//       const cachedToken = await getCachedData(`${config.redis_cache_key_prefix}:user:${email}:accessToken`);

//       if (cachedToken !== token) {
//         // console.log("here is cached token", cachedToken)
//         throw new AppError(httpStatus.UNAUTHORIZED, "Token is not valid");
//       }

//       const user = await User.isUserExistsByEmail(email);

//       if (!user) {
//         throw new AppError(httpStatus.NOT_FOUND, "This user is not found!");
//       }

//       if (requiredRoles && !requiredRoles.includes(role)) {
//         // console.log("here is a required role")
//         throw new AppError(
//           httpStatus.UNAUTHORIZED,
//           "You have no access to this route",
//         );
//       }

//       req.user = decoded as JwtPayload;
//       next();
//     } catch (error) {
//       if (error instanceof TokenExpiredError) {
//         throw new AppError(
//           httpStatus.UNAUTHORIZED,
//           "Your session has expired. Please login again.",
//         );
//       } else if (error instanceof JsonWebTokenError) {
//         throw new AppError(
//           httpStatus.UNAUTHORIZED,
//           "Invalid token. Please login again.",
//         );
//       }
//       throw error;
//     }
//   });
// };

// import { NextFunction, Request, Response } from "express";
// import AppError from "../errors/AppError";
// import httpStatus from "http-status";
// import jwt, {
//   JsonWebTokenError,
//   JwtPayload,
//   TokenExpiredError,
// } from "jsonwebtoken";
// import { getCachedData } from "../utils/redis.utils";
// import config from "../config";
// import { User } from "../modules/Auth/auth.model";
// import catchAsync from "../utils/catchAsync";

// export const auth = (...requiredRoles: ("admin" | "moderator" | "superAdmin" | "customer" | "seller")[]) => {
//   return catchAsync(async (req: Request, res: Response, next: NextFunction) => {
//     const token = req.cookies.accessToken;

//     // console.log("here is the token", token)

//     if (!token) {
//       throw new AppError(
//         httpStatus.UNAUTHORIZED,
//         "You are not authorized. Login first"
//       );
//     }

//     // 🔐 Validate secret before using
//     if (!config.jwt_access_secret) {
//       console.error("❌ JWT_ACCESS_SECRET is missing in config.ts or .env");
//       throw new AppError(
//         httpStatus.INTERNAL_SERVER_ERROR,
//         "Server error: JWT secret is not configured"
//       );
//     }

//     try {
//       const decoded = jwt.verify(token, config.jwt_access_secret) as JwtPayload;
//       const { email, role } = decoded;

//       const cachedToken = await getCachedData(
//         `${config.redis_cache_key_prefix}:user:${email}:accessToken`
//       );

//       if (cachedToken !== token) {
//         throw new AppError(httpStatus.UNAUTHORIZED, "Token is not valid");
//       }

//       const user = await User.isUserExistsByEmail(email);
//       if (!user) {
//         throw new AppError(httpStatus.NOT_FOUND, "This user is not found!");
//       }

//       if (requiredRoles.length && !requiredRoles.includes(role)) {
//         throw new AppError(
//           httpStatus.UNAUTHORIZED,
//           "You have no access"
//         );
//       }

//       req.user = decoded;
//       next();
//     } catch (error) {
//       if (error instanceof TokenExpiredError) {
//         throw new AppError(
//           httpStatus.UNAUTHORIZED,
//           "Your session has expired. Please login again."
//         );
//       } else if (error instanceof JsonWebTokenError) {
//         throw new AppError(
//           httpStatus.UNAUTHORIZED,
//           "Invalid token. Please login again."
//         );
//       }
//       throw error;
//     }
//   });
// };

import { NextFunction, Request, Response } from "express";
import jwt, {
  JsonWebTokenError,
  JwtPayload,
  TokenExpiredError,
} from "jsonwebtoken";
import httpStatus from "http-status";

import AppError from "../errors/AppError";
import config from "../config";
import { getCachedData } from "../utils/redis.utils";
import { User } from "../modules/Auth/auth.model";
import catchAsync from "../utils/catchAsync";

type Role = "admin" | "moderator" | "superAdmin" | "customer" | "seller";

/**
 *
 * Middleware to authenticate and authorize users based on JWT tokens and roles.`
 * @param requiredRoles - Array of roles required to access the route.
 * @throws AppError - Throws errors for unauthorized access, invalid tokens, and server misconfigurations.
 * @returns Middleware function for Express.js
 * First, it checks for the presence of a JWT token in cookies. If absent, it throws an unauthorized error.
 * It verifies the token using a secret key from the configuration. If the token is expired or invalid, it throws appropriate errors.
 * The middleware checks if the token matches the one stored in Redis cache for the user. If not, it throws an unauthorized error.
 * It verifies if the user exists in the database. If not, it throws a not found error.
 * Finally, it checks if the user's role is included in the required roles for the route. If not, it throws a forbidden error.
 * If all checks pass, it attaches the decoded token payload to the request object and calls the next middleware.
 */
export const auth = (...requiredRoles: Role[]) =>
  catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies?.accessToken;

    if (!token) {
      throw new AppError(
        httpStatus.UNAUTHORIZED,
        "You are not authorized. Login first"
      );
    }

    if (!config.jwt_access_secret) {
      console.error("JWT_ACCESS_SECRET is missing");
      throw new AppError(
        httpStatus.INTERNAL_SERVER_ERROR,
        "Server misconfiguration"
      );
    }

    let decoded: JwtPayload;

    try {
      decoded = jwt.verify(token, config.jwt_access_secret) as JwtPayload;
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        throw new AppError(
          httpStatus.UNAUTHORIZED,
          "Session expired. Login again."
        );
      }
      if (error instanceof JsonWebTokenError) {
        throw new AppError(
          httpStatus.UNAUTHORIZED,
          "Invalid token. Login again."
        );
      }
      throw error;
    }

    const { email, role } = decoded;

    const redisKey = `${config.redis_cache_key_prefix}:user:${email}:accessToken`;
    const cachedToken = await getCachedData(redisKey);

    if (cachedToken !== token) {
      throw new AppError(httpStatus.UNAUTHORIZED, "Token is not valid");
    }

    const user = await User.isUserExistsByEmail(email);
    if (!user) {
      throw new AppError(httpStatus.NOT_FOUND, "User not found");
    }

    if (requiredRoles.length && !requiredRoles.includes(role)) {
      throw new AppError(httpStatus.FORBIDDEN, "Access denied");
    }

    req.user = decoded;
    next();
  });
