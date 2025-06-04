import { Model } from "mongoose";

export enum UserRole {
  SUPER_ADMIN = "superAdmin",
  ADMIN = "admin",
  MODERATOR = "moderator",
  CUSTOMER = "customer",
  SELLER = "seller",
}

export interface IUser {
  name: string;
  email: string;
  phone: string;
  password?: string; // Made optional
  role: UserRole;
  provider?: 'local' | 'google' | 'facebook' | string; // Added provider
  providerId?: string | null; // Added providerId
  lastLogin: Date;
  isVerified: boolean;
  failedLoginAttempts?: number;
  lastFailedLogin?: Date;
  accountLocked?: boolean;
  accountLockedUntil?: Date;
  // Instance methods
  isAccountLocked(): boolean;
  incrementFailedLoginAttempts(): Promise<void>;
  resetFailedLoginAttempts(): Promise<void>;
}

export interface ILoginUser {
  email: string;
  password: string;
}

export interface IUserModel extends Model<IUser> {
  isUserExistsByEmail(email: string): Promise<IUser | null>;
  isPasswordMatched(
    plainTextPassword: string,
    hashedPassword: string
  ): Promise<boolean>;
}

export interface ITokenPayload {
  email: string;
  role: UserRole;
  iat?: number;
  exp?: number;
}

export interface IAuthResponse {
  user: IUser;
  accessToken: string;
  refreshToken: string;
}

export interface IPaginationParams {
  page?: number;
  limit?: number;
  searchTerm?: string;
}

export interface IPaginatedResponse<T> {
  meta: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
    hasNextPage: boolean;
    hasPrevPage: boolean;
  };
  data: T[];
}

// Token management interfaces
export interface ITokenData {
  token: string;
  expiresAt: number;
}

export interface IVerificationData {
  code: string;
  expiresAt: number;
  attempts: number;
}

export interface IResetPasswordData {
  token: string;
  expiresAt: number;
  attempts: number;
}
