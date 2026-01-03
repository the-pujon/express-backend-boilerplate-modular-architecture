import { UserRole } from "./auth.interface";

export const AUTH_CONFIG = {
  // Token settings
  VERIFICATION_TOKEN_LENGTH: 6,
  VERIFICATION_TOKEN_EXPIRY_MINUTES: 10,
  RESET_TOKEN_EXPIRY_MINUTES: 10,
  PASSWORD_RESET_TOKEN_LENGTH: 20,

  // Cache settings
  CACHE_PREFIXES: {
    VERIFICATION: "verification:",
    RESET_PASSWORD: "reset:",
    USER_TOKENS: "user:tokens:",
    RATE_LIMIT: "ratelimit:",
  },

  // Rate limiting
  RATE_LIMIT: {
    LOGIN: {
      WINDOW_MS: 15 * 60 * 1000, // 15 minutes
      MAX_ATTEMPTS: 20,
    },
    SIGNUP: {
      WINDOW_MS: 60 * 60 * 1000, // 1 hour
      MAX_ATTEMPTS: 20,
    },
    PASSWORD_RESET: {
      WINDOW_MS: 60 * 60 * 1000, // 1 hour
      MAX_ATTEMPTS: 20,
    },
  },

  // Role hierarchy
  ROLE_HIERARCHY: {
    [UserRole.SUPER_ADMIN]: 4,
    [UserRole.ADMIN]: 3,
    [UserRole.MODERATOR]: 2,
    [UserRole.CUSTOMER]: 1,
  },

  // Security settings
  PASSWORD_MIN_LENGTH: 8,
  PASSWORD_REQUIREMENTS: {
    UPPERCASE: true,
    LOWERCASE: true,
    NUMBERS: true,
    SPECIAL_CHARS: true,
  },
} as const;
