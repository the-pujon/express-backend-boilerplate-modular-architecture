import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import httpStatus from 'http-status';
import { User } from '../../app/modules/Auth/auth.model';
import { getCachedData } from '../../app/utils/redis.utils';
import { auth } from '../../app/middlewares/auth';
import AppError from '../../app/errors/AppError';
import config from '../../app/config';
import { ROLE_PERMISSIONS } from '../../app/modules/Auth/auth.permissions';
import { UserRole } from '../../app/modules/Auth/auth.interface';

// Mock dependencies
jest.mock('jsonwebtoken');
jest.mock('../../app/modules/Auth/auth.model');
jest.mock('../../app/utils/redis.utils');
jest.mock('../../app/config', () => ({
  jwt_access_secret: 'test_access_secret',
  redis_cache_key_prefix: 'test_prefix',
}));
// No need to mock ROLE_PERMISSIONS if using actual values, but ensure it's correctly imported/used
// jest.mock('../../app/modules/Auth/auth.permissions');


describe('Auth Middleware', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockRequest = {
      cookies: {},
    };
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    mockNext = jest.fn();
    jest.clearAllMocks(); // Clear mocks before each test
  });

  describe('Token Checks', () => {
    it('should throw UNAUTHORIZED if no token is provided', async () => {
      const middleware = auth('SOME_PERMISSION');
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
      const error = (mockNext as jest.Mock).mock.calls[0][0] as AppError;
      expect(error.statusCode).toBe(httpStatus.UNAUTHORIZED);
      expect(error.message).toBe('You are not authorized. Login first');
    });

    it('should throw UNAUTHORIZED if jwt.verify throws JsonWebTokenError', async () => {
      mockRequest.cookies.accessToken = 'malformed-token';
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new jwt.JsonWebTokenError('jwt malformed');
      });

      const middleware = auth('SOME_PERMISSION');
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
      const error = (mockNext as jest.Mock).mock.calls[0][0] as AppError;
      expect(error.statusCode).toBe(httpStatus.UNAUTHORIZED);
      expect(error.message).toBe('Invalid token. Please login again.');
    });

    it('should throw UNAUTHORIZED if jwt.verify throws TokenExpiredError', async () => {
      mockRequest.cookies.accessToken = 'expired-token';
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new jwt.TokenExpiredError('jwt expired', new Date());
      });

      const middleware = auth('SOME_PERMISSION');
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
      const error = (mockNext as jest.Mock).mock.calls[0][0] as AppError;
      expect(error.statusCode).toBe(httpStatus.UNAUTHORIZED);
      expect(error.message).toBe('Your session has expired. Please login again.');
    });

    it('should throw UNAUTHORIZED if token is not in cache', async () => {
      mockRequest.cookies.accessToken = 'valid-token-not-in-cache';
      (jwt.verify as jest.Mock).mockReturnValue({ email: 'test@example.com', role: UserRole.CUSTOMER });
      (getCachedData as jest.Mock).mockResolvedValue(null); // Not in cache

      const middleware = auth('SOME_PERMISSION');
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
      const error = (mockNext as jest.Mock).mock.calls[0][0] as AppError;
      expect(error.statusCode).toBe(httpStatus.UNAUTHORIZED);
      expect(error.message).toBe('Token is not valid');
    });

     it('should throw UNAUTHORIZED if cached token does not match provided token', async () => {
      mockRequest.cookies.accessToken = 'provided-token';
      (jwt.verify as jest.Mock).mockReturnValue({ email: 'test@example.com', role: UserRole.CUSTOMER });
      (getCachedData as jest.Mock).mockResolvedValue('different-cached-token'); // Different token in cache

      const middleware = auth('SOME_PERMISSION');
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
      const error = (mockNext as jest.Mock).mock.calls[0][0] as AppError;
      expect(error.statusCode).toBe(httpStatus.UNAUTHORIZED);
      expect(error.message).toBe('Token is not valid');
    });
  });

  describe('User and Permission Checks', () => {
    const mockUserPayload = {
      email: 'test@example.com',
      role: UserRole.ADMIN, // Example role
      // Any other fields expected in JWT payload
    };
    const mockDbUser = {
      _id: 'userId123',
      email: 'test@example.com',
      role: UserRole.ADMIN,
      // Other user fields
    };

    beforeEach(() => {
      // Common setup for these tests
      mockRequest.cookies.accessToken = 'valid-token';
      (jwt.verify as jest.Mock).mockReturnValue(mockUserPayload);
      (getCachedData as jest.Mock).mockResolvedValue('valid-token'); // Token is in cache and matches
    });

    it('should throw NOT_FOUND if user does not exist in DB', async () => {
      (User.isUserExistsByEmail as jest.Mock).mockResolvedValue(null);

      const middleware = auth('ANY_PERMISSION');
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
      const error = (mockNext as jest.Mock).mock.calls[0][0] as AppError;
      expect(error.statusCode).toBe(httpStatus.NOT_FOUND);
      expect(error.message).toBe('This user is not found!');
    });

    it('should call next() if user has the single required permission', async () => {
      (User.isUserExistsByEmail as jest.Mock).mockResolvedValue(mockDbUser);
      // Assuming UserRole.ADMIN has PERMISSIONS.MANAGE_USERS_VIEW (as per previous setup)
      const requiredPermission = ROLE_PERMISSIONS[UserRole.ADMIN][0]; // Get a permission admin has

      const middleware = auth(requiredPermission);
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(); // No error
      expect(mockRequest.user).toEqual(mockUserPayload);
    });

    it('should call next() if user has all multiple required permissions', async () => {
      (User.isUserExistsByEmail as jest.Mock).mockResolvedValue(mockDbUser);
      // Select a few permissions that UserRole.ADMIN has
      const requiredPermissions = [
        ROLE_PERMISSIONS[UserRole.ADMIN][0],
        ROLE_PERMISSIONS[UserRole.ADMIN][1],
      ].filter(Boolean); // Ensure we don't pass undefined if role has <2 permissions

      if (requiredPermissions.length < 2) {
        console.warn(`Skipping multi-permission test for ${UserRole.ADMIN} as it has less than 2 permissions defined.`);
        return;
      }

      const middleware = auth(...requiredPermissions);
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith();
      expect(mockRequest.user).toEqual(mockUserPayload);
    });

    it('should throw FORBIDDEN if user lacks a single required permission', async () => {
      (User.isUserExistsByEmail as jest.Mock).mockResolvedValue(mockDbUser);
      const unassignedPermission = 'A_PERMISSION_ADMIN_DOES_NOT_HAVE';

      const middleware = auth(unassignedPermission);
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
      const error = (mockNext as jest.Mock).mock.calls[0][0] as AppError;
      expect(error.statusCode).toBe(httpStatus.FORBIDDEN);
      expect(error.message).toBe('You do not have sufficient permissions for this action');
    });

    it('should throw FORBIDDEN if user lacks one of multiple required permissions', async () => {
      (User.isUserExistsByEmail as jest.Mock).mockResolvedValue(mockDbUser);
      const assignedPermission = ROLE_PERMISSIONS[UserRole.ADMIN][0];
      const unassignedPermission = 'A_PERMISSION_ADMIN_DOES_NOT_HAVE_EITHER';


      const middleware = auth(assignedPermission, unassignedPermission);
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
      const error = (mockNext as jest.Mock).mock.calls[0][0] as AppError;
      expect(error.statusCode).toBe(httpStatus.FORBIDDEN);
      expect(error.message).toBe('You do not have sufficient permissions for this action');
    });

    it('should throw FORBIDDEN if user role has no permissions defined and a permission is required', async () => {
        const customerUserPayload = { email: 'customer@example.com', role: UserRole.CUSTOMER };
        const customerDbUser = { ...mockDbUser, role: UserRole.CUSTOMER };
        (jwt.verify as jest.Mock).mockReturnValue(customerUserPayload);
        (User.isUserExistsByEmail as jest.Mock).mockResolvedValue(customerDbUser);

        // Assuming ROLE_PERMISSIONS[UserRole.CUSTOMER] might be an empty array or not contain 'SPECIFIC_CUSTOMER_PERMISSION'
        // For this test, let's ensure customer has specific permissions that DON'T include the one we're testing against.
        // Or, more directly, test against a permission they definitely don't have.

        const nonCustomerPermission = 'MANAGE_USERS_VIEW'; // A permission customer typically doesn't have

        const middleware = auth(nonCustomerPermission);
        await middleware(mockRequest as Request, mockResponse as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
        const error = (mockNext as jest.Mock).mock.calls[0][0] as AppError;
        expect(error.statusCode).toBe(httpStatus.FORBIDDEN);
        expect(error.message).toBe('You do not have sufficient permissions for this action');
    });


    it('should throw FORBIDDEN if auth is called with a permission that does not exist in PERMISSIONS enum (conceptually, relies on ROLE_PERMISSIONS mapping)', async () => {
      (User.isUserExistsByEmail as jest.Mock).mockResolvedValue(mockDbUser);
      // This tests if a route is defined with a typo or a non-existent permission string
      const middleware = auth('NON_EXISTENT_PERMISSION_STRING');
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
      const error = (mockNext as jest.Mock).mock.calls[0][0] as AppError;
      expect(error.statusCode).toBe(httpStatus.FORBIDDEN);
      // The message comes because 'NON_EXISTENT_PERMISSION_STRING' won't be in the user's role's permission list
      expect(error.message).toBe('You do not have sufficient permissions for this action');
    });
  });

   describe('Edge Cases', () => {
    it('should throw an error if JWT secret is not configured (though mocked here)', async () => {
      // Temporarily unmock config and set secret to undefined
      jest.unmock('../../app/config');
      const originalConfig = config.jwt_access_secret;
      (config as any).jwt_access_secret = undefined; // Or null

      mockRequest.cookies.accessToken = 'any-token';

      const middleware = auth('SOME_PERMISSION');
      // We expect the middleware to throw directly or pass an AppError to next
      // For this specific check, the error is thrown during jwt.verify or earlier if secret is checked upfront
      // In the current auth middleware, jwt.verify will throw if secret is bad.

      // Restore original behavior if jwt.verify is not designed to throw on bad secret type but on use
      (jwt.verify as jest.Mock).mockImplementation(() => {
         if (!config.jwt_access_secret) throw new Error("Test: JWT secret missing"); // Simulate internal error
      });

      await middleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(Error)); // Could be AppError or generic Error
      const error = (mockNext as jest.Mock).mock.calls[0][0];
      // Check if it's the specific AppError for missing secret, or a generic one if jwt.verify fails first
      // Based on current auth.ts, it's caught and re-thrown as AppError or JsonWebTokenError.
      // If the check for jwt_access_secret is at the start of the middleware:
      // expect(error.message).toBe('Server error: JWT secret is not configured');
      // If jwt.verify is the first to use it and fails:
      // This depends on how jwt.verify handles a null/undefined secret. It usually throws TypeError.
      // Let's assume our middleware catches this and returns a specific AppError.
      // The current middleware has a check: `if (!config.jwt_access_secret)`
      // This path is hard to test precisely with the current mock structure for jwt.verify itself.
      // The provided auth.ts has a check:
      // if (!config.jwt_access_secret) { ... throw new AppError(...) }
      // This means it should be an AppError with INTERNAL_SERVER_ERROR.

      // Let's adjust the mock to truly simulate the config being undefined when the middleware runs
      jest.resetModules(); // Reset modules to re-import with new mock value (if needed)
      jest.mock('../../app/config', () => ({
        // Original mocks
        redis_cache_key_prefix: 'test_prefix',
        // jwt_access_secret is deliberately omitted or set to undefined
        jwt_access_secret: undefined,
      }));

      // Re-import auth after config mock is changed
      const authMiddlewareWithMissingSecret = require('../../app/middlewares/auth').auth;

      const newMiddleware = authMiddlewareWithMissingSecret('SOME_PERMISSION');
      await newMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(expect.any(AppError));
      const appError = (mockNext as jest.Mock).mock.calls[0][0] as AppError;
      expect(appError.statusCode).toBe(httpStatus.INTERNAL_SERVER_ERROR);
      expect(appError.message).toBe('Server error: JWT secret is not configured');

      // Restore original config mock for other tests
      jest.unmock('../../app/config');
      jest.mock('../../app/config', () => ({
        jwt_access_secret: 'test_access_secret',
        redis_cache_key_prefix: 'test_prefix',
      }));
      (config as any).jwt_access_secret = originalConfig; // Restore for safety
    });
  });
});
