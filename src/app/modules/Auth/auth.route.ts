import express from 'express';

import validateRequest from '../../middlewares/validateRequest';
import { AuthControllers } from './auth.controller';
import { AuthValidation } from './auth.validation';
import { auth } from '../../middlewares/auth';
import { PERMISSIONS } from './auth.permissions';


const router = express.Router();

router.post(
  '/signup',
  validateRequest(AuthValidation.userValidationZodSchema),
  AuthControllers.signupUser,
);
router.post(
  '/login',
  validateRequest(AuthValidation.loginValidationSchema),
  AuthControllers.loginUser,
);
router.post(
  '/logout',
  AuthControllers.logout,
);
router.get(
  '/users',
  auth(PERMISSIONS.MANAGE_USERS_VIEW),
  AuthControllers.getUsers,
);
router.post(
  '/forgot-password',
  AuthControllers.forgotPassword,
);
router.post(
  '/reset-password/:token',
  AuthControllers.resetPassword,
);
router.post(
  '/verify-email',
  AuthControllers.verifyEmail,
);
router.post(
  '/resend-Verify-Email-Code',
  validateRequest(AuthValidation.resendVerifyEmailCode),
  AuthControllers.resendVerifyEmailCode,
);

router.post("/refresh-token", AuthControllers.refreshTokenController);
router.patch(
  '/change-role',
  auth(PERMISSIONS.MANAGE_USERS_EDIT_ROLE),
  AuthControllers.changeRole,
);

router.delete(
  '/delete-user/:id',
  auth(PERMISSIONS.MANAGE_USERS_DELETE),
  AuthControllers.deleteUser,
);



export const AuthRoutes = router;
