# Express.js Backend Boilerplate Documentation

A production-ready Express.js backend boilerplate with TypeScript, featuring a modular architecture, comprehensive security features, and best practices implementation.

## 📋 Table of Contents
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Core Features](#core-features)
- [Implementation Guidelines](#implementation-guidelines)
- [Security](#security)
- [Error Handling](#error-handling)
- [File Upload](#file-upload)
- [Caching](#caching)
- [Email System](#email-system)
- [Payment Integration](#payment-integration)
- [Development Guide](#development-guide)

## 🏗️ System Architecture

### Core Components
1. **Application Layer**
   - Express.js server setup
   - Middleware configuration
   - Route management
   - Error handling

2. **Service Layer**
   - Business logic implementation
   - External service integration
   - Data processing

3. **Data Layer**
   - MongoDB integration
   - Redis caching
   - File storage (Cloudinary)

### Directory Structure
```
src/
├── __tests__/        # Unit and integration tests
│   ├── modules/        # Tests for individual modules
│   └── setup.ts        # Jest setup file
├── app/
│   ├── config/         # Environment and service configurations
│   ├── errors/         # Custom error handlers and classes
│   ├── helpers/        # Utility helper functions
│   ├── interface/      # TypeScript type definitions
│   ├── middlewares/    # Express middleware functions
│   ├── modules/        # Feature-based modules
│   ├── routes/         # API route definitions
│   ├── shared/         # Shared utilities and constants
│   └── utils/          # Common utility functions
├── app.ts             # Express app configuration
└── server.ts          # Server entry point

templates/              # Email templates (at the root level)
```

## ⚙️ Configuration

### Environment Variables
Create a `.env` file in the project root and populate it with the following variables:

```bash
# Server Configuration
PORT=4000
NODE_ENV=development

# Database
MONGODB_URI=your_mongodb_uri

# Authentication
BCRYPT_SALT_ROUNDS=12
JWT_ACCESS_SECRET=your_access_secret
JWT_ACCESS_EXPIRES_IN=1d
JWT_REFRESH_SECRET=your_refresh_secret
JWT_REFRESH_EXPIRES_IN=7d
JWT_PASSWORD_SECRET=your_password_secret
JWT_PASSWORD_EXPIRES_IN=1h
RESET_PASS_UI_LINK=your_reset_password_ui_link # Link to your frontend password reset page

# Redis Configuration
REDIS_URL=your_redis_url
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password
REDIS_TTL=3600
REDIS_CACHE_KEY_PREFIX=app:
REDIS_TTL_ACCESS_TOKEN=3600
REDIS_TTL_REFRESH_TOKEN=604800

# Cloudinary Configuration
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret

# Email Configuration
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USER=your_email
EMAIL_PASS=your_password

# Payment Gateway (SSLCommerz)
STORE_ID=your_store_id
STORE_PASSWD=your_store_password
IS_LIVE=false
```

## 🔧 Core Features

### 1. Authentication System
- JWT-based authentication using `jsonwebtoken` for secure stateless sessions.
- **Access and Refresh Tokens:**
    - Access tokens for API authorization, sent as HTTP-only cookies.
    - Refresh tokens for obtaining new access tokens, also sent as HTTP-only cookies.
    - Both token types are additionally cached in Redis for enhanced security and control.
- **Email Verification:**
    - New users receive a time-limited verification code via email, stored in Redis.
- **Password Reset:**
    - Secure, time-limited token-based password reset via email, with tokens stored in Redis.
- **Role-Based Access Control (RBAC):**
    - Middleware (`auth.ts`) protects routes based on user roles (e.g., `superAdmin`, `admin`, `customer`).
    - Defined role hierarchy for managing user permissions and role modifications.
- **Additional Security Features:**
    - Password hashing using `bcrypt`.
    - Rate limiting for sensitive actions (signup, login, password reset) using Redis.
    - Account locking mechanism after multiple failed login attempts.
    - Configurable password strength validation.
- **Logout:** Clears tokens from cookies and Redis.

### 2. Error Handling
The boilerplate implements a robust error handling system via the `globalErrorHandler` middleware (`src/app/middlewares/globalErrorhandler.ts`). This middleware catches errors and sends a standardized JSON response.

#### Custom Error Class (`src/app/errors/AppError.ts`)
A custom error class `AppError` is used for application-specific errors:
```typescript
class AppError extends Error {
  public statusCode: number;

  constructor(statusCode: number, message: string, stack = '') {
    super(message);
    this.statusCode = statusCode;

    if (stack) {
      this.stack = stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}
```

#### Specific Error Handlers
The `globalErrorHandler` utilizes helper functions to process specific error types:
- `handleCastError` (`src/app/errors/handleCastError.ts`): Formats MongoDB cast errors.
- `handleDuplicateError` (`src/app/errors/handleDuplicateError.ts`): Formats MongoDB duplicate key errors.
- `handleValidationError` (`src/app/errors/handleValidationError.ts`): Formats Mongoose schema validation errors.
- `handleZodError` (`src/app/errors/handleZodError.ts`): Formats validation errors from `zod` schemas.
- `handleMulterErrors` (`src/app/errors/handleMulterErrors.ts`): A middleware that converts `multer` specific errors into `AppError` instances.

(Refer to "Implementation Guidelines > 3. Error Handling" for more details on how `AppError` is used and the structure of error responses.)

### 3. File Upload System
Handles file uploads (images, PDFs) with Cloudinary integration for storage.
- **Cloudinary Integration:** Uses `cloudinary` and `multer-storage-cloudinary`. Files are uploaded to Cloudinary, with utilities for upload and deletion (`src/app/utils/cloudinary_file_upload.ts`, `src/app/utils/cloudinaryDelete.ts`).
- **Multer Middleware:** Primarily uses `CloudinaryStorage` (configured in `src/app/utils/multerConfig.ts`) for direct streaming to Cloudinary. An alternative local disk storage setup (`src/app/middlewares/multerMiddleware.ts`) also exists, which might be used for specific scenarios.
- **File Type Validation:** Enforced by Multer configurations, supporting various image types and PDFs. PDFs are uploaded as raw files; images can be transformed.
- **Size Restrictions:** File size limits (e.g., 1MB) are enforced, handled by `src/app/errors/handleMulterErrors.ts`.
- **Automatic Cleanup:** Temporary local files (if disk storage is used) are deleted post-upload. Cloudinary files can also be deleted.

(See "Implementation Guidelines > 4. File Upload" for usage examples.)

### 4. Caching System
Utilizes Redis for efficient data caching, managed by helper functions in `src/app/utils/redis.utils.ts`.
- **Redis Integration:** Powered by the `redis` library, configured via `src/app/config/redis.config.ts`.
- **Key Caching Operations:** Includes `cacheData` (with TTL), `getCachedData`, `deleteCachedData` (pattern-based), and `clearAllCachedData`.
- **Common Use Cases:** Token storage, query result caching, rate limiting data, temporary data (e.g., email verification codes, password reset tokens).
- **Cache Invalidation:** Supports targeted deletion and full cache flushing.

(Refer to "Implementation Guidelines > 5. Caching Implementation" for detailed usage.)

### 5. Email System
Facilitates sending transactional emails using `nodemailer` and HTML templates.
- **Nodemailer Integration:** Configured in `src/app/utils/sendEmail.ts` using SMTP credentials from environment variables. Supports secure transport (SSL/TLS).
- **HTML Email Templates:** Located in `templates/` (root directory). A utility `getEmailTemplate` loads and populates templates with dynamic data.
- **Key Use Cases:** Email verification codes, password reset links.

(Refer to "Email System Implementation" for more details.)

## Prerequisites

Before you begin, ensure you have the following installed:
- **Node.js**: Version `20.16.0` or later is recommended (as per `Dockerfile`). You can use [nvm](https://github.com/nvm-sh/nvm) to manage Node.js versions.
- **npm**: Bundled with Node.js.
- **MongoDB**: A running MongoDB instance. Ensure it's accessible and provide the connection URI in your `.env` file.
- **Redis**: A running Redis instance. Ensure it's accessible and configure connection details in your `.env` file.
- **Docker (Optional)**: For running the application in a containerized environment. See "Docker Deployment" section.

## 🛠️ Implementation Guidelines

### 1. Creating New Modules
```typescript
// 1. Create module structure
modules/
  └── YourModule/
      ├── controller.ts
      ├── service.ts
      ├── model.ts
      ├── validation.ts
      └── routes.ts

// 2. Implement controller
export const createItem = catchAsync(async (req: Request, res: Response) => {
  const result = await YourService.createItem(req.body);
  sendResponse(res, {
    statusCode: httpStatus.CREATED,
    success: true,
    data: result
  });
});

// 3. Add routes
router.post('/', validateRequest(YourValidation.createSchema), createItem);
```

### 2. Using Middleware
```typescript
// Authentication middleware
router.use(auth());

// File upload middleware
// Assuming 'upload' is your configured Multer instance (e.g., from src/app/utils/multerConfig.ts)
router.post('/upload', 
  upload.single('file'), // 'upload' is the variable holding the multer instance
  uploadController
);

// Request validation
router.post('/create',
  validateRequest(validationSchema),
  controller
);
```

### 3. Error Handling
```typescript
try {
  // Your code
} catch (error) {
  throw new AppError('Error message', httpStatus.BAD_REQUEST);
}
```

### 4. File Upload
Example using `multer` with `multer-storage-cloudinary` (setup similar to `src/app/utils/multerConfig.ts`):

```typescript
import multer from 'multer';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import cloudinary from './path-to-your-cloudinary-config'; // Import your Cloudinary instance

// Configure Cloudinary storage (example, actual config in `src/app/utils/multerConfig.ts`)
const storage = new CloudinaryStorage({
  cloudinary: cloudinary, // Your configured Cloudinary instance from `src/app/utils/cloudinary.ts`
  params: {
    folder: 'your-app-folder', // Example folder in Cloudinary
    format: async (req: any, file: any) => 'png', // Or dynamically determine format like path.extname(file.originalname).substring(1)
    public_id: (req: any, file: any) => file.originalname.split('.')[0] + '-' + Date.now(), // Example public_id
  } as Record<string, unknown>,
});

// Configure multer instance
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 1 * 1024 * 1024 // Example: 1MB limit (consistent with handleMulterErrors)
  },
  fileFilter: (req, file, cb) => {
    // Add your file filter logic here (e.g., check mimetypes)
    // Example:
    // const allowedTypes = ['image/jpeg', 'image/png'];
    // if (allowedTypes.includes(file.mimetype)) {
    //   cb(null, true);
    // } else {
    //   cb(new Error('Invalid file type'));
    // }
    cb(null, true); // Basic accept all for example
  }
});

// Use in a route
// Assuming 'uploadController' handles the logic after file processing by multer
router.post('/upload', upload.single('file'), uploadController);
```
The `handleMulterErrors` middleware will catch size limit errors and other multer-specific issues.

### 5. Caching Implementation
```typescript
// Cache data with TTL
await cacheData(
  'cache-key',
  { data: 'value' },
  3600 // TTL in seconds
);

// Retrieve cached data
const cachedData = await getCachedData('cache-key');

// Delete cached data by pattern
await deleteCachedData('pattern*');

// Clear all cached data
await clearAllCachedData();
```

The Redis caching system provides the following utilities:

1. **cacheData**
   - Caches data with a specified TTL (Time To Live)
   - Automatically serializes data to JSON
   - Logs errors if caching operations fail

2. **getCachedData**
   - Retrieves cached data by key
   - Automatically deserializes JSON data
   - Returns null if data doesn't exist or on error

3. **deleteCachedData**
   - Deletes cached data matching a pattern
   - Supports wildcard patterns
   - Handles multiple key deletion

4. **clearAllCachedData**
   - Clears all cached data from Redis
   - Useful for cache invalidation

Example usage in a service:
```typescript
// In your service file
const getData = async (id: string) => {
  // Try to get from cache first
  const cachedData = await getCachedData(`data:${id}`);
  if (cachedData) {
    return cachedData;
  }

  // If not in cache, get from database
  const data = await YourModel.findById(id);
  
  // Cache the result
  await cacheData(`data:${id}`, data, 3600); // Cache for 1 hour
  
  return data;
};
```

## 🔒 Security Features

### 1. Authentication
- JWT token-based authentication
- Refresh token rotation
- Token blacklisting
- Password hashing with bcrypt

### 2. Request Validation
- Zod schema validation
- Input sanitization
- Type checking

### 3. File Upload Security
- File type validation
- Size restrictions
- Secure storage
- Automatic cleanup

### 4. API Security
- CORS protection
- Rate limiting
- XSS protection
- SQL injection prevention

## 📧 Email System Implementation

### 1. Email Templates
Located in `templates/`:
- `verification-email.html`
- `reset-password-email.html`

### 2. Sending Emails
```typescript
await sendEmail({
  to: user.email,
  subject: 'Email Verification',
  html: verificationEmailTemplate
});
```

## 💳 Payment Integration

### SSLCommerz Integration
```typescript
const sslcommerz = new SSLCommerz(
  config.store_id,
  config.store_passwd,
  config.is_live === 'true'
);

// Create payment session
const paymentSession = await sslcommerz.initiatePayment({
  // payment details
});
```

## 🚀 Development Guide

### 1. Setup Development Environment
```bash
# Install dependencies
npm install

# Create .env file (if .env.example exists)
# cp .env.example .env

# Start development server
npm run dev
```

### 2. Running Tests
The project uses Jest for testing.
```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate test coverage report
npm run test:coverage
```

### 3. Building and Running for Production (Standalone)
If you are not using Docker for production, you'll need to build the TypeScript code into JavaScript and then run the compiled output.

1.  **Build the application:**
    The `tsconfig.json` is configured to output compiled files to the `dist` directory.
    ```bash
    # Compile TypeScript to JavaScript
    npx tsc
    ```
    You might want to add this as a `build` script in your `package.json` (if not already present):
    ```json
    {
      "scripts": {
        "dev": "ts-node-dev --respawn --transpile-only src/server.ts",
        "test": "jest",
        "test:watch": "jest --watch",
        "test:coverage": "jest --coverage",
        "build": "tsc"
      }
    }
    ```
    If you add the script, you can then run `npm run build`.

2.  **Run the built application:**
    After a successful build, run the application using Node.js:
    ```bash
    # Set NODE_ENV to production for optimal performance and ensure .env is configured for production
    NODE_ENV=production node dist/server.js
    ```

### 4. Docker Deployment
```bash
# Build and run with Docker
docker-compose up --build
```
Note: The current `Dockerfile` is configured to run the application in development mode using `npm run dev`. For a production deployment, you would typically modify the `Dockerfile` to build the TypeScript source into JavaScript and run that with Node.js directly.

## 📝 Best Practices

1. **Code Organization**
   - Follow modular architecture
   - Keep controllers thin
   - Implement proper separation of concerns

2. **Error Handling**
   - Use custom error classes
   - Implement proper error logging
   - Handle all possible error scenarios

3. **Security**
   - Validate all inputs
   - Implement proper authentication
   - Use environment variables
   - Follow security best practices

4. **Performance**
   - Implement caching where appropriate
   - Optimize database queries
   - Use proper indexing

## 📚 Additional Resources

- [Express.js Documentation](https://expressjs.com/)
- [TypeScript Documentation](https://www.typescriptlang.org/)
- [MongoDB Documentation](https://docs.mongodb.com/)
- [Redis Documentation](https://redis.io/documentation)
- [Cloudinary Documentation](https://cloudinary.com/documentation)
- [SSLCommerz Documentation](https://developer.sslcommerz.com/)

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

ISC License