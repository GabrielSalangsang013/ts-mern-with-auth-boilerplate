import dotenv from 'dotenv';
dotenv.config();
import rateLimit from 'express-rate-limit';
// @ts-ignore
import MongoStore from 'rate-limit-mongo';

export const userLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'user-limits', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many user requests, Please try again later.',
});

export const loginLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'login-limits', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many login requests, Please try again later.',
});

export const verificationCodeLoginLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'verification-code-login-limits', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many verification code login requests, Please try again later.',
});

export const verificationCodeLoginLogoutLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'verification-code-login-logout-limits', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many verification code login logout requests, Please try again later.',
});

export const registerLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'register-limits', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many register requests, Please try again later.',
});

export const activateLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'activate-limits', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many activate requests, Please try again later.',
});

export const forgotPasswordLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'forgot-password-limits', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many forgot password requests, Please try again later.',
});

export const resetPasswordLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'reset-password-limits', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many reset password requests, Please try again later.',
});

export const resetPasswordVerifyTokenLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'reset-password-verify-token-limits', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many reset password verify token requests, Please try again later.',
});

export const deleteUserLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'delete-user-limits', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many delete user requests, Please try again later.',
});

export const logoutLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'logout-limits', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many logout requests, Please try again later.',
});

export const enableGoogleAuthenticatorLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'enable-google-authenticator-limiter', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many enable google authenticator requests, Please try again later.',
});

export const activateGoogleAuthenticatorLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'activate-google-authenticator-limiter', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many activate google authenticator requests, Please try again later.',
});

export const disableGoogleAuthenticatorLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env["MONGO_DB_URI_LIMITER"] as string, // * MongoDB connection URI
    collectionName: 'disable-google-authenticator-limiter', // * MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // * Time window in milliseconds
    errorHandler: console.error, // * Optional error handler
  }),
  max: 100, // * Maximum number of requests per time window
  message: 'Too many disable google authenticator requests, Please try again later.',
});