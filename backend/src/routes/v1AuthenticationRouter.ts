import express from 'express';

// * ------------ CONTROLLERS --------------------
import v1AuthenticationController from '../controllers/v1AuthenticationController.js';
// * ------------ CONTROLLERS --------------------

// * ------------ middleware --------------------
import * as middlewareLimiter from '../middlewares/v1AuthenticationLimiter.js';
import * as middleware from '../middlewares/index.js';
// * ------------ middleware --------------------

const router = express.Router();

// * API THAT VERIFY PUBLIC CSRF TOKEN IN THE MIDDLEWARE
router.post('/register', 
    middlewareLimiter.registerLimiter, 
    middleware.verifyPublicCSRFToken, 
    v1AuthenticationController.register);

router.post('/login', 
    middlewareLimiter.loginLimiter, 
    middleware.verifyPublicCSRFToken, 
    v1AuthenticationController.login);

router.post('/activate', 
    middlewareLimiter.activateLimiter, 
    middleware.verifyPublicCSRFToken, 
    v1AuthenticationController.activate);

router.post('/forgot-password', 
    middlewareLimiter.forgotPasswordLimiter,
    middleware.verifyPublicCSRFToken, 
    v1AuthenticationController.forgotPassword);

// * API TWO/MULTI FACTOR AUTHENTICATION
router.post('/verification-code-login', 
    middlewareLimiter.verificationCodeLoginLimiter, 
    middleware.verifyPublicCSRFToken, 
    v1AuthenticationController.verificationCodeLogin);

router.post('/verification-code-login/logout', 
    middlewareLimiter.verificationCodeLoginLogoutLimiter, 
    middleware.verifyPublicCSRFToken, 
    v1AuthenticationController.verificationCodeLoginLogout);

router.post('/google-authenticator-code-login', 
    middlewareLimiter.verificationCodeLoginLimiter,
    middleware.verifyPublicCSRFToken, 
    v1AuthenticationController.googleAuthenticatorCodeLogin);

// * API SINGLE SIGN ON
router.post('/sso/sign-in/google-identity-services', 
    middlewareLimiter.loginLimiter, 
    middleware.verifyPublicCSRFToken, 
    v1AuthenticationController.ssoSignInGoogleIdentityServices);

router.post('/sso/sign-up/google-identity-services', 
    middlewareLimiter.loginLimiter, 
    middleware.verifyPublicCSRFToken, 
    v1AuthenticationController.ssoSignUpGoogleIdentityServices);

router.post('/sso/sign-in/firebase-facebook', 
    middlewareLimiter.loginLimiter, 
    middleware.verifyPublicCSRFToken, 
    v1AuthenticationController.ssoSignInFirebaseFacebook);

router.post('/sso/sign-up/firebase-facebook', 
    middlewareLimiter.loginLimiter, 
    middleware.verifyPublicCSRFToken, 
    v1AuthenticationController.ssoSignInFirebaseFacebook);

router.post('/sso/sign-in/firebase-google', 
    middlewareLimiter.loginLimiter, 
    middleware.verifyPublicCSRFToken, 
    v1AuthenticationController.ssoSignInFirebaseGoogle);

router.post('/sso/sign-up/firebase-google', 
    middlewareLimiter.loginLimiter, 
    middleware.verifyPublicCSRFToken, 
    v1AuthenticationController.ssoSignUpFirebaseGoogle);

// * API THAT VERIFY PRIVATE CSRF TOKEN FIRST IN THE MIDDLEWARE
router.get('/user', 
    middlewareLimiter.userLimiter, 
    middleware.isMFAMode, 
    middleware.sendPublicCSRFTokenToUser, 
    middleware.isAuthenticated, 
    v1AuthenticationController.user); 
    
 // * USER MUST BE AUTHETICATED
router.delete('/user', 
    middlewareLimiter.deleteUserLimiter, 
    middleware.sendPublicCSRFTokenToUser, 
    middleware.isAuthenticated, 
    v1AuthenticationController.deleteUser); 

router.post('/logout', 
    middlewareLimiter.logoutLimiter, 
    middleware.sendPublicCSRFTokenToUser, 
    middleware.isAuthenticated, 
    v1AuthenticationController.logout); 

router.post('/user/enable-google-authenticator', 
    middlewareLimiter.enableGoogleAuthenticatorLimiter, 
    middleware.isAuthenticated, 
    v1AuthenticationController.enableGoogleAuthenticator);

router.post('/user/activate-google-authenticator',
    middlewareLimiter.activateGoogleAuthenticatorLimiter, 
    middleware.isAuthenticated, 
    v1AuthenticationController.activateGoogleAuthenticator);

router.post('/user/disable-google-authenticator', 
    middlewareLimiter.disableGoogleAuthenticatorLimiter, 
    middleware.isAuthenticated, 
    v1AuthenticationController.disableGoogleAuthenticator);

// * API THAT VERIFY PRIVATE CSRF TOKEN VIA REQUEST BODY INSIDE CONTROLLER
router.post('/reset-password', 
    middlewareLimiter.resetPasswordLimiter, 
    v1AuthenticationController.resetPassword);

router.post('/account-recovery/reset-password/verify-token', 
    middlewareLimiter.resetPasswordVerifyTokenLimiter, 
    v1AuthenticationController.accountRecoveryResetPasswordVerifyToken);

export default router;