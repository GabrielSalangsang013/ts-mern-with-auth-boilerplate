import express from 'express';
import jwt from 'jsonwebtoken';
import argon2 from 'argon2';
import Tokens from 'csrf';
import xss from 'xss'; 
import mongoSanitize from 'express-mongo-sanitize';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import lodash from 'lodash';
import { OAuth2Client } from 'google-auth-library';
const client = new OAuth2Client();

import admin from 'firebase-admin';
import serviceAccount from '../config/firebase-credential.json' assert { type: "json" };

const firebaseAdmin = admin.initializeApp({
   credential: admin.credential.cert(serviceAccount as admin.ServiceAccount)
});

// * ----------------- MODELS -----------------
import User from '../models/userModel.js';
import Profile from '../models/profileModel.js';
import CSRFTokenSecret from '../models/csrfTokenSecretModel.js';
import GoogleAuthenticator from '../models/googleAuthenticatorModel.js';
// * ----------------- MODELS -----------------

// * ----------------- UTILITIES -----------------
import sendEmail from '../utils/sendEmail.js'; // * FOR SENDING EMAIL TO THE USER
import ErrorResponse from '../utils/ErrorResponse.js'; // * FOR SENDING ERROR TO THE ERROR HANDLER MIDDLEWARE
import tryCatch from "../utils/tryCatch.js"; // * FOR AVOIDING RETYPING TRY AND CATCH IN EACH CONTROLLER
import generateRandomPasswordSSO from '../utils/generateRandomPasswordSSO.js';
import generateRandomUsernameSSO from '../utils/generateRandomUsernameSSO.js';
import * as validations from '../utils/v1AuthenticationValidations.js';
// * ----------------- UTILITIES -----------------

// * ----------------- CONSTANTS -----------------
import * as emailTemplates from '../constants/v1AuthenticationEmailTemplates.js'; // * EMAIL TEMPLATES
import * as errorCodes from '../constants/v1AuthenticationErrorCodes.js'; // * ALL ERROR CODES
import * as cookiesSettings from '../constants/v1AuthenticationCookiesSettings.js'; // * ALL COOKIES SETTINGS
import * as jwtTokensSettings from '../constants/v1AuthenticationJWTTokensSettings.js'; // * ALL JWT TOKEN SETTINGS
import * as userSettings from '../constants/v1AuthenticationUserSettings.js'; // * ALL USER SETTINGS
// * ----------------- CONSTANTS -----------------

// * ------------ TYPES --------------------
import * as TYPES from '../types/index.js';
// * ------------ TYPES --------------------

const user = tryCatch(async (req: express.Request, res: express.Response) => {    
    // * SANITIZED AUTHENTICATED USER INFORMATION BEFORE SENDING - REMOVED _ID FIELD
    let authenticatedUser =  lodash.get(req, 'authenticatedUser') as unknown as any;
    
    // * IF USER HAS GOOGLE AUTH AND IS SCANNED - DON'T SEND ANYMORE THE QR-CODE TO CLIENT
    authenticatedUser = await User.findOne({_id: authenticatedUser._id})
                                    .select('-_id -createdAt -updatedAt')
                                    .populate('profile', '-_id -createdAt -updatedAt')
                                    .populate('googleAuthenticator', '-_id +qr_code -createdAt -updatedAt');
    if(authenticatedUser.googleAuthenticator) {
        if(authenticatedUser.googleAuthenticator.isActivated) {
            authenticatedUser.googleAuthenticator.qr_code = undefined;
        }
    }

    return res.status(200).json({status: 'ok', user: authenticatedUser});
});

const deleteUser = tryCatch(async (req: express.Request, res: express.Response) => {  
    const authenticatedUser =  lodash.get(req, 'authenticatedUser') as unknown as any;
    const userOwner = await User.findOne({_id: authenticatedUser._id}).lean();

    if(userOwner === null) {
        throw new ErrorResponse(401, 'User is not exist. Please sign up.', errorCodes.USER_NOT_EXIST_DELETE_USER);
    }

    if(userOwner.hasOwnProperty('social_id')) {
        firebaseAdmin.auth().deleteUser(userOwner.social_id).catch((error: any) => {
            throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_DELETE_USER);
        });
    }

    await Profile.findOneAndDelete({user_id: userOwner._id});
    await CSRFTokenSecret.findOneAndDelete({user_id: userOwner._id});
    await GoogleAuthenticator.findOneAndDelete({user_id: userOwner._id});
    await User.findOneAndDelete({_id: userOwner._id});

    // RUN LOGOUT
    const tokens = new Tokens();
    const csrfTokenSecret = process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string;
    const csrfToken = tokens.create(csrfTokenSecret);

    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, 'expiredtoken', {
        httpOnly: true,
        secure: true,
        sameSite: 'none', 
        path: '/', 
        expires: new Date(0)
    });

    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
    });

    return res.status(200).json({status: 'ok'});
});

const register = tryCatch(async (req: express.Request, res: express.Response) => {
    let {username, email, password, repeatPassword, fullName} = mongoSanitize.sanitize(req.body);
    if(!username || !email || !password || !repeatPassword || !fullName) throw new ErrorResponse(400, "Please complete the Registration Form.", errorCodes.INCOMPLETE_REGISTER_FORM);

    username = xss(username);
    email = xss(email);
    password = xss(password);
    repeatPassword = xss(repeatPassword);
    fullName = xss(fullName);

    const { error } = validations.registerValidate(username, email, password, repeatPassword, fullName);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_REGISTER);
    
    let existingUser = await User.findOne({ username });
    if (existingUser) throw new ErrorResponse(400, "Username already exist.", errorCodes.USERNAME_EXIST_REGISTER);

    existingUser = await User.findOne({ email });
    if (existingUser) throw new ErrorResponse(400, "Email already exist.", errorCodes.EMAIL_EXIST_REGISTER);

    const ACCOUNT_ACTIVATION_TOKEN = jwt.sign({username, email, password, repeatPassword, fullName}, process.env["ACCOUNT_ACTIVATION_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_REGISTER_ACCOUNT_ACTIVATION_EXPIRES_IN_STRING});
    const activateAccountURL = `${process.env["REACT_URL"] as string}/activate/${ACCOUNT_ACTIVATION_TOKEN}`;

    await sendEmail({
        to: email,
        subject: emailTemplates.ACCOUNT_ACTIVATION_EMAIL_SUBJECT,
        text: emailTemplates.ACCOUNT_ACTIVATION_EMAIL_TEXT,
        html: emailTemplates.ACCOUNT_ACTIVATION_EMAIL_HTML(username, activateAccountURL),
    });

    return res.status(200).json({ status: 'ok' });
});

const activate = tryCatch(async (req: express.Request, res: express.Response) => {
    let { token } = mongoSanitize.sanitize(req.body);
    if(!token) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_ACCOUNT_ACTIVATION_JWT_TOKEN);

    jwt.verify(token, process.env["ACCOUNT_ACTIVATION_TOKEN_SECRET"] as string, (error: any, jwtActivateTokenDecoded: any) => {
        if(error) throw new ErrorResponse(401, "Expired link or Invalid Credential. Please sign up again.", errorCodes.EXPIRED_ACCOUNT_ACTIVATION_JWT_TOKEN_OR_INVALID_ACCOUNT_ACTIVATION_JWT_TOKEN);
        token = jwtActivateTokenDecoded;
    })

    let { username, email, password, repeatPassword, fullName } = mongoSanitize.sanitize(token);
    if(!username || !email || !password || !repeatPassword || !fullName) throw new ErrorResponse(400, "Please complete the Registration Form.", errorCodes.INCOMPLETE_REGISTER_FORM_ACTIVATE);

    username = xss(username);
    email = xss(email);
    password = xss(password);
    repeatPassword = xss(repeatPassword);
    fullName = xss(fullName);

    const { error } = validations.activateValidate(username, email, password, repeatPassword, fullName);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_REGISTER_ACTIVATE);

    let existingUser = await User.findOne({ username });
    if (existingUser) throw new ErrorResponse(400, "Account has already been activated.", errorCodes.USERNAME_EXIST_REGISTER_ACTIVATE);

    existingUser = await User.findOne({ email });
    if (existingUser)  throw new ErrorResponse(400, "Account has already been activated.", errorCodes.EMAIL_EXIST_REGISTER_ACTIVATE);
    
    const tokens = new Tokens();
    const csrfTokenSecret = tokens.secretSync();
    const csrfToken = tokens.create(csrfTokenSecret);

    const savedCSRFTokenSecret = await CSRFTokenSecret.create({secret: csrfTokenSecret});
    const savedProfile = await Profile.create({fullName: fullName, profilePicture: userSettings.DEFAULT_PROFILE_PICTURE});
    const savedUser = await User.create({
        username: username, 
        email: email, 
        password: password,
        profile: [savedProfile._id],
        csrfTokenSecret: [savedCSRFTokenSecret._id]
    });

    await CSRFTokenSecret.findOneAndUpdate({_id: savedCSRFTokenSecret._id}, { user_id: savedUser._id });
    await Profile.findOneAndUpdate({_id: savedProfile._id}, { user_id: savedUser._id });

    let authenticationToken = jwt.sign({_id: savedUser._id}, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_AUTHENTICATION_TOKEN_EXPIRATION_STRING});
    
    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, authenticationToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    return res.status(200).json({status: 'ok'});
});

const login = tryCatch(async (req: express.Request, res: express.Response) => {
    let {username, password} = mongoSanitize.sanitize(req.body);
    if(!username || !password) throw new ErrorResponse(400, "Please complete the Login form.", errorCodes.INCOMPLETE_LOGIN_FORM);

    username = xss(username);
    password = xss(password);

    const { error } = validations.loginValidate(username, password);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_LOGIN);

    const existingUser = await User.findOne({ username }).select('+password').populate('profile').populate('googleAuthenticator');
    if (!existingUser) throw new ErrorResponse(401, 'Invalid username.', errorCodes.USERNAME_NOT_EXIST_LOGIN);

    const isMatched = await existingUser.matchPasswords(password);
    if (!isMatched) throw new ErrorResponse(401, 'Invalid password.', errorCodes.PASSWORD_NOT_MATCH_LOGIN);

    if (existingUser.isSSO) throw new ErrorResponse(401, 'The user is SSO account.', errorCodes.USER_SSO_ACCOUNT_LOGIN);

    function generateMFACode() {
        return Array.from({ length: 7 }, () => (Math.random() < 0.33 ? String.fromCharCode(Math.floor(Math.random() * 26) + 65) : Math.random() < 0.67 ? String.fromCharCode(Math.floor(Math.random() * 26) + 97) : Math.floor(Math.random() * 10))).join('');
    }

    let sendVerificationCodeLogin = generateMFACode();

    while(!/\d/.test(sendVerificationCodeLogin)) {
        sendVerificationCodeLogin = generateMFACode();
    }
    
    const hashedSendVerificationCodeLogin = await argon2.hash(sendVerificationCodeLogin);

    await User.findOneAndUpdate({ username }, {verificationCodeLogin: hashedSendVerificationCodeLogin});

    await sendEmail({
        to: existingUser.email,
        subject: emailTemplates.MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_SUBJECT,
        text: emailTemplates.MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_TEXT,
        html: emailTemplates.MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_HTML(username, sendVerificationCodeLogin)
    });

    let mfa_token;

    if(existingUser.toObject().hasOwnProperty('googleAuthenticator')) {
        if(existingUser.googleAuthenticator.isActivated) {
            mfa_token = jwt.sign({_id: existingUser._id, username: existingUser.username, profilePicture: existingUser.profile.profilePicture, hasGoogleAuthenticator: true }, process.env["MFA_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_MFA_LOGIN_TOKEN_EXPIRATION_STRING});
        }else {
            mfa_token = jwt.sign({_id: existingUser._id, username: existingUser.username, profilePicture: existingUser.profile.profilePicture, hasGoogleAuthenticator: false }, process.env["MFA_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_MFA_LOGIN_TOKEN_EXPIRATION_STRING});
        }
    }else {
        mfa_token = jwt.sign({_id: existingUser._id, username: existingUser.username, profilePicture: existingUser.profile.profilePicture, hasGoogleAuthenticator: false }, process.env["MFA_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_MFA_LOGIN_TOKEN_EXPIRATION_STRING});
    }
    
    res.cookie(cookiesSettings.COOKIE_MFA_TOKEN_NAME, mfa_token, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_MFA_LOGIN_TOKEN_EXPIRATION)
    });

    return res.status(200).json({status: 'ok'});
});

const verificationCodeLogin = tryCatch(async (req: express.Request, res: express.Response) => {
    let {verificationCodeLogin} = mongoSanitize.sanitize(req.body);
    let mfa_token = req.cookies[cookiesSettings.COOKIE_MFA_TOKEN_NAME];

    if(!verificationCodeLogin || !mfa_token) throw new ErrorResponse(400, "Please complete the Login form.", errorCodes.INCOMPLETE_LOGIN_FORM_VERIFICATION_CODE_LOGIN);

    jwt.verify(mfa_token, process.env["MFA_TOKEN_SECRET"] as string, (error: any, jwtMFALoginTokenDecoded: any) => {
        if(error) throw new ErrorResponse(401, "Expired or Incomplete Credential. Please login again.", errorCodes.INVALID_OR_EXPIRED_MULTI_FACTOR_AUTHENTICATION_LOGIN_CODE);
        mfa_token = mongoSanitize.sanitize(jwtMFALoginTokenDecoded._id);
    });

    verificationCodeLogin = xss(verificationCodeLogin);
    mfa_token = xss(mfa_token);

    const { error } = validations.verificationCodeLoginValidate(verificationCodeLogin);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_VERIFICATION_CODE_LOGIN);

    const existingUser = await User.findOne({ _id: mfa_token }).select('+verificationCodeLogin').populate('csrfTokenSecret').populate('googleAuthenticator');
    if (!existingUser) throw new ErrorResponse(401, 'User not exist.', errorCodes.USER_NOT_EXIST_VERIFICATION_CODE_LOGIN);

    const isMatchedVerificationCodeLogin = await existingUser.matchVerificationCodeLogin(verificationCodeLogin);
    if (!isMatchedVerificationCodeLogin) throw new ErrorResponse(401, 'Invalid verification code login.', errorCodes.VERIFICATION_CODE_LOGIN_NOT_MATCH);

    const tokens = new Tokens();
    const csrfTokenSecret = existingUser.csrfTokenSecret.secret;
    const csrfToken = tokens.create(csrfTokenSecret);

    let authenticationToken = jwt.sign({_id: existingUser._id}, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_AUTHENTICATION_TOKEN_EXPIRATION_STRING});

    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, authenticationToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    res.cookie(cookiesSettings.COOKIE_MFA_TOKEN_NAME, 'expiredtoken', {
        httpOnly: true,
        secure: true,
        sameSite: 'none', 
        path: '/', 
        expires: new Date(0)
    });

    return res.status(200).json({status: 'ok'});
});

const verificationCodeLoginLogout = tryCatch(async (req: express.Request, res: express.Response) => {
    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, 'expiredtoken', {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        path: '/',
        expires: new Date(0)
    });
    
    res.cookie(cookiesSettings.COOKIE_MFA_TOKEN_NAME, 'expiredtoken', {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        path: '/',
        expires: new Date(0)
    });

    return res.status(200).json({status: 'ok'});
});

const logout = tryCatch(async (req: express.Request, res: express.Response) => {
    const tokens = new Tokens();
    const csrfTokenSecret = process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string;
    const csrfToken = tokens.create(csrfTokenSecret);

    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, 'expiredtoken', {
        httpOnly: true,
        secure: true,
        sameSite: 'none', 
        path: '/', 
        expires: new Date(0)
    });

    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
    });

    return res.status(200).json({status: 'ok'});
});

const forgotPassword = tryCatch(async (req: express.Request, res: express.Response) => {
    let {email} = mongoSanitize.sanitize(req.body);
    if(!email) throw new ErrorResponse(400, "Please complete the Forgot Password Form.", errorCodes.INCOMPLETE_FORGOT_PASSWORD_FORM);

    email = xss(email);

    const { error } = validations.forgotPasswordValidate(email);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_FORGOT_PASSWORD);

    let existingUser = await User.findOne({ email }).populate('csrfTokenSecret');
    if (!existingUser) throw new ErrorResponse(400, "Email is not exist.", errorCodes.EMAIL_NOT_EXIST_FORGOT_PASSWORD);

    if (existingUser.isSSO) throw new ErrorResponse(401, 'The user is SSO account.', errorCodes.USER_SSO_ACCOUNT_FORGOT_PASSWORD);

    await User.findOneAndUpdate({ email }, { forgotPassword: true });

    const tokens = new Tokens();
    const csrfTokenSecret = existingUser.csrfTokenSecret.secret;
    const csrfToken = tokens.create(csrfTokenSecret);

    const ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN = jwt.sign({csrfToken}, process.env["ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_ACCOUNT_RECOVERY_RESET_PASSWORD_EXPIRES_IN_STRING});
    const ACCOUNT_RECOVERY_RESET_PASSWORD_JWT_TOKEN = jwt.sign({email}, process.env["ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_ACCOUNT_RECOVERY_RESET_PASSWORD_EXPIRES_IN_STRING});

    const recoverAccountResetPasswordURL = `${process.env["REACT_URL"] as string}/reset-password/${ACCOUNT_RECOVERY_RESET_PASSWORD_JWT_TOKEN}/${ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN}`;

    await sendEmail({
        to: email,
        subject: emailTemplates.RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_SUBJECT,
        text: emailTemplates.RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_TEXT,
        html: emailTemplates.RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_HTML(existingUser.username, recoverAccountResetPasswordURL),
    });

    return res.status(200).json({ status: 'ok' });
});

const googleAuthenticatorCodeLogin = tryCatch(async (req: express.Request, res: express.Response) => {
    let {googleAuthenticatorCodeLogin} = mongoSanitize.sanitize(req.body);
    let mfa_token = req.cookies[cookiesSettings.COOKIE_MFA_TOKEN_NAME];

    if(!googleAuthenticatorCodeLogin || !mfa_token) throw new ErrorResponse(400, "Please complete the Login form.", errorCodes.INCOMPLETE_LOGIN_FORM_GOOGLE_AUTHENTICATOR_CODE_LOGIN);

    jwt.verify(mfa_token, process.env["MFA_TOKEN_SECRET"] as string, (error: any, jwtMFALoginTokenDecoded: any) => {
        if(error) throw new ErrorResponse(401, "Expired or Incomplete Credential. Please login again.", errorCodes.INVALID_OR_EXPIRED_MULTI_FACTOR_AUTHENTICATION_LOGIN_CODE_GOOGLE_AUTHENTICATOR_CODE_LOGIN);
        mfa_token = mongoSanitize.sanitize(jwtMFALoginTokenDecoded._id);
    });

    googleAuthenticatorCodeLogin = xss(googleAuthenticatorCodeLogin);
    mfa_token = xss(mfa_token);

    const { error } = validations.googleAuthenticatorCodeLoginValidate(googleAuthenticatorCodeLogin);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_GOOGLE_AUTHENTICATOR_CODE_LOGIN);

    const existingUser = await User.findOne({ _id: mfa_token })
                                    .populate('csrfTokenSecret', '+secret')
                                    .populate('googleAuthenticator', '+secret +encoding');
    if (!existingUser) throw new ErrorResponse(401, 'User not exist.', errorCodes.USER_NOT_EXIST_VERIFICATION_CODE_LOGIN);

    const isVerified = speakeasy.totp.verify({
        secret: existingUser.googleAuthenticator.secret,
        encoding: existingUser.googleAuthenticator.encoding,
        token: googleAuthenticatorCodeLogin
    });

    if(!isVerified) throw new ErrorResponse(401, 'Invalid Google Authenticator Code Login.', errorCodes.INVALID_GOOGLE_AUTHENTICATOR_CODE_LOGIN);

    const tokens = new Tokens();
    const csrfTokenSecret = existingUser.csrfTokenSecret.secret;
    const csrfToken = tokens.create(csrfTokenSecret);

    let authenticationToken = jwt.sign({_id: existingUser._id}, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_AUTHENTICATION_TOKEN_EXPIRATION_STRING});

    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, authenticationToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    res.cookie(cookiesSettings.COOKIE_MFA_TOKEN_NAME, 'expiredtoken', {
        httpOnly: true,
        secure: true,
        sameSite: 'none', 
        path: '/', 
        expires: new Date(0)
    });

    return res.status(200).json({status: 'ok'});
});

const enableGoogleAuthenticator = tryCatch(async (req: express.Request, res: express.Response) => {
    const authenticatedUser = lodash.get(req, 'authenticatedUser') as unknown as any;
    const googleAuthenticatorSecret: any = speakeasy.generateSecret({name: process.env["GOOGLE_AUTHENTICATOR_NAME"] as string});
    const googleAuthenticatorQRCode = await qrcode.toDataURL(googleAuthenticatorSecret.otpauth_url);
    const savedGoogleAuthenticator = await GoogleAuthenticator.create({
        secret: googleAuthenticatorSecret.ascii, 
        encoding: 'ascii', 
        qr_code: googleAuthenticatorQRCode,
        otpauth_url: googleAuthenticatorSecret.otpauth_url,
        isActivated: false
    });

    await User.findOneAndUpdate(authenticatedUser._id, { googleAuthenticator: [savedGoogleAuthenticator._id] });
    await GoogleAuthenticator.findOneAndUpdate({_id: savedGoogleAuthenticator._id}, { user_id: authenticatedUser._id });

    res.status(200).json({status: 'ok', qr_code: googleAuthenticatorQRCode});
});

const activateGoogleAuthenticator = tryCatch(async (req: express.Request, res: express.Response) => {
    const authenticatedUser = lodash.get(req, 'authenticatedUser') as unknown as any;
    await GoogleAuthenticator.findOneAndUpdate({ user_id: authenticatedUser._id }, { isActivated: true });
    res.status(200).json({ status: 'ok' });
});

const disableGoogleAuthenticator = tryCatch(async (req: express.Request, res: express.Response) => {
    const authenticatedUser = lodash.get(req, 'authenticatedUser') as unknown as any;
    await GoogleAuthenticator.findOneAndDelete({ user_id: authenticatedUser._id });
    await User.updateOne({ _id: authenticatedUser._id }, { $unset: { googleAuthenticator: authenticatedUser.googleAuthenticator._id } })
    res.status(200).json({ status: 'ok' });
});

const resetPassword = tryCatch(async (req: express.Request, res: express.Response) => {
    let { token, csrfToken, password, repeatPassword } = mongoSanitize.sanitize(req.body);

    if(!token || !csrfToken) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_JWT_TOKEN_OR_CSRF_TOKEN_RESET_PASSWORD);
    
    jwt.verify(csrfToken, process.env["ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET"] as string, (error: any, jwtCSRFTokenDecoded: any) => {
        if(error) throw new ErrorResponse(401, "Expired link or Invalid Credential. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_CSRF_TOKEN_RESET_PASSWORD);
        csrfToken = jwtCSRFTokenDecoded;
    });

    jwt.verify(token, process.env["ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET"] as string, (error: any, jwtRecoveryAccountTokenDecoded: any) => {
        if(error) throw new ErrorResponse(401, "Expired link or Invalid Credential. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_JWT_TOKEN_RESET_PASSWORD);
        token = jwtRecoveryAccountTokenDecoded;
    });
    
    let { email } = mongoSanitize.sanitize(token);
    let csrfTokenObj = mongoSanitize.sanitize(csrfToken);

    if(!email || !password || !repeatPassword) throw new ErrorResponse(400, "Please complete the Recovery Account Reset Password Form.", errorCodes.INCOMPLETE_RESET_PASSWORD_FORM);
    if(password !== repeatPassword) throw new ErrorResponse(400, "Password and Repeat Password is not match.", errorCodes.PASSWORD_REPEAT_PASSWORD_NOT_MATCH_RESET_PASSWORD_FORM);

    email = xss(email);
    password = xss(password);
    repeatPassword = xss(repeatPassword);

    const { error } = validations.resetPasswordValidate(email, password, repeatPassword);

    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_RESET_PASSWORD);
    
    let existingUser = await User.findOne({ email }).populate('csrfTokenSecret');
    if (!existingUser) throw new ErrorResponse(400, "Email is not exist.", errorCodes.EMAIL_NOT_EXIST_RESET_PASSWORD);

    if (existingUser.isSSO) throw new ErrorResponse(401, 'The user is SSO account.', errorCodes.USER_SSO_ACCOUNT_RESET_PASSWORD);

    const tokens = new Tokens();
    if (!tokens.verify(existingUser.csrfTokenSecret.secret, csrfTokenObj.csrfToken)) throw new ErrorResponse(403, "Invalid Credential.", errorCodes.INVALID_CSRF_TOKEN_RESET_PASSWORD);
    
    const hashedPassword = await argon2.hash(password);
    await User.findOneAndUpdate({ email }, { password: hashedPassword, forgotPassword: false });

    return res.status(200).json({ status: 'ok'});
});

const accountRecoveryResetPasswordVerifyToken = tryCatch(async (req: express.Request, res: express.Response) => {
    let { token, csrfToken } = mongoSanitize.sanitize(req.body);
    if(!token || !csrfToken) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_JWT_TOKEN_OR_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
   
    jwt.verify(csrfToken, process.env["ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET"] as string, (error: any, jwtCSRFTokenDecoded: any) => {
        if(error) throw new ErrorResponse(401, "Expired link or Invalid Credential. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
        csrfToken = jwtCSRFTokenDecoded;
    });

    jwt.verify(token, process.env["ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET"] as string, (error: any, jwtRecoveryAccountTokenDecoded: any) => {
        if(error) throw new ErrorResponse(401, "Expired link or Invalid Credential. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_JWT_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
        token = jwtRecoveryAccountTokenDecoded;
    });

    let { email } = mongoSanitize.sanitize(token);
    let csrfTokenObj = mongoSanitize.sanitize(csrfToken);

    if(!email) throw new ErrorResponse(400, "Please complete the Forgot Password Form.", errorCodes.INCOMPLETE_FORGOT_PASSWORD_FORM_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);

    email = xss(email);

    const { error } = validations.accountRecoveryResetPasswordVerifyTokenValidate(email);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_FORGOT_PASSWORD_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);

    let existingUser = await User.findOne({ email, forgotPassword: true }).populate('csrfTokenSecret');
    if (!existingUser) throw new ErrorResponse(400, "Email is not exist or user does not request forgot password.", errorCodes.EMAIL_NOT_EXIST_OR_USER_NOT_REQUEST_FORGOT_PASSWORD_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);

    const tokens = new Tokens();
    if (!tokens.verify(existingUser.csrfTokenSecret.secret, csrfTokenObj.csrfToken)) throw new ErrorResponse(403, "Invalid Credential.", errorCodes.INVALID_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);

    return res.status(200).json({ status: 'ok' });
});

const ssoSignInGoogleIdentityServices = tryCatch(async (req: express.Request, res: express.Response) => {    
    if(process.env.NODE_ENV === 'DEVELOPMENT') {
        if(req.cookies.g_state) {
            res.cookie('g_state', 'expiredtoken', {
                httpOnly: true,
                secure: true,
                sameSite: 'none', 
                path: '/', 
                expires: new Date(0)
            });
        }
    }

    const { token } = mongoSanitize.sanitize(req.body);

    if(!token) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_SSO_JWT_TOKEN_SSO_SIGN_IN_GOOGLE_IDENTITY_SERVICES);

    type payloadType = {
        email?: string,
        name?: string
    }

    async function verify(): Promise<payloadType> {
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_IDENITY_SERVICES_CLIENT_ID
        });

        const payload: payloadType | undefined = ticket.getPayload();

        if(payload === undefined) {
            throw new ErrorResponse(401, "Failed to sign in. Please try again.", errorCodes.PAYLOAD_UNDEFINED_SSO_SIGN_IN_GOOGLE_IDENTITY_SERVICES);
        }

        return payload;
    }

    let payload = await verify().catch((error) => {
        throw new ErrorResponse(401, "Failed to sign in. Please try again.", errorCodes.FAILED_VALIDATION_SSO_SIGN_IN_GOOGLE_IDENTITY_SERVICES);
    });

    let { email, name } = payload;

    if(!email || !name) throw new ErrorResponse(400, "Credential must have email, and name.", errorCodes.INCOMPLETE_CREDENTIAL_SSO_SIGN_IN_GOOGLE_IDENTITY_SERVICES);

    email = xss(email);
    name = xss(name);

    const { error } = validations.ssoGoogleIdentityServicesValidate(email, name);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_CREDENTIAL_SSO_SIGN_IN_GOOGLE_IDENTITY_SERVICES);

    const existingUser = await User.findOne({ email }).populate('csrfTokenSecret');
    const tokens = new Tokens();

    // * IF USER EXIST BY EMAIL JUST LOGIN 
    if (existingUser) {
        const csrfTokenSecret = existingUser.csrfTokenSecret.secret;
        const csrfToken = tokens.create(csrfTokenSecret);

        let authenticationToken = jwt.sign({_id: existingUser._id}, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_AUTHENTICATION_TOKEN_EXPIRATION_STRING});
        
        res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, authenticationToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'none', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
        });

        res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'none', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
        });

        return res.status(200).json({status: 'ok'});
    }

    throw new ErrorResponse(401, 'User is not exist. Please sign up.', errorCodes.USER_NOT_EXIST_SSO_SIGN_IN_GOOGLE_IDENTITY_SERVICES);
});

const ssoSignUpGoogleIdentityServices = tryCatch(async (req: express.Request, res: express.Response) => {    
    if(process.env.NODE_ENV === 'DEVELOPMENT') {
        if(req.cookies.g_state) {
            res.cookie('g_state', 'expiredtoken', {
                httpOnly: true,
                secure: true,
                sameSite: 'none', 
                path: '/', 
                expires: new Date(0)
            });
        }
    }

    const { token } = mongoSanitize.sanitize(req.body);

    if(!token) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_SSO_JWT_TOKEN_SSO_SIGN_UP_GOOGLE_IDENTITY_SERVICES);

    type payloadType = {
        email?: string,
        name?: string
    }

    async function verify(): Promise<payloadType> {
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_IDENITY_SERVICES_CLIENT_ID
        });

        const payload: payloadType | undefined = ticket.getPayload();

        if(payload === undefined) {
            throw new ErrorResponse(401, "Failed to sign in. Please try again.", errorCodes.PAYLOAD_UNDEFINED_SSO_SIGN_UP_GOOGLE_IDENTITY_SERVICES);
        }

        return payload;
    }

    let payload = await verify().catch((error) => {
        throw new ErrorResponse(401, error, errorCodes.FAILED_VALIDATION_SSO_SIGN_UP_GOOGLE_IDENTITY_SERVICES);
    });

    let { email, name } = payload;

    if(!email || !name) throw new ErrorResponse(400, "Credential must have email, and name.", errorCodes.INCOMPLETE_CREDENTIAL_SSO_SIGN_UP_GOOGLE_IDENTITY_SERVICES);

    email = xss(email);
    name = xss(name);

    const { error } = validations.ssoGoogleIdentityServicesValidate(email, name);
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_CREDENTIAL_SSO_SIGN_UP_GOOGLE_IDENTITY_SERVICES);

    const existingUser = await User.findOne({ email }).populate('csrfTokenSecret');
    const tokens = new Tokens();

    if (existingUser) throw new ErrorResponse(401, 'User is already exist.', errorCodes.USER_ALREADY_EXIST_SSO_SIGN_UP_GOOGLE_IDENTITY_SERVICES);

    // * IF USER NOT EXIST. REGISTER THE USER AFTER THAT AUTOMATICALLY LOGIN THE USER
    const csrfTokenSecret = tokens.secretSync();
    const csrfToken = tokens.create(csrfTokenSecret);

    const savedCSRFTokenSecret = await CSRFTokenSecret.create({secret: csrfTokenSecret});
    const savedProfile = await Profile.create({fullName: name, profilePicture: userSettings.DEFAULT_PROFILE_PICTURE});
    const savedUser = await User.create({
        username: name.split(" ")[0] + "_" + generateRandomUsernameSSO(), 
        email: email, 
        password: generateRandomPasswordSSO(),
        profile: [savedProfile._id],
        csrfTokenSecret: [savedCSRFTokenSecret._id],
        isSSO: true
    });

    await CSRFTokenSecret.findOneAndUpdate({_id: savedCSRFTokenSecret._id}, { user_id: savedUser._id });
    await Profile.findOneAndUpdate({_id: savedProfile._id}, { user_id: savedUser._id });

    let authenticationToken = jwt.sign({_id: savedUser._id}, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_AUTHENTICATION_TOKEN_EXPIRATION_STRING});
    
    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, authenticationToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    return res.status(200).json({status: 'ok'});
});

const ssoSignInFirebaseFacebook = tryCatch(async (req: express.Request, res: express.Response) => {
    const { token } = mongoSanitize.sanitize(req.body);
    if(!token) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_SSO_JWT_TOKEN_SSO_SIGN_IN_FIREBASE_FACEBOOK);

    let { email, name, user_id }: TYPES.SSO_FIREBASE_FACEBOOK_TOKEN_DECODED = mongoSanitize.sanitize(jwt.decode(token) as TYPES.SSO_FIREBASE_FACEBOOK_TOKEN_DECODED);
    if(!email || !name || !user_id) {
        firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
            throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_IN_FIREBASE_FACEBOOK);
        });
        throw new ErrorResponse(400, "Credential must have email, name, and others.", errorCodes.INCOMPLETE_CREDENTIAL_SSO_SIGN_IN_FIREBASE_FACEBOOK);
    }
    
    email = xss(email);
    name = xss(name);
    user_id = xss(user_id);

    const { error } = validations.ssoFirebaseFacebookValidate(email, name, user_id);
    if (error) {
        firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
            throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_IN_FIREBASE_FACEBOOK);
        });
        throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_CREDENTIAL_SSO_SIGN_IN_FIREBASE_FACEBOOK);
    }

    // * LEAN() MEANS TURN MONGOOSE DOCUMENT TO JAVASCRIPT OBJECT FOR THE PURPOSE OF CHECKING IF THE EXISTING USER HAS SOCIAL_ID PROPERTY
    let existingUser = await User.findOne({ email }).populate('csrfTokenSecret').lean();
    const tokens = new Tokens();

    if (existingUser) {
        if(!existingUser.hasOwnProperty('social_id')) {
            existingUser = await User.findOneAndUpdate({ email }, { social_id: user_id }).populate('csrfTokenSecret');
        }

        if(existingUser == null) {
            throw new ErrorResponse(401, 'User is not exist. Please sign up.', errorCodes.USER_NOT_EXIST_SSO_SIGN_IN_FIREBASE_GOOGLE);
        }

        const csrfTokenSecret = existingUser.csrfTokenSecret.secret;
        const csrfToken = tokens.create(csrfTokenSecret);

        let authenticationToken = jwt.sign({_id: existingUser._id}, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_AUTHENTICATION_TOKEN_EXPIRATION_STRING});
        
        res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, authenticationToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'none', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
        });

        res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'none', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
        });

        return res.status(200).json({status: 'ok'});
    }

    firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
        throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_IN_FIREBASE_FACEBOOK);
    });

    throw new ErrorResponse(401, 'User is not exist. Please sign up.', errorCodes.USER_NOT_EXIST_SSO_SIGN_IN_FIREBASE_FACEBOOK);
});

const ssoSignUpFirebaseFacebook = tryCatch(async (req: express.Request, res: express.Response) => {
    const { token } = mongoSanitize.sanitize(req.body);
    if(!token) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_SSO_JWT_TOKEN_SSO_SIGN_UP_FIREBASE_FACEBOOK);

    let { email, name, user_id }: TYPES.SSO_FIREBASE_FACEBOOK_TOKEN_DECODED = mongoSanitize.sanitize(jwt.decode(token) as TYPES.SSO_FIREBASE_FACEBOOK_TOKEN_DECODED);
    if(!email || !name || !user_id) {
        firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
            throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_UP_FIREBASE_FACEBOOK);
        });
        throw new ErrorResponse(400, "Credential must have email, name, and others.", errorCodes.INCOMPLETE_CREDENTIAL_SSO_SIGN_UP_FIREBASE_FACEBOOK);
    }
    
    email = xss(email);
    name = xss(name);
    user_id = xss(user_id);

    const { error } = validations.ssoFirebaseFacebookValidate(email, name, user_id);
    if (error) {
        firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
            throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_UP_FIREBASE_FACEBOOK);
        });
        throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_CREDENTIAL_SSO_SIGN_UP_FIREBASE_FACEBOOK);
    }

    const existingUser = await User.findOne({ email }).populate('csrfTokenSecret');
    const tokens = new Tokens();

    // * IF USER EXIST BY EMAIL JUST LOGIN 
    if (existingUser) {
        firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
            throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_UP_FIREBASE_FACEBOOK);
        });
        throw new ErrorResponse(401, 'User is already exist.', errorCodes.USER_ALREADY_EXIST_SSO_SIGN_UP_FIREBASE_FACEBOOK);
    }

    // * IF USER NOT EXIST. REGISTER THE USER AFTER THAT AUTOMATICALLY LOGIN THE USER
    const csrfTokenSecret = tokens.secretSync();
    const csrfToken = tokens.create(csrfTokenSecret);

    const savedCSRFTokenSecret = await CSRFTokenSecret.create({secret: csrfTokenSecret});
    const savedProfile = await Profile.create({fullName: name, profilePicture: userSettings.DEFAULT_PROFILE_PICTURE});
    const savedUser = await User.create({
        username: name.split(" ")[0] + "_" + generateRandomUsernameSSO(), 
        email: email, 
        password: generateRandomPasswordSSO(),
        profile: [savedProfile._id],
        csrfTokenSecret: [savedCSRFTokenSecret._id],
        isSSO: true,
        social_id: user_id
    });

    await CSRFTokenSecret.findOneAndUpdate({_id: savedCSRFTokenSecret._id}, { user_id: savedUser._id });
    await Profile.findOneAndUpdate({_id: savedProfile._id}, { user_id: savedUser._id });

    let authenticationToken = jwt.sign({_id: savedUser._id}, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_AUTHENTICATION_TOKEN_EXPIRATION_STRING});
    
    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, authenticationToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    return res.status(200).json({status: 'ok'});
});

const ssoSignInFirebaseGoogle = tryCatch(async (req: express.Request, res: express.Response) => {
    // * NOTE FIBASE GOOGLE ACCESS TOKEN HAS EMAIL VERIFIED FIELD 
    // * WHICH SSO GOOGLE IDENTITY SERVICES DON'T HAVE THAT.
    //  *SO IF YOU THINK WHY IT HAS email_verified IN THIS CONTROLLER BECAUSE ONLY FIREBASE HAVE THAT.

    const { token } = mongoSanitize.sanitize(req.body);
    if(!token) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_SSO_JWT_TOKEN_SSO_SIGN_IN_FIREBASE_GOOGLE);

    let { email, name, email_verified, user_id }: TYPES.SSO_FIREBASE_GOOGLE_TOKEN_DECODED = mongoSanitize.sanitize(jwt.decode(token) as TYPES.SSO_FIREBASE_GOOGLE_TOKEN_DECODED);
    if(!email || !name || !email_verified || !user_id) {
        firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
            throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_IN_FIREBASE_GOOGLE);
        });
        throw new ErrorResponse(400, "Credential must have email, name, email verified, and others.", errorCodes.INCOMPLETE_CREDENTIAL_SSO_SIGN_IN_FIREBASE_GOOGLE);
    }
    if(!email_verified) {
        firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
            throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_IN_FIREBASE_GOOGLE);
        });
        throw new ErrorResponse(400, "Email is not verified.", errorCodes.EMAIL_NOT_VERIFIED_SSO_SIGN_IN_FIREBASE_GOOGLE);
    }

    email = xss(email);
    name = xss(name);
    user_id = xss(user_id);

    const { error } = validations.ssoFirebaseGoogleValidate(email, name, user_id);
    if (error) {
        firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
            throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_IN_FIREBASE_GOOGLE);
        });
        throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_CREDENTIAL_SSO_SIGN_IN_FIREBASE_GOOGLE);
    }

    // * LEAN() MEANS TURN MONGOOSE DOCUMENT TO JAVASCRIPT OBJECT FOR THE PURPOSE OF CHECKING IF THE EXISTING USER HAS SOCIAL_ID PROPERTY
    let existingUser = await User.findOne({ email }).populate('csrfTokenSecret').lean();
    const tokens = new Tokens();

    // * IF USER EXIST BY EMAIL JUST LOGIN 
    if (existingUser) {
        if(!existingUser.hasOwnProperty('social_id')) {
            existingUser = await User.findOneAndUpdate({ email }, { social_id: user_id }).populate('csrfTokenSecret');
        }

        if(existingUser == null) {
            throw new ErrorResponse(401, 'User is not exist. Please sign up.', errorCodes.USER_NOT_EXIST_SSO_SIGN_IN_FIREBASE_GOOGLE);
        }

        const csrfTokenSecret = existingUser.csrfTokenSecret.secret;
        const csrfToken = tokens.create(csrfTokenSecret);

        let authenticationToken = jwt.sign({_id: existingUser._id}, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_AUTHENTICATION_TOKEN_EXPIRATION_STRING});
        
        res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, authenticationToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'none', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
        });

        res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'none', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
        });

        return res.status(200).json({status: 'ok'});
    }

    firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
        throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_IN_FIREBASE_GOOGLE);
    });
    throw new ErrorResponse(401, 'User is not exist. Please sign up.', errorCodes.USER_NOT_EXIST_SSO_SIGN_IN_FIREBASE_GOOGLE);
});

const ssoSignUpFirebaseGoogle = tryCatch(async (req: express.Request, res: express.Response) => {
    // * NOTE FIBASE GOOGLE ACCESS TOKEN HAS EMAIL VERIFIED FIELD 
    // * WHICH SSO GOOGLE IDENTITY SERVICES DON'T HAVE THAT.
    //  *SO IF YOU THINK WHY IT HAS email_verified IN THIS CONTROLLER BECAUSE ONLY FIREBASE HAVE THAT.

    const { token } = mongoSanitize.sanitize(req.body);
    if(!token) throw new ErrorResponse(401, "Incomplete Credential.", errorCodes.NO_SSO_JWT_TOKEN_SSO_SIGN_UP_FIREBASE_GOOGLE);

    let { email, name, email_verified, user_id }: TYPES.SSO_FIREBASE_GOOGLE_TOKEN_DECODED = mongoSanitize.sanitize(jwt.decode(token) as TYPES.SSO_FIREBASE_GOOGLE_TOKEN_DECODED);
    if(!email || !name || !email_verified || !user_id) {
        firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
            throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_UP_FIREBASE_GOOGLE);
        });
        throw new ErrorResponse(400, "Credential must have email, name, email verified, and others.", errorCodes.INCOMPLETE_CREDENTIAL_SSO_SIGN_UP_FIREBASE_GOOGLE);
    }
    if(!email_verified) {
        firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
            throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_UP_FIREBASE_GOOGLE);
        });
        throw new ErrorResponse(400, "Email is not verified.", errorCodes.EMAIL_NOT_VERIFIED_SSO_SIGN_UP_FIREBASE_GOOGLE);
    }

    email = xss(email);
    name = xss(name);
    user_id = xss(user_id);

    const { error } = validations.ssoFirebaseGoogleValidate(email, name, user_id);
    if (error) {
        firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
            throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_UP_FIREBASE_GOOGLE);
        });
        throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_CREDENTIAL_SSO_SIGN_UP_FIREBASE_GOOGLE);
    }

    const existingUser = await User.findOne({ email }).populate('csrfTokenSecret');
    const tokens = new Tokens();

    // * IF USER EXIST BY EMAIL JUST LOGIN 
    if (existingUser) {
        firebaseAdmin.auth().deleteUser(user_id).catch((error: any) => {
            throw new ErrorResponse(400, 'Failed to delete account.', errorCodes.FAILED_DELETE_ACCOUNT_IN_FIREBASE_DATABASE_SSO_SIGN_UP_FIREBASE_GOOGLE);
        });
        throw new ErrorResponse(401, 'User is already exist.', errorCodes.USER_ALREADY_EXIST_SSO_SIGN_UP_FIREBASE_GOOGLE);
    }

    // * IF USER NOT EXIST. REGISTER THE USER AFTER THAT AUTOMATICALLY LOGIN THE USER
    const csrfTokenSecret = tokens.secretSync();
    const csrfToken = tokens.create(csrfTokenSecret);

    const savedCSRFTokenSecret = await CSRFTokenSecret.create({secret: csrfTokenSecret});
    const savedProfile = await Profile.create({fullName: name, profilePicture: userSettings.DEFAULT_PROFILE_PICTURE});
    const savedUser = await User.create({
        username: name.split(" ")[0] + "_" + generateRandomUsernameSSO(), 
        email: email, 
        password: generateRandomPasswordSSO(),
        profile: [savedProfile._id],
        csrfTokenSecret: [savedCSRFTokenSecret._id],
        isSSO: true,
        social_id: user_id
    });

    await CSRFTokenSecret.findOneAndUpdate({_id: savedCSRFTokenSecret._id}, { user_id: savedUser._id });
    await Profile.findOneAndUpdate({_id: savedProfile._id}, { user_id: savedUser._id });

    let authenticationToken = jwt.sign({_id: savedUser._id}, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, {expiresIn: jwtTokensSettings.JWT_AUTHENTICATION_TOKEN_EXPIRATION_STRING});
    
    res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, authenticationToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'none', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_EXPIRATION)
    });

    return res.status(200).json({status: 'ok'});
});

export default {
    user,
    deleteUser,
    register,
    activate,
    login,
    verificationCodeLogin,
    verificationCodeLoginLogout,
    googleAuthenticatorCodeLogin,
    logout,
    forgotPassword,
    enableGoogleAuthenticator,
    disableGoogleAuthenticator,
    activateGoogleAuthenticator,
    resetPassword,
    accountRecoveryResetPasswordVerifyToken,
    ssoSignInGoogleIdentityServices,
    ssoSignUpGoogleIdentityServices,
    ssoSignInFirebaseFacebook,
    ssoSignUpFirebaseFacebook,
    ssoSignInFirebaseGoogle,
    ssoSignUpFirebaseGoogle
};