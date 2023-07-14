import express from 'express';
import jwt from 'jsonwebtoken';
import Tokens from 'csrf';
import lodash from 'lodash';

// * ------------ MODELS --------------------
import User from "../models/userModel.js";
// * ------------ MODELS --------------------

// * ------------ CONSTANTS --------------------
import * as cookiesSettings from '../constants/v1AuthenticationCookiesSettings.js'; // * ALL COOKIES SETTINGS
import * as errorCodes from '../constants/v1AuthenticationErrorCodes.js'; // * ALL ERROR CODES
// * ------------ CONSTANTS --------------------

// * ------------ TYPES --------------------
import * as TYPES from '../types/index.js';
// * ------------ TYPES --------------------

export function isMFAMode(req: express.Request, res: express.Response, next: express.NextFunction): any {
    const MFA_LOGIN_TOKEN: string = req.cookies[cookiesSettings.COOKIE_MFA_TOKEN_NAME];

    if (MFA_LOGIN_TOKEN) {
        const MFA_TOKEN_SECRET: string = process.env["MFA_TOKEN_SECRET"] as string;
        try {
            if (jwt.verify(MFA_LOGIN_TOKEN as string, MFA_TOKEN_SECRET)) {
                const { username, profilePicture, hasGoogleAuthenticator }: TYPES.MFA_LOGIN_TOKEN = jwt.decode(MFA_LOGIN_TOKEN) as TYPES.MFA_LOGIN_TOKEN;

                return res.status(200).json({
                    status: 'MFA-Mode', 
                    user: {
                        username, 
                        profilePicture, 
                        hasGoogleAuthenticator
                    }
                });
            }
        } catch (error) {
            // * Handle verification error
        }
    }

    next();
}

export function isAuthenticated(req: express.Request, res: express.Response, next: express.NextFunction): any {
    const authenticationToken: string = req.cookies[cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME];
    const csrfToken:any = req.cookies[cookiesSettings.COOKIE_CSRF_TOKEN_NAME];
    const tokens = new Tokens();
    
    if (authenticationToken == null) {
        // NOT AUTHENTICATED USER
        if (!tokens.verify(process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string, csrfToken)) {
            const csrfTokenSecret = process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string;
            const csrfToken:any = tokens.create(csrfTokenSecret);
        
            res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
                httpOnly: true, 
                secure: true, 
                sameSite: 'strict', 
                path: '/', 
                expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
            });
        }

        return res.status(401).json({message: 'Invalid Credential.', errorCode: errorCodes.NO_JWT_TOKEN_AUTHENTICATE_JWT_TOKEN});
    }

    jwt.verify(authenticationToken, process.env["AUTHENTICATION_TOKEN_SECRET"] as string, async (error: any, authenticatedUser: any): Promise<any> => {
        if (error) {
            // THE USER HAS JWT TOKEN BUT INVALID
            res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, 'expiredtoken', {
                httpOnly: true,
                secure: true,
                sameSite: 'strict', 
                path: '/', 
                expires: new Date(0)
            });
    
            const csrfTokenSecret = process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string;
            const csrfToken:any = tokens.create(csrfTokenSecret);
        
            res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
                httpOnly: true, 
                secure: true, 
                sameSite: 'strict', 
                path: '/', 
                expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
            });

            return res.status(403).json({message: 'Invalid Credential.', errorCode: errorCodes.INVALID_JWT_TOKEN_AUTHENTICATE_JWT_TOKEN});
        }

        let existingUser = await User.findOne({_id: authenticatedUser._id})
                                        .select('-username -email -isSSO -createdAt -updatedAt')
                                        .populate('profile', '-fullName -profilePicture -createdAt -updatedAt')
                                        .populate('csrfTokenSecret')
                                        .populate('googleAuthenticator', '-isActivated -createdAt -updatedAt');
        if (!existingUser) return res.status(404).json({message: "Invalid Credential.", errorCode: errorCodes.NO_USER_FOUND_IN_DATABASE_INSIDE_JWT_DECODED_TOKEN_AUTHENTICATE_JWT_TOKEN});
        if (!tokens.verify(existingUser.csrfTokenSecret.secret, csrfToken)) {
            // THE USER HAS CSRF TOKEN BUT INVALID
            res.cookie(cookiesSettings.COOKIE_AUTHENTICATION_TOKEN_NAME, 'expiredtoken', {
                httpOnly: true,
                secure: true,
                sameSite: 'strict', 
                path: '/', 
                expires: new Date(0)
            });
        
            const csrfTokenSecret = process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string;
            const csrfToken:any = tokens.create(csrfTokenSecret);
        
            res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
                httpOnly: true, 
                secure: true, 
                sameSite: 'strict', 
                path: '/', 
                expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
            });
            
            return res.status(403).json({message: 'Invalid Credential.', errorCode: errorCodes.INVALID_CSRF_TOKEN_VERIFY_PRIVATE_CSRF_TOKEN});
        }

        // * WE NO LONGER NEED CSRF TOKEN SECRET - THE USER IS REALLY AUTHENTICED USER
        existingUser.csrfTokenSecret = undefined;

        // * EXISTING USER - FINAL DATA - WE DON'T SEND THIS, WE HOLD THIS DATA FOR UPDATE PURPOSES
        // * {
        // *    _id: ObjectId,
        // *    profile: {
        // *        _id: ObjectId
        // *    },
        // *    googleAuthenticator?: {
        // *        _id: ObjectId,    
        // *    }
        // * }
        
        lodash.merge(req, { authenticatedUser: existingUser });
        next();
    });
}

export function verifyPublicCSRFToken(req: express.Request, res: express.Response, next: express.NextFunction): any {
    const csrfToken:any = req.cookies[cookiesSettings.COOKIE_CSRF_TOKEN_NAME];
    const tokens = new Tokens();

    if (csrfToken == null) {
        // THE USER HAS NO CSRF TOKEN
        const csrfTokenSecret = process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string;
        const csrfToken:any = tokens.create(csrfTokenSecret);
    
        res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
        });

        return res.status(401).json({message: 'Invalid Credential.', errorCode: errorCodes.NO_CSRF_TOKEN_VERIFY_PUBLIC_CSRF_TOKEN});
    }

    if (!tokens.verify(process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string, csrfToken)) {
        // THE USER HAS CSRF TOKEN BUT INVALID 
        const csrfTokenSecret = process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string;
        const csrfToken:any = tokens.create(csrfTokenSecret);
    
        res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
        });
        
        return res.status(403).json({message: 'Invalid Credential.', errorCode: errorCodes.INVALID_CSRF_TOKEN_VERIFY_PUBLIC_CSRF_TOKEN});
    }

    next();
}

export function sendPublicCSRFTokenToUser(req: express.Request, res: express.Response, next: express.NextFunction): any {
    // IF USER DOESN'T HAVE CSRF TOKEN, THE USER WILL RECEIVE A PUBLIC CSRF TOKEN
    const existingCsrfToken = req.cookies[cookiesSettings.COOKIE_CSRF_TOKEN_NAME];
    
    if (existingCsrfToken == null) {
        const tokens = new Tokens();
        const csrfTokenSecret = process.env["PUBLIC_CSRF_TOKEN_SECRET"] as string;
        const csrfToken = tokens.create(csrfTokenSecret);

        res.cookie(cookiesSettings.COOKIE_CSRF_TOKEN_NAME, csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
        });
    }

    next();
}
