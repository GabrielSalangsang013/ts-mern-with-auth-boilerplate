import { Document } from 'mongoose';

export interface User extends Document {
    username: string;
    email: string;
    password: string;
    forgotPassword: boolean;
    isSSO: boolean;
    verificationCodeLogin: string;
    googleAuthenticator: string | any;
    csrfTokenSecret: string | any;
    profile: string | any;
    matchPasswords(password: string): Promise<boolean>;
    matchVerificationCodeLogin(verificationCodeLogin: string): Promise<boolean>;
    social_id: string;
}

export interface Profile extends Document {
    fullName: string;
    profilePicture: string;
    user_id: string | any;
}

export interface GoogleAuthenticator extends Document {
    secret: string;
    encoding: string;
    qr_code: string;
    otpauth_url: string;
    isActivated: boolean;
    user_id: string | any;
}

export interface CsrfTokenSecret extends Document {
    secret: string;
    user_id: string | any;
}

export interface ValidationResult {
    error: any;
    value: any;
}
