import { JwtPayload } from "jsonwebtoken";

export type Error = {
    name?: string,
    errors?: any,
    statusCode: number,
    message: string,
    errorCode: number
}

export type RETURN_ERROR = {
    message: string,
    errorCode: number
}

export type MFA_LOGIN_TOKEN = JwtPayload & {
    username: string;
    profilePicture: string;
    hasGoogleAuthentication: boolean;
};

export type SSO_GOOGLE_IDENTITY_SERVICES_TOKEN_DECODED = {
    email: string;
    name: string; 
    picture: string;
}

export type SSO_FIREBASE_FACEBOOK_TOKEN_DECODED = {
    email: string;
    name: string; 
    picture: string;
    user_id: string;
}

export type SSO_FIREBASE_GOOGLE_TOKEN_DECODED = {
    email: string;
    name: string; 
    picture: string;
    email_verified: boolean;
    user_id: string;
}