import Joi from 'joi';
import he from 'he';
import { ValidationResult } from '../interfaces/index.js';

export function registerValidate(username: string, email: string, password: string, repeatPassword: string, fullName: string) {
    const schema = Joi.object({
        username: Joi.string()
            .required()
            .trim()
            .min(4)
            .max(20)
            .pattern(/^[a-zA-Z0-9_]+$/)
            .custom((value, helpers) => {
                if (/\b(admin|root|superuser)\b/i.test(value)) {
                    return helpers.error('username-security');
                }
                return value;
            })
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('username-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Username must be a string',
                'string.empty': 'Username is required',
                'string.min': 'Username must be at least 4 characters',
                'string.max': 'Username must not exceed 20 characters',
                'string.pattern.base': 'Username can only contain letters, numbers, and underscores',
                'any.required': 'Username is required',
                'username-security': 'Username should not contain sensitive information',
                'username-xss-nosql': 'Invalid characters detected',
            }),
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            }),
        password: Joi.string()
            .required()
            .min(12)
            .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).+$/)
            .custom((value, helpers) => {
                if (/\b(password|123456789)\b/i.test(value)) {
                    return helpers.error('password-security');
                }
                return value;
            })
            .messages({
                'string.base': 'Password must be a string',
                'string.empty': 'Password is required',
                'string.min': 'Password must be at least 12 characters',
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
                'any.required': 'Password is required',
                'password-security': 'Password should not be commonly used or easily guessable',
            }),
        repeatPassword: Joi.string()
            .required()
            .valid(Joi.ref('password'))
            .messages({
                'string.base': 'Repeat Password must be a string',
                'string.empty': 'Please repeat your password',
                'any.only': 'Passwords must match',
                'any.required': 'Please repeat your password',
            }),
        fullName: Joi.string()
            .required()
            .trim()
            .max(50)
            .regex(/^[A-Za-z.\s]+$/)
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('full-name-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Full Name must be a string',
                'string.empty': 'Full Name is required',
                'string.max': 'Full Name must not exceed 50 characters',
                'string.pattern.base': 'Full Name must contain letters and dots only',
                'any.required': 'Full Name is required',
                'full-name-xss-nosql': 'Full Name contains potentially unsafe characters or invalid characters',
            })
    });

    return schema.validate({ username, email, password, repeatPassword, fullName });
}

export function activateValidate(username: string, email: string, password: string, repeatPassword: string, fullName: string): ValidationResult {
  const schema = Joi.object({
        username: Joi.string()
            .required()
            .trim()
            .min(4)
            .max(20)
            .pattern(/^[a-zA-Z0-9_]+$/)
            .custom((value, helpers) => {
                if (/\b(admin|root|superuser)\b/i.test(value)) {
                    return helpers.error('username-security');
                }
                return value;
            })
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('username-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Username must be a string',
                'string.empty': 'Username is required',
                'string.min': 'Username must be at least 4 characters',
                'string.max': 'Username must not exceed 20 characters',
                'string.pattern.base': 'Username can only contain letters, numbers, and underscores',
                'any.required': 'Username is required',
                'username-security': 'Username should not contain sensitive information',
                'username-xss-nosql': 'Invalid characters detected',
            }),
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            }),
        password: Joi.string()
            .required()
            .min(12)
            .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).+$/)
            .custom((value, helpers) => {
                if (/\b(password|123456789)\b/i.test(value)) {
                    return helpers.error('password-security');
                }
                return value;
            })
            .messages({
                'string.base': 'Password must be a string',
                'string.empty': 'Password is required',
                'string.min': 'Password must be at least 12 characters',
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
                'any.required': 'Password is required',
                'password-security': 'Password should not be commonly used or easily guessable',
            }),
        repeatPassword: Joi.string()
            .required()
            .valid(Joi.ref('password'))
            .messages({
                'string.base': 'Repeat Password must be a string',
                'string.empty': 'Please repeat your password',
                'any.only': 'Passwords must match',
                'any.required': 'Please repeat your password',
            }),
        fullName: Joi.string()
            .required()
            .trim()
            .max(50)
            .regex(/^[A-Za-z.\s]+$/)
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('full-name-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Full Name must be a string',
                'string.empty': 'Full Name is required',
                'string.max': 'Full Name must not exceed 50 characters',
                'string.pattern.base': 'Full Name must contain letters and dots only',
                'any.required': 'Full Name is required',
                'full-name-xss-nosql': 'Full Name contains potentially unsafe characters or invalid characters',
        })
    })

  return schema.validate({ username, email, password, repeatPassword, fullName });
}

export function loginValidate(username: string, password: string): ValidationResult { 
    const schema = Joi.object({
        username: Joi.string()
            .required()
            .trim()
            .min(4)
            .max(20)
            .pattern(/^[a-zA-Z0-9_]+$/)
            .custom((value, helpers) => {
                if (/\b(admin|root|superuser)\b/i.test(value)) {
                    return helpers.error('username-security');
                }
                return value;
            })
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('username-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Username must be a string',
                'string.empty': 'Username is required',
                'string.min': 'Username must be at least 4 characters',
                'string.max': 'Username must not exceed 20 characters',
                'string.pattern.base': 'Username can only contain letters, numbers, and underscores',
                'any.required': 'Username is required',
                'username-security': 'Username should not contain sensitive information',
                'username-xss-nosql': 'Invalid characters detected',
            }),
        password: Joi.string()
            .required()
            .min(12)
            .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).+$/)
            .custom((value, helpers) => {
                if (/\b(password|123456789)\b/i.test(value)) {
                    return helpers.error('password-security');
                }
                return value;
            })
            .messages({
                'string.base': 'Password must be a string',
                'string.empty': 'Password is required',
                'string.min': 'Password must be at least 12 characters',
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
                'any.required': 'Password is required',
                'password-security': 'Password should not be commonly used or easily guessable',
            })
    });

    return schema.validate({username, password});
}

export function verificationCodeLoginValidate(verificationCodeLogin: string): ValidationResult {
    const schema = Joi.object({
        verificationCodeLogin: Joi.string()
            .required()
            .length(7)
            .pattern(/^(?=.*[a-zA-Z])(?=.*[0-9])[a-zA-Z0-9]{7}$/)
            .custom((value, helpers) => {
                if (/\b(admin|root|superuser)\b/i.test(value)) {
                    return helpers.error('verification-code-login-security');
                }
                return value;
            })
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('verification-code-login-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Verification login code must be a string',
                'string.empty': 'Verification login code is required',
                'string.length': 'Verification login code must be {#limit} characters',
                'string.pattern.base': 'Verification login code must be 7 characters and contain only numbers and letters',
                'verification-code-login-security': 'Verification login code should not contain sensitive information',
                'verification-code-login-xss-nosql': 'Invalid characters detected',
            })
    });

    return schema.validate({verificationCodeLogin});
}

export function forgotPasswordValidate(email: string): ValidationResult {
    const schema = Joi.object({
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            })
    });

    return schema.validate({email});
}

export function googleAuthenticatorCodeLoginValidate(googleAuthenticationCodeLogin: string): ValidationResult {
    const schema = Joi.object({
        googleAuthenticationCodeLogin: Joi.string()
            .required()
            .pattern(/^\d{6}$/)
            .messages({
                'string.base': 'Google Authentication Code Login must be a string',
                'string.empty': 'Google Authentication Code Login is required',
                'string.pattern.base': 'Code must be a 6-digit number',
                'any.required': 'Google Authentication Code Login is required',
            }),
    });

    return schema.validate({googleAuthenticationCodeLogin});
}

export function resetPasswordValidate(email: string, password: string, repeatPassword: string): ValidationResult {
    const schema = Joi.object({
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            }),
        password: Joi.string()
            .required()
            .min(12)
            .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).+$/)
            .custom((value, helpers) => {
                if (/\b(password|123456789)\b/i.test(value)) {
                    return helpers.error('password-security');
                }
                return value;
            })
            .messages({
                'string.base': 'Password must be a string',
                'string.empty': 'Password is required',
                'string.min': 'Password must be at least 12 characters',
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
                'any.required': 'Password is required',
                'password-security': 'Password should not be commonly used or easily guessable',
            }),
        repeatPassword: Joi.string()
            .required()
            .valid(Joi.ref('password'))
            .messages({
                'string.base': 'Repeat Password must be a string',
                'string.empty': 'Please repeat your password',
                'any.only': 'Passwords must match',
                'any.required': 'Please repeat your password',
            }),
    });

    return schema.validate({email, password, repeatPassword});
}

export function accountRecoveryResetPasswordVerifyTokenValidate(email: string): ValidationResult {
    const schema = Joi.object({
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            })
    });

    return schema.validate({email});
}

export function ssoGoogleIdentityServicesValidate(email: string, name: string): ValidationResult {
    const schema = Joi.object({
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            }),
        name: Joi.string()
            .required()
            .trim()
            .max(50)
            .regex(/^[A-Za-z.\s]+$/)
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('full-name-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Full Name must be a string',
                'string.empty': 'Full Name is required',
                'string.max': 'Full Name must not exceed 50 characters',
                'string.pattern.base': 'Full Name must contain letters and dots only',
                'any.required': 'Full Name is required',
                'full-name-xss-nosql': 'Full Name contains potentially unsafe characters or invalid characters',
            })
    });

    return schema.validate({email, name});
}

export function ssoFirebaseFacebookValidate(email: string, name: string, user_id: string): ValidationResult {
    const schema = Joi.object({
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            }),
        name: Joi.string()
            .required()
            .trim()
            .max(50)
            .regex(/^[A-Za-z.\s]+$/)
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('full-name-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Full Name must be a string',
                'string.empty': 'Full Name is required',
                'string.max': 'Full Name must not exceed 50 characters',
                'string.pattern.base': 'Full Name must contain letters and dots only',
                'any.required': 'Full Name is required',
                'full-name-xss-nosql': 'Full Name contains potentially unsafe characters or invalid characters',
            }),
        user_id: Joi.string()
            .required()
            .trim()
            .max(255)
            .regex(/^[a-zA-Z0-9]+$/)
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('user-id-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'User id must be a string',
                'string.empty': 'User id is required',
                'string.max': 'User id must not exceed 255 characters',
                'string.pattern.base': 'User id must contain letters and numbers only',
                'any.required': 'User id is required',
                'full-name-xss-nosql': 'User id contains potentially unsafe characters or invalid characters',
            })
    });
    
    return schema.validate({email, name, user_id});
}

export function ssoFirebaseGoogleValidate(email: string, name: string, user_id: string): ValidationResult {
    const schema = Joi.object({
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            }),
        name: Joi.string()
            .required()
            .trim()
            .max(50)
            .regex(/^[A-Za-z.\s]+$/)
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('full-name-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Full Name must be a string',
                'string.empty': 'Full Name is required',
                'string.max': 'Full Name must not exceed 50 characters',
                'string.pattern.base': 'Full Name must contain letters and dots only',
                'any.required': 'Full Name is required',
                'full-name-xss-nosql': 'Full Name contains potentially unsafe characters or invalid characters',
            }),
        user_id: Joi.string()
            .required()
            .trim()
            .max(255)
            .regex(/^[a-zA-Z0-9]+$/)
            .custom((value, helpers) => {
                const sanitizedValue = he.escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('user-id-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'User id must be a string',
                'string.empty': 'User id is required',
                'string.max': 'User id must not exceed 255 characters',
                'string.pattern.base': 'User id must contain letters and numbers only',
                'any.required': 'User id is required',
                'full-name-xss-nosql': 'User id contains potentially unsafe characters or invalid characters',
            })
    });

    return schema.validate({email, name, user_id});
}