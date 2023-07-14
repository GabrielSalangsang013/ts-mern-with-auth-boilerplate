import mongoose, { Schema } from 'mongoose';
import he from 'he';
import argon2 from 'argon2';
import { User } from '../interfaces/index.js';

const userSchema: Schema<User> = new Schema<User>(
  {
    username: {
      type: String,
      unique: true,
      trim: true,
      required: [true, 'Username is required'],
      minlength: [4, 'Username must be at least 4 characters'],
      maxlength: [20, 'Username must not exceed 20 characters'],
      match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores'],
      validate: [
        {
          validator: function(value: string) {
            return !/\b(admin|root|superuser)\b/i.test(value);
          },
          message: 'Username should not contain sensitive information',
        },
        {
          validator: function(value: string) {
            const sanitizedValue = he.escape(value);
            return sanitizedValue === value;
          },
          message: 'Invalid characters detected',
        },
      ],
    },
    email: {
      type: String,
      unique: true,
      trim: true,
      required: [true, 'Email is required'],
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        'Please enter a valid email address',
      ],
      validate: [
        {
          validator: function(value: string) {
            const sanitizedValue = he.escape(value);
            return sanitizedValue === value;
          },
          message: 'Invalid email format or potentially unsafe characters',
        },
      ],
    },
    password: {
      type: String,
      select: false,
      required: [true, 'Password is required'],
      minlength: [12, 'Password must be at least 12 characters'],
      match: [
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).+$/,
        'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
      ],
      validate: [
        {
          validator: function(value: string) {
            return !/\b(password|123456789)\b/i.test(value);
          },
          message: 'Password should not be commonly used or easily guessable',
        },
      ]
    },
    forgotPassword: {
      type: 'boolean',
      select: false,
      required: false,
      default: false
    },
    isSSO: {
      type: 'boolean',
      required: true,
      default: false
    },
    verificationCodeLogin: { 
      type: String,
      select: false,
      minlength: [7, 'Verification login code must be 7 characters'],
      maxlength: [7, 'Verification login code must be 7 characters'],
      match: [
        /^(?=.*[a-zA-Z])(?=.*[0-9])[a-zA-Z0-9]{7}$/,
        'Verification login code must be 7 characters and contain only numbers and letters',
      ],
      validate: [
        {
          validator: function(value: string) {
            return !/\b(admin|root|superuser)\b/i.test(value);
          },
          message: 'Verification login code should not contain sensitive information',
        },{
          validator: function(value: string) {
            const sanitizedValue = he.escape(value);
            return sanitizedValue === value;
          },
          message: 'Invalid verification login code format or potentially unsafe characters',
        },
      ]
    },
    googleAuthenticator: {
      type: Schema.Types.ObjectId,
      select: false,
      ref: 'GoogleAuthentication',
      required: false
    },
    csrfTokenSecret: {
      type: Schema.Types.ObjectId,
      select: false,
      ref: 'CSRFTokenSecret',
      required: true
    },
    profile: {
      type: Schema.Types.ObjectId,
      ref: 'Profile',
      required: true
    },
    social_id: {
      type: String,
      required: false
    }
  },
  { timestamps: true, versionKey: false }
);

userSchema.pre('save', async function (this: User, next: any) {
  if (!this.isModified('password')) {
    return next();
  }

  try {
    const hashedPassword = await argon2.hash(this.password);
    this.password = hashedPassword;
    return next();
  } catch (error) {
    return next(error);
  }
});

userSchema.methods.matchPasswords = async function (password: string) {
  return await argon2.verify(this.password, password);
};

userSchema.methods.matchVerificationCodeLogin = async function (verificationCodeLogin: string) {
  return await argon2.verify(this.verificationCodeLogin, verificationCodeLogin);
};

export default mongoose.model<User>('User', userSchema);