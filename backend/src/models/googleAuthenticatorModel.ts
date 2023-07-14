import mongoose, { Schema } from 'mongoose';
import { GoogleAuthenticator } from '../interfaces/index.js';

const googleAuthenticationSchema: Schema<GoogleAuthenticator> = new Schema<GoogleAuthenticator>({
  secret: {
    type: String,
    select: false,
    required: true
  },
  encoding: {
    type: String,
    select: false,
    required: true
  },
  qr_code: {
    type: String,
    select: false,
    required: true
  },
  otpauth_url: {
    type: String,
    select: false,
    required: true
  },
  isActivated: {
    type: 'boolean',
    required: true,
    default: false
  },
  user_id: {
    type: Schema.Types.ObjectId,
    select: false,
    ref: 'User'
  }
}, { timestamps: true, versionKey: false });

export default mongoose.model<GoogleAuthenticator>('GoogleAuthentication', googleAuthenticationSchema);