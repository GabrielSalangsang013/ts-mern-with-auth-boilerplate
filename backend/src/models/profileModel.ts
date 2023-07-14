import mongoose, { Schema } from 'mongoose';
import he from 'he';
import { Profile } from '../interfaces/index.js';
import * as userSettings from '../constants/v1AuthenticationUserSettings.js'; // * ALL USER SETTINGS

const profileSchema: Schema<Profile> = new Schema<Profile>({
  fullName: {
    type: String,
    trim: true,
    required: [true, 'Full Name is required'],
    maxlength: [50, 'Full Name must not exceed 50 characters'],
    match: [/^[A-Za-z.\s]+$/, 'Full Name must contain letters and dots only'],
    validate: [
      {
        validator: function(value: string) {
          const sanitizedValue = he.escape(value);
          return sanitizedValue === value;
        },
        message: 'Full Name contains potentially unsafe characters or invalid characters',
      },
    ],
  },
  profilePicture: {
      type: String,
      required: true,
      default: userSettings.DEFAULT_PROFILE_PICTURE
  },
  user_id: {
      type: Schema.Types.ObjectId,
      select: false,
      ref: 'User'
  }
},{ timestamps: true, versionKey: false })

export default mongoose.model<Profile>('Profile', profileSchema);