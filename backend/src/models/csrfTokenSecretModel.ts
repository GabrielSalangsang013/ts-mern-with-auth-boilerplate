import mongoose, { Schema } from 'mongoose';
import { CsrfTokenSecret } from '../interfaces/index.js';

const csrfTokenSecretSchema: Schema<CsrfTokenSecret> = new Schema<CsrfTokenSecret>({
  secret: {
    type: String,
    required: true
  },
  user_id: {
      type: Schema.Types.ObjectId,
      select: false,
      ref: 'User'
  }
}, {versionKey: false});

export default mongoose.model<CsrfTokenSecret>('CSRFTokenSecret', csrfTokenSecretSchema);