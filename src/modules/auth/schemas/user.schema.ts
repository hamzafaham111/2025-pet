import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

@Schema()
export class User extends Document {
  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ type: String, default: null })
  verificationCode: string | null;

  @Prop({ type: String, default: null })
  verificationToken: string | null;

  @Prop({ type: Boolean, default: false })
  isVerified: boolean;

  @Prop({ required: false })
  resetPasswordToken?: string;

  @Prop({ required: false })
  resetPasswordExpires?: Date;

  @Prop({ type: String, default: null })
  refreshToken: string | null;

 // Declare _id type explicitly to avoid overwriting the Document type's _id property
 declare _id: Types.ObjectId;  // <-- Use declare here instead of defining _id explicitly
}

export const UserSchema = SchemaFactory.createForClass(User);
