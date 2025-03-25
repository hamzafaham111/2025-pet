// First, define your User interface
import { Document, Types } from 'mongoose';

export interface IUser {
  _id: Types.ObjectId;
  email: string;
  password: string;
  refreshToken?: string;
  isVerified: boolean;
  // ... other user properties
}

export interface IUserDocument extends IUser, Document {
  _id: Types.ObjectId;
}