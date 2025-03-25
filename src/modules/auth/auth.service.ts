import { HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { User } from './schemas/user.schema';  // <-- Importing User type from schema
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto'; // For generating a random verification code
import { MailerService } from '@nestjs-modules/mailer'; // For sending email

@Injectable()

export class AuthService {
  constructor(
    @InjectModel('User') private userModel: Model<User>,  // <-- Injecting the User model here
    private jwtService: JwtService,
    private mailerService: MailerService,  // <-- Injecting the mail service
  ) { }
  // Register a new user
  async register(registerDto: RegisterDto): Promise<any> {
    const { email, password } = registerDto;

    // Check if user already exists
    const userExists = await this.userModel.findOne({ email });
    if (userExists) {
      console.log({ message: 'User already exists' });
      // Throw an HTTP exception with status code 400 (Bad Request)
      throw new HttpException(
        { message: 'User already exists' },
        HttpStatus.BAD_REQUEST,
      );
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate a 7-digit verification code
    const verificationCode = crypto.randomInt(1000000, 9999999).toString();

    const verificationToken = crypto.randomBytes(32).toString('hex');
    // Create and save the new user (with verification code)
    const newUser = new this.userModel({
      email,
      password: hashedPassword,
      verificationCode,
      verificationToken,
      isVerified: false, // Assuming isVerified is a field in User schema to track email verification
    });

    // Send the verification code via email
    await this.sendVerificationEmail(newUser.email, verificationCode);

    // Save the user
    await newUser.save();

    console.log({ message: `User ${email} registered. Verification code sent.` });

    // Return a response with success and verification instructions
    return {
      user: newUser,
      message: 'Registration successful. Please check your email to verify your account.',
      redirectTo: `${process.env.FRONTEND_URL}/auth/verify-email/${verificationToken}`, // URL or route for the verification page
    };
  }

  // Send verification email
  private async sendVerificationEmail(email: string, verificationCode: string): Promise<void> {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Email Verification Code',
      text: `Your email verification code is: ${verificationCode}`,
      html: `<p>Your email verification code is: <strong>${verificationCode}</strong></p>`,
    });
  }

  // Verify the email with the code
  async verifyEmail(token: string, code: string): Promise<any> {
    console.log({token, code});
    const user = await this.userModel.findOne({ 
      verificationToken: token,
      verificationCode: code
    });

    console.log(user);
    if (!user) {
      throw new Error('Invalid verification code or token');
    }

    user.isVerified = true;
    user.verificationToken = null;
    user.verificationCode = null;
    await user.save();

    return {
      message: 'Email verified successfully',
      email: user.email
    };
  }

  // Login a user and generate a JWT token
  async login(loginDto: LoginDto): Promise<any> {
    const { email, password } = loginDto;
    console.log({email, password});
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new Error('Invalid email or password');
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new Error('Invalid email or password');
    }

    // Check if user is verified
    if (!user.isVerified) {
      // Generate verification code for email
      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      // Generate token for redirect
      const verificationToken = crypto.randomBytes(32).toString('hex');
      
      user.verificationCode = verificationCode;
      user.verificationToken = verificationToken;
      await user.save();

      await this.mailerService.sendMail({
        to: user.email,
        subject: 'Verify Your Email',
        html: `
          <h3>Please verify your email</h3>
          <p>Your verification code is: <strong>${verificationCode}</strong></p>
          <p>Please use this code to verify your account.</p>
        `,
      });

      return {
        statusCode: 403,
        message: 'Email verification required',
        email: user.email,
        redirectTo: `${process.env.FRONTEND_URL}/auth/verify-email/${verificationToken}`
      };
    }

    // For verified users
    const accessToken = this.jwtService.sign(
      { email: user.email, sub: user._id },
      { expiresIn: '30m' }
    );

    const refreshToken = this.jwtService.sign(
      { email: user.email, sub: user._id },
      { expiresIn: '7d' }
    );

    // Save refresh token to user document
    user.refreshToken = refreshToken;
    await user.save();

    return {
      message: `User ${user.email} successfully logged in`,
      accessToken,
      refreshToken,
    };
  }

  async logout(user: User) {
    user.refreshToken = null;
    await user.save();
    return {
      message: `User ${user.email} successfully logged out`,
    };
  }
  // Add this method to your AuthService class
  async forgotPassword(email: string): Promise<void> {
    const user = await this.userModel.findOne({ email });
    
    if (!user) {
      // Don't reveal if email exists or not for security
      return;
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour from now

    // Save reset token to user
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetTokenExpiry;
    await user.save();

    // Create reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/auth/reset-password/${resetToken}`;

    // Send reset email
    await this.mailerService.sendMail({
      to: email,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset</p>
        <p>Click this <a href="${resetUrl}">link</a> to reset your password</p>
        <p>This link will expire in 1 hour</p>
        <p>If you didn't request this, please ignore this email</p>
      `,
    });
  }

  // Add this method to your AuthService class
  async resetPassword(token: string, newPassword: string): Promise<void> {
    // Find user with valid reset token
    const user = await this.userModel.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      throw new HttpException(
        'Invalid or expired reset token',
        HttpStatus.BAD_REQUEST
      );
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user password and clear reset token
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();
  }

  // async verifyAndRefreshToken(token: string) {
  //   try {
  //     // Verify the access token
  //     const payload = this.jwtService.verify(token);
      
  //     // If token is valid and not near expiration, return success
  //     const tokenExp = payload.exp * 1000; // Convert to milliseconds
  //     const currentTime = Date.now();
  //     const timeUntilExp = tokenExp - currentTime;
      
  //     // If token is valid and has more than 5 minutes left, return success
  //     if (timeUntilExp > 5 * 60 * 1000) {
  //       return { 
  //         valid: true,
  //         user: payload
  //       };
  //     }

  //     // If token is about to expire, try to refresh it
  //     const user = await this.userModel.findById(payload.sub);
  //     if (!user) {
  //       throw new UnauthorizedException('User not found');
  //     }

  //     // Get refresh token from user document
  //     const refreshToken = user.refreshToken;
  //     if (!refreshToken) {
  //       throw new UnauthorizedException('No refresh token found');
  //     }

  //     try {
  //       // Verify refresh token
  //       const refreshPayload = this.jwtService.verify(refreshToken);
        
  //       // Generate new access token
  //       const newAccessToken = this.jwtService.sign(
  //         { email: user.email, sub: user._id },
  //         { expiresIn: '30m' }
  //       );

  //       return {
  //         valid: true,
  //         user: payload,
  //         newToken: newAccessToken
  //       };
  //     } catch (error) {
  //       // If refresh token is invalid, force re-login
  //       throw new UnauthorizedException('Invalid refresh token');
  //     }
  //   } catch (error) {
  //     if (error.name === 'TokenExpiredError') {
  //       throw new UnauthorizedException('Token expired');
  //     }
  //     throw new UnauthorizedException('Invalid token');
  //   }
  // }

  async verifyAndRefreshToken(token: string) {
    try {
      // Verify the access token
      const payload = this.jwtService.verify(token);
      console.log({payload});
      // If token is valid and not near expiration, return success
      const tokenExp = payload.exp * 1000; // Convert to milliseconds
      const currentTime = Date.now();
      const timeUntilExp = tokenExp - currentTime;
      
      // If token is valid and has more than 5 minutes left, return success
      if (timeUntilExp > 5 * 60 * 1000) {
        return { 
          valid: true,
          user: payload
        };
      }
      console.log("token is valid and not near expiration");
      // If token is about to expire, try to refresh it
      const user = await this.userModel.findById(payload.sub);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }
      console.log("user found");
      // Get refresh token from user document
      const refreshToken = user.refreshToken;
      console.log({refreshToken}); 
      if (!refreshToken) {
        throw new UnauthorizedException('No refresh token found');
      }
      console.log("refresh token found");
      try {
        // Verify refresh token
        const refreshPayload = this.jwtService.verify(refreshToken);
        console.log({refreshPayload});
        // Check if refresh token is expired
        const refreshTokenExp = refreshPayload.exp * 1000;
        if (refreshTokenExp < Date.now()) {
          throw new UnauthorizedException('Refresh token expired');
        }
        console.log("refresh token is not expired");
        // Check if refresh token matches the user
        if (refreshPayload.sub !== user._id.toString()) {
          console.log('Invalid refresh token');
          throw new UnauthorizedException('Invalid refresh token');
        }
        console.log("refresh token matches the user"); 
        // Generate new access token
        const newAccessToken = this.jwtService.sign(
          { 
            email: user.email, 
            sub: user._id,
            isVerified: user.isVerified // Include verification status
          },
          { expiresIn: '30m' }
        );
        console.log("new access token generated");
        // Optionally, you might want to generate a new refresh token too
        const newRefreshToken = this.jwtService.sign(
          { sub: user._id },
          { expiresIn: '7d' }
        );
        console.log("new refresh token generated");
        // Update user's refresh token in database
        await this.userModel.findByIdAndUpdate(user._id, {
          refreshToken: newRefreshToken
        });
        console.log("updated refresh token");
        return {
          valid: true,
          user: payload,
          newToken: newAccessToken,
          newRefreshToken // Include new refresh token in response
        };
      } catch (error) {
        if (error.name === 'TokenExpiredError') {
          throw new UnauthorizedException('Refresh token expired');
        }
        console.log('Invalid refresh token');
        // If refresh token is invalid, force re-login
        throw new UnauthorizedException('Invalid refresh token');
      }
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        console.log('Token expired');
        throw new UnauthorizedException('Token expired');
      }
      console.log('Invalid token');
      throw new UnauthorizedException('Invalid token');
    }
  }
}
