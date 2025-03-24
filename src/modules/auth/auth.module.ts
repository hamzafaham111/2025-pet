import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { MailerModule } from '@nestjs-modules/mailer';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserSchema } from './schemas/user.schema';
import { JwtStrategy } from './jwt.strategy';  // Import your custom JwtStrategy

@Module({
  imports: [
    MongooseModule.forFeature([{ name: 'User', schema: UserSchema }]),
    JwtModule.register({
      secret: 'your-jwt-secret',  // Use a secret key for signing JWT
      signOptions: { expiresIn: '1h' },
    }),
    MailerModule.forRoot({
      transport: {
        host: 'smtp.gmail.com',
        port: 587,
        secure: false, // true for 465, false for other ports
        auth: {
          user: 'hamzafaham111@gmail.com',
          pass: 'lbjo gkrj iach gjob',
        },
      },
      defaults: {
        from: '"No Reply" <hamzafaham111@gmail.com>',
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],  // Include JwtStrategy as a provider
})
export class AuthModule {}
