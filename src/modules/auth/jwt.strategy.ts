import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt'; // You need passport-jwt package
import { JwtPayload } from './jwt-payload.interface';
import { AuthService } from './auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),  // Get token from Bearer Header
      secretOrKey: 'your-jwt-secret',  // Use your JWT secret key here
    });
  }

  async validate(payload: JwtPayload) {
    // Validate the payload by checking the user from the database if necessary
    return { email: payload.email, sub: payload.sub };
  }
}
