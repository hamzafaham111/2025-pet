import { Module } from '@nestjs/common';
import { AuthModule } from './modules/auth/auth.module'; // Other business modules
import { DatabaseModule } from './infrastructure/database/database.module';

@Module({
  imports: [
    DatabaseModule, // Make sure to include DatabaseModule
    AuthModule,
  ],
})
export class AppModule {}
