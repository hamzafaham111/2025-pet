import { Module, Global } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule, ConfigService } from '@nestjs/config';
import * as mongoose from 'mongoose';
@Global() // Makes this module available globally in the app
@Module({
  imports: [
    ConfigModule.forRoot(), // Make sure environment variables are loaded
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => {
        const dbUri = configService.get<string>('DB_URL');
        try {
          // Attempt MongoDB connection
          await mongoose.connect(dbUri!);
          console.log({message:'Database connection successful'});
        } catch (error) {
          // If there's an error with the database connection
          console.log({message:`Database connection failed: ${error.message}`});
        }

        return { uri: dbUri };
        
      },
      inject: [ConfigService],
    }),
  ],
})
export class DatabaseModule {}
