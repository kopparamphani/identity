import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { DbModule } from './db/db.module';
import { HealthController } from './health/health.controller';

// Root module. Health + DB + auth features.
@Module({
  imports: [
    // Loads .env once, globally. Real secrets come from Sealed Secrets in prod.
    ConfigModule.forRoot({ isGlobal: true }),
    DbModule,
    AuthModule,
  ],
  controllers: [HealthController],
})
export class AppModule {}
