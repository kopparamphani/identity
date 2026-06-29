import { Module } from '@nestjs/common';
import { HealthController } from './health/health.controller';

// Root module. Right now it only wires up health checks.
// Real identity features (accounts, auth) get added here later.
@Module({
  controllers: [HealthController],
})
export class AppModule {}
