import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PasswordService } from './password.service';
import { GoogleVerifierService } from './google-verifier.service';
import { EmailService } from './email.service';

// Wires the auth endpoints. Secret is passed per-sign call from env (ConfigService),
// so JwtModule here just provides the service.
@Module({
  imports: [JwtModule.register({})],
  controllers: [AuthController],
  providers: [
    AuthService,
    PasswordService,
    GoogleVerifierService,
    EmailService,
  ],
})
export class AuthModule {}
