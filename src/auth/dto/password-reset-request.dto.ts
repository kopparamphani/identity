import { IsEmail } from 'class-validator';

// Body for POST /auth/password-reset/request. snake_case per contract.
// Only an email — we ALWAYS answer 202, so no other input is needed.
export class PasswordResetRequestDto {
  @IsEmail()
  email!: string;
}
