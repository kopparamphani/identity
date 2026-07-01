import { IsNotEmpty, IsString } from 'class-validator';

// Body for POST /auth/password-reset/confirm. snake_case per contract.
// NOTE: new_password strength is NOT validated here — PasswordService owns that
// (length + breach) so we can return the right 422 reason, same as signup.
export class PasswordResetConfirmDto {
  @IsString()
  @IsNotEmpty()
  token!: string;

  @IsString()
  @IsNotEmpty()
  new_password!: string;
}
