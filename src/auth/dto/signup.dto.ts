import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

// Wire shape is snake_case and LOCKED by the OpenAPI contract.
// NOTE: password strength is NOT validated here — PasswordService owns that
// (length + breach) so we can return the right 422 reason.
export class SignupDto {
  @IsEmail()
  email!: string;

  @IsString()
  @IsNotEmpty()
  password!: string;

  @IsString()
  @IsNotEmpty()
  display_name!: string;
}
