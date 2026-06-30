import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

// Login wire shape, snake_case per contract.
export class LoginDto {
  @IsEmail()
  email!: string;

  @IsString()
  @IsNotEmpty()
  password!: string;
}
