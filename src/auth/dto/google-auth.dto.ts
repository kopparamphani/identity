import { IsNotEmpty, IsString } from 'class-validator';

// Wire shape for POST /auth/google. snake_case to match the contract style.
// We only need the Google ID token; the client gets it from Google's SDK and
// hands it to us. We verify it server-side (never trust the client's claims).
export class GoogleAuthDto {
  @IsString()
  @IsNotEmpty()
  id_token!: string;
}
