import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OAuth2Client } from 'google-auth-library';

// What we trust AFTER Google's library validates the token's signature,
// expiry, issuer and audience. sub = Google's stable user id (the join key);
// email + name feed account creation / linking.
export interface GoogleIdentity {
  sub: string;
  email: string;
  name?: string;
  // Did Google confirm this email belongs to the user? We REFUSE to link or
  // create on an unverified email — else someone could claim a victim's address.
  emailVerified: boolean;
}

// Thin wrapper around google-auth-library. INTENT: keep all Google-specific
// crypto in ONE injectable so AuthService stays provider-agnostic and tests can
// swap this out with a stub (no real Google credentials needed in CI).
@Injectable()
export class GoogleVerifierService {
  // One client reused across requests. audience is checked at verify time.
  private readonly client: OAuth2Client;
  private readonly clientId: string;

  constructor(config: ConfigService) {
    // Required for deploy — fail fast at boot if the Google client id is missing.
    this.clientId = config.getOrThrow<string>('GOOGLE_CLIENT_ID');
    this.client = new OAuth2Client(this.clientId);
  }

  // Verify the ID token against OUR client id. The library rejects bad
  // signatures, wrong audience, wrong issuer and expired tokens. ANY failure
  // (thrown or missing sub/email) -> 401, never trust a half-valid token.
  async verify(idToken: string): Promise<GoogleIdentity> {
    let payload;
    try {
      const ticket = await this.client.verifyIdToken({
        idToken,
        audience: this.clientId,
      });
      payload = ticket.getPayload();
    } catch {
      // Bad/expired/forged token -> generic 401, no detail leaked.
      throw new UnauthorizedException('Invalid Google token');
    }

    // A valid token MUST carry sub + email for us to resolve an account.
    if (!payload?.sub || !payload.email) {
      throw new UnauthorizedException('Invalid Google token');
    }

    // email_verified must be the literal true. Google may omit it or send a
    // string; treat anything that is not boolean true as NOT verified.
    return {
      sub: payload.sub,
      email: payload.email,
      name: payload.name,
      emailVerified: payload.email_verified === true,
    };
  }
}
