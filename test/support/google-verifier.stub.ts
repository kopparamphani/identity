import { UnauthorizedException } from '@nestjs/common';
import { GoogleIdentity } from '../../src/auth/google-verifier.service';

// Controllable stand-in for GoogleVerifierService. INTENT: tests OWN what Google
// "says" — no network, no live credentials, fully deterministic. Like: a fake
// passport officer who stamps exactly the name you handed them, or refuses.
//
// Set `next` to the identity the next verify() should return, or set `fail` to
// make verify() throw 401 (mimics a bad/expired/forged token).
export class GoogleVerifierStub {
  // What the next verify() call hands back. Tests set this before calling.
  next: GoogleIdentity | null = null;
  // When true, verify() throws 401 like the real service does on a bad token.
  fail = false;

  // Point verify() at a specific Google identity (sub/email/name).
  // emailVerified defaults to true (the common case) so existing tests that
  // only care about sub/email keep working; pass false to test the gate.
  willReturn(identity: Partial<GoogleIdentity> & Pick<GoogleIdentity, 'sub' | 'email'>): void {
    this.fail = false;
    this.next = { emailVerified: true, ...identity };
  }

  // Make the next verify() reject — simulates an invalid/expired token.
  willThrow(): void {
    this.fail = true;
    this.next = null;
  }

  // Same signature as the real GoogleVerifierService.verify.
  // eslint-disable-next-line @typescript-eslint/require-await
  async verify(_idToken: string): Promise<GoogleIdentity> {
    if (this.fail || !this.next) {
      throw new UnauthorizedException('Invalid Google token');
    }
    return this.next;
  }
}
