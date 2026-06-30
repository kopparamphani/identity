import { Injectable, Logger } from '@nestjs/common';
import * as argon2 from 'argon2';
import { createHash } from 'crypto';
import { BREACHED_FALLBACK } from './breached-passwords';

// Min length is LOCKED (ADR-0025 / NFR): 8 chars, any characters, no composition.
const MIN_LENGTH = 8;

// Why a password fails policy. Controller maps both to HTTP 422.
export type PasswordPolicyResult =
  | { ok: true }
  | { ok: false; reason: 'too_short' | 'breached' };

@Injectable()
export class PasswordService {
  private readonly logger = new Logger(PasswordService.name);

  // Argon2id with OWASP-baseline params (ADR-0024). Tune later.
  async hash(plain: string): Promise<string> {
    return argon2.hash(plain, {
      type: argon2.argon2id,
      memoryCost: 19456, // ~19 MiB
      timeCost: 2,
      parallelism: 1,
    });
  }

  async verify(hash: string, plain: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, plain);
    } catch {
      // Bad hash format etc. — treat as no-match, never throw to caller.
      return false;
    }
  }

  // Gate a new password: length first (cheap), then breach check.
  async checkPolicy(plain: string): Promise<PasswordPolicyResult> {
    if (plain.length < MIN_LENGTH) {
      return { ok: false, reason: 'too_short' };
    }
    if (await this.isBreached(plain)) {
      return { ok: false, reason: 'breached' };
    }
    return { ok: true };
  }

  // k-anonymity: send only first 5 chars of SHA-1; full password never leaves us.
  // Fail-open (ADR-0025): if HIBP is unreachable, fall back to the bundled list
  // and audit-log that we couldn't reach the live service.
  private async isBreached(plain: string): Promise<boolean> {
    const sha1 = createHash('sha1').update(plain).digest('hex').toUpperCase();
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);

    try {
      const res = await fetch(
        `https://api.pwnedpasswords.com/range/${prefix}`,
        { signal: AbortSignal.timeout(2500) },
      );
      if (!res.ok) {
        throw new Error(`HIBP responded ${res.status}`);
      }
      const body = await res.text();
      // Each line: "<SHA1-suffix>:<count>". Match = this password is breached.
      for (const line of body.split('\n')) {
        const [lineSuffix] = line.split(':');
        if (lineSuffix.trim().toUpperCase() === suffix) {
          return true;
        }
      }
      return false;
    } catch (err) {
      // FAIL-OPEN: allow via live check but still block the worst via fallback.
      this.logger.warn(
        `AUDIT fail-open: HIBP unreachable, using bundled list. ${String(err)}`,
      );
      return BREACHED_FALLBACK.has(plain.toLowerCase());
    }
  }
}
