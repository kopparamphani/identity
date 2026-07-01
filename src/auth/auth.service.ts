import {
  ConflictException,
  Inject,
  Injectable,
  Logger,
  OnModuleInit,
  UnauthorizedException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { and, eq, gt, isNull, sql } from 'drizzle-orm';
import { createHash, randomBytes } from 'crypto';
import { DRIZZLE, DrizzleDB } from '../db/db.module';
import { account, passwordReset, session } from '../db/schema';
import { PasswordService } from './password.service';
import { EmailService } from './email.service';
import {
  GoogleIdentity,
  GoogleVerifierService,
} from './google-verifier.service';

// LOCKED policy (data model + ADR-0024): 5 bad tries -> 15 min lockout.
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

// Token lifetimes (ADR-0024). Access 15 min, refresh 30 days.
const ACCESS_TTL_SECONDS = 15 * 60;
const REFRESH_TTL_DAYS = 30;

// Entropy of the opaque refresh token. 32 random bytes -> ~256 bits, base64url.
const REFRESH_TOKEN_BYTES = 32;

// Entropy of the reset token. Same 32 bytes -> ~256 bits, base64url. Unguessable.
const RESET_TOKEN_BYTES = 32;

// Reset-link life: 1 hour, one-time use (LOCKED in NFR / data model).
const RESET_TTL_MS = 60 * 60 * 1000;

// Postgres unique-violation SQLSTATE. Thrown when two concurrent first-time
// Google sign-ins both try to insert the same email/sub. We catch this to turn
// a lost insert race into a clean retry-as-login instead of a 500.
const PG_UNIQUE_VIOLATION = '23505';

// What the controller needs to answer: the JWT body + the opaque refresh token.
export interface IssuedTokens {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  // High-entropy random refresh token (raw). Controller puts it in the cookie.
  // We only ever STORE its sha256 hash, never this value.
  refresh_token: string;
}

// Thrown when a locked account tries to log in -> controller maps to 429.
export class AccountLockedException extends Error {}

// Thrown when a reset ticket is missing / already used / expired. Controller
// maps it to a GENERIC 400 — we never reveal which of the three it was.
export class InvalidResetTokenException extends Error {}

// Google result = the usual tokens + whether we minted a brand-new account.
// created -> 201, existing -> 200 (controller picks the status from this flag).
export interface GoogleAuthResult {
  tokens: IssuedTokens;
  created: boolean;
}

@Injectable()
export class AuthService implements OnModuleInit {
  // Audit logger. Identity changes (e.g. Google link) get a deliberate INFO
  // line here. TODO: replace with a real audit-table row once that table exists.
  private readonly logger = new Logger(AuthService.name);

  // Fixed dummy Argon2id hash, computed once at startup. Used on the
  // missing-account / null-hash login path so that branch costs ~the same
  // CPU as a real verify -> no timing oracle for user enumeration.
  private dummyHash!: string;

  constructor(
    @Inject(DRIZZLE) private readonly db: DrizzleDB,
    private readonly passwords: PasswordService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly googleVerifier: GoogleVerifierService,
    private readonly email: EmailService,
  ) {}

  // Precompute the dummy hash once when the module boots, not per-request.
  async onModuleInit(): Promise<void> {
    this.dummyHash = await this.passwords.hash('dummy-password-for-timing');
  }

  // SIGN UP: validate password, reject dup email, create account, auto-login.
  async signup(
    email: string,
    password: string,
    displayName: string,
  ): Promise<IssuedTokens> {
    // Password gate first (length + breach) -> 422 before we touch the DB.
    const policy = await this.passwords.checkPolicy(password);
    if (!policy.ok) {
      throw new UnprocessableEntityException(
        policy.reason === 'too_short'
          ? 'Password must be at least 8 characters'
          : 'Password is known to be breached; pick another',
      );
    }

    const normalizedEmail = email.toLowerCase();

    // One email = one account. Reject duplicates -> 409.
    const existing = await this.db
      .select({ id: account.accountId })
      .from(account)
      .where(eq(account.email, normalizedEmail))
      .limit(1);
    if (existing.length > 0) {
      throw new ConflictException('Email already used');
    }

    const passwordHash = await this.passwords.hash(password);

    let created;
    try {
      [created] = await this.db
        .insert(account)
        .values({
          email: normalizedEmail,
          displayName,
          passwordHash,
          authProvider: 'local',
        })
        .returning({ id: account.accountId });
    } catch (err) {
      // Race: another signup with the same email slipped in between our check
      // and this insert. The unique constraint catches it -> map to the SAME
      // 409 the pre-check gives, never a 500.
      if (this.isUniqueViolation(err)) {
        throw new ConflictException('Email already used');
      }
      throw err;
    }

    // Auto-login: brand-new account gets a session right away.
    return this.issueTokens(created.id);
  }

  // LOG IN: check lockout, verify password, count failures, lock at 5.
  async login(email: string, password: string): Promise<IssuedTokens> {
    const normalizedEmail = email.toLowerCase();

    const [found] = await this.db
      .select()
      .from(account)
      .where(eq(account.email, normalizedEmail))
      .limit(1);

    // Unknown email / Google-only account (no local hash): DON'T return early.
    // Returning fast here leaks (via timing) that the account doesn't exist.
    // Burn the same ~Argon2id work against a dummy hash, discard it, then throw
    // the IDENTICAL generic 401 -> both branches cost roughly the same.
    if (!found || !found.passwordHash) {
      await this.passwords.verify(this.dummyHash, password);
      throw new UnauthorizedException('Incorrect credentials');
    }

    // Door still slammed? Refuse even if the password is right -> 429.
    if (found.lockedUntil && found.lockedUntil > new Date()) {
      throw new AccountLockedException('Account temporarily locked');
    }

    const good = await this.passwords.verify(found.passwordHash, password);
    if (!good) {
      await this.registerFailedAttempt(found.accountId, found.failedLoginAttempts);
      throw new UnauthorizedException('Incorrect credentials');
    }

    // Good login -> wipe the lockout memory.
    await this.db
      .update(account)
      .set({ failedLoginAttempts: 0, lockedUntil: null, updatedAt: new Date() })
      .where(eq(account.accountId, found.accountId));

    return this.issueTokens(found.accountId);
  }

  // GOOGLE SIGN-IN (REQ-ACC-01/02 Google paths). Single endpoint handles BOTH
  // sign up and login: we verify the ID token, then resolve to an account by
  // three rules, then issue the SAME tokens as 1a (reuses issueTokens).
  //   1. Known google_subject_id        -> log in (existing, 200).
  //   2. Same email, local-only account -> LINK (set sub + auth_provider=both),
  //      then log in (existing, 200). Lets a password user adopt Google.
  //   3. Otherwise                       -> create a Google-only account (201).
  async googleAuth(idToken: string): Promise<GoogleAuthResult> {
    // Verify FIRST. Bad/expired/forged token never reaches the DB -> 401.
    const identity = await this.googleVerifier.verify(idToken);

    try {
      return await this.resolveGoogleAccount(identity);
    } catch (err) {
      // Concurrent first-time sign-in race: two requests both passed the
      // by-sub/by-email reads as "nobody here", then both tried to INSERT. The
      // second insert hits the unique constraint (email or google_subject_id).
      // That is NOT a real failure — the row now exists, so retry as a plain
      // login by sub and hand back tokens. Double-submit -> clean 200, not 500.
      if (this.isUniqueViolation(err)) {
        const [bySub] = await this.db
          .select({ id: account.accountId })
          .from(account)
          .where(eq(account.googleSubjectId, identity.sub))
          .limit(1);
        if (bySub) {
          return { tokens: await this.issueTokens(bySub.id), created: false };
        }
      }
      throw err;
    }
  }

  // Resolve a verified Google identity to an account by the three rules. Split
  // out from googleAuth so the public method can wrap it with race-retry.
  private async resolveGoogleAccount(
    identity: GoogleIdentity,
  ): Promise<GoogleAuthResult> {
    const normalizedEmail = identity.email.toLowerCase();

    // Rule 1: we've seen this Google user before -> straight log in.
    // (No email_verified re-check: this account was already established.)
    const [bySub] = await this.db
      .select({ id: account.accountId })
      .from(account)
      .where(eq(account.googleSubjectId, identity.sub))
      .limit(1);
    if (bySub) {
      return { tokens: await this.issueTokens(bySub.id), created: false };
    }

    // BLOCKER gate: linking (Rule 2) and creating (Rule 3) both attach this
    // email to an account. An unverified email could belong to someone else, so
    // refuse before we touch either path.
    if (!identity.emailVerified) {
      throw new UnauthorizedException('Google email not verified');
    }

    // Rule 2: an account already owns this email.
    const [byEmail] = await this.db
      .select({
        id: account.accountId,
        authProvider: account.authProvider,
        googleSubjectId: account.googleSubjectId,
      })
      .from(account)
      .where(eq(account.email, normalizedEmail))
      .limit(1);
    if (byEmail) {
      // Only a pure local account with NO sub yet may be linked. If the row is
      // already 'google'/'both' (or somehow already carries a sub), it is bound
      // to an immutable Google id. A different incoming sub here means someone
      // is trying to rebind that identity -> refuse, never silently overwrite.
      if (byEmail.authProvider !== 'local' || byEmail.googleSubjectId !== null) {
        throw new UnauthorizedException('Account already linked to Google');
      }

      // LINK: attach the Google subject and flip provider to 'both' so the user
      // can sign in either way. Password hash is left untouched.
      await this.db
        .update(account)
        .set({
          googleSubjectId: identity.sub,
          authProvider: 'both',
          updatedAt: new Date(),
        })
        .where(eq(account.accountId, byEmail.id));

      // SHOULD 3 audit: deliberate identity-change record (who + what + when).
      // Only account_id + sub — never the full Google payload. TODO: persist to
      // a real audit table once one exists.
      this.logger.log(
        `audit identity-change: account_id=${byEmail.id} change=google-link google_sub=${identity.sub}`,
      );

      return { tokens: await this.issueTokens(byEmail.id), created: false };
    }

    // Rule 3: nobody here yet -> create a fresh Google-only account.
    // No password hash (Google owns the credential); display name from the
    // token's name, falling back to the email when Google omits it.
    const [created] = await this.db
      .insert(account)
      .values({
        email: normalizedEmail,
        displayName: identity.name || identity.email,
        passwordHash: null,
        authProvider: 'google',
        googleSubjectId: identity.sub,
      })
      .returning({ id: account.accountId });

    return { tokens: await this.issueTokens(created.id), created: true };
  }

  // PASSWORD RESET — REQUEST (REQ-ACC-03). Caller ALWAYS gets a generic 202;
  // this method NEVER tells anyone whether the email exists (no enumeration).
  //   - Local-capable account (has a password_hash, i.e. provider local/both):
  //     mint a high-entropy one-time token, store only its sha256 with a 1-hour
  //     expiry, email the reset link with the RAW token.
  //   - Google-only account (no password_hash) or unknown email: no-op, no mail.
  // Either way the controller returns the same 202 message.
  async requestPasswordReset(email: string): Promise<void> {
    const normalizedEmail = email.toLowerCase();

    const [found] = await this.db
      .select({
        id: account.accountId,
        email: account.email,
        passwordHash: account.passwordHash,
      })
      .from(account)
      .where(eq(account.email, normalizedEmail))
      .limit(1);

    // No local password to reset (unknown, or Google-only) -> silently stop.
    // No mail, no leak. The caller still sees the same generic 202.
    if (!found || !found.passwordHash) {
      return;
    }

    // TIMING: don't await token-insert + SMTP in the request path. If a real
    // account did that work while unknown/Google-only emails returned instantly,
    // the response time itself would leak "this account exists" — defeating the
    // whole no-enumeration promise. So kick it off and DON'T block the 202.
    // Like: drop the letter in the mailbox and walk away; don't wait for the
    // mail truck. Errors are logged, never surfaced (still a generic 202).
    void this.createAndSendResetLink(found.id, found.email);
  }

  // Off the response path (see requestPasswordReset). Mint a one-time token,
  // store only its hash, email the RAW token link. Swallow+log any failure so a
  // dead SMTP or DB hiccup can't crash the request or leak via a 500.
  private async createAndSendResetLink(
    accountId: string,
    toEmail: string,
  ): Promise<void> {
    try {
      // Raw token goes in the email link; only its hash is ever stored.
      const rawToken = this.generateResetToken();
      const expiresAt = new Date(Date.now() + RESET_TTL_MS);

      await this.db.insert(passwordReset).values({
        accountId,
        tokenHash: this.hashToken(rawToken),
        expiresAt,
      });

      // Link the web app opens to set a new password. Base URL is deploy config.
      const baseUrl = this.config.getOrThrow<string>('APP_BASE_URL');
      const resetUrl = `${baseUrl}/reset?token=${rawToken}`;
      await this.email.sendPasswordReset(toEmail, resetUrl);
    } catch (err) {
      // Fire-and-forget: a failed send must NOT bubble (no unhandled rejection,
      // no crash, no info leak). Log for ops; the caller already got its 202.
      this.logger.error(
        `password-reset send failed for account_id=${accountId}: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  }

  // PASSWORD RESET — CONFIRM (REQ-ACC-03). Consume a reset ticket and set a new
  // password. Generic failures only — never reveal WHY a bad link failed.
  //   - Look up BY sha256(token). Missing / already used / expired -> 400.
  //   - Enforce password policy (length + breach), reusing PasswordService -> 422.
  //   - Set new Argon2id hash, stamp the ticket used (one-time), revoke ALL
  //     sessions for the account (force re-login everywhere) -> 200.
  // Thrown: InvalidResetTokenException (controller -> 400),
  //         UnprocessableEntityException (controller -> 422).
  async confirmPasswordReset(token: string, newPassword: string): Promise<void> {
    const tokenHash = this.hashToken(token);

    // BLOCKER FIX — atomic one-time consume. The OLD code did select-then-check-
    // then-update: two concurrent confirms with the SAME token could both pass
    // the check before either stamped used_at, so BOTH succeeded (race). Now the
    // CONSUME itself is the gate: one conditional UPDATE stamps used_at ONLY if
    // the ticket is still unused AND unexpired. Postgres serializes the row
    // write, so exactly ONE update wins (1 row); the loser matches 0 rows.
    // Like: one turnstile — first person through locks it behind them.
    const [winner] = await this.db
      .update(passwordReset)
      .set({ usedAt: new Date() })
      .where(
        and(
          eq(passwordReset.tokenHash, tokenHash),
          isNull(passwordReset.usedAt),
          gt(passwordReset.expiresAt, sql`now()`),
        ),
      )
      .returning({ accountId: passwordReset.accountId });

    // 0 rows -> not found, already spent, or expired. One generic error; we
    // deliberately don't say which, so an attacker can't probe tickets.
    if (!winner) {
      throw new InvalidResetTokenException('Invalid or expired reset link');
    }

    const accountId = winner.accountId;

    // NOTE: the ticket is now spent even if the password check below fails (422).
    // That's the safe trade: a one-time link is truly one-time. A user who typed
    // a weak password just requests a fresh link. Better than leaving a live
    // ticket after we've already committed to consuming it in the race gate.

    // Same policy gate as signup: length first (cheap), then breach -> 422.
    const policy = await this.passwords.checkPolicy(newPassword);
    if (!policy.ok) {
      throw new UnprocessableEntityException(
        policy.reason === 'too_short'
          ? 'Password must be at least 8 characters'
          : 'Password is known to be breached; pick another',
      );
    }

    const passwordHash = await this.passwords.hash(newPassword);

    // Set the new password. Leave auth_provider alone: a 'both' account keeps
    // Google linked; a 'local' account stays local.
    await this.db
      .update(account)
      .set({
        passwordHash,
        // A successful reset is also a way back in -> clear any lockout memory.
        failedLoginAttempts: 0,
        lockedUntil: null,
        updatedAt: new Date(),
      })
      .where(eq(account.accountId, accountId));

    // SHOULD 2 — kill sibling tickets. A password change should invalidate EVERY
    // other outstanding reset link for this account (e.g. an old email the user
    // never used). Stamp all still-unused tickets spent. We already consumed the
    // winner above, so exclude it. now() would also work but explicit is clearer.
    await this.db
      .update(passwordReset)
      .set({ usedAt: new Date() })
      .where(
        and(
          eq(passwordReset.accountId, accountId),
          isNull(passwordReset.usedAt),
        ),
      );

    // SECURITY: a reset means "I (re)claim this account" -> kill every live
    // session so any thief who had one is logged out everywhere. Reuses the
    // same revoke flag logout/refresh honor.
    await this.db
      .update(session)
      .set({ revoked: true })
      .where(eq(session.accountId, accountId));
  }

  // Is this error a Postgres unique-constraint violation? postgres-js surfaces
  // the SQLSTATE on err.code. Used to turn an insert race into retry-as-login.
  private isUniqueViolation(err: unknown): boolean {
    return (
      typeof err === 'object' &&
      err !== null &&
      (err as { code?: string }).code === PG_UNIQUE_VIOLATION
    );
  }

  // One more wrong try. At the threshold, lock for 15 min.
  private async registerFailedAttempt(
    accountId: string,
    currentAttempts: number,
  ): Promise<void> {
    const attempts = currentAttempts + 1;
    const lockedUntil =
      attempts >= MAX_FAILED_ATTEMPTS
        ? new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000)
        : null;

    await this.db
      .update(account)
      .set({
        failedLoginAttempts: attempts,
        lockedUntil,
        updatedAt: new Date(),
      })
      .where(eq(account.accountId, accountId));
  }

  // LOG OUT: revoke the session behind this cookie. We never stored the raw
  // token, so hash the incoming one and revoke BY token_hash. Idempotent-ish:
  // missing / unknown / already-revoked all still return 204 (no info leak).
  async logout(refreshToken: string | undefined): Promise<void> {
    if (!refreshToken) {
      return;
    }
    await this.db
      .update(session)
      .set({ revoked: true })
      .where(eq(session.tokenHash, this.hashToken(refreshToken)));
  }

  // REFRESH: hash the incoming cookie token, look up the session BY token_hash
  // (parameterized — never the raw token, never the PK). Must exist + not
  // revoked + not expired. ROTATE: mint a brand-new token, store its hash on a
  // new row, revoke the old row. Old/rotated token is then dead.
  async refresh(refreshToken: string | undefined): Promise<IssuedTokens> {
    if (!refreshToken) {
      throw new UnauthorizedException('Missing refresh token');
    }

    const tokenHash = this.hashToken(refreshToken);

    const [row] = await this.db
      .select()
      .from(session)
      .where(and(eq(session.tokenHash, tokenHash), eq(session.revoked, false)))
      .limit(1);

    if (!row || row.expiresAt <= new Date()) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    // Revoke the presented session — the rotated token replaces it.
    await this.db
      .update(session)
      .set({ revoked: true, lastSeenAt: new Date() })
      .where(eq(session.sessionId, row.sessionId));

    // Fresh session row carries the rotated token forward (same 30-day window).
    return this.issueTokens(row.accountId);
  }

  // Create a new session row (storing only the token hash) + sign the access
  // JWT. Returns the RAW refresh token to the caller; it's never persisted raw.
  private async issueTokens(accountId: string): Promise<IssuedTokens> {
    const expiresAt = new Date(
      Date.now() + REFRESH_TTL_DAYS * 24 * 60 * 60 * 1000,
    );

    const refreshToken = this.generateRefreshToken();

    await this.db.insert(session).values({
      accountId,
      tokenHash: this.hashToken(refreshToken),
      expiresAt,
    });

    const accessToken = await this.signAccessToken(accountId);
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TTL_SECONDS,
      refresh_token: refreshToken,
    };
  }

  // High-entropy opaque token the client holds. base64url so it's cookie-safe.
  private generateRefreshToken(): string {
    return randomBytes(REFRESH_TOKEN_BYTES).toString('base64url');
  }

  // High-entropy reset token for the email link. base64url so it's URL-safe.
  private generateResetToken(): string {
    return randomBytes(RESET_TOKEN_BYTES).toString('base64url');
  }

  // sha256(token) hex — what we store + look up by. One-way: a DB leak can't
  // reverse it back into a usable bearer token.
  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  // sub = account id. Signed with JWT_SECRET (env now, Sealed Secret in prod).
  private async signAccessToken(accountId: string): Promise<string> {
    return this.jwt.signAsync(
      { sub: accountId },
      {
        secret: this.config.getOrThrow<string>('JWT_SECRET'),
        expiresIn: ACCESS_TTL_SECONDS,
      },
    );
  }
}
