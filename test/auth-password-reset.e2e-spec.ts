import { INestApplication } from '@nestjs/common';
import { sql } from 'drizzle-orm';
import request from 'supertest';
import { DrizzleDB } from '../src/db/db.module';
import { EmailService } from '../src/auth/email.service';
import { bootTestApp, resetTables } from './support/app-harness';
import { EmailStub } from './support/email.stub';

// Forgotten-password reset e2e (Iteration 1c). Boots the REAL app against the
// disposable Postgres, but swaps EmailService for a stub we control — so NO real
// SMTP is touched and we can capture the reset link/token. We assert the locked
// behavior: always-202 (no enumeration), one-time + expiring token, sessions
// revoked on success, old password dies + new one works, weak/breached -> 422.

describe('Auth password reset (e2e)', () => {
  let app: INestApplication;
  let db: DrizzleDB;
  // Shared stub: the running app holds THIS object, so the test reads its inbox.
  const mailer = new EmailStub();

  // Long enough + not on the bundled breach list -> passes policy deterministically.
  const OLD_PASSWORD = 'Sup3r-Saf3-Pass!';
  const NEW_PASSWORD = 'Even-Saf3r-Pass!9';
  const EMAIL = 'alice@example.com';

  beforeAll(async () => {
    const booted = await bootTestApp((builder) =>
      builder.overrideProvider(EmailService).useValue(mailer),
    );
    app = booted.app;
    db = booted.db;
  });

  // Offline + deterministic: HIBP fetch fails -> breach check uses bundled list.
  beforeEach(async () => {
    jest
      .spyOn(global, 'fetch')
      .mockRejectedValue(new Error('network disabled in tests'));
    await resetTables(db);
    mailer.reset();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(async () => {
    await app.close();
  });

  // Make a local account we can reset. Returns the signup response.
  const signup = (over: Partial<Record<string, string>> = {}) =>
    request(app.getHttpServer())
      .post('/auth/signup')
      .send({ email: EMAIL, password: OLD_PASSWORD, display_name: 'Alice', ...over });

  const requestReset = (email: string) =>
    request(app.getHttpServer())
      .post('/auth/password-reset/request')
      .send({ email });

  const confirmReset = (token: string, new_password: string) =>
    request(app.getHttpServer())
      .post('/auth/password-reset/confirm')
      .send({ token, new_password });

  const login = (password: string) =>
    request(app.getHttpServer()).post('/auth/login').send({ email: EMAIL, password });

  // INTENT: full happy path. Request mails a token; confirm rotates the password;
  // old password then fails (401) and the new one logs in (200).
  it('request -> 202 + token captured; confirm -> 200; old pw fails, new pw works', async () => {
    await signup();
    mailer.reset(); // ignore anything from signup (none expected, but be clean)

    const req = await requestReset(EMAIL);
    expect(req.status).toBe(202);
    // Email now sends fire-and-forget -> poll the stub instead of reading now.
    const token = await mailer.waitForToken();
    expect(token).toBeDefined();
    expect(token.length).toBeGreaterThan(20); // high-entropy

    const confirm = await confirmReset(token, NEW_PASSWORD);
    expect(confirm.status).toBe(200);

    // Old password is dead.
    const oldTry = await login(OLD_PASSWORD);
    expect(oldTry.status).toBe(401);

    // New password works.
    const newTry = await login(NEW_PASSWORD);
    expect(newTry.status).toBe(200);
    expect(typeof newTry.body.access_token).toBe('string');
  });

  // INTENT: one-time use. Replaying the same token after a successful confirm
  // must be refused with the generic 400.
  it('reusing the same token -> 400', async () => {
    await signup();
    await requestReset(EMAIL);
    const token = await mailer.waitForToken();

    const first = await confirmReset(token, NEW_PASSWORD);
    expect(first.status).toBe(200);

    const replay = await confirmReset(token, 'Yet-An0ther-Pass!');
    expect(replay.status).toBe(400);
  });

  // INTENT: expiry. Age the ticket past its 1-hour window directly in the DB,
  // then confirm must fail with the generic 400.
  it('expired token -> 400', async () => {
    await signup();
    await requestReset(EMAIL);
    const token = await mailer.waitForToken();

    // Push expiry into the past so the 1-hour window is over.
    await db.execute(
      sql`UPDATE "password_reset" SET "expires_at" = now() - interval '1 minute'`,
    );

    const res = await confirmReset(token, NEW_PASSWORD);
    expect(res.status).toBe(400);
  });

  // INTENT: password policy still applies on reset. A bundled-breached new
  // password -> 422 (fetch mocked to throw -> fail-open to bundled list).
  it('breached new_password -> 422', async () => {
    await signup();
    await requestReset(EMAIL);
    const token = await mailer.waitForToken();

    const res = await confirmReset(token, 'password'); // on BREACHED_FALLBACK
    expect(res.status).toBe(422);
  });

  // INTENT: too-short new password -> 422 (length gate before breach).
  it('too-short new_password -> 422', async () => {
    await signup();
    await requestReset(EMAIL);
    const token = await mailer.waitForToken();

    const res = await confirmReset(token, 'short7!'); // 7 chars
    expect(res.status).toBe(422);
  });

  // INTENT: no enumeration. Request for an email with NO account still returns
  // 202, and NO mail is sent.
  it('request for unknown email -> 202, no email sent (no leak)', async () => {
    const res = await requestReset('nobody@example.com');
    expect(res.status).toBe(202);
    expect(mailer.sent.length).toBe(0);
  });

  // INTENT: a successful reset revokes ALL sessions. The refresh cookie issued
  // at signup must be dead after the reset (forced re-login everywhere).
  it('confirm revokes all sessions -> old refresh cookie -> 401', async () => {
    const signedUp = await signup();
    const raw = signedUp.headers['set-cookie'] as unknown as string[];
    const cookie = raw.find((c) => c.startsWith('refresh_token='))!;

    await requestReset(EMAIL);
    const token = await mailer.waitForToken();
    const confirm = await confirmReset(token, NEW_PASSWORD);
    expect(confirm.status).toBe(200);

    // The session minted at signup is now revoked -> refresh fails.
    const refresh = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', cookie);
    expect(refresh.status).toBe(401);
  });

  // INTENT: bad input gate. Empty body fields are caught by the ValidationPipe
  // (422) before any logic runs.
  it('confirm with missing fields -> 422', async () => {
    const res = await request(app.getHttpServer())
      .post('/auth/password-reset/confirm')
      .send({});
    expect(res.status).toBe(422);
  });

  // INTENT (BLOCKER): atomic one-time consume. Fire TWO confirms with the SAME
  // valid token at the SAME time (Promise.all, in-process against real product
  // code). Exactly ONE must win (200) and ONE must lose (400) — never both. Then
  // the password is set ONCE (new works, old dead) and ALL sessions are revoked.
  it('two concurrent confirms, same token -> exactly one 200 and one 400', async () => {
    const signedUp = await signup();
    const raw = signedUp.headers['set-cookie'] as unknown as string[];
    const cookie = raw.find((c) => c.startsWith('refresh_token='))!;

    await requestReset(EMAIL);
    const token = await mailer.waitForToken();

    // Both racers use the SAME token. Same new password so whichever wins, the
    // outcome we assert (new pw works) holds regardless of which one it was.
    const [a, b] = await Promise.all([
      confirmReset(token, NEW_PASSWORD),
      confirmReset(token, NEW_PASSWORD),
    ]);

    const statuses = [a.status, b.status].sort();
    // The race gate must let through exactly one winner.
    expect(statuses).toEqual([200, 400]);

    // Password was set once and works; the old one is dead.
    expect((await login(OLD_PASSWORD)).status).toBe(401);
    expect((await login(NEW_PASSWORD)).status).toBe(200);

    // Sessions revoked: the signup refresh cookie no longer refreshes.
    const refresh = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', cookie);
    expect(refresh.status).toBe(401);
  });

  // INTENT (SHOULD 2): sibling-ticket invalidation. Request TWICE -> two live
  // tickets. Confirm with the 2nd. A successful reset must kill EVERY other
  // outstanding link, so the 1st token is now rejected (generic 400).
  it('sibling tickets are killed on confirm -> first token -> 400', async () => {
    await signup();

    // First ticket.
    await requestReset(EMAIL);
    const firstToken = await mailer.waitForToken(1);

    // Second ticket (now two unused tickets exist for this account).
    await requestReset(EMAIL);
    const secondToken = await mailer.waitForToken(2);
    expect(secondToken).not.toBe(firstToken);

    // Confirm with the 2nd -> success + invalidates the 1st.
    const confirm = await confirmReset(secondToken, NEW_PASSWORD);
    expect(confirm.status).toBe(200);

    // The 1st token is now a dead sibling -> generic 400.
    const stale = await confirmReset(firstToken, 'Another-G00d-Pass!');
    expect(stale.status).toBe(400);
  });
});
