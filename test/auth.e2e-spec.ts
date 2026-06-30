import { INestApplication } from '@nestjs/common';
import { sql } from 'drizzle-orm';
import request from 'supertest';
import { DrizzleDB } from '../src/db/db.module';
import { bootTestApp, resetTables } from './support/app-harness';

// Auth flow e2e. Boots the REAL app against a disposable Postgres and pokes it
// over HTTP exactly like a web client would. Money math isn't here — this is
// the identity gate that everything else sits behind.

// Pull the refresh_token cookie string out of a Set-Cookie header array.
// Like: find the one envelope labelled "refresh_token" in the mail pile.
function refreshCookie(res: request.Response): string | undefined {
  const raw = res.headers['set-cookie'] as unknown as string[] | undefined;
  if (!raw) return undefined;
  return raw.find((c) => c.startsWith('refresh_token='));
}

// Pull just the token value out of a "refresh_token=<value>; Path=/; ..." cookie.
// Like: read the name written on the envelope, ignore the postmarks.
function tokenValue(cookie: string): string {
  return cookie.split(';')[0].split('=')[1];
}

describe('Auth (e2e)', () => {
  let app: INestApplication;
  let db: DrizzleDB;

  // A password long enough to pass length AND not on the bundled breach list,
  // so fail-open lets it through deterministically.
  const GOOD_PASSWORD = 'Sup3r-Saf3-Pass!';

  beforeAll(async () => {
    const booted = await bootTestApp();
    app = booted.app;
    db = booted.db;
  });

  // Offline + deterministic: force the HIBP fetch to FAIL so breach checks fall
  // back to the bundled list. Real network is never touched in tests.
  beforeEach(async () => {
    jest
      .spyOn(global, 'fetch')
      .mockRejectedValue(new Error('network disabled in tests'));
    await resetTables(db);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(async () => {
    await app.close();
  });

  // Tiny helper: sign up a fresh user, return the response.
  const signup = (over: Partial<Record<string, string>> = {}) =>
    request(app.getHttpServer())
      .post('/auth/signup')
      .send({
        email: 'alice@example.com',
        password: GOOD_PASSWORD,
        display_name: 'Alice',
        ...over,
      });

  // ---- SIGNUP ----

  // INTENT: a clean signup mints a session and hands back the token contract.
  // Objective: POST /auth/signup -> 201 + access_token/token_type/expires_in
  //            and an httpOnly refresh_token cookie.
  it('signup success -> 201 with token body + httpOnly refresh cookie', async () => {
    const res = await signup();

    expect(res.status).toBe(201);
    expect(typeof res.body.access_token).toBe('string');
    expect(res.body.access_token.length).toBeGreaterThan(0);
    expect(res.body.token_type).toBe('Bearer');
    expect(res.body.expires_in).toBe(15 * 60); // 15 min access TTL

    const cookie = refreshCookie(res);
    expect(cookie).toBeDefined();
    // httpOnly = JS in the browser can't read it. Non-negotiable for refresh tokens.
    expect(cookie!.toLowerCase()).toContain('httponly');
  });

  // INTENT: one email = one account. Second signup with same email is refused.
  // Objective: duplicate email -> 409.
  it('signup duplicate email -> 409', async () => {
    await signup();
    const res = await signup({ display_name: 'Alice Two' });
    expect(res.status).toBe(409);
  });

  // INTENT: password policy blocks too-short passwords before any DB write.
  // Objective: 7-char password -> 422.
  it('signup too-short password -> 422', async () => {
    const res = await signup({ password: 'short7!' }); // 7 chars
    expect(res.status).toBe(422);
  });

  // INTENT: known-breached passwords are blocked. We force fail-open to the
  // bundled list (fetch mocked to throw), so "password" is a guaranteed hit.
  // Objective: bundled-breached password -> 422.
  it('signup known-breached password -> 422', async () => {
    const res = await signup({ password: 'password' }); // on BREACHED_FALLBACK
    expect(res.status).toBe(422);
  });

  // ---- LOGIN ----

  // INTENT: right email + right password gets you in with a fresh access token.
  // Objective: POST /auth/login correct -> 200 + access_token.
  it('login correct -> 200 + access_token', async () => {
    await signup();
    const res = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: 'alice@example.com', password: GOOD_PASSWORD });

    expect(res.status).toBe(200);
    expect(typeof res.body.access_token).toBe('string');
    expect(res.body.token_type).toBe('Bearer');
  });

  // INTENT: wrong password is rejected, and we don't say WHICH part was wrong.
  // Objective: wrong password -> 401.
  it('login wrong password -> 401', async () => {
    await signup();
    const res = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: 'alice@example.com', password: 'WrongPass!1' });

    expect(res.status).toBe(401);
  });

  // INTENT: brute-force defense. 5 bad tries slam the door for 15 min; the 6th
  // attempt is 429, and even the CORRECT password is refused while locked.
  // Objective: 5 wrong logins -> 6th -> 429; correct-while-locked -> 429.
  it('lockout: 5 wrong logins, then 6th -> 429, and correct-while-locked -> 429', async () => {
    await signup();
    const login = (password: string) =>
      request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: 'alice@example.com', password });

    // Tries 1-5: wrong password. First four are plain 401s; the 5th trips the
    // lock (still returns 401 on that attempt — the lock takes effect after).
    for (let i = 0; i < 5; i++) {
      const r = await login('WrongPass!1');
      expect(r.status).toBe(401);
    }

    // 6th attempt (wrong) is now refused as locked.
    const sixth = await login('WrongPass!1');
    expect(sixth.status).toBe(429);

    // Even the RIGHT password is refused while the door is locked.
    const correctWhileLocked = await login(GOOD_PASSWORD);
    expect(correctWhileLocked.status).toBe(429);
  });

  // ---- LOGOUT + REFRESH ----

  // INTENT: a valid refresh cookie mints a NEW access token AND rotates the
  // refresh token. The response must carry a fresh refresh cookie whose value
  // differs from the one we sent in.
  // Objective: POST /auth/refresh with valid cookie -> 200 + access_token,
  //            and a NEW refresh_token cookie (rotation).
  it('refresh with valid cookie -> 200 + new access_token + rotated refresh cookie', async () => {
    const signedUp = await signup();
    const cookie = refreshCookie(signedUp)!;

    const res = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(typeof res.body.access_token).toBe('string');
    expect(res.body.token_type).toBe('Bearer');

    // Rotation: a new refresh cookie comes back and its token VALUE differs.
    const rotated = refreshCookie(res);
    expect(rotated).toBeDefined();
    expect(tokenValue(rotated!)).not.toBe(tokenValue(cookie));
    expect(rotated!.toLowerCase()).toContain('httponly');
  });

  // INTENT: rotation kills the old token. After one refresh, replaying the
  // ORIGINAL cookie must fail — it's been revoked/replaced.
  // Objective: refresh once (rotate), then refresh again with the OLD cookie -> 401.
  it('rotation: old refresh token is rejected after it is rotated -> 401', async () => {
    const signedUp = await signup();
    const oldCookie = refreshCookie(signedUp)!;

    const first = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', oldCookie);
    expect(first.status).toBe(200);

    // Replay the now-rotated original token. Must be dead.
    const replay = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', oldCookie);
    expect(replay.status).toBe(401);

    // The freshly rotated token, however, still works.
    const newCookie = refreshCookie(first)!;
    const withNew = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', newCookie);
    expect(withNew.status).toBe(200);
  });

  // INTENT: a token that doesn't match any stored hash is refused. Proves we
  // look up BY hash, not by trusting the raw value.
  // Objective: refresh with a garbage cookie -> 401.
  it('refresh with unknown/garbage token -> 401', async () => {
    const res = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', 'refresh_token=not-a-real-token');
    expect(res.status).toBe(401);
  });

  // INTENT: an expired session is refused even though it isn't revoked. We age
  // the row directly in the DB to simulate the 30-day window passing.
  // Objective: expired session -> refresh -> 401.
  it('refresh with expired session -> 401', async () => {
    const signedUp = await signup();
    const cookie = refreshCookie(signedUp)!;

    // Force this account's session to look expired (past the window).
    await db.execute(
      sql`UPDATE "session" SET "expires_at" = now() - interval '1 day'`,
    );

    const res = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', cookie);
    expect(res.status).toBe(401);
  });

  // INTENT: logout revokes the session. The same cookie must then be useless.
  // Objective: logout -> 204; refresh with that revoked cookie -> 401.
  it('logout -> 204, then refresh with revoked cookie -> 401', async () => {
    const signedUp = await signup();
    const cookie = refreshCookie(signedUp)!;

    const out = await request(app.getHttpServer())
      .post('/auth/logout')
      .set('Cookie', cookie);
    expect(out.status).toBe(204);

    const res = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', cookie);
    expect(res.status).toBe(401);
  });

  // FUTURE TEST (not in 1a): once a JWT-guarded protected route exists, add
  // "expired/invalid bearer token -> 401 on that route". No guarded endpoint
  // exists in iteration 1a, so there is nothing to assert against yet.
});
