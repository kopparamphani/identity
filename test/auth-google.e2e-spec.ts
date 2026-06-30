import { INestApplication } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import request from 'supertest';
import { DrizzleDB } from '../src/db/db.module';
import { account } from '../src/db/schema';
import { GoogleVerifierService } from '../src/auth/google-verifier.service';
import { bootTestApp, resetTables } from './support/app-harness';
import { GoogleVerifierStub } from './support/google-verifier.stub';

// Google sign-in e2e (Iteration 1b, POST /auth/google). Boots the REAL app
// against the disposable Postgres, but swaps the Google verifier for a stub we
// control — so NO real Google call ever happens and every run is deterministic.
// We assert the three resolution rules (login by sub / link by email / create),
// the bad-token + missing-field gates, and that Google-minted tokens ride the
// SAME refresh/logout machinery as 1a.

// Pull the refresh_token cookie string out of a Set-Cookie header array.
function refreshCookie(res: request.Response): string | undefined {
  const raw = res.headers['set-cookie'] as unknown as string[] | undefined;
  if (!raw) return undefined;
  return raw.find((c) => c.startsWith('refresh_token='));
}

describe('Auth Google (e2e)', () => {
  let app: INestApplication;
  let db: DrizzleDB;
  // Shared stub instance: the running app holds THIS object, so tests steer it.
  const verifier = new GoogleVerifierStub();

  // Same good password 1a uses (passes length + not on bundled breach list).
  const GOOD_PASSWORD = 'Sup3r-Saf3-Pass!';

  beforeAll(async () => {
    // Boot the app but override the real Google verifier with our stub. Same
    // object identity, so verifier.willReturn(...) inside a test controls the app.
    const booted = await bootTestApp((builder) =>
      builder.overrideProvider(GoogleVerifierService).useValue(verifier),
    );
    app = booted.app;
    db = booted.db;
  });

  // Offline: kill real fetch (breach check falls back to bundled list) and wipe
  // tables so every test starts on a clean board. Also reset the stub.
  beforeEach(async () => {
    jest
      .spyOn(global, 'fetch')
      .mockRejectedValue(new Error('network disabled in tests'));
    await resetTables(db);
    verifier.fail = false;
    verifier.next = null;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(async () => {
    await app.close();
  });

  // Fire POST /auth/google with a placeholder token — the stub ignores it.
  const google = (idToken = 'any-id-token') =>
    request(app.getHttpServer()).post('/auth/google').send({ id_token: idToken });

  // Read one account row straight from the DB by email (lowercased).
  const accountByEmail = async (email: string) => {
    const rows = await db
      .select()
      .from(account)
      .where(eq(account.email, email.toLowerCase()))
      .limit(1);
    return rows[0];
  };

  // ---- RULE 3: brand-new Google user ----

  // INTENT: an unknown sub + unknown email mints a fresh GOOGLE-ONLY account.
  // Objective: POST /auth/google (new) -> 201 + token body + refresh cookie;
  //            DB row: auth_provider='google', password_hash NULL, sub stored.
  it('new Google user -> 201, creates google-only account', async () => {
    verifier.willReturn({
      sub: 'google-sub-new-001',
      email: 'newuser@example.com',
      name: 'New User',
    });

    const res = await google();

    expect(res.status).toBe(201);
    expect(typeof res.body.access_token).toBe('string');
    expect(res.body.access_token.length).toBeGreaterThan(0);
    expect(res.body.token_type).toBe('Bearer');
    expect(res.body.expires_in).toBe(15 * 60); // 15 min access TTL, same as 1a

    const cookie = refreshCookie(res);
    expect(cookie).toBeDefined();
    expect(cookie!.toLowerCase()).toContain('httponly');

    // DB proof: google-owned credential, no password, sub is the join key.
    const row = await accountByEmail('newuser@example.com');
    expect(row).toBeDefined();
    expect(row.authProvider).toBe('google');
    expect(row.passwordHash).toBeNull();
    expect(row.googleSubjectId).toBe('google-sub-new-001');
  });

  // ---- RULE 1: returning Google user ----

  // INTENT: signing in again with the SAME sub logs into the SAME row — no dup.
  // Objective: second /auth/google with same sub -> 200, exactly one account row.
  it('returning Google user (same sub) -> 200, no duplicate account', async () => {
    verifier.willReturn({
      sub: 'google-sub-returning-002',
      email: 'returning@example.com',
      name: 'Returning User',
    });

    // First call creates the account (201).
    const first = await google();
    expect(first.status).toBe(201);

    // Second call with the SAME sub is a plain login (200).
    const second = await google();
    expect(second.status).toBe(200);
    expect(typeof second.body.access_token).toBe('string');

    // Only ONE account exists for this Google user.
    const rows = await db
      .select()
      .from(account)
      .where(eq(account.googleSubjectId, 'google-sub-returning-002'));
    expect(rows.length).toBe(1);
  });

  // ---- RULE 2: linking a pre-existing local account ----

  // INTENT: a password user who later "Sign in with Google" on the SAME email
  // gets LINKED — provider flips to 'both', sub gets attached, and the ORIGINAL
  // password still works (we never clobbered the hash). Mixed-case email on the
  // Google side proves we normalize before matching.
  // Objective: signup(local) then google(same email, MiXeD case) -> 200; row
  //            auth_provider='both', sub set, password_hash unchanged, login OK.
  it('local account + Google same email (mixed-case) -> 200, links to both', async () => {
    // 1) Create a local password account.
    const signupRes = await request(app.getHttpServer())
      .post('/auth/signup')
      .send({
        email: 'linkme@example.com',
        password: GOOD_PASSWORD,
        display_name: 'Link Me',
      });
    expect(signupRes.status).toBe(201);

    // Capture the original hash so we can prove it is untouched after linking.
    const before = await accountByEmail('linkme@example.com');
    expect(before.authProvider).toBe('local');
    expect(before.passwordHash).not.toBeNull();
    const originalHash = before.passwordHash;

    // 2) Google sign-in with the SAME email but MIXED CASE -> must normalize.
    verifier.willReturn({
      sub: 'google-sub-link-003',
      email: 'LinkMe@Example.COM',
      name: 'Link Me Google',
    });
    const res = await google();
    expect(res.status).toBe(200); // existing account, linked -> not 201

    // DB proof: linked. provider='both', sub attached, hash byte-for-byte same.
    const after = await accountByEmail('linkme@example.com');
    expect(after.authProvider).toBe('both');
    expect(after.googleSubjectId).toBe('google-sub-link-003');
    expect(after.passwordHash).toBe(originalHash);
    // No accidental duplicate row from the mixed-case email.
    const all = await db
      .select()
      .from(account)
      .where(eq(account.email, 'linkme@example.com'));
    expect(all.length).toBe(1);

    // 3) Local login STILL works after linking — Google didn't break password.
    const login = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: 'linkme@example.com', password: GOOD_PASSWORD });
    expect(login.status).toBe(200);
    expect(typeof login.body.access_token).toBe('string');
  });

  // ---- BLOCKER: unverified Google email ----

  // INTENT: Google says the email is NOT verified -> we refuse to link OR create.
  // An unverified email could belong to someone else; binding it would let an
  // attacker claim a victim's address.
  // Objective: emailVerified=false on a brand-new user -> 401, NO account row.
  it('email_verified=false (new user) -> 401, nothing created', async () => {
    verifier.willReturn({
      sub: 'google-sub-unverified-005',
      email: 'unverified@example.com',
      name: 'Unverified User',
      emailVerified: false,
    });

    const res = await google();
    expect(res.status).toBe(401);

    // No create path ran.
    const rows = await db.select().from(account);
    expect(rows.length).toBe(0);
  });

  // INTENT: same gate must block the LINK path too. A local account exists; an
  // unverified Google email on that address must NOT link it.
  // Objective: signup(local) then google(same email, emailVerified=false) -> 401;
  //            row stays auth_provider='local', no sub attached.
  it('email_verified=false (local exists) -> 401, no link', async () => {
    const signupRes = await request(app.getHttpServer())
      .post('/auth/signup')
      .send({
        email: 'nolink@example.com',
        password: GOOD_PASSWORD,
        display_name: 'No Link',
      });
    expect(signupRes.status).toBe(201);

    verifier.willReturn({
      sub: 'google-sub-unverified-006',
      email: 'nolink@example.com',
      name: 'No Link Google',
      emailVerified: false,
    });
    const res = await google();
    expect(res.status).toBe(401);

    // Unchanged: still local, no sub.
    const after = await accountByEmail('nolink@example.com');
    expect(after.authProvider).toBe('local');
    expect(after.googleSubjectId).toBeNull();
  });

  // ---- SHOULD 1: never rebind an existing Google sub ----

  // INTENT: an account already linked to Google owns an immutable sub. A second
  // sign-in carrying a DIFFERENT sub on the SAME email must be refused, never
  // silently rebound to the new sub.
  // Objective: create google account (sub A), then google(same email, sub B)
  //            -> 401; row keeps sub A.
  it('existing Google account, different sub, same email -> 401, no rebind', async () => {
    // First sign-in establishes the Google account with sub A.
    verifier.willReturn({
      sub: 'google-sub-original-A',
      email: 'rebind@example.com',
      name: 'Rebind User',
    });
    const first = await google();
    expect(first.status).toBe(201);

    // Second sign-in: SAME email, DIFFERENT sub -> attempt to rebind.
    verifier.willReturn({
      sub: 'google-sub-attacker-B',
      email: 'rebind@example.com',
      name: 'Rebind Attacker',
    });
    const second = await google();
    expect(second.status).toBe(401);

    // Sub is unchanged: still A, never rebound to B.
    const after = await accountByEmail('rebind@example.com');
    expect(after.googleSubjectId).toBe('google-sub-original-A');
    expect(after.authProvider).toBe('google');
  });

  // ---- SHOULD 2: concurrent first-time sign-in race ----

  // INTENT: two concurrent first-time sign-ins (same sub+email) race the insert.
  // One wins; the loser hits the unique constraint and is retried-as-login. Both
  // return cleanly (200/201), exactly ONE account row, never a 500.
  // Objective: fire two /auth/google in parallel -> statuses in {200,201}, one row.
  it('concurrent first-time sign-in (same sub) -> clean, one account, no 500', async () => {
    verifier.willReturn({
      sub: 'google-sub-race-007',
      email: 'race@example.com',
      name: 'Race User',
    });

    const [a, b] = await Promise.all([google(), google()]);

    // Neither blew up with a 500.
    for (const res of [a, b]) {
      expect([200, 201]).toContain(res.status);
      expect(typeof res.body.access_token).toBe('string');
    }
    // Exactly one of them created (201); the other logged in (200).
    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual([200, 201]);

    // Only ONE account row for this Google user.
    const rows = await db
      .select()
      .from(account)
      .where(eq(account.googleSubjectId, 'google-sub-race-007'));
    expect(rows.length).toBe(1);
  });

  // ---- BAD TOKEN ----

  // INTENT: a bad/expired/forged token is refused BEFORE any DB write. The
  // verifier throws -> 401, and nothing gets created.
  // Objective: verifier throws -> 401; no account row appears.
  it('invalid/expired token -> 401, nothing created', async () => {
    verifier.willThrow();

    const res = await google('garbage-token');
    expect(res.status).toBe(401);

    // Defense: prove the bad token never leaked into a DB row.
    const rows = await db.select().from(account);
    expect(rows.length).toBe(0);
  });

  // ---- MISSING FIELD ----

  // INTENT: the contract requires id_token. A body without it is rejected by the
  // ValidationPipe before the service runs.
  // Objective: POST /auth/google with empty body -> 422.
  it('missing id_token -> 422', async () => {
    const res = await request(app.getHttpServer())
      .post('/auth/google')
      .send({});
    expect(res.status).toBe(422);
  });

  // ---- SHARED TOKEN MACHINERY ----

  // INTENT: tokens minted via Google are NOT special — the refresh cookie works
  // on /auth/refresh and is killed by /auth/logout, exactly like 1a's tokens.
  // Proves Google reuses issueTokens / sessions, not a parallel path.
  // Objective: google -> refresh(200) -> logout(204) -> refresh(401).
  it('Google refresh token works on /auth/refresh and is revoked by /auth/logout', async () => {
    verifier.willReturn({
      sub: 'google-sub-machinery-004',
      email: 'machinery@example.com',
      name: 'Machinery User',
    });

    const created = await google();
    expect(created.status).toBe(201);
    const cookie = refreshCookie(created)!;
    expect(cookie).toBeDefined();

    // The Google-issued refresh cookie mints a new access token.
    const refreshed = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', cookie);
    expect(refreshed.status).toBe(200);
    expect(typeof refreshed.body.access_token).toBe('string');

    // After rotation the ORIGINAL cookie is dead; use the rotated one to logout.
    const rotated = refreshCookie(refreshed)!;
    const out = await request(app.getHttpServer())
      .post('/auth/logout')
      .set('Cookie', rotated);
    expect(out.status).toBe(204);

    // Revoked: the logged-out session can no longer refresh.
    const afterLogout = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', rotated);
    expect(afterLogout.status).toBe(401);
  });
});
