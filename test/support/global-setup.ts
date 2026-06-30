import {
  migrateTestDb,
  startTestPostgres,
  TEST_DATABASE_URL,
} from './test-db';

// Runs ONCE before the whole e2e suite. Like: set the table before dinner.
// Spin up the disposable Postgres, point the app at it, run migrations.
export default function globalSetup(): void {
  // Make sure every worker/app boot reads the throwaway DB, not a real one.
  process.env.DATABASE_URL = TEST_DATABASE_URL;
  // App refuses to sign tokens without this — set a fixed test secret.
  process.env.JWT_SECRET = process.env.JWT_SECRET ?? 'test-secret-not-for-prod';
  // Keep cookies non-Secure so supertest (http) can read them.
  process.env.NODE_ENV = 'test';
  // GoogleVerifierService getOrThrow's this at boot. Fixed test value; real
  // Google verification is stubbed in the Google e2e (no live credentials).
  process.env.GOOGLE_CLIENT_ID =
    process.env.GOOGLE_CLIENT_ID ?? 'test-google-client-id.apps.googleusercontent.com';

  // Stash for teardown (separate Node process can't see in-memory state otherwise,
  // but env carved here is enough since teardown re-derives the name).
  startTestPostgres();
  migrateTestDb();
}
