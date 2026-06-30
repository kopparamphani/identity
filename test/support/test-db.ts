import { execFileSync } from 'child_process';
import { randomBytes } from 'crypto';

// Disposable Postgres for e2e. Like: a scratch database we spin up, use, throw away.
// We do NOT touch any real/dev DB — tests get their own throwaway container.

// One stable container name so setup can start it and teardown can kill it.
export const TEST_PG_CONTAINER = 'identity-e2e-pg';

// Host port we map the container's 5432 onto. 5433 to avoid clashing with a
// dev Postgres that may already sit on 5432.
const HOST_PORT = process.env.TEST_PG_PORT ?? '5433';

// Test DB creds. Throwaway only — fine to hardcode for a disposable container.
const PG_USER = 'postgres';
const PG_PASSWORD = 'test';
const PG_DB = 'identity_test';

// The connection string the app + drizzle-kit will read from DATABASE_URL.
export const TEST_DATABASE_URL = `postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${HOST_PORT}/${PG_DB}`;

// Run docker, surface its output if it blows up.
function docker(args: string[], opts: { quiet?: boolean } = {}): string {
  try {
    return execFileSync('docker', args, {
      encoding: 'utf8',
      stdio: opts.quiet ? ['ignore', 'pipe', 'ignore'] : ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    const e = err as { stderr?: Buffer | string; message?: string };
    throw new Error(
      `docker ${args.join(' ')} failed: ${e.stderr?.toString() ?? e.message}`,
    );
  }
}

// Kill any leftover container from a previous crashed run. Ignore "not found".
export function removeTestContainer(): void {
  try {
    docker(['rm', '-f', TEST_PG_CONTAINER], { quiet: true });
  } catch {
    // No container to remove — fine.
  }
}

// Boot the disposable Postgres and block until it actually accepts connections.
export function startTestPostgres(): void {
  // Clean slate first.
  removeTestContainer();

  docker([
    'run',
    '-d',
    '--name',
    TEST_PG_CONTAINER,
    '-e',
    `POSTGRES_USER=${PG_USER}`,
    '-e',
    `POSTGRES_PASSWORD=${PG_PASSWORD}`,
    '-e',
    `POSTGRES_DB=${PG_DB}`,
    '-p',
    `${HOST_PORT}:5432`,
    'postgres:16',
  ]);

  // Wait for "ready to accept connections". pg_isready inside the container is
  // the cleanest signal that we can run migrations now.
  const deadline = Date.now() + 60_000;
  for (;;) {
    try {
      docker(
        ['exec', TEST_PG_CONTAINER, 'pg_isready', '-U', PG_USER, '-d', PG_DB],
        { quiet: true },
      );
      return; // ready
    } catch {
      if (Date.now() > deadline) {
        throw new Error('Test Postgres did not become ready within 60s');
      }
      // Tiny busy-wait. execFileSync is sync so we can't await; sleep via docker.
      sleep(500);
    }
  }
}

// Synchronous sleep — global setup is sync, so we cannot use async timers.
function sleep(ms: number): void {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    // burn a little; cheap crypto call keeps the loop honest
    randomBytes(8);
  }
}

// Apply the real Drizzle migrations so the schema matches production exactly.
export function migrateTestDb(): void {
  execFileSync('npx', ['drizzle-kit', 'migrate'], {
    encoding: 'utf8',
    stdio: 'inherit',
    env: { ...process.env, DATABASE_URL: TEST_DATABASE_URL },
    cwd: process.cwd(),
    shell: process.platform === 'win32', // npx needs a shell on Windows
  });
}
