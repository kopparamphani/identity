import { removeTestContainer } from './test-db';

// Runs ONCE after the whole e2e suite. Like: clear the table, wash up.
// Kill the disposable Postgres so nothing lingers.
export default function globalTeardown(): void {
  removeTestContainer();
}
