import {
  pgTable,
  uuid,
  text,
  integer,
  timestamp,
  boolean,
  pgEnum,
  index,
} from 'drizzle-orm/pg-core';

// How a person proves who they are. local = email+password, google = OAuth, both = linked.
export const authProvider = pgEnum('auth_provider', ['local', 'google', 'both']);

// account = one human's login. One email = one account (unique).
// Columns are snake_case on the wire/DB to match the data model exactly.
export const account = pgTable('account', {
  accountId: uuid('account_id').defaultRandom().primaryKey(),
  email: text('email').notNull().unique(),
  displayName: text('display_name').notNull(),
  // null for Google-only accounts; never plain text. Argon2id hash for local.
  passwordHash: text('password_hash'),
  authProvider: authProvider('auth_provider').notNull().default('local'),
  // Google's stable user id. Unused in 1a (Google is 1b) but column exists per model.
  googleSubjectId: text('google_subject_id').unique(),
  // Lockout memory: count wrong tries, reset to 0 on good login.
  failedLoginAttempts: integer('failed_login_attempts').notNull().default(0),
  // When set + still in the future, login is refused (slams the door 15 min).
  lockedUntil: timestamp('locked_until', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

// session = one live login (the refresh-token row). Revoke = logout.
// SECURITY: we NEVER store the raw refresh token. session_id is an internal
// surrogate PK that never leaves the server. The client holds a high-entropy
// random token; we keep only its sha256 in token_hash. A DB read leaks no
// usable bearer credential. Lookups on refresh/logout go BY token_hash.
export const session = pgTable(
  'session',
  {
    sessionId: uuid('session_id').defaultRandom().primaryKey(),
    // sha256 of the opaque refresh token (hex). Unique so a hash maps to one row.
    tokenHash: text('token_hash').notNull().unique(),
    accountId: uuid('account_id')
      .notNull()
      .references(() => account.accountId),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).notNull().defaultNow(),
    // Flip true on logout. Refresh refuses revoked sessions.
    revoked: boolean('revoked').notNull().default(false),
    // 30-day life. Refresh refuses expired sessions even if not revoked.
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  },
  (t) => [
    // Password reset revokes EVERY session for an account (revoke-by-account_id).
    // Without this index that update scans the whole table -> index it.
    index('session_account_id_idx').on(t.accountId),
  ],
);

// password_reset = one forgotten-password reset ticket (REQ-ACC-03).
// SECURITY mirror of session: we NEVER store the raw reset token. The user gets
// a high-entropy random token by email; we keep only its sha256 in token_hash.
// A DB leak gives no usable reset link. Lookups on confirm go BY token_hash.
// One-time use: used_at stamped on confirm so a token can't be replayed.
// expires_at = created_at + 1 hour (LOCKED in NFR).
export const passwordReset = pgTable(
  'password_reset',
  {
    resetId: uuid('reset_id').defaultRandom().primaryKey(),
    accountId: uuid('account_id')
      .notNull()
      .references(() => account.accountId),
    // sha256 of the raw reset token (hex). Unique so a hash maps to one ticket.
    tokenHash: text('token_hash').notNull().unique(),
    // Hard cutoff: confirm refuses a ticket past this instant (1 hour life).
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    // Null until consumed. Once set, the ticket is spent -> can't be reused.
    usedAt: timestamp('used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    // Confirm invalidates ALL other unused tickets for the account
    // (kill-siblings-by-account_id). Without this index that update scans the
    // whole table -> index it.
    index('password_reset_account_id_idx').on(t.accountId),
  ],
);

export type Account = typeof account.$inferSelect;
export type NewAccount = typeof account.$inferInsert;
export type Session = typeof session.$inferSelect;
export type NewSession = typeof session.$inferInsert;
export type PasswordReset = typeof passwordReset.$inferSelect;
export type NewPasswordReset = typeof passwordReset.$inferInsert;
