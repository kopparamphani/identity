import {
  pgTable,
  uuid,
  text,
  integer,
  timestamp,
  boolean,
  pgEnum,
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
export const session = pgTable('session', {
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
});

export type Account = typeof account.$inferSelect;
export type NewAccount = typeof account.$inferInsert;
export type Session = typeof session.$inferSelect;
export type NewSession = typeof session.$inferInsert;
