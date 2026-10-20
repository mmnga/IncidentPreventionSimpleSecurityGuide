-- SYNTHETIC reference schema. No real data or credentials.
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('member','admin')),
 active INTEGER NOT NULL DEFAULT 1, auth_version INTEGER NOT NULL DEFAULT 1,
 mfa_enrolled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 auth_version INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, owner_id TEXT NOT NULL,
 title TEXT NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS budgets (
 principal TEXT NOT NULL, purpose TEXT NOT NULL, window INTEGER NOT NULL,
 used INTEGER NOT NULL, PRIMARY KEY(principal,purpose,window)
);
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL,
 auth_version INTEGER NOT NULL, status TEXT NOT NULL,
 result_json TEXT, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS inquiries (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, owner_id TEXT NOT NULL,
 body TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox (
 event_id TEXT PRIMARY KEY, kind TEXT NOT NULL, recipient_id TEXT NOT NULL,
 receipt_id TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS webhook_seen (event_id TEXT PRIMARY KEY, received_at INTEGER NOT NULL);
