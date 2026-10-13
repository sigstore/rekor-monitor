--
-- Copyright 2026 The Sigstore Authors.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- Remove ON DELETE CASCADE from foreign keys, restoring the pre-002 schema.
-- SQLite does not support ALTER CONSTRAINT, so we recreate affected tables.
--
-- Ordering matters: matches references subscriptions, so we stash match
-- data in a temp table first, allowing us to safely drop and recreate
-- subscriptions, then recreate matches pointing at the new table.
-- This works correctly with foreign_keys=ON.

-- 1. Stash matches data and drop the table so subscriptions can be recreated
CREATE TEMP TABLE matches_backup AS SELECT * FROM matches;
DROP TABLE matches;

-- 2. Recreate subscriptions without ON DELETE CASCADE
CREATE TABLE subscriptions_new (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL REFERENCES users(id),
	monitored_value TEXT NOT NULL,
	webhook_url TEXT NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO subscriptions_new SELECT * FROM subscriptions;
DROP TABLE subscriptions;
ALTER TABLE subscriptions_new RENAME TO subscriptions;

-- 3. Recreate matches without ON DELETE CASCADE, restoring stashed data
CREATE TABLE matches (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	origin TEXT NOT NULL,
	log_index INTEGER NOT NULL,
	uuid TEXT NOT NULL,
	cert_subject TEXT,
	issuer TEXT,
	fingerprint TEXT,
	subject TEXT,
	oid_extension TEXT,
	extension_value TEXT,
	subscription_id INTEGER REFERENCES subscriptions(id),
	notified_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO matches SELECT * FROM matches_backup;
DROP TABLE matches_backup;

-- 4. Recreate sessions without ON DELETE CASCADE
CREATE TABLE sessions_new (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL REFERENCES users(id),
	token_hash TEXT NOT NULL UNIQUE,
	expires_at DATETIME NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO sessions_new SELECT * FROM sessions;
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
