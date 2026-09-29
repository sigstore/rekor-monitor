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
-- Add a required, human-readable name to subscriptions, unique per user.
-- SQLite cannot ADD a NOT NULL column and a composite UNIQUE index in one
-- shot, so we rebuild the table like 000002. Existing rows are backfilled
-- with 'Subscription #<id>', which is globally unique and therefore
-- trivially unique per user.
--
-- Ordering matters: matches references subscriptions with ON DELETE
-- CASCADE, so dropping subscriptions would cascade-delete matches. We stash
-- matches in a temp table first, then recreate it afterwards (mirroring
-- 000002). Indexes on both tables are recreated explicitly.

-- 1. Stash matches data and drop the table so subscriptions can be recreated
CREATE TEMP TABLE matches_backup AS SELECT * FROM matches;
DROP TABLE matches;

-- 2. Recreate subscriptions with the new name column, backfilling existing rows
CREATE TABLE subscriptions_new (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	monitored_value TEXT NOT NULL,
	webhook_url TEXT NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	consecutive_failures INTEGER NOT NULL DEFAULT 0,
	last_failure_at DATETIME,
	disabled_at DATETIME,
	next_retry_at DATETIME,
	notification_type TEXT NOT NULL DEFAULT 'webhook'
		CHECK (notification_type IN ('webhook', 'email')),
	name TEXT NOT NULL
);
INSERT INTO subscriptions_new (
	id, user_id, monitored_value, webhook_url, created_at,
	consecutive_failures, last_failure_at, disabled_at, next_retry_at,
	notification_type, name
)
SELECT
	id, user_id, monitored_value, webhook_url, created_at,
	consecutive_failures, last_failure_at, disabled_at, next_retry_at,
	notification_type, 'Subscription #' || id
FROM subscriptions;
DROP TABLE subscriptions;
ALTER TABLE subscriptions_new RENAME TO subscriptions;

-- 3. Recreate subscriptions indexes (idx_subscriptions_user_id from 000005)
--    plus the new per-user unique name index.
CREATE INDEX idx_subscriptions_user_id ON subscriptions(user_id);
CREATE UNIQUE INDEX idx_subscriptions_user_name ON subscriptions(user_id, name);

-- 4. Recreate matches with ON DELETE CASCADE, restoring stashed data
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
	subscription_id INTEGER REFERENCES subscriptions(id) ON DELETE CASCADE,
	notified_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO matches SELECT * FROM matches_backup;
DROP TABLE matches_backup;

-- 5. Recreate the matches index from 000006.
CREATE INDEX idx_matches_subscription_id ON matches(subscription_id);
