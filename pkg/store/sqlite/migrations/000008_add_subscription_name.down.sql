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
-- Remove the subscription name column and its per-user unique index,
-- restoring the pre-000008 schema. The backfilled labels are dropped; this
-- is lossy on the name only but structurally reversible.
--
-- Mirrors the up migration's table-rebuild: matches references subscriptions
-- with ON DELETE CASCADE, so we stash matches first to avoid cascade-deleting
-- them when subscriptions is dropped, then recreate it afterwards.

-- 1. Stash matches data and drop the table so subscriptions can be recreated
CREATE TEMP TABLE matches_backup AS SELECT * FROM matches;
DROP TABLE matches;

-- 2. Recreate subscriptions without the name column
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
		CHECK (notification_type IN ('webhook', 'email'))
);
INSERT INTO subscriptions_new (
	id, user_id, monitored_value, webhook_url, created_at,
	consecutive_failures, last_failure_at, disabled_at, next_retry_at,
	notification_type
)
SELECT
	id, user_id, monitored_value, webhook_url, created_at,
	consecutive_failures, last_failure_at, disabled_at, next_retry_at,
	notification_type
FROM subscriptions;
DROP TABLE subscriptions;
ALTER TABLE subscriptions_new RENAME TO subscriptions;

-- 3. Recreate the subscriptions index from 000005.
CREATE INDEX idx_subscriptions_user_id ON subscriptions(user_id);

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
