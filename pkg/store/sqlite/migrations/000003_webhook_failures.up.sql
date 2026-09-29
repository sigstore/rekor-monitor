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
-- Add webhook failure tracking columns to subscriptions table
-- Supports exponential backoff and auto-disable on repeated failures

ALTER TABLE subscriptions ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE subscriptions ADD COLUMN last_failure_at DATETIME;
ALTER TABLE subscriptions ADD COLUMN disabled_at DATETIME;
ALTER TABLE subscriptions ADD COLUMN next_retry_at DATETIME;
