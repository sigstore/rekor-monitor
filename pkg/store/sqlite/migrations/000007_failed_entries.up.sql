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
-- Record log entries that could not be parsed or processed during an
-- identity search, so operators can investigate them later instead of
-- losing them to log output.

CREATE TABLE IF NOT EXISTS failed_entries (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	origin TEXT NOT NULL,
	log_index INTEGER NOT NULL,
	uuid TEXT NOT NULL,
	error TEXT NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
