#!/usr/bin/env bash
#
# Copyright 2026 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

DB="${1:-rekor_watch.db}"

read -rp "Email: " email
read -rp "Name: " name
read -rp "CertSubject: " cert_subject
read -rp "Webhook URL: " webhook_url

monitored_value=$(printf '{"type":"certIdentity","certSubject":"%s","issuers":[]}' "$cert_subject")

sqlite3 "$DB" <<SQL
INSERT OR IGNORE INTO users (email) VALUES ('${email}');

INSERT INTO subscriptions (user_id, name, monitored_value, webhook_url)
VALUES (
  (SELECT id FROM users WHERE email = '${email}'),
  '${name}',
  '${monitored_value}',
  '${webhook_url}'
);
SQL

echo "Done. User and subscription added."
