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

# Obtains a Gmail OAuth2 access token from a client ID and secret.
#
# First run: opens a browser for consent, saves a refresh token to disk.
# Subsequent runs: uses the saved refresh token to get a fresh access token.
#
# Usage:
#   export GMAIL_CLIENT_ID="your-client-id"
#   export GMAIL_CLIENT_SECRET="your-client-secret"
#   ./scripts/gmail-oauth2-token.sh
#
# The access token is printed to stdout. Use it as:
#   --smtp-password "$(./scripts/gmail-oauth2-token.sh)"

: "${GMAIL_CLIENT_ID:?Set GMAIL_CLIENT_ID}"
: "${GMAIL_CLIENT_SECRET:?Set GMAIL_CLIENT_SECRET}"

TOKEN_FILE="${GMAIL_TOKEN_FILE:-$HOME/.rekor-watch-gmail-refresh-token}"
SCOPE="https://mail.google.com/"
REDIRECT_URI="http://localhost:8484"

get_refresh_token() {
  auth_url="https://accounts.google.com/o/oauth2/v2/auth"
  auth_url+="?client_id=${GMAIL_CLIENT_ID}"
  auth_url+="&redirect_uri=${REDIRECT_URI}"
  auth_url+="&response_type=code"
  auth_url+="&scope=${SCOPE}"
  auth_url+="&access_type=offline"
  auth_url+="&prompt=consent"

  echo "Opening browser for Google consent..." >&2
  if command -v open &>/dev/null; then
    open "$auth_url"
  elif command -v xdg-open &>/dev/null; then
    xdg-open "$auth_url"
  else
    echo "Open this URL in your browser:" >&2
    echo "$auth_url" >&2
  fi

  echo "Waiting for callback on ${REDIRECT_URI}..." >&2
  # Listen for the OAuth2 callback and extract the authorization code.
  response=$(nc -l 8484 </dev/null 2>/dev/null || true)
  code=$(echo "$response" |
    head -1 |
    sed -n 's/.*[?&]code=\([^& ]*\).*/\1/p')

  if [[ -z "$code" ]]; then
    echo "Error: failed to capture authorization code." >&2
    exit 1
  fi

  # Exchange authorization code for tokens.
  token_response=$(curl -s -X POST \
    "https://oauth2.googleapis.com/token" \
    -d "code=${code}" \
    -d "client_id=${GMAIL_CLIENT_ID}" \
    -d "client_secret=${GMAIL_CLIENT_SECRET}" \
    -d "redirect_uri=${REDIRECT_URI}" \
    -d "grant_type=authorization_code")

  refresh_token=$(echo "$token_response" | jq -r '.refresh_token // empty')
  if [[ -z "$refresh_token" ]]; then
    echo "Error: no refresh token in response:" >&2
    echo "$token_response" >&2
    exit 1
  fi

  echo "$refresh_token" >"$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  echo "Refresh token saved to ${TOKEN_FILE}" >&2

  echo "$token_response" | jq -r '.access_token'
}

refresh_access_token() {
  refresh_token=$(cat "$TOKEN_FILE")
  token_response=$(curl -s -X POST \
    "https://oauth2.googleapis.com/token" \
    -d "refresh_token=${refresh_token}" \
    -d "client_id=${GMAIL_CLIENT_ID}" \
    -d "client_secret=${GMAIL_CLIENT_SECRET}" \
    -d "grant_type=refresh_token")

  access_token=$(echo "$token_response" | jq -r '.access_token // empty')
  if [[ -z "$access_token" ]]; then
    echo "Error: failed to refresh access token:" >&2
    echo "$token_response" >&2
    echo "Try deleting ${TOKEN_FILE} and re-running." >&2
    exit 1
  fi

  echo "$access_token"
}

if [[ -f "$TOKEN_FILE" ]]; then
  refresh_access_token
else
  get_refresh_token
fi
