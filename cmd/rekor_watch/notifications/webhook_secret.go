//
// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package notifications

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// secretPrefix is the Standard Webhooks symmetric-secret prefix; the HMAC key
// is the standard-base64 decoding of everything after it. The signing side
// (the standard-webhooks library) strips and decodes the same prefix.
const secretPrefix = "whsec_"

// minMasterKeyBytes is the minimum decoded size of the master key. 32 bytes
// gives a 256-bit key, matching the HMAC-SHA256 block strength.
const minMasterKeyBytes = 32

// derivedSecretBytes is the number of HKDF output bytes per derived secret.
const derivedSecretBytes = 24

// WebhookSecretDeriver derives per-subscription webhook signing secrets on
// demand from a single server-side master key. No secret is ever stored: a
// secret is fully determined by (master key, subscription ID, version), so it
// can be recomputed when needed and a regenerate is just a version bump.
type WebhookSecretDeriver struct {
	masterKey []byte
}

// LoadWebhookSecretDeriver reads the master key from keyFilePath. The file must
// contain the standard-base64 encoding of at least 32 random bytes (trailing
// whitespace is trimmed). It fails closed: any problem reading or decoding the
// key returns an error so the caller can refuse to start rather than run with
// no key material.
func LoadWebhookSecretDeriver(keyFilePath string) (*WebhookSecretDeriver, error) {
	raw, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read webhook master key file: %w", err)
	}

	masterKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("webhook master key file is not valid base64: %w", err)
	}
	if len(masterKey) < minMasterKeyBytes {
		return nil, fmt.Errorf("webhook master key must be at least %d bytes, got %d", minMasterKeyBytes, len(masterKey))
	}

	return &WebhookSecretDeriver{masterKey: masterKey}, nil
}

// Secret returns the Standard Webhooks secret "whsec_<base64std(24B)>" for the
// given subscription ID and version. It is deterministic: the same inputs and
// master key always yield the same secret, and any change to the version (a
// regenerate) yields a fresh, unrelated secret.
func (d *WebhookSecretDeriver) Secret(subID int64, version int) (string, error) {
	info := fmt.Sprintf("rekor-watch/webhook-secret/v1|sub=%d|ver=%d", subID, version)
	kb, err := hkdf.Key(sha256.New, d.masterKey, nil, info, derivedSecretBytes)
	if err != nil {
		return "", fmt.Errorf("failed to derive webhook secret: %w", err)
	}
	return secretPrefix + base64.StdEncoding.EncodeToString(kb), nil
}
