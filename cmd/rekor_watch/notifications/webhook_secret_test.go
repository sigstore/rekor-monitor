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
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeKeyFile writes a master key file containing base64std of the given raw
// bytes and returns its path.
func writeKeyFile(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "webhook-master.key")
	contents := base64.StdEncoding.EncodeToString(raw) + "\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	return path
}

func TestLoadWebhookSecretDeriver_validKeyFileLoads(t *testing.T) {
	path := writeKeyFile(t, []byte("0123456789abcdef0123456789abcdef")) // 32 bytes
	d, err := LoadWebhookSecretDeriver(path)
	if err != nil {
		t.Fatalf("LoadWebhookSecretDeriver() error: %v", err)
	}
	if d == nil {
		t.Fatal("LoadWebhookSecretDeriver() returned nil deriver")
	}
}

func TestLoadWebhookSecretDeriver_rejectsMissingFile(t *testing.T) {
	if _, err := LoadWebhookSecretDeriver(filepath.Join(t.TempDir(), "nope.key")); err == nil {
		t.Error("LoadWebhookSecretDeriver() with a missing file should fail closed")
	}
}

func TestLoadWebhookSecretDeriver_rejectsShortKey(t *testing.T) {
	path := writeKeyFile(t, []byte("too short")) // < 32 bytes
	if _, err := LoadWebhookSecretDeriver(path); err == nil {
		t.Error("LoadWebhookSecretDeriver() with a < 32 byte key should fail closed")
	}
}

func TestLoadWebhookSecretDeriver_rejectsBadBase64(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(path, []byte("!!! not base64 !!!"), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	if _, err := LoadWebhookSecretDeriver(path); err == nil {
		t.Error("LoadWebhookSecretDeriver() with non-base64 contents should fail closed")
	}
}

func newTestDeriver(t *testing.T) *WebhookSecretDeriver {
	t.Helper()
	d, err := LoadWebhookSecretDeriver(writeKeyFile(t, []byte("0123456789abcdef0123456789abcdef")))
	if err != nil {
		t.Fatalf("LoadWebhookSecretDeriver() error: %v", err)
	}
	return d
}

func TestDeriver_Secret_deterministicForSameInputs(t *testing.T) {
	d := newTestDeriver(t)
	a, err := d.Secret(42, 1)
	if err != nil {
		t.Fatalf("Secret() error: %v", err)
	}
	b, err := d.Secret(42, 1)
	if err != nil {
		t.Fatalf("Secret() error: %v", err)
	}
	if a != b {
		t.Errorf("Secret() not deterministic: %q != %q", a, b)
	}
}

func TestDeriver_Secret_differsAcrossSubIDs(t *testing.T) {
	d := newTestDeriver(t)
	a, _ := d.Secret(1, 1)
	b, _ := d.Secret(2, 1)
	if a == b {
		t.Errorf("Secret() should differ across subscription IDs, both = %q", a)
	}
}

func TestDeriver_Secret_differsAcrossVersions(t *testing.T) {
	d := newTestDeriver(t)
	a, _ := d.Secret(1, 1)
	b, _ := d.Secret(1, 2)
	if a == b {
		t.Errorf("Secret() should differ across versions (regenerate), both = %q", a)
	}
}

func TestDeriver_Secret_differsAcrossMasterKeys(t *testing.T) {
	d1 := newTestDeriver(t)
	d2, err := LoadWebhookSecretDeriver(writeKeyFile(t, []byte("ffffffffffffffffffffffffffffffff")))
	if err != nil {
		t.Fatalf("LoadWebhookSecretDeriver() error: %v", err)
	}
	a, _ := d1.Secret(1, 1)
	b, _ := d2.Secret(1, 1)
	if a == b {
		t.Errorf("Secret() should differ across master keys, both = %q", a)
	}
}

func TestDeriver_Secret_whsecPrefixAnd24Bytes(t *testing.T) {
	d := newTestDeriver(t)
	secret, err := d.Secret(7, 3)
	if err != nil {
		t.Fatalf("Secret() error: %v", err)
	}
	if !strings.HasPrefix(secret, "whsec_") {
		t.Errorf("Secret() = %q, want a 'whsec_' prefix", secret)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		t.Fatalf("Secret() payload is not std base64: %v", err)
	}
	if len(raw) != 24 {
		t.Errorf("Secret() decodes to %d bytes, want 24", len(raw))
	}
}
