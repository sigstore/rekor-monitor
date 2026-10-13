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
	"testing"
	"time"

	standardwebhooks "github.com/standard-webhooks/standard-webhooks/libraries/go"
)

// TestStandardWebhooksSign_matchesCanonicalVector pins our use of the Standard
// Webhooks library against the spec's canonical `v1` test vector. It is the
// guard that the secret format we derive (whsec_<base64>) and the exact signed
// string the library produces stay interoperable with reference verifiers.
func TestStandardWebhooksSign_matchesCanonicalVector(t *testing.T) {
	const (
		secret  = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
		id      = "msg_p5jXN8AQM9LWM0D4loKWxJek"
		tsUnix  = int64(1614265330)
		body    = `{"test": 2432232314}`
		wantSig = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
	)

	wh, err := standardwebhooks.NewWebhook(secret)
	if err != nil {
		t.Fatalf("NewWebhook() error: %v", err)
	}
	got, err := wh.Sign(id, time.Unix(tsUnix, 0), []byte(body))
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if got != wantSig {
		t.Errorf("Sign() = %q, want %q", got, wantSig)
	}
}

// TestStandardWebhooksNewWebhook_rejectsBadSecret confirms the library fails
// closed on a malformed secret (non-base64 after the whsec_ prefix).
func TestStandardWebhooksNewWebhook_rejectsBadSecret(t *testing.T) {
	if _, err := standardwebhooks.NewWebhook("whsec_!!!not base64!!!"); err == nil {
		t.Error("NewWebhook() with a non-base64 secret should return an error")
	}
}
