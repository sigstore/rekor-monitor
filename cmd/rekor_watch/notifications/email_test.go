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
	"encoding/json"
	"strings"
	"testing"
)

// TestRenderMatchEmail covers the rendering contract: the body surfaces the
// match data and the monitored value, and untrusted Rekor content is
// HTML-escaped so it can never reach the recipient as live markup.
func TestRenderMatchEmail(t *testing.T) {
	subject, body := RenderMatchEmail(NotificationPayload{
		Data: NotificationData{
			SubscriptionName: `prod-certs <sub>`,
			MonitoredValue:   json.RawMessage(`{"type":"subject","subject":"watched@example.com"}`),
			Entries: []NotificationMatch{{
				Origin:      "rekor.example",
				LogIndex:    42,
				UUID:        "abc-123",
				CertSubject: `<script>alert("xss")</script>`,
			}},
		},
	})

	if !strings.Contains(subject, "42") {
		t.Errorf("subject should reference the log index, got %q", subject)
	}
	for _, want := range []string{"rekor.example", "abc-123", "watched@example.com", "prod-certs"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q, got: %s", want, body)
		}
	}
	if strings.Contains(body, "<script>") {
		t.Errorf("body contains unescaped content: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("expected escaped content, got: %s", body)
	}
	// The subscription name is user-controlled, so it must be escaped too.
	if !strings.Contains(body, "prod-certs &lt;sub&gt;") {
		t.Errorf("expected escaped subscription name, got: %s", body)
	}
}
