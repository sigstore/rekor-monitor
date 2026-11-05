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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookSender_Send_Success(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	payload := NotificationPayload{
		Type:      NotificationEventTypeMatchCreated,
		Timestamp: "2026-05-21T12:00:00Z",
		Data: NotificationData{
			SubscriptionName: "prod-certs",
			MonitoredValue:   json.RawMessage(`{"type":"subject","subject":"test@example.com"}`),
			Entries: []NotificationMatch{{
				Origin:   "test-origin",
				LogIndex: 42,
				UUID:     "abc-123",
				Subject:  "test@example.com",
			}},
		},
	}

	sender := NewWebhookSender("", http.DefaultClient)

	if err := sender.Send(context.Background(), srv.URL, payload); err != nil {
		t.Fatalf("Send() returned error: %v", err)
	}

	if receivedContentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", receivedContentType)
	}

	var got NotificationPayload
	if err := json.Unmarshal(receivedBody, &got); err != nil {
		t.Fatalf("failed to unmarshal received body: %v", err)
	}
	if len(got.Data.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got.Data.Entries))
	}
	if got.Data.Entries[0].LogIndex != 42 {
		t.Errorf("expected log_index 42, got %d", got.Data.Entries[0].LogIndex)
	}
	if got.Data.Entries[0].Subject != "test@example.com" {
		t.Errorf("expected subject test@example.com, got %s", got.Data.Entries[0].Subject)
	}
	if got.Data.SubscriptionName != "prod-certs" {
		t.Errorf("expected subscription_name prod-certs, got %s", got.Data.SubscriptionName)
	}
}

func TestWebhookSender_Send_4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	sender := NewWebhookSender("", http.DefaultClient)
	payload := NotificationPayload{
		Type:      NotificationEventTypeMatchCreated,
		Timestamp: "2026-05-21T12:00:00Z",
		Data: NotificationData{
			MonitoredValue: json.RawMessage(`{}`),
			Entries: []NotificationMatch{
				{Origin: "o"},
			},
		},
	}

	err := sender.Send(context.Background(), srv.URL, payload)
	if err == nil {
		t.Fatal("expected error for 400 response, got nil")
	}
}

func TestWebhookSender_Send_5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sender := NewWebhookSender("", http.DefaultClient)
	payload := NotificationPayload{
		Type:      NotificationEventTypeMatchCreated,
		Timestamp: "2026-05-21T12:00:00Z",
		Data: NotificationData{
			MonitoredValue: json.RawMessage(`{}`),
			Entries:        []NotificationMatch{{Origin: "o"}},
		},
	}

	err := sender.Send(context.Background(), srv.URL, payload)
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

// TestNotificationPayload_wireEnvelopeShape pins the literal JSON wire
// contract that subscribers depend on: a top-level {type, timestamp,
// data} object with the match fields nested under data, never promoted
// to the root. Decoding back into NotificationPayload would be circular —
// marshaling and unmarshaling through the same struct is self-consistent
// regardless of the actual wire shape — so this inspects the raw keys.
func TestNotificationPayload_wireEnvelopeShape(t *testing.T) {
	payload := NotificationPayload{
		Type:      NotificationEventTypeMatchCreated,
		Timestamp: "2026-05-21T12:00:00Z",
		Data: NotificationData{
			SubscriptionName: "my-sub",
			MonitoredValue:   json.RawMessage(`{"type":"subject","subject":"target"}`),
			Entries:          []NotificationMatch{{Origin: "o", LogIndex: 7, UUID: "u"}},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		t.Fatalf("failed to unmarshal envelope: %v", err)
	}
	for _, key := range []string{"type", "timestamp", "data"} {
		if _, ok := root[key]; !ok {
			t.Errorf("envelope missing top-level key %q: %s", key, body)
		}
	}
	// Match fields must be nested under data, not at the envelope root —
	// this nesting is the crux of the breaking change.
	for _, key := range []string{"subscription_name", "monitored_value", "entries"} {
		if _, ok := root[key]; ok {
			t.Errorf("%q must be nested under data, not at the envelope root: %s", key, body)
		}
	}

	var typ string
	if err := json.Unmarshal(root["type"], &typ); err != nil {
		t.Fatalf("type is not a JSON string: %v", err)
	}
	if typ != "rekor.match.created" {
		t.Errorf("envelope type = %q, want %q", typ, "rekor.match.created")
	}

	var data map[string]json.RawMessage
	if err := json.Unmarshal(root["data"], &data); err != nil {
		t.Fatalf("failed to unmarshal data: %v", err)
	}
	for _, key := range []string{"subscription_name", "monitored_value", "entries"} {
		if _, ok := data[key]; !ok {
			t.Errorf("data.%s missing: %s", key, body)
		}
	}

	// Entry fields keep their wire names under data.entries — subscribers
	// read these directly.
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(data["entries"], &entries); err != nil {
		t.Fatalf("data.entries is not a JSON array: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	for _, key := range []string{"origin", "log_index", "uuid"} {
		if _, ok := entries[0][key]; !ok {
			t.Errorf("entry missing wire key %q: %s", key, body)
		}
	}
}
