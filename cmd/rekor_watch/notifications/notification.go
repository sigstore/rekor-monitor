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

import "encoding/json"

// NotificationEventTypeMatchCreated is the event type emitted when a new
// log entry matches a subscription. It is the only event type emitted
// today; subscribers should switch on the envelope's `type` field to
// remain forward-compatible.
const NotificationEventTypeMatchCreated = "rekor.match.created"

// NotificationData is the per-event payload carried under the envelope's
// `data` field. Each delivery per (subscription, polling cycle) carries
// up to 100 entries; subscriptions with more pending matches drain over
// successive cycles.
//
// Order within Entries is unspecified.
//
// Consumers must deduplicate by the (MonitoredValue, Origin, LogIndex)
// tuple: the same match may be delivered more than once if a previous
// delivery's response was lost (e.g. a network timeout after the receiver
// processed the payload).
type NotificationData struct {
	SubscriptionName string              `json:"subscription_name"`
	MonitoredValue   json.RawMessage     `json:"monitored_value"`
	Entries          []NotificationMatch `json:"entries"`
}

// NotificationPayload is the body POSTed to a subscription's webhook URL.
// It conforms to the Standard Webhooks envelope shape {type, timestamp,
// data} so subscribers can switch on `type` and read `timestamp` as the
// delivery time.
type NotificationPayload struct {
	Type string `json:"type"`
	// Timestamp is the delivery cycle's wall-clock time, RFC3339 in UTC.
	Timestamp string           `json:"timestamp"`
	Data      NotificationData `json:"data"`
}

// NotificationMatch mirrors the relevant fields from a log entry match.
type NotificationMatch struct {
	Origin         string `json:"origin"`
	LogIndex       int64  `json:"log_index"`
	UUID           string `json:"uuid"`
	CertSubject    string `json:"cert_subject,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	Subject        string `json:"subject,omitempty"`
	OIDExtension   string `json:"oid_extension,omitempty"`
	ExtensionValue string `json:"extension_value,omitempty"`
}
