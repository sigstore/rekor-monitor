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

package main

import (
	"testing"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/store"
)

func sub(userID int64, webhook string, val identity.MonitoredValue) *store.Subscription {
	return &store.Subscription{
		UserID:           userID,
		MonitoredValue:   val,
		WebhookURL:       webhook,
		NotificationType: store.NotificationTypeWebhook,
	}
}

func TestCollectMonitoredValues_Empty(t *testing.T) {
	vals := collectMonitoredValues(nil)
	if len(vals) != 0 {
		t.Fatalf("expected 0 values, got %d", len(vals))
	}
}

func TestCollectMonitoredValues_Deduplicates(t *testing.T) {
	cert := identity.CertIdentityValue{
		CertSubject: "user@example.com",
		Issuers:     []string{"https://accounts.google.com"},
	}
	subs := []*store.Subscription{
		sub(1, "https://hook1", cert),
		sub(2, "https://hook2", cert),
	}

	vals := collectMonitoredValues(subs)
	if len(vals) != 1 {
		t.Fatalf("expected 1 unique value, got %d", len(vals))
	}

	got, _ := vals[0].String()
	want, _ := cert.String()
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestCollectMonitoredValues_MultipleDistinct(t *testing.T) {
	cert := identity.CertIdentityValue{
		CertSubject: "user@example.com",
		Issuers:     []string{"https://accounts.google.com"},
	}
	fp := identity.FingerprintValue{Fingerprint: "abc123"}

	subs := []*store.Subscription{
		sub(1, "https://hook1", cert),
		sub(2, "https://hook2", fp),
	}

	vals := collectMonitoredValues(subs)
	if len(vals) != 2 {
		t.Fatalf("expected 2 unique values, got %d", len(vals))
	}
}

func TestGroupSubscriptionsByValue_Empty(t *testing.T) {
	m := groupSubscriptionsByValue(nil)
	if len(m) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(m))
	}
}

func TestGroupSubscriptionsByValue_GroupsByKey(t *testing.T) {
	cert := identity.CertIdentityValue{
		CertSubject: "user@example.com",
		Issuers:     []string{"https://accounts.google.com"},
	}
	fp := identity.FingerprintValue{Fingerprint: "abc123"}

	s1 := sub(1, "https://hook1", cert)
	s2 := sub(2, "https://hook2", cert)
	s3 := sub(3, "https://hook3", fp)

	m := groupSubscriptionsByValue([]*store.Subscription{s1, s2, s3})

	certKey, _ := cert.String()
	fpKey, _ := fp.String()

	if len(m) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(m))
	}
	if len(m[certKey]) != 2 {
		t.Fatalf("expected 2 subs for cert key, got %d", len(m[certKey]))
	}
	if len(m[fpKey]) != 1 {
		t.Fatalf("expected 1 sub for fp key, got %d", len(m[fpKey]))
	}
	if m[fpKey][0].WebhookURL != "https://hook3" {
		t.Fatalf("expected hook3, got %s", m[fpKey][0].WebhookURL)
	}
}
