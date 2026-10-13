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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/rekor-monitor/cmd/rekor_watch/notifications"
	"github.com/sigstore/rekor-monitor/cmd/rekor_watch/web"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	safenet "github.com/sigstore/rekor-monitor/pkg/net"
	"github.com/sigstore/rekor-monitor/pkg/store"
	"github.com/sigstore/rekor-monitor/pkg/store/sqlite"
)

// deliverAt runs the notifier once as if the current time were now, so tests
// can drive retry/backoff windows deterministically.
func deliverAt(ctx context.Context, n *notifier, now time.Time) error {
	return n.runOnce(ctx, now)
}

func setupTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	ctx := context.Background()
	s, err := sqlite.NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func insertSubAndMatch(t *testing.T, s *sqlite.Store, webhookURL string) int64 {
	t.Helper()
	ctx := context.Background()

	user := &store.User{Email: "test@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	sub := &store.Subscription{
		UserID:           user.ID,
		Name:             "test-sub",
		MonitoredValue:   identity.SubjectValue{Subject: "user@example.com"},
		WebhookURL:       webhookURL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	match := &store.Match{
		Origin:         "test-origin",
		LogIndex:       42,
		UUID:           "abc-123",
		Subject:        "user@example.com",
		SubscriptionID: sub.ID,
	}
	if err := s.SaveMatch(ctx, match); err != nil {
		t.Fatalf("failed to save match: %v", err)
	}

	matches, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("failed to list pending matches: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected at least one pending match")
	}
	return matches[len(matches)-1].ID
}

func TestSendNotifications_Success(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	insertSubAndMatch(t, s, srv.URL)

	ctx := context.Background()
	if err := deliverAt(ctx, newNotifier(s, "test-user-agent", http.DefaultClient, nil, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	var payload notifications.NotificationPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal webhook payload: %v", err)
	}
	if payload.Data.SubscriptionName != "test-sub" {
		t.Errorf("expected subscription_name %q, got %q", "test-sub", payload.Data.SubscriptionName)
	}
	if len(payload.Data.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(payload.Data.Entries))
	}
	if payload.Data.Entries[0].LogIndex != 42 {
		t.Errorf("expected log_index 42, got %d", payload.Data.Entries[0].LogIndex)
	}

	// Verify match is marked as notified
	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected 0 pending matches after notification, got %d", len(pending))
	}
}

// TestSendNotifications_EnvelopeStamps pins the envelope's `type` and
// `timestamp` fields: type is the match-created constant and timestamp
// is the dispatcher cycle's wall-clock time (RFC3339 UTC). A regression
// that left either field unset or stamped a different value would change
// the wire contract subscribers depend on.
func TestSendNotifications_EnvelopeStamps(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	insertSubAndMatch(t, s, srv.URL)

	cycle := time.Now()
	if err := deliverAt(context.Background(), newNotifier(s, "test-ua", http.DefaultClient, nil, nil), cycle); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	var payload notifications.NotificationPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal envelope: %v", err)
	}
	if payload.Type != notifications.NotificationEventTypeMatchCreated {
		t.Errorf("envelope type = %q, want %q",
			payload.Type, notifications.NotificationEventTypeMatchCreated)
	}
	wantTS := cycle.UTC().Format(time.RFC3339)
	if payload.Timestamp != wantTS {
		t.Errorf("envelope timestamp = %q, want %q (cycle time, UTC RFC3339)",
			payload.Timestamp, wantTS)
	}
}

// TestSendNotifications_OneRequestPerSubscription verifies that one webhook
// POST is sent per subscription per cycle, carrying every pending match for
// that subscription (regardless of how many matches each sub has).
func TestSendNotifications_OneRequestPerSubscription(t *testing.T) {
	callCount := 0
	var batchSizes []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		body, _ := io.ReadAll(r.Body)
		var p notifications.NotificationPayload
		if err := json.Unmarshal(body, &p); err != nil {
			t.Errorf("unmarshal: %v", err)
		}
		batchSizes = append(batchSizes, len(p.Data.Entries))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	ctx := context.Background()

	owner := &store.User{Email: "owner@example.com"}
	if err := s.SaveUser(ctx, owner); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	sub1 := &store.Subscription{
		UserID:           owner.ID,
		Name:             "sub1",
		MonitoredValue:   identity.SubjectValue{Subject: "user1@example.com"},
		WebhookURL:       srv.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub1); err != nil {
		t.Fatalf("failed to save sub1: %v", err)
	}
	sub2 := &store.Subscription{
		UserID:           owner.ID,
		Name:             "sub2",
		MonitoredValue:   identity.SubjectValue{Subject: "user2@example.com"},
		WebhookURL:       srv.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub2); err != nil {
		t.Fatalf("failed to save sub2: %v", err)
	}

	for _, m := range []*store.Match{
		{Origin: "o", LogIndex: 1, UUID: "u1", Subject: "user1@example.com", SubscriptionID: sub1.ID},
		{Origin: "o", LogIndex: 2, UUID: "u2", Subject: "user1@example.com", SubscriptionID: sub1.ID},
		{Origin: "o", LogIndex: 3, UUID: "u3", Subject: "user2@example.com", SubscriptionID: sub2.ID},
	} {
		if err := s.SaveMatch(ctx, m); err != nil {
			t.Fatalf("failed to save match: %v", err)
		}
	}

	if err := deliverAt(ctx, newNotifier(s, "test-user-agent", http.DefaultClient, nil, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	if callCount != 2 {
		t.Fatalf("expected 2 HTTP calls (one per subscription), got %d", callCount)
	}
	// Total matches across batches should equal total matches inserted.
	total := 0
	for _, sz := range batchSizes {
		total += sz
	}
	if total != 3 {
		t.Errorf("expected 3 matches across batches, got %d (sizes %v)", total, batchSizes)
	}

	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected 0 pending, got %d", len(pending))
	}
}

func TestSendNotifications_WebhookFailure_NotMarkedNotified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	insertSubAndMatch(t, s, srv.URL)

	ctx := context.Background()
	if err := deliverAt(ctx, newNotifier(s, "test-user-agent", http.DefaultClient, nil, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 1 {
		t.Errorf("expected 1 pending match after failed webhook, got %d", len(pending))
	}
}

func TestSendNotifications_PartialFailure_DifferentURLs(t *testing.T) {
	srvFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srvFail.Close()

	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srvOK.Close()

	s := setupTestStore(t)
	ctx := context.Background()

	userA := &store.User{Email: "a@example.com"}
	if err := s.SaveUser(ctx, userA); err != nil {
		t.Fatalf("failed to save userA: %v", err)
	}
	userB := &store.User{Email: "b@example.com"}
	if err := s.SaveUser(ctx, userB); err != nil {
		t.Fatalf("failed to save userB: %v", err)
	}
	sub1 := &store.Subscription{
		UserID:           userA.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "user1@example.com"},
		WebhookURL:       srvFail.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub1); err != nil {
		t.Fatalf("failed to save sub1: %v", err)
	}
	sub2 := &store.Subscription{
		UserID:           userB.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "user2@example.com"},
		WebhookURL:       srvOK.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub2); err != nil {
		t.Fatalf("failed to save sub2: %v", err)
	}

	if err := s.SaveMatch(ctx, &store.Match{
		Origin: "o", LogIndex: 1, UUID: "u1",
		Subject: "user1@example.com", SubscriptionID: sub1.ID,
	}); err != nil {
		t.Fatalf("failed to save match1: %v", err)
	}
	if err := s.SaveMatch(ctx, &store.Match{
		Origin: "o", LogIndex: 2, UUID: "u2",
		Subject: "user2@example.com", SubscriptionID: sub2.ID,
	}); err != nil {
		t.Fatalf("failed to save match2: %v", err)
	}

	if err := deliverAt(ctx, newNotifier(s, "test-user-agent", http.DefaultClient, nil, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending match, got %d", len(pending))
	}
	if pending[0].Subscription.WebhookURL != srvFail.URL {
		t.Errorf("expected pending match for failing URL, got %s", pending[0].Subscription.WebhookURL)
	}
}

func TestSendNotifications_SafeClientBlocksLocalAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	insertSubAndMatch(t, s, srv.URL)

	ctx := context.Background()
	safeClient := safenet.NewSafeHTTPClient()
	if err := deliverAt(ctx, newNotifier(s, "test-user-agent", safeClient, nil, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	// The safe client should have blocked the request to the local
	// httptest server, so the match must still be pending.
	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending match (blocked by safe client), got %d", len(pending))
	}
}

func TestSendNotifications_SafeClientBlocksLocalAddress_ErrorMessage(t *testing.T) {
	safeClient := safenet.NewSafeHTTPClient()

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	_, err = safeClient.Do(req)
	if err == nil {
		t.Fatal("expected error when connecting to loopback address with safe client")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("expected error to mention 'blocked', got: %v", err)
	}
}

// TestSendNotifications_RateLimitDefersBatch verifies that when the rate
// limiter denies a subscription's batch, no POST is made and all matches
// remain pending for the next cycle.
func TestSendNotifications_RateLimitDefersBatch(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	ctx := context.Background()

	owner := &store.User{Email: "owner@example.com"}
	if err := s.SaveUser(ctx, owner); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	sub := &store.Subscription{
		UserID:           owner.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "user@example.com"},
		WebhookURL:       srv.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	for i := range 5 {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin: "o", LogIndex: int64(i), UUID: fmt.Sprintf("u%d", i),
			Subject: "user@example.com", SubscriptionID: sub.ID,
		}); err != nil {
			t.Fatalf("failed to save match %d: %v", i, err)
		}
	}

	// Pre-fill the bucket so the limiter denies the batch.
	limiter := web.NewRateLimiter(1, 1*time.Minute)
	if allowed, _ := limiter.Allow(webhookHost(srv.URL)); !allowed {
		t.Fatal("failed to pre-fill limiter bucket")
	}

	if err := deliverAt(ctx, newNotifier(s, "test-user-agent", http.DefaultClient, limiter, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	if callCount != 0 {
		t.Errorf("expected 0 webhook calls when batch is rate-limited, got %d", callCount)
	}
	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 5 {
		t.Errorf("expected all 5 matches to remain pending, got %d", len(pending))
	}
}

func TestSendNotifications_RateLimitedOnly_DoesNotResetFailures(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	ctx := context.Background()

	user := &store.User{Email: "rate-limited@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "rate-limited@example.com"},
		WebhookURL:       srv.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	for i := range 2 {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin: "o", LogIndex: int64(i), UUID: fmt.Sprintf("u%d", i),
			Subject: "rate-limited@example.com", SubscriptionID: sub.ID,
		}); err != nil {
			t.Fatalf("failed to save match %d: %v", i, err)
		}
	}

	pastRetry := time.Now().Add(-time.Minute)
	if _, err := s.RecordNotificationFailure(ctx, sub.ID, time.Now(), pastRetry); err != nil {
		t.Fatalf("RecordNotificationFailure() error: %v", err)
	}

	limiter := web.NewRateLimiter(1, 1*time.Minute)
	if allowed, _ := limiter.Allow(webhookHost(srv.URL)); !allowed {
		t.Fatal("failed to pre-fill limiter bucket")
	}

	if err := deliverAt(ctx, newNotifier(s, "test-user-agent", http.DefaultClient, limiter, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	if callCount != 0 {
		t.Fatalf("expected 0 webhook calls after rate limit skip, got %d", callCount)
	}

	subs, err := s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatalf("ListSubscriptions() error: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 subscription, got %d", len(subs))
	}
	if subs[0].ConsecutiveFailures != 1 {
		t.Errorf("expected ConsecutiveFailures to remain 1, got %d", subs[0].ConsecutiveFailures)
	}
	if subs[0].NextRetryAt == nil {
		t.Fatal("expected NextRetryAt to remain set")
	}
}

func TestSendNotifications_RateLimitIsPerHost(t *testing.T) {
	callCountA := 0
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCountA++
		w.WriteHeader(http.StatusOK)
	}))
	defer srvA.Close()

	callCountB := 0
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCountB++
		w.WriteHeader(http.StatusOK)
	}))
	defer srvB.Close()

	s := setupTestStore(t)
	ctx := context.Background()

	owner := &store.User{Email: "owner@example.com"}
	if err := s.SaveUser(ctx, owner); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	subA := &store.Subscription{
		UserID:           owner.ID,
		Name:             "subA",
		MonitoredValue:   identity.SubjectValue{Subject: "a@example.com"},
		WebhookURL:       srvA.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, subA); err != nil {
		t.Fatalf("failed to save subA: %v", err)
	}
	subB := &store.Subscription{
		UserID:           owner.ID,
		Name:             "subB",
		MonitoredValue:   identity.SubjectValue{Subject: "b@example.com"},
		WebhookURL:       srvB.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, subB); err != nil {
		t.Fatalf("failed to save subB: %v", err)
	}

	// 3 matches for host A, 3 matches for host B.
	for i := range 3 {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin: "o", LogIndex: int64(i), UUID: fmt.Sprintf("a%d", i),
			Subject: "a@example.com", SubscriptionID: subA.ID,
		}); err != nil {
			t.Fatalf("failed to save match: %v", err)
		}
		if err := s.SaveMatch(ctx, &store.Match{
			Origin: "o", LogIndex: int64(10 + i), UUID: fmt.Sprintf("b%d", i),
			Subject: "b@example.com", SubscriptionID: subB.ID,
		}); err != nil {
			t.Fatalf("failed to save match: %v", err)
		}
	}

	// Both hosts share the same limiter but each gets its own bucket,
	// so each host should be allowed exactly 1 request. With batching that
	// single allowed POST per host carries all 3 matches for that host.
	limiter := web.NewRateLimiter(1, 1*time.Minute)

	if err := deliverAt(ctx, newNotifier(s, "test-user-agent", http.DefaultClient, limiter, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	if callCountA != 1 {
		t.Errorf("expected 1 webhook call to host A, got %d", callCountA)
	}
	if callCountB != 1 {
		t.Errorf("expected 1 webhook call to host B, got %d", callCountB)
	}

	// All 6 matches should be delivered (one batch per host).
	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected 0 pending matches, got %d", len(pending))
	}
}

func TestSendNotifications_NoPending(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	if err := deliverAt(ctx, newNotifier(s, "test-user-agent", http.DefaultClient, nil, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() with no pending matches should not error: %v", err)
	}
}

func TestNotificationBackoff(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{0, 0},
		{1, 1 * time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, 8 * time.Minute},
		{5, 16 * time.Minute},
		{6, 32 * time.Minute},
		{7, 1 * time.Hour},
		{8, 1 * time.Hour}, // capped
		{100, 1 * time.Hour},
	}
	for _, tt := range tests {
		got := notificationBackoff(tt.failures)
		if got != tt.want {
			t.Errorf("notificationBackoff(%d) = %v, want %v", tt.failures, got, tt.want)
		}
	}
}

func TestNotificationBackoffWithJitter(t *testing.T) {
	// Zero failures should always return zero, no jitter.
	if got := notificationBackoffWithJitter(0); got != 0 {
		t.Errorf("notificationBackoffWithJitter(0) = %v, want 0", got)
	}

	// For non-zero failures, verify jitter stays within ±25% of base.
	for _, failures := range []int{1, 3, 5, 7, 10} {
		base := notificationBackoff(failures)
		lo := time.Duration(float64(base) * (1 - notificationBackoffJitter))
		hi := time.Duration(float64(base) * (1 + notificationBackoffJitter))
		if hi > notificationBackoffMax {
			hi = notificationBackoffMax
		}

		for range 100 {
			got := notificationBackoffWithJitter(failures)
			if got < lo || got > hi {
				t.Errorf("notificationBackoffWithJitter(%d) = %v, want in [%v, %v] (base %v)",
					failures, got, lo, hi, base)
			}
		}
	}

	// Verify jitter actually varies (not always the same value).
	seen := make(map[time.Duration]bool)
	for range 50 {
		seen[notificationBackoffWithJitter(3)] = true
	}
	if len(seen) < 2 {
		t.Error("notificationBackoffWithJitter(3) returned the same value 50 times; jitter appears broken")
	}
}

func TestSendNotifications_WebhookFailure_RecordsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	insertSubAndMatch(t, s, srv.URL)

	ctx := context.Background()
	if err := deliverAt(ctx, newNotifier(s, "test-user-agent", http.DefaultClient, nil, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	// Verify failure was recorded
	subs, err := s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatalf("ListSubscriptions() error: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 subscription, got %d", len(subs))
	}
	if subs[0].ConsecutiveFailures != 1 {
		t.Errorf("expected ConsecutiveFailures 1, got %d", subs[0].ConsecutiveFailures)
	}
	if subs[0].LastFailureAt == nil {
		t.Error("expected LastFailureAt to be set")
	}
	if subs[0].NextRetryAt == nil {
		t.Error("expected NextRetryAt to be set after failure")
	}
}

func TestSendNotifications_BackoffSkipsSubscription(t *testing.T) {
	for _, tc := range []struct {
		name      string
		notifType store.NotificationType
	}{
		{"Webhook", store.NotificationTypeWebhook},
		{"Email", store.NotificationTypeEmail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			callCount := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				callCount++
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()
			mock := &mockNotifEmailSender{}

			s := setupTestStore(t)
			ctx := context.Background()

			user := &store.User{Email: "backoff@example.com"}
			if err := s.SaveUser(ctx, user); err != nil {
				t.Fatalf("failed to save user: %v", err)
			}

			sub := &store.Subscription{
				UserID:           user.ID,
				MonitoredValue:   identity.SubjectValue{Subject: "user@example.com"},
				NotificationType: tc.notifType,
			}
			if tc.notifType == store.NotificationTypeWebhook {
				sub.WebhookURL = srv.URL
			}
			if err := s.SaveSubscription(ctx, sub); err != nil {
				t.Fatalf("failed to save subscription: %v", err)
			}

			// Record a recent failure to trigger backoff (next retry far in the future)
			nextRetry := time.Now().Add(time.Hour)
			if _, err := s.RecordNotificationFailure(ctx, sub.ID, time.Now(), nextRetry); err != nil {
				t.Fatalf("RecordNotificationFailure() error: %v", err)
			}

			// Add a match
			match := &store.Match{
				Origin:         "o",
				LogIndex:       1,
				UUID:           "u1",
				Subject:        "user@example.com",
				SubscriptionID: sub.ID,
			}
			if err := s.SaveMatch(ctx, match); err != nil {
				t.Fatalf("failed to save match: %v", err)
			}

			// Send notifications — should skip due to backoff (failure was just recorded)
			if err := deliverAt(ctx, newNotifier(s, "test-user-agent", http.DefaultClient, nil, mock), time.Now()); err != nil {
				t.Fatalf("runOnce() error: %v", err)
			}

			if dispatched := callCount + len(mock.sent); dispatched != 0 {
				t.Errorf("expected 0 dispatches (backed off), got %d", dispatched)
			}

			// Match should still be pending
			pending, err := s.ListPendingMatches(ctx)
			if err != nil {
				t.Fatalf("ListPendingMatches() error: %v", err)
			}
			if len(pending) != 1 {
				t.Errorf("expected 1 pending match (skipped by backoff), got %d", len(pending))
			}
		})
	}
}

func TestSendNotifications_Success_ResetsFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		notifType store.NotificationType
	}{
		{"Webhook", store.NotificationTypeWebhook},
		{"Email", store.NotificationTypeEmail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()
			mock := &mockNotifEmailSender{}

			s := setupTestStore(t)
			ctx := context.Background()

			user := &store.User{Email: "reset@example.com"}
			if err := s.SaveUser(ctx, user); err != nil {
				t.Fatalf("failed to save user: %v", err)
			}

			sub := &store.Subscription{
				UserID:           user.ID,
				MonitoredValue:   identity.SubjectValue{Subject: "user@example.com"},
				NotificationType: tc.notifType,
			}
			if tc.notifType == store.NotificationTypeWebhook {
				sub.WebhookURL = srv.URL
			}
			if err := s.SaveSubscription(ctx, sub); err != nil {
				t.Fatalf("failed to save subscription: %v", err)
			}

			// Record an old failure (beyond backoff window) so we can test reset
			pastRetry := time.Now().Add(-time.Hour)
			if _, err := s.RecordNotificationFailure(ctx, sub.ID, time.Now().Add(-time.Hour), pastRetry); err != nil {
				t.Fatalf("RecordNotificationFailure() error: %v", err)
			}

			// Add a match
			match := &store.Match{
				Origin:         "o",
				LogIndex:       1,
				UUID:           "u1",
				Subject:        "user@example.com",
				SubscriptionID: sub.ID,
			}
			if err := s.SaveMatch(ctx, match); err != nil {
				t.Fatalf("failed to save match: %v", err)
			}

			if err := deliverAt(ctx, newNotifier(s, "test-user-agent", http.DefaultClient, nil, mock), time.Now()); err != nil {
				t.Fatalf("runOnce() error: %v", err)
			}

			// Email arm must dispatch to the subscription owner's address,
			// not e.g. the monitored value. The webhook arm's URL routing
			// is implicit (httptest only sees its own server).
			if tc.notifType == store.NotificationTypeEmail {
				if len(mock.sent) != 1 {
					t.Fatalf("expected 1 email sent, got %d", len(mock.sent))
				}
				if mock.sent[0].To != user.Email {
					t.Errorf("recipient = %q, want %q", mock.sent[0].To, user.Email)
				}
			}

			// Verify failure counters were reset
			subs, err := s.ListSubscriptions(ctx)
			if err != nil {
				t.Fatalf("ListSubscriptions() error: %v", err)
			}
			if subs[0].ConsecutiveFailures != 0 {
				t.Errorf("expected ConsecutiveFailures 0 after success, got %d", subs[0].ConsecutiveFailures)
			}
			if subs[0].LastFailureAt != nil {
				t.Error("expected LastFailureAt nil after success")
			}
		})
	}
}

// TestNotificationFailureBackoff_E2E exercises the full lifecycle:
//
//  1. Notification failure records backoff state
//  2. Immediate retry is blocked by backoff
//  3. After backoff expires (time advances), retry succeeds and resets counters
//  4. Further failures accumulate to auto-disable threshold
//  5. Disabled subscription's matches are excluded from pending
//  6. Re-enabling preserves backoff state; only successful delivery resets it
func TestNotificationFailureBackoff_E2E(t *testing.T) {
	webhookOK := false
	webhookCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		webhookCalls++
		if webhookOK {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()

	s := setupTestStore(t)
	ctx := context.Background()

	user := &store.User{Email: "e2e-backoff@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "target@example.com"},
		WebhookURL:       srv.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	matchIdx := int64(0)
	addMatch := func() {
		matchIdx++
		m := &store.Match{
			Origin: "test-origin", LogIndex: matchIdx,
			UUID: fmt.Sprintf("uuid-%d", matchIdx), Subject: "target@example.com",
			SubscriptionID: sub.ID,
		}
		if err := s.SaveMatch(ctx, m); err != nil {
			t.Fatalf("failed to save match %d: %v", matchIdx, err)
		}
	}

	getSub := func() *store.Subscription {
		subs, err := s.ListSubscriptions(ctx)
		if err != nil {
			t.Fatalf("ListSubscriptions() error: %v", err)
		}
		for _, s := range subs {
			if s.ID == sub.ID {
				return s
			}
		}
		t.Fatal("subscription not found")
		return nil
	}

	now := time.Now()

	// ── Phase 1: First failure ──
	addMatch()
	webhookCalls = 0
	if err := deliverAt(ctx, newNotifier(s, "test-ua", http.DefaultClient, nil, nil), now); err != nil {
		t.Fatalf("phase 1: runOnce() error: %v", err)
	}
	if webhookCalls != 1 {
		t.Fatalf("phase 1: expected 1 webhook call, got %d", webhookCalls)
	}
	st := getSub()
	if st.ConsecutiveFailures != 1 {
		t.Errorf("phase 1: expected 1 failure, got %d", st.ConsecutiveFailures)
	}
	if st.NextRetryAt == nil {
		t.Fatal("phase 1: expected NextRetryAt to be set")
	}

	// Match should still be pending (webhook failed)
	pending, _ := s.ListPendingMatches(ctx)
	if len(pending) != 1 {
		t.Fatalf("phase 1: expected 1 pending match, got %d", len(pending))
	}

	// ── Phase 2: Backoff prevents immediate retry ──
	webhookCalls = 0
	if err := deliverAt(ctx, newNotifier(s, "test-ua", http.DefaultClient, nil, nil), now); err != nil {
		t.Fatalf("phase 2: runOnce() error: %v", err)
	}
	if webhookCalls != 0 {
		t.Errorf("phase 2: expected 0 calls (backed off), got %d", webhookCalls)
	}

	// ── Phase 3: Time advances past backoff, retry succeeds ──
	webhookOK = true
	webhookCalls = 0
	future := st.NextRetryAt.Add(time.Second)
	if err := deliverAt(ctx, newNotifier(s, "test-ua", http.DefaultClient, nil, nil), future); err != nil {
		t.Fatalf("phase 3: runOnce() error: %v", err)
	}
	if webhookCalls != 1 {
		t.Fatalf("phase 3: expected 1 call after backoff, got %d", webhookCalls)
	}
	st = getSub()
	if st.ConsecutiveFailures != 0 {
		t.Errorf("phase 3: expected 0 failures after success, got %d", st.ConsecutiveFailures)
	}
	if st.NextRetryAt != nil {
		t.Error("phase 3: expected NextRetryAt nil after success")
	}

	// ── Phase 4: Accumulate failures to auto-disable threshold ──
	// Add multiple matches per iteration to exercise the *batched* failure
	// path: each failed cycle has one POST carrying ≥2 matches and must
	// still increment ConsecutiveFailures by exactly 1 (not by batch size).
	webhookOK = false
	now = time.Now()
	for i := 1; i <= notificationMaxConsecutiveFailures; i++ {
		addMatch()
		addMatch()
		webhookCalls = 0
		if err := deliverAt(ctx, newNotifier(s, "test-ua", http.DefaultClient, nil, nil), now); err != nil {
			t.Fatalf("phase 4 iter %d: runOnce() error: %v", i, err)
		}
		if webhookCalls != 1 {
			t.Fatalf("phase 4 iter %d: expected 1 batched POST, got %d", i, webhookCalls)
		}
		st = getSub()
		if st.ConsecutiveFailures != i {
			t.Errorf("phase 4 iter %d: expected %d failures, got %d", i, i, st.ConsecutiveFailures)
		}
		// The threshold boundary: still active just below threshold,
		// auto-disabled exactly at threshold. Pin the boundary
		// explicitly so a >= → > regression is caught directly.
		if i < notificationMaxConsecutiveFailures && st.DisabledAt != nil {
			t.Errorf("phase 4 iter %d: sub should still be active below threshold, got DisabledAt=%v", i, st.DisabledAt)
		}
		if i == notificationMaxConsecutiveFailures && st.DisabledAt == nil {
			t.Errorf("phase 4 iter %d: sub should be disabled at threshold, got DisabledAt=nil", i)
		}
		// Advance time past the backoff for next iteration
		if st.NextRetryAt != nil {
			now = st.NextRetryAt.Add(time.Second)
		}
	}
	st = getSub()
	if st.DisabledAt == nil {
		t.Fatal("phase 4: subscription should be disabled at threshold")
	}
	addMatch()

	// ── Phase 5: Re-enable preserves backoff state ──
	if err := s.SetSubscriptionEnabled(ctx, sub.ID, user.ID, true); err != nil {
		t.Fatalf("phase 6: SetSubscriptionEnabled() error: %v", err)
	}
	st = getSub()
	if st.DisabledAt != nil {
		t.Error("phase 6: DisabledAt should be nil after enable")
	}
	if st.ConsecutiveFailures != notificationMaxConsecutiveFailures {
		t.Errorf("phase 6: ConsecutiveFailures should be preserved (%d), got %d", notificationMaxConsecutiveFailures, st.ConsecutiveFailures)
	}
	if st.NextRetryAt == nil {
		t.Error("phase 6: NextRetryAt should be preserved after enable")
	}

	// ── Phase 6: Successful delivery resets everything ──
	webhookOK = true
	webhookCalls = 0
	future = st.NextRetryAt.Add(time.Second)
	if err := deliverAt(ctx, newNotifier(s, "test-ua", http.DefaultClient, nil, nil), future); err != nil {
		t.Fatalf("phase 7: runOnce() error: %v", err)
	}
	// Should deliver all pending matches for this subscription
	if webhookCalls == 0 {
		t.Error("phase 7: expected webhook calls after backoff expired")
	}
	st = getSub()
	if st.ConsecutiveFailures != 0 {
		t.Errorf("phase 7: expected 0 failures after success, got %d", st.ConsecutiveFailures)
	}
	if st.NextRetryAt != nil {
		t.Error("phase 7: expected NextRetryAt nil after success")
	}
}

// TestWebhookFailure_BatchedDeliveryIsolatesSubscriptions verifies that a
// failed batch for one subscription does not block other subscriptions,
// every match for the failing subscription stays pending, and the failure
// counter increments exactly once for the failing subscription.
func TestWebhookFailure_BatchedDeliveryIsolatesSubscriptions(t *testing.T) {
	failCalls := 0
	srvFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		failCalls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srvFail.Close()

	okCalls := 0
	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		okCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srvOK.Close()

	s := setupTestStore(t)
	ctx := context.Background()

	userA := &store.User{Email: "multi-fail@example.com"}
	if err := s.SaveUser(ctx, userA); err != nil {
		t.Fatalf("failed to save userA: %v", err)
	}
	userB := &store.User{Email: "multi-ok@example.com"}
	if err := s.SaveUser(ctx, userB); err != nil {
		t.Fatalf("failed to save userB: %v", err)
	}

	subFail := &store.Subscription{
		UserID:           userA.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "fail@example.com"},
		WebhookURL:       srvFail.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	subOK := &store.Subscription{
		UserID:           userB.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "ok@example.com"},
		WebhookURL:       srvOK.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, subFail); err != nil {
		t.Fatalf("failed to save subFail: %v", err)
	}
	if err := s.SaveSubscription(ctx, subOK); err != nil {
		t.Fatalf("failed to save subOK: %v", err)
	}

	// 3 matches for failing sub, 2 matches for OK sub
	for i := int64(1); i <= 3; i++ {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin: "o", LogIndex: i, UUID: fmt.Sprintf("fail-%d", i),
			Subject: "fail@example.com", SubscriptionID: subFail.ID,
		}); err != nil {
			t.Fatalf("failed to save match: %v", err)
		}
	}
	for i := int64(1); i <= 2; i++ {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin: "o", LogIndex: 100 + i, UUID: fmt.Sprintf("ok-%d", i),
			Subject: "ok@example.com", SubscriptionID: subOK.ID,
		}); err != nil {
			t.Fatalf("failed to save match: %v", err)
		}
	}

	if err := deliverAt(ctx, newNotifier(s, "test-ua", http.DefaultClient, nil, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	// One POST per subscription per cycle: 1 for each.
	if failCalls != 1 {
		t.Errorf("expected 1 webhook call to failing sub (single batched POST), got %d", failCalls)
	}
	if okCalls != 1 {
		t.Errorf("expected 1 webhook call to OK sub (single batched POST), got %d", okCalls)
	}

	// 3 matches still pending for failing sub, 0 for OK sub
	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	failPending := 0
	okPending := 0
	for _, pm := range pending {
		if pm.Subscription.ID == subFail.ID {
			failPending++
		}
		if pm.Subscription.ID == subOK.ID {
			okPending++
		}
	}
	if failPending != 3 {
		t.Errorf("expected 3 pending for failing sub, got %d", failPending)
	}
	if okPending != 0 {
		t.Errorf("expected 0 pending for OK sub, got %d", okPending)
	}

	// Failure should be recorded on failing sub
	subs, err := s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatalf("ListSubscriptions() error: %v", err)
	}
	for _, sub := range subs {
		if sub.ID == subFail.ID && sub.ConsecutiveFailures != 1 {
			t.Errorf("expected 1 failure on failing sub, got %d", sub.ConsecutiveFailures)
		}
		if sub.ID == subOK.ID && sub.ConsecutiveFailures != 0 {
			t.Errorf("expected 0 failures on OK sub, got %d", sub.ConsecutiveFailures)
		}
	}
}

// faultyStore wraps a real store.Store and lets tests inject errors on
// specific methods exercised by runOnce. Only the overridden
// methods are intercepted; everything else delegates to the embedded
// store via the embedded interface.
type faultyStore struct {
	store.Store
	recordFailureErr   error
	setEnabledErr      error
	markNotifiedErr    error
	setEnabledCalls    int
	markNotifiedCalls  int
	markNotifiedIDs    []int64
	recordFailureCalls int
	recordSuccessCalls int
}

func (f *faultyStore) RecordNotificationFailure(ctx context.Context, subscriptionID int64, lastFailureAt, nextRetryAt time.Time) (int, error) {
	f.recordFailureCalls++
	if f.recordFailureErr != nil {
		return 0, f.recordFailureErr
	}
	return f.Store.RecordNotificationFailure(ctx, subscriptionID, lastFailureAt, nextRetryAt)
}

func (f *faultyStore) RecordNotificationSuccess(ctx context.Context, subscriptionID int64) error {
	f.recordSuccessCalls++
	return f.Store.RecordNotificationSuccess(ctx, subscriptionID)
}

func (f *faultyStore) SetSubscriptionEnabled(ctx context.Context, id, userID int64, enabled bool) error {
	f.setEnabledCalls++
	if f.setEnabledErr != nil {
		return f.setEnabledErr
	}
	return f.Store.SetSubscriptionEnabled(ctx, id, userID, enabled)
}

func (f *faultyStore) MarkMatchesNotified(ctx context.Context, matchIDs []int64) error {
	f.markNotifiedCalls++
	f.markNotifiedIDs = append(f.markNotifiedIDs, matchIDs...)
	if f.markNotifiedErr != nil {
		return f.markNotifiedErr
	}
	return f.Store.MarkMatchesNotified(ctx, matchIDs)
}

// TestSendNotifications_LargeBacklogDrains verifies that a backlog far larger
// than a single batch eventually drains to zero pending, no match is delivered
// twice, and no payload exceeds the documented cap.
func TestSendNotifications_LargeBacklogDrains(t *testing.T) {
	var delivered []notifications.NotificationMatch
	var maxBatch int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p notifications.NotificationPayload
		if err := json.Unmarshal(body, &p); err != nil {
			t.Errorf("unmarshal: %v", err)
		}
		delivered = append(delivered, p.Data.Entries...)
		if len(p.Data.Entries) > maxBatch {
			maxBatch = len(p.Data.Entries)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	ctx := context.Background()

	user := &store.User{Email: "drain@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("save user: %v", err)
	}
	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "drain@example.com"},
		WebhookURL:       srv.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("save sub: %v", err)
	}

	const total = 2*MaxMatchesPerBatch + 50
	for i := int64(1); i <= total; i++ {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin: "o", LogIndex: i, UUID: fmt.Sprintf("u%d", i),
			Subject: "drain@example.com", SubscriptionID: sub.ID,
		}); err != nil {
			t.Fatalf("save match %d: %v", i, err)
		}
	}

	// Run cycles until the backlog is empty, bounded so a regression that
	// never makes progress fails fast.
	for cycle := 0; cycle < 10; cycle++ {
		pending, err := s.ListPendingMatches(ctx)
		if err != nil {
			t.Fatalf("ListPendingMatches() error: %v", err)
		}
		if len(pending) == 0 {
			break
		}
		if err := deliverAt(ctx, newNotifier(s, "test-ua", http.DefaultClient, nil, nil), time.Now()); err != nil {
			t.Fatalf("cycle %d runOnce() error: %v", cycle, err)
		}
	}

	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("backlog never drained: %d pending remain", len(pending))
	}
	if maxBatch > MaxMatchesPerBatch {
		t.Errorf("a batch exceeded the documented cap: %d > %d", maxBatch, MaxMatchesPerBatch)
	}
	seen := make(map[int64]bool, total)
	for _, e := range delivered {
		if seen[e.LogIndex] {
			t.Errorf("log_index %d delivered more than once", e.LogIndex)
		}
		seen[e.LogIndex] = true
	}
	if len(seen) != int(total) {
		t.Errorf("expected %d unique matches delivered, got %d", total, len(seen))
	}
}

// TestSendNotifications_RetryAfterFailureCarriesFullBatch verifies that when
// a batched POST fails, every selected match stays pending and the next cycle
// reposts the full set (no quiet mutation, no dropped matches).
func TestSendNotifications_RetryAfterFailureCarriesFullBatch(t *testing.T) {
	var posted [][]int64
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p notifications.NotificationPayload
		if err := json.Unmarshal(body, &p); err != nil {
			t.Errorf("unmarshal: %v", err)
		}
		ids := make([]int64, len(p.Data.Entries))
		for i, e := range p.Data.Entries {
			ids[i] = e.LogIndex
		}
		posted = append(posted, ids)
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	ctx := context.Background()

	user := &store.User{Email: "retry@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("save user: %v", err)
	}
	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "retry@example.com"},
		WebhookURL:       srv.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("save sub: %v", err)
	}
	const n = 5
	for i := int64(1); i <= n; i++ {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin: "o", LogIndex: i, UUID: fmt.Sprintf("u%d", i),
			Subject: "retry@example.com", SubscriptionID: sub.ID,
		}); err != nil {
			t.Fatalf("save match: %v", err)
		}
	}

	// Cycle 1: failure.
	now := time.Now()
	if err := deliverAt(ctx, newNotifier(s, "test-ua", http.DefaultClient, nil, nil), now); err != nil {
		t.Fatalf("cycle 1 error: %v", err)
	}
	subs, _ := s.ListSubscriptions(ctx)
	if subs[0].ConsecutiveFailures != 1 {
		t.Fatalf("expected ConsecutiveFailures=1 after failure, got %d", subs[0].ConsecutiveFailures)
	}

	// Cycle 2: server now OK; advance past backoff.
	fail = false
	future := subs[0].NextRetryAt.Add(time.Second)
	if err := deliverAt(ctx, newNotifier(s, "test-ua", http.DefaultClient, nil, nil), future); err != nil {
		t.Fatalf("cycle 2 error: %v", err)
	}

	if len(posted) != 2 {
		t.Fatalf("expected 2 POSTs across both cycles, got %d", len(posted))
	}
	// Both POSTs must carry the same N entries — failure mustn't drop matches.
	for i, ids := range posted {
		if len(ids) != n {
			t.Errorf("POST %d carried %d entries, want %d", i+1, len(ids), n)
		}
	}
	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected 0 pending after retry success, got %d", len(pending))
	}
	subs, _ = s.ListSubscriptions(ctx)
	if subs[0].ConsecutiveFailures != 0 {
		t.Errorf("expected ConsecutiveFailures=0 after retry success, got %d", subs[0].ConsecutiveFailures)
	}
}

// TestSendNotifications_NextCycleSendsOnlyNewMatches verifies that after a
// successful cycle, the next cycle picks up only matches inserted afterwards
// — proving the `WHERE notified_at IS NULL` filter and matchIDs construction
// are correctly scoped.
func TestSendNotifications_NextCycleSendsOnlyNewMatches(t *testing.T) {
	var batches [][]int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p notifications.NotificationPayload
		if err := json.Unmarshal(body, &p); err != nil {
			t.Errorf("unmarshal: %v", err)
		}
		ids := make([]int64, len(p.Data.Entries))
		for i, e := range p.Data.Entries {
			ids[i] = e.LogIndex
		}
		batches = append(batches, ids)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	ctx := context.Background()

	user := &store.User{Email: "incremental@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("save user: %v", err)
	}
	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "incremental@example.com"},
		WebhookURL:       srv.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("save sub: %v", err)
	}

	// Cycle 1: 3 matches.
	for i := int64(1); i <= 3; i++ {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin: "o", LogIndex: i, UUID: fmt.Sprintf("u%d", i),
			Subject: "incremental@example.com", SubscriptionID: sub.ID,
		}); err != nil {
			t.Fatalf("save match: %v", err)
		}
	}
	if err := deliverAt(ctx, newNotifier(s, "test-ua", http.DefaultClient, nil, nil), time.Now()); err != nil {
		t.Fatalf("cycle 1 error: %v", err)
	}

	// Cycle 2: 2 new matches arrive after cycle 1 delivered.
	for i := int64(10); i <= 11; i++ {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin: "o", LogIndex: i, UUID: fmt.Sprintf("u%d", i),
			Subject: "incremental@example.com", SubscriptionID: sub.ID,
		}); err != nil {
			t.Fatalf("save match: %v", err)
		}
	}
	if err := deliverAt(ctx, newNotifier(s, "test-ua", http.DefaultClient, nil, nil), time.Now()); err != nil {
		t.Fatalf("cycle 2 error: %v", err)
	}

	if len(batches) != 2 {
		t.Fatalf("expected 2 POSTs, got %d", len(batches))
	}
	if len(batches[0]) != 3 {
		t.Errorf("cycle 1 should deliver 3 matches, got %d", len(batches[0]))
	}
	if len(batches[1]) != 2 {
		t.Errorf("cycle 2 should deliver only the 2 new matches, got %d", len(batches[1]))
	}
	// Cycle 2 must not include cycle-1's log indices.
	cycle1 := map[int64]bool{1: true, 2: true, 3: true}
	for _, idx := range batches[1] {
		if cycle1[idx] {
			t.Errorf("cycle 2 re-delivered already-notified log_index %d", idx)
		}
	}
}

// TestSendNotifications_BatchFailure_AllStayPending verifies that when the
// batched POST fails, no match is marked notified and the failure counter for
// the subscription increments exactly once.
func TestSendNotifications_BatchFailure_AllStayPending(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	ctx := context.Background()

	user := &store.User{Email: "batch-fail@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("save user: %v", err)
	}
	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "fail@example.com"},
		WebhookURL:       srv.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("save sub: %v", err)
	}

	const n = 5
	for i := int64(1); i <= n; i++ {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin: "o", LogIndex: i, UUID: fmt.Sprintf("u%d", i),
			Subject: "fail@example.com", SubscriptionID: sub.ID,
		}); err != nil {
			t.Fatalf("save match %d: %v", i, err)
		}
	}

	if err := deliverAt(ctx, newNotifier(s, "test-ua", http.DefaultClient, nil, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	if calls != 1 {
		t.Errorf("expected 1 webhook POST (single batch), got %d", calls)
	}
	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != n {
		t.Errorf("expected all %d matches to remain pending after batch failure, got %d", n, len(pending))
	}

	subs, err := s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatalf("ListSubscriptions() error: %v", err)
	}
	if subs[0].ConsecutiveFailures != 1 {
		t.Errorf("expected ConsecutiveFailures=1, got %d", subs[0].ConsecutiveFailures)
	}
}

// captureLogs redirects the global logger to a buffer for the duration of
// the test and returns it. The original output is restored on cleanup.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	original := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(original) })
	return &buf
}

// TestSendNotifications_RecordFailureError verifies that when
// RecordNotificationFailure itself errors, runOnce logs and
// continues without crashing — and that the auto-disable check is
// skipped (the else-if would otherwise read a stale newCount of 0).
func TestSendNotifications_RecordFailureError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	insertSubAndMatch(t, s, srv.URL)

	logs := captureLogs(t)
	fs := &faultyStore{Store: s, recordFailureErr: errors.New("boom: db down")}

	if err := deliverAt(context.Background(), newNotifier(fs, "test-ua", http.DefaultClient, nil, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	if fs.recordFailureCalls != 1 {
		t.Errorf("expected RecordNotificationFailure called once, got %d", fs.recordFailureCalls)
	}
	if fs.setEnabledCalls != 0 {
		t.Errorf("auto-disable must be skipped when RecordNotificationFailure errors, got %d calls", fs.setEnabledCalls)
	}
	if !strings.Contains(logs.String(), "Failed to record notification failure") {
		t.Errorf("expected log to surface the record-failure error, got: %s", logs.String())
	}
}

// TestSendNotifications_AutoDisableError verifies that when the
// auto-disable call fails, runOnce logs the error and
// continues. The subscription remains active (DisabledAt nil) AND is
// still eligible for retry on the next cycle — a regression that
// gated additional behavior on ConsecutiveFailures >= threshold would
// silently skip the retry.
func TestSendNotifications_AutoDisableError(t *testing.T) {
	webhookOK := false
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if webhookOK {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	s := setupTestStore(t)
	ctx := context.Background()

	user := &store.User{Email: "auto-disable-err@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "user@example.com"},
		WebhookURL:       srv.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	// Pre-load failures so the next failure trips the auto-disable threshold.
	pastRetry := time.Now().Add(-time.Hour)
	for i := 0; i < notificationMaxConsecutiveFailures-1; i++ {
		if _, err := s.RecordNotificationFailure(ctx, sub.ID, time.Now(), pastRetry); err != nil {
			t.Fatalf("seed RecordNotificationFailure error: %v", err)
		}
	}
	if err := s.SaveMatch(ctx, &store.Match{
		Origin: "o", LogIndex: 1, UUID: "u1",
		Subject: "user@example.com", SubscriptionID: sub.ID,
	}); err != nil {
		t.Fatalf("failed to save match: %v", err)
	}

	logs := captureLogs(t)
	fs := &faultyStore{Store: s, setEnabledErr: errors.New("boom: cannot disable")}

	now := time.Now()
	if err := deliverAt(ctx, newNotifier(fs, "test-ua", http.DefaultClient, nil, nil), now); err != nil {
		t.Fatalf("first runOnce() error: %v", err)
	}

	if fs.setEnabledCalls != 1 {
		t.Errorf("expected SetSubscriptionEnabled called once, got %d", fs.setEnabledCalls)
	}
	subs, _ := s.ListSubscriptions(ctx)
	if subs[0].DisabledAt != nil {
		t.Error("subscription must not appear disabled when SetSubscriptionEnabled failed")
	}
	if subs[0].ConsecutiveFailures != notificationMaxConsecutiveFailures {
		t.Errorf("expected ConsecutiveFailures %d, got %d", notificationMaxConsecutiveFailures, subs[0].ConsecutiveFailures)
	}
	if !strings.Contains(logs.String(), "Failed to disable subscription") {
		t.Errorf("expected log to surface the disable error, got: %s", logs.String())
	}

	// Second cycle: webhook now succeeds. Clear the disable error and
	// advance time past the freshly-recorded backoff window. The match
	// must be retried — proving that a transient disable-store failure
	// doesn't strand the subscription. A regression that started gating
	// delivery on ConsecutiveFailures >= threshold would skip this call.
	fs.setEnabledErr = nil
	webhookOK = true
	callsBefore := calls
	future := subs[0].NextRetryAt.Add(time.Second)
	if err := deliverAt(ctx, newNotifier(fs, "test-ua", http.DefaultClient, nil, nil), future); err != nil {
		t.Fatalf("second runOnce() error: %v", err)
	}

	if calls != callsBefore+1 {
		t.Errorf("expected 1 retry attempt on next cycle, got %d new calls", calls-callsBefore)
	}
	subs, _ = s.ListSubscriptions(ctx)
	if subs[0].ConsecutiveFailures != 0 {
		t.Errorf("expected ConsecutiveFailures reset to 0 after retry success, got %d", subs[0].ConsecutiveFailures)
	}
}

// TestSendNotifications_MarkNotifiedError verifies that when
// MarkMatchesNotified errors, runOnce logs the error and still
// records the cycle as a success (the webhook delivery succeeded — the
// consumer received the batch). Pre-seeded failures + RecordNotificationSuccess
// counter guard against a regression that gates the success-reset on a
// clean MarkMatchesNotified.
func TestSendNotifications_MarkNotifiedError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := setupTestStore(t)
	ctx := context.Background()

	user := &store.User{Email: "mark-err@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "user@example.com"},
		WebhookURL:       srv.URL,
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	// Pre-seed failures so a successful cycle reset is observable.
	pastRetry := time.Now().Add(-time.Hour)
	for i := 0; i < 3; i++ {
		if _, err := s.RecordNotificationFailure(ctx, sub.ID, time.Now(), pastRetry); err != nil {
			t.Fatalf("seed RecordNotificationFailure error: %v", err)
		}
	}

	// Two matches for the same subscription. Both must remain pending
	// because the single bulk MarkMatchesNotified errored.
	for i := int64(1); i <= 2; i++ {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin: "o", LogIndex: i, UUID: fmt.Sprintf("u%d", i),
			Subject: "user@example.com", SubscriptionID: sub.ID,
		}); err != nil {
			t.Fatalf("failed to save match %d: %v", i, err)
		}
	}

	logs := captureLogs(t)
	fs := &faultyStore{Store: s, markNotifiedErr: errors.New("boom: mark failed")}

	if err := deliverAt(ctx, newNotifier(fs, "test-ua", http.DefaultClient, nil, nil), time.Now()); err != nil {
		t.Fatalf("runOnce() error: %v", err)
	}

	if calls != 1 {
		t.Errorf("expected 1 webhook call (single batched POST), got %d", calls)
	}
	if fs.markNotifiedCalls != 1 {
		t.Errorf("expected MarkMatchesNotified called once with the batch, got %d calls", fs.markNotifiedCalls)
	}
	if len(fs.markNotifiedIDs) != 2 {
		t.Errorf("expected MarkMatchesNotified called with 2 IDs, got %d", len(fs.markNotifiedIDs))
	}
	if fs.recordSuccessCalls != 1 {
		t.Errorf("expected RecordNotificationSuccess called once (batch delivered despite mark error), got %d", fs.recordSuccessCalls)
	}
	if !strings.Contains(logs.String(), "Failed to mark") {
		t.Errorf("expected log to surface the mark-notified error, got: %s", logs.String())
	}

	// Failure counters were reset because the batch delivered — the
	// success-reset gate fires even when MarkMatchesNotified errored.
	subs, _ := s.ListSubscriptions(ctx)
	if subs[0].ConsecutiveFailures != 0 {
		t.Errorf("expected ConsecutiveFailures reset to 0 after successful batch, got %d", subs[0].ConsecutiveFailures)
	}

	// Both matches remain pending because the bulk mark failed.
	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 2 {
		t.Errorf("expected both matches to remain pending after MarkMatchesNotified error, got %d", len(pending))
	}
}

// mockNotifEmailSender records emails sent by runOnce.
type mockNotifEmailSender struct {
	sent []mockNotifEmail
	err  error // if non-nil, Send returns this error
}

type mockNotifEmail struct {
	To      string
	Subject string
	Body    string
}

func (m *mockNotifEmailSender) Send(_ context.Context, to, subject, body string) error {
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, mockNotifEmail{To: to, Subject: subject, Body: body})
	return nil
}
