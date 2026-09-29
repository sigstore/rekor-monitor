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

package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/store"
	"github.com/transparency-dev/formats/log"
)

// createTestSubscription creates a user and subscription for tests that need a valid subscription_id.
func createTestSubscription(ctx context.Context, t *testing.T, s *Store) (subID, userID int64) {
	t.Helper()
	user := &store.User{Email: "test@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	sub := &store.Subscription{
		UserID: user.ID,
		MonitoredValue: identity.CertIdentityValue{
			CertSubject: "test@example.com",
			Issuers:     []string{"https://accounts.google.com"},
		},
		WebhookURL:       "https://hooks.example.com/notify",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to create test subscription: %v", err)
	}
	return sub.ID, user.ID
}

func TestNewStore_InMemory(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create in-memory store: %v", err)
	}
	defer s.Close()
}

func TestNewStore_File(t *testing.T) {
	ctx := context.Background()

	// Create a temp directory for the database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("failed to create file-based store: %v", err)
	}
	defer s.Close()

	// Check that the file was created
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("database file was not created")
	}
}

func TestNewStore_EnablesForeignKeysOnEveryConnection(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")

	s, err := NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	s.db.SetMaxOpenConns(2)

	conn1, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatalf("failed to get first connection: %v", err)
	}
	defer conn1.Close()

	conn2, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatalf("failed to get second connection: %v", err)
	}
	defer conn2.Close()

	for i, conn := range []*sql.Conn{conn1, conn2} {
		var foreignKeys int
		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			t.Fatalf("failed to query foreign_keys on connection %d: %v", i+1, err)
		}
		if foreignKeys != 1 {
			t.Errorf("connection %d foreign_keys = %d, want 1", i+1, foreignKeys)
		}
	}
}

func TestLoadCheckpoint_NotFound(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	// Loading a non-existent checkpoint should return nil, nil
	checkpoint, err := s.LoadCheckpoint(ctx, "nonexistent-origin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checkpoint != nil {
		t.Error("expected nil checkpoint for non-existent origin")
	}
}

func TestHasAnyCheckpoint(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	// An empty store has no checkpoints: a fresh deploy, not a rollover.
	has, err := s.HasAnyCheckpoint(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Error("expected HasAnyCheckpoint to be false on an empty store")
	}

	if err := s.SaveCheckpoint(ctx, &log.Checkpoint{Origin: "some-origin", Size: 1, Hash: []byte{0x01}}); err != nil {
		t.Fatalf("failed to save checkpoint: %v", err)
	}

	// Once any origin has a checkpoint, a never-seen origin must be treated
	// as a rollover rather than a first-time deploy.
	has, err = s.HasAnyCheckpoint(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !has {
		t.Error("expected HasAnyCheckpoint to be true after saving a checkpoint")
	}
}

func TestSaveAndLoadCheckpoint(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	origin := "log2025-alpha3.rekor.sigstage.dev/api/v2"
	testHash := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Save a checkpoint
	checkpoint := &log.Checkpoint{
		Origin: origin,
		Size:   1000,
		Hash:   testHash,
	}

	if err := s.SaveCheckpoint(ctx, checkpoint); err != nil {
		t.Fatalf("failed to save checkpoint: %v", err)
	}

	// Load the checkpoint
	loaded, err := s.LoadCheckpoint(ctx, origin)
	if err != nil {
		t.Fatalf("failed to load checkpoint: %v", err)
	}
	if loaded == nil {
		t.Fatal("loaded checkpoint is nil")
	}

	// Verify the data
	if loaded.Origin != origin {
		t.Errorf("origin mismatch: got %s, want %s", loaded.Origin, origin)
	}
	if loaded.Size != 1000 {
		t.Errorf("size mismatch: got %d, want %d", loaded.Size, 1000)
	}
	if !bytes.Equal(loaded.Hash, testHash) {
		t.Errorf("hash mismatch: got %x, want %x", loaded.Hash, testHash)
	}
}

func TestSaveCheckpoint_Update(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	origin := "test-origin"
	hash1 := []byte{0x01, 0x02, 0x03}
	hash2 := []byte{0x04, 0x05, 0x06}

	// Save initial checkpoint
	checkpoint1 := &log.Checkpoint{
		Origin: origin,
		Size:   100,
		Hash:   hash1,
	}
	if err := s.SaveCheckpoint(ctx, checkpoint1); err != nil {
		t.Fatalf("failed to save initial checkpoint: %v", err)
	}

	// Update the checkpoint
	checkpoint2 := &log.Checkpoint{
		Origin: origin,
		Size:   200,
		Hash:   hash2,
	}
	if err := s.SaveCheckpoint(ctx, checkpoint2); err != nil {
		t.Fatalf("failed to update checkpoint: %v", err)
	}

	// Load and verify the updated checkpoint
	loaded, err := s.LoadCheckpoint(ctx, origin)
	if err != nil {
		t.Fatalf("failed to load checkpoint: %v", err)
	}

	if loaded.Size != 200 {
		t.Errorf("size mismatch after update: got %d, want %d", loaded.Size, 200)
	}
	if !bytes.Equal(loaded.Hash, hash2) {
		t.Errorf("hash mismatch after update: got %x, want %x", loaded.Hash, hash2)
	}
}

func TestMultipleOrigins(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	// Save checkpoints for different origins
	origins := []string{"origin1", "origin2", "origin3"}
	for i, origin := range origins {
		checkpoint := &log.Checkpoint{
			Origin: origin,
			Size:   uint64(i * 100),
			Hash:   []byte{byte(i)},
		}
		if err := s.SaveCheckpoint(ctx, checkpoint); err != nil {
			t.Fatalf("failed to save checkpoint for %s: %v", origin, err)
		}
	}

	// Load and verify each origin
	for i, origin := range origins {
		loaded, err := s.LoadCheckpoint(ctx, origin)
		if err != nil {
			t.Fatalf("failed to load checkpoint for %s: %v", origin, err)
		}
		if loaded == nil {
			t.Fatalf("checkpoint for %s is nil", origin)
		}
		if loaded.Size != uint64(i*100) {
			t.Errorf("size mismatch for %s: got %d, want %d", origin, loaded.Size, i*100)
		}
	}
}

func TestPersistenceAcrossRestart(t *testing.T) {
	ctx := context.Background()

	// Create a temp directory for the database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "persist.db")

	origin := "persist-test-origin"
	hash := []byte{0xde, 0xad, 0xbe, 0xef}

	// First "run": create store, save checkpoint, close
	{
		s, err := NewStore(ctx, dbPath)
		if err != nil {
			t.Fatalf("failed to create store (first run): %v", err)
		}

		checkpoint := &log.Checkpoint{
			Origin: origin,
			Size:   5000,
			Hash:   hash,
		}
		if err := s.SaveCheckpoint(ctx, checkpoint); err != nil {
			t.Fatalf("failed to save checkpoint: %v", err)
		}

		if err := s.Close(); err != nil {
			t.Fatalf("failed to close store: %v", err)
		}
	}

	// Second "run": open store, verify checkpoint exists
	{
		s, err := NewStore(ctx, dbPath)
		if err != nil {
			t.Fatalf("failed to create store (second run): %v", err)
		}
		defer s.Close()

		loaded, err := s.LoadCheckpoint(ctx, origin)
		if err != nil {
			t.Fatalf("failed to load checkpoint: %v", err)
		}
		if loaded == nil {
			t.Fatal("checkpoint not persisted across restart")
		}

		if loaded.Size != 5000 {
			t.Errorf("size mismatch after restart: got %d, want %d", loaded.Size, 5000)
		}
		if !bytes.Equal(loaded.Hash, hash) {
			t.Errorf("hash mismatch after restart: got %x, want %x", loaded.Hash, hash)
		}
	}
}

// Match CRUD tests

func TestTransaction_CommitSuccess(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	subID, userID := createTestSubscription(ctx, t, s)
	origin := "tx-test-origin"

	// Start transaction
	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}

	// Save matches within transaction
	matches := []*store.Match{
		{
			Origin:         origin,
			LogIndex:       100,
			UUID:           "uuid-1",
			CertSubject:    "user1@example.com",
			SubscriptionID: subID,
		},
		{
			Origin:         origin,
			LogIndex:       101,
			UUID:           "uuid-2",
			CertSubject:    "user2@example.com",
			SubscriptionID: subID,
		},
	}

	for _, match := range matches {
		if err := tx.SaveMatch(ctx, match); err != nil {
			tx.Rollback()
			t.Fatalf("failed to save match: %v", err)
		}
	}

	// Save checkpoint within transaction
	checkpoint := &log.Checkpoint{
		Origin: origin,
		Size:   1000,
		Hash:   []byte{0x01, 0x02, 0x03},
	}
	if err := tx.SaveCheckpoint(ctx, checkpoint); err != nil {
		tx.Rollback()
		t.Fatalf("failed to save checkpoint: %v", err)
	}

	// Commit
	if err := tx.Commit(); err != nil {
		t.Fatalf("failed to commit: %v", err)
	}

	// Verify checkpoint was saved
	loadedCheckpoint, err := s.LoadCheckpoint(ctx, origin)
	if err != nil {
		t.Fatalf("failed to load checkpoint: %v", err)
	}
	if loadedCheckpoint == nil {
		t.Fatal("checkpoint not saved")
	}
	if loadedCheckpoint.Size != 1000 {
		t.Errorf("checkpoint size mismatch: got %d, want %d", loadedCheckpoint.Size, 1000)
	}

	// Verify all matches were saved
	allMatches, err := s.ListMatchesWithSubByUser(ctx, userID)
	if err != nil {
		t.Fatalf("failed to list matches: %v", err)
	}
	if len(allMatches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(allMatches))
	}
}

func TestTransaction_RollbackOnError(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	subID, userID := createTestSubscription(ctx, t, s)
	origin := "tx-rollback-origin"

	// Start transaction
	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}

	// Save a match
	match := &store.Match{
		Origin:         origin,
		LogIndex:       200,
		UUID:           "uuid-rollback",
		SubscriptionID: subID,
	}
	if err := tx.SaveMatch(ctx, match); err != nil {
		tx.Rollback()
		t.Fatalf("failed to save match: %v", err)
	}

	// Rollback instead of commit
	if err := tx.Rollback(); err != nil {
		t.Fatalf("failed to rollback: %v", err)
	}

	// Verify match was NOT saved
	allMatches, err := s.ListMatchesWithSubByUser(ctx, userID)
	if err != nil {
		t.Fatalf("failed to list matches: %v", err)
	}
	if len(allMatches) != 0 {
		t.Errorf("expected 0 matches after rollback, got %d", len(allMatches))
	}
}

func TestTransaction_ReadWithinTransaction(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	origin := "tx-read-origin"

	// Start transaction
	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}

	// Save checkpoint within transaction
	checkpoint := &log.Checkpoint{
		Origin: origin,
		Size:   500,
		Hash:   []byte{0xaa, 0xbb},
	}
	if err := tx.SaveCheckpoint(ctx, checkpoint); err != nil {
		tx.Rollback()
		t.Fatalf("failed to save checkpoint: %v", err)
	}

	// Read within same transaction - should see uncommitted data
	loaded, err := tx.LoadCheckpoint(ctx, origin)
	if err != nil {
		tx.Rollback()
		t.Fatalf("failed to load checkpoint within tx: %v", err)
	}
	if loaded == nil {
		tx.Rollback()
		t.Fatal("checkpoint not visible within transaction")
	}
	if loaded.Size != 500 {
		t.Errorf("checkpoint size mismatch within tx: got %d, want %d", loaded.Size, 500)
	}

	// Commit
	if err := tx.Commit(); err != nil {
		t.Fatalf("failed to commit: %v", err)
	}
}

// User tests

func TestSaveUser(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "alice@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	if user.ID == 0 {
		t.Error("expected non-zero ID after save")
	}

	got, err := s.GetUserByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("failed to get user by email: %v", err)
	}
	if got == nil {
		t.Fatal("expected user, got nil")
	}
	if got.ID != user.ID {
		t.Errorf("ID mismatch: got %d, want %d", got.ID, user.ID)
	}
	if got.Email != "alice@example.com" {
		t.Errorf("email mismatch: got %s, want alice@example.com", got.Email)
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

func TestSaveUser_DuplicateEmail(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user1 := &store.User{Email: "dup@example.com"}
	if err := s.SaveUser(ctx, user1); err != nil {
		t.Fatalf("failed to save first user: %v", err)
	}

	user2 := &store.User{Email: "dup@example.com"}
	if err := s.SaveUser(ctx, user2); err == nil {
		t.Fatal("expected error saving duplicate email, got nil")
	}
}

func TestGetUserByEmail_NotFound(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	got, err := s.GetUserByEmail(ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil user, got %+v", got)
	}
}

// Subscription tests

func TestSaveSubscription(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "sub@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	sub := &store.Subscription{
		UserID: user.ID,
		Name:   "My subscription",
		MonitoredValue: identity.CertIdentityValue{
			CertSubject: "user@example.com",
			Issuers:     []string{"https://accounts.google.com"},
		},
		WebhookURL:       "https://hooks.example.com/notify",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}
	if sub.ID == 0 {
		t.Error("expected non-zero ID after save")
	}

	subs, err := s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatalf("failed to list subscriptions: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 subscription, got %d", len(subs))
	}

	got := subs[0]
	if got.ID != sub.ID {
		t.Errorf("ID mismatch: got %d, want %d", got.ID, sub.ID)
	}
	if got.UserID != user.ID {
		t.Errorf("UserID mismatch: got %d, want %d", got.UserID, user.ID)
	}
	if got.Name != "My subscription" {
		t.Errorf("Name mismatch: got %q, want %q", got.Name, "My subscription")
	}
	if got.WebhookURL != "https://hooks.example.com/notify" {
		t.Errorf("WebhookURL mismatch: got %s", got.WebhookURL)
	}
	if got.NotificationType != store.NotificationTypeWebhook {
		t.Errorf("NotificationType: got %q, want %q", got.NotificationType, store.NotificationTypeWebhook)
	}

	certID, ok := got.MonitoredValue.(identity.CertIdentityValue)
	if !ok {
		t.Fatalf("expected CertIdentityValue, got %T", got.MonitoredValue)
	}
	if certID.CertSubject != "user@example.com" {
		t.Errorf("CertSubject mismatch: got %s", certID.CertSubject)
	}
	if len(certID.Issuers) != 1 || certID.Issuers[0] != "https://accounts.google.com" {
		t.Errorf("Issuers mismatch: got %v", certID.Issuers)
	}
}

func TestSaveSubscription_DifferentValueTypes(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "types@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	values := []identity.MonitoredValue{
		identity.CertIdentityValue{
			CertSubject: "cert@example.com",
			Issuers:     []string{"https://issuer.example.com"},
		},
		identity.FingerprintValue{
			Fingerprint: "DEADBEEF",
		},
		identity.SubjectValue{
			Subject: "subject@example.com",
		},
	}

	for i, mv := range values {
		sub := &store.Subscription{
			UserID:           user.ID,
			Name:             fmt.Sprintf("sub-%d", i),
			MonitoredValue:   mv,
			WebhookURL:       "https://hooks.example.com/notify",
			NotificationType: store.NotificationTypeWebhook,
		}
		if err := s.SaveSubscription(ctx, sub); err != nil {
			t.Fatalf("failed to save subscription (type %s): %v", mv.Type(), err)
		}
	}

	subs, err := s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatalf("failed to list subscriptions: %v", err)
	}
	if len(subs) != 3 {
		t.Fatalf("expected 3 subscriptions, got %d", len(subs))
	}

	// ListSubscriptions returns ORDER BY created_at DESC, so reverse order
	typesSeen := map[identity.MatchedIdentityType]bool{}
	for _, sub := range subs {
		typesSeen[sub.MonitoredValue.Type()] = true
	}

	for _, expectedType := range []identity.MatchedIdentityType{
		identity.MatchedIdentityTypeCertIdentity,
		identity.MatchedIdentityTypeFingerprint,
		identity.MatchedIdentityTypeSubject,
	} {
		if !typesSeen[expectedType] {
			t.Errorf("missing subscription type: %s", expectedType)
		}
	}
}

func TestSaveSubscription_InvalidMonitoredValue(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "invalid@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.CertIdentityValue{CertSubject: ""},
		WebhookURL:       "https://hooks.example.com/notify",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err == nil {
		t.Fatal("expected error for invalid monitored value, got nil")
	}
}

func TestSaveSubscription_NonExistentUser(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	sub := &store.Subscription{
		UserID: 9999,
		MonitoredValue: identity.CertIdentityValue{
			CertSubject: "orphan@example.com",
		},
		WebhookURL:       "https://hooks.example.com/notify",
		NotificationType: store.NotificationTypeWebhook,
	}
	err = s.SaveSubscription(ctx, sub)

	if err == nil {
		t.Fatal("expected foreign key error for non-existent user, got nil")
	}
	if !strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
		t.Fatalf("expected foreign key constraint error, got: %v", err)
	}
}

// TestSaveSubscription_RejectsUnknownNotificationType pins the DB CHECK
// as the sole gatekeeper for valid channel values now that the Go-side
// Subscription.Verify() helper is gone.
func TestSaveSubscription_RejectsUnknownNotificationType(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "badtype@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	sub := &store.Subscription{
		UserID: user.ID,
		MonitoredValue: identity.CertIdentityValue{
			CertSubject: "user@example.com",
			Issuers:     []string{"https://accounts.google.com"},
		},
		WebhookURL:       "https://hooks.example.com/notify",
		NotificationType: "sms",
	}
	if err := s.SaveSubscription(ctx, sub); err == nil {
		t.Fatal("expected DB CHECK to reject unknown notification type, got nil")
	}
}

func TestSaveSubscription_RejectsEmptyNotificationType(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "emptytype@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	sub := &store.Subscription{
		UserID: user.ID,
		MonitoredValue: identity.CertIdentityValue{
			CertSubject: "user@example.com",
			Issuers:     []string{"https://accounts.google.com"},
		},
		WebhookURL: "https://hooks.example.com/notify",
	}
	if err := s.SaveSubscription(ctx, sub); err == nil {
		t.Fatal("expected save to reject empty notification type, got nil")
	}
}

func TestSaveSubscription_DuplicateName(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "dupname@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	first := &store.Subscription{
		UserID:           user.ID,
		Name:             "My monitor",
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "AAA"},
		WebhookURL:       "https://hooks.example.com/1",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, first); err != nil {
		t.Fatalf("failed to save first subscription: %v", err)
	}

	dup := &store.Subscription{
		UserID:           user.ID,
		Name:             "My monitor",
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "BBB"},
		WebhookURL:       "https://hooks.example.com/2",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, dup); !errors.Is(err, store.ErrDuplicateName) {
		t.Fatalf("expected ErrDuplicateName, got %v", err)
	}

	// The same name is allowed for a different user.
	other := &store.User{Email: "other-dupname@example.com"}
	if err := s.SaveUser(ctx, other); err != nil {
		t.Fatalf("failed to save other user: %v", err)
	}
	otherSub := &store.Subscription{
		UserID:           other.ID,
		Name:             "My monitor",
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "CCC"},
		WebhookURL:       "https://hooks.example.com/3",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, otherSub); err != nil {
		t.Fatalf("same name for a different user should be allowed, got %v", err)
	}
}

// UpdateSubscription tests

func TestUpdateSubscription(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "update@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	sub := &store.Subscription{
		UserID: user.ID,
		MonitoredValue: identity.CertIdentityValue{
			CertSubject: "original@example.com",
			Issuers:     []string{"https://accounts.google.com"},
		},
		WebhookURL:       "https://hooks.example.com/original",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	sub.MonitoredValue = identity.FingerprintValue{Fingerprint: "NEWFINGERPRINT"}
	sub.WebhookURL = "https://hooks.example.com/updated"
	if err := s.UpdateSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to update subscription: %v", err)
	}

	subs, err := s.ListSubscriptionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to list subscriptions: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 subscription, got %d", len(subs))
	}

	got := subs[0]
	if got.WebhookURL != "https://hooks.example.com/updated" {
		t.Errorf("WebhookURL not updated: got %s", got.WebhookURL)
	}
	if got.NotificationType != store.NotificationTypeWebhook {
		t.Errorf("NotificationType: got %q, want %q", got.NotificationType, store.NotificationTypeWebhook)
	}
	fp, ok := got.MonitoredValue.(identity.FingerprintValue)
	if !ok {
		t.Fatalf("expected FingerprintValue, got %T", got.MonitoredValue)
	}
	if fp.Fingerprint != "NEWFINGERPRINT" {
		t.Errorf("Fingerprint not updated: got %s", fp.Fingerprint)
	}
}

func TestUpdateSubscription_NotOwned(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	userA := &store.User{Email: "ownerA@example.com"}
	userB := &store.User{Email: "ownerB@example.com"}
	if err := s.SaveUser(ctx, userA); err != nil {
		t.Fatalf("failed to save userA: %v", err)
	}
	if err := s.SaveUser(ctx, userB); err != nil {
		t.Fatalf("failed to save userB: %v", err)
	}

	sub := &store.Subscription{
		UserID: userA.ID,
		MonitoredValue: identity.CertIdentityValue{
			CertSubject: "a@example.com",
			Issuers:     []string{"https://accounts.google.com"},
		},
		WebhookURL:       "https://hooks.example.com/a",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	sub.UserID = userB.ID
	sub.WebhookURL = "https://hooks.example.com/hijacked"
	err = s.UpdateSubscription(ctx, sub)
	if err == nil {
		t.Fatal("expected error updating subscription not owned by user, got nil")
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestUpdateSubscription_NotFound(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "notfound@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	sub := &store.Subscription{
		ID:     9999,
		UserID: user.ID,
		MonitoredValue: identity.FingerprintValue{
			Fingerprint: "DEADBEEF",
		},
		WebhookURL:       "https://hooks.example.com/nope",
		NotificationType: store.NotificationTypeWebhook,
	}
	err = s.UpdateSubscription(ctx, sub)
	if err == nil {
		t.Fatal("expected error updating non-existent subscription, got nil")
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestUpdateSubscription_DuplicateName(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "update-dupname@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	first := &store.Subscription{
		UserID:           user.ID,
		Name:             "first",
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "AAA"},
		WebhookURL:       "https://hooks.example.com/1",
		NotificationType: store.NotificationTypeWebhook,
	}
	second := &store.Subscription{
		UserID:           user.ID,
		Name:             "second",
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "BBB"},
		WebhookURL:       "https://hooks.example.com/2",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, first); err != nil {
		t.Fatalf("failed to save first subscription: %v", err)
	}
	if err := s.SaveSubscription(ctx, second); err != nil {
		t.Fatalf("failed to save second subscription: %v", err)
	}

	// Renaming "second" onto "first"'s name must collide.
	second.Name = "first"
	if err := s.UpdateSubscription(ctx, second); !errors.Is(err, store.ErrDuplicateName) {
		t.Fatalf("expected ErrDuplicateName, got %v", err)
	}

	// Updating a subscription while keeping its own name must succeed.
	first.WebhookURL = "https://hooks.example.com/1-updated"
	if err := s.UpdateSubscription(ctx, first); err != nil {
		t.Fatalf("update keeping own name should succeed, got %v", err)
	}
}

// DeleteSubscription tests

func TestDeleteSubscription(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "del@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "DEADBEEF"},
		WebhookURL:       "https://hooks.example.com/del",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	if err := s.DeleteSubscription(ctx, sub.ID, user.ID); err != nil {
		t.Fatalf("failed to delete subscription: %v", err)
	}

	subs, err := s.ListSubscriptionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to list subscriptions: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("expected 0 subscriptions, got %d", len(subs))
	}
}

func TestDeleteSubscription_NotOwned(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	owner := &store.User{Email: "owner-del@example.com"}
	if err := s.SaveUser(ctx, owner); err != nil {
		t.Fatalf("failed to save owner: %v", err)
	}

	other := &store.User{Email: "other-del@example.com"}
	if err := s.SaveUser(ctx, other); err != nil {
		t.Fatalf("failed to save other user: %v", err)
	}

	sub := &store.Subscription{
		UserID:           owner.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "OWNED"},
		WebhookURL:       "https://hooks.example.com/owned",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	err = s.DeleteSubscription(ctx, sub.ID, other.ID)
	if err == nil {
		t.Fatal("expected error deleting unowned subscription, got nil")
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestDeleteSubscription_NotFound(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "del-nf@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	err = s.DeleteSubscription(ctx, 9999, user.ID)
	if err == nil {
		t.Fatal("expected error deleting non-existent subscription, got nil")
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// GetUserByID tests

func TestGetUserByID(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "byid@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	got, err := s.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to get user by ID: %v", err)
	}
	if got == nil {
		t.Fatal("expected user, got nil")
	}
	if got.Email != "byid@example.com" {
		t.Errorf("email mismatch: got %s, want byid@example.com", got.Email)
	}
}

func TestGetUserByID_NotFound(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	got, err := s.GetUserByID(ctx, 9999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil user, got %+v", got)
	}
}

// User-scoped query tests

func TestListSubscriptionsByUser(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user1 := &store.User{Email: "subs1@example.com"}
	user2 := &store.User{Email: "subs2@example.com"}
	if err := s.SaveUser(ctx, user1); err != nil {
		t.Fatalf("failed to save user1: %v", err)
	}
	if err := s.SaveUser(ctx, user2); err != nil {
		t.Fatalf("failed to save user2: %v", err)
	}

	sub1 := &store.Subscription{
		UserID:           user1.ID,
		MonitoredValue:   identity.CertIdentityValue{CertSubject: "s1@example.com", Issuers: []string{"https://issuer.example.com"}},
		WebhookURL:       "https://hooks.example.com/1",
		NotificationType: store.NotificationTypeWebhook,
	}
	sub2 := &store.Subscription{
		UserID:           user2.ID,
		MonitoredValue:   identity.CertIdentityValue{CertSubject: "s2@example.com", Issuers: []string{"https://issuer.example.com"}},
		WebhookURL:       "https://hooks.example.com/2",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub1); err != nil {
		t.Fatalf("failed to save sub1: %v", err)
	}
	if err := s.SaveSubscription(ctx, sub2); err != nil {
		t.Fatalf("failed to save sub2: %v", err)
	}

	// User1 should see only their subscription
	subs1, err := s.ListSubscriptionsByUser(ctx, user1.ID)
	if err != nil {
		t.Fatalf("failed to list subs for user1: %v", err)
	}
	if len(subs1) != 1 {
		t.Errorf("user1: expected 1 subscription, got %d", len(subs1))
	}

	// User2 should see only their subscription
	subs2, err := s.ListSubscriptionsByUser(ctx, user2.ID)
	if err != nil {
		t.Fatalf("failed to list subs for user2: %v", err)
	}
	if len(subs2) != 1 {
		t.Errorf("user2: expected 1 subscription, got %d", len(subs2))
	}
}

func TestCountSubscriptionsByUser_emptyReturnsZero(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "empty@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	count, err := s.CountSubscriptionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountSubscriptionsByUser() error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestCountSubscriptionsByUser_countsOnlyOwnedByUser(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	owner := &store.User{Email: "owner@example.com"}
	other := &store.User{Email: "other@example.com"}
	if err := s.SaveUser(ctx, owner); err != nil {
		t.Fatalf("failed to save owner: %v", err)
	}
	if err := s.SaveUser(ctx, other); err != nil {
		t.Fatalf("failed to save other: %v", err)
	}

	for i, mv := range []identity.MonitoredValue{
		identity.FingerprintValue{Fingerprint: "AAA"},
		identity.FingerprintValue{Fingerprint: "BBB"},
	} {
		ownerSub := &store.Subscription{
			UserID:           owner.ID,
			Name:             fmt.Sprintf("owner-%d", i),
			MonitoredValue:   mv,
			WebhookURL:       fmt.Sprintf("https://hooks.example.com/owner-%d", i),
			NotificationType: store.NotificationTypeWebhook,
		}
		if err := s.SaveSubscription(ctx, ownerSub); err != nil {
			t.Fatalf("failed to save owner sub %d: %v", i, err)
		}
	}
	otherSub := &store.Subscription{
		UserID:           other.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "CCC"},
		WebhookURL:       "https://hooks.example.com/other",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, otherSub); err != nil {
		t.Fatalf("failed to save other sub: %v", err)
	}

	count, err := s.CountSubscriptionsByUser(ctx, owner.ID)
	if err != nil {
		t.Fatalf("CountSubscriptionsByUser() error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 for owner, got %d", count)
	}
}

func TestCountSubscriptionsByUser_includesDisabled(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "mixed@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	active := &store.Subscription{
		UserID:           user.ID,
		Name:             "active",
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "ACT"},
		WebhookURL:       "https://hooks.example.com/active",
		NotificationType: store.NotificationTypeWebhook,
	}
	disabled := &store.Subscription{
		UserID:           user.ID,
		Name:             "disabled",
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "DIS"},
		WebhookURL:       "https://hooks.example.com/disabled",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, active); err != nil {
		t.Fatalf("failed to save active sub: %v", err)
	}
	if err := s.SaveSubscription(ctx, disabled); err != nil {
		t.Fatalf("failed to save disabled sub: %v", err)
	}
	if err := s.SetSubscriptionEnabled(ctx, disabled.ID, user.ID, false); err != nil {
		t.Fatalf("failed to disable sub: %v", err)
	}

	count, err := s.CountSubscriptionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountSubscriptionsByUser() error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 (active + disabled), got %d", count)
	}
}

// Auth token tests

func TestCreateAndConsumeAuthToken(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	token := &store.AuthToken{
		Email:     "token@example.com",
		TokenHash: "test-token-abc123",
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
	}
	if err := s.CreateAuthToken(ctx, token); err != nil {
		t.Fatalf("failed to create auth token: %v", err)
	}
	if token.ID == 0 {
		t.Error("expected non-zero ID after create")
	}

	consumed, err := s.ConsumeAuthToken(ctx, "test-token-abc123")
	if err != nil {
		t.Fatalf("failed to consume auth token: %v", err)
	}
	if consumed == nil {
		t.Fatal("expected consumed token, got nil")
	}
	if consumed.Email != "token@example.com" {
		t.Errorf(
			"email mismatch: got %s, want token@example.com",
			consumed.Email,
		)
	}
}

func TestConsumeAuthToken_AlreadyUsed(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	token := &store.AuthToken{
		Email:     "reuse@example.com",
		TokenHash: "reuse-token",
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
	}
	if err := s.CreateAuthToken(ctx, token); err != nil {
		t.Fatalf("failed to create auth token: %v", err)
	}

	// First consume should succeed
	consumed, err := s.ConsumeAuthToken(ctx, "reuse-token")
	if err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if consumed == nil {
		t.Fatal("expected consumed token, got nil")
	}

	// Second consume should return nil (already used)
	consumed2, err := s.ConsumeAuthToken(ctx, "reuse-token")
	if err != nil {
		t.Fatalf("second consume failed: %v", err)
	}
	if consumed2 != nil {
		t.Error("expected nil for already-used token")
	}
}

func TestConsumeAuthToken_Expired(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	token := &store.AuthToken{
		Email:     "expired@example.com",
		TokenHash: "expired-token",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Minute),
	}
	if err := s.CreateAuthToken(ctx, token); err != nil {
		t.Fatalf("failed to create auth token: %v", err)
	}

	consumed, err := s.ConsumeAuthToken(ctx, "expired-token")
	if err != nil {
		t.Fatalf("consume failed: %v", err)
	}
	if consumed != nil {
		t.Error("expected nil for expired token")
	}
}

func TestConsumeAuthToken_NotFound(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	consumed, err := s.ConsumeAuthToken(ctx, "nonexistent-token")
	if err != nil {
		t.Fatalf("consume failed: %v", err)
	}
	if consumed != nil {
		t.Error("expected nil for nonexistent token")
	}
}

func TestDeleteExpiredAuthTokens(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	// Use different emails so per-email invalidation doesn't
	// interfere with the test setup.
	expired := &store.AuthToken{
		Email:     "expired@example.com",
		TokenHash: "expired-cleanup",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	used := &store.AuthToken{
		Email:     "used@example.com",
		TokenHash: "used-cleanup",
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
	}
	valid := &store.AuthToken{
		Email:     "valid@example.com",
		TokenHash: "valid-cleanup",
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
	}
	for _, tok := range []*store.AuthToken{expired, used, valid} {
		if err := s.CreateAuthToken(ctx, tok); err != nil {
			t.Fatalf(
				"failed to create token %s: %v",
				tok.TokenHash, err,
			)
		}
	}

	// Consume the "used" token so it gets marked used_at
	consumed, err := s.ConsumeAuthToken(ctx, "used-cleanup")
	if err != nil {
		t.Fatalf("failed to consume used token: %v", err)
	}
	if consumed == nil {
		t.Fatal("expected consumed token, got nil")
	}

	// Cleanup should remove both the expired and used tokens
	deleted, err := s.DeleteExpiredAuthTokens(ctx)
	if err != nil {
		t.Fatalf("failed to delete expired tokens: %v", err)
	}
	if deleted != 2 {
		t.Errorf(
			"expected 2 deleted (1 expired + 1 used), got %d",
			deleted,
		)
	}

	// The valid-unused token should still be consumable
	consumed, err = s.ConsumeAuthToken(ctx, "valid-cleanup")
	if err != nil {
		t.Fatalf("failed to consume valid token: %v", err)
	}
	if consumed == nil {
		t.Error("valid token should still exist after cleanup")
	}
}

// Session tests

func TestCreateAndGetSession(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "session@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	session := &store.Session{
		UserID:    user.ID,
		TokenHash: "session-token-xyz",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	if err := s.CreateSession(ctx, session); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	if session.ID == 0 {
		t.Error("expected non-zero ID after create")
	}

	got, _, err := s.GetSessionWithUser(ctx, "session-token-xyz")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if got == nil {
		t.Fatal("expected session, got nil")
	}
	if got.UserID != user.ID {
		t.Errorf(
			"user ID mismatch: got %d, want %d",
			got.UserID, user.ID,
		)
	}
}

func TestGetSessionWithUser_Expired(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "expired-session@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	session := &store.Session{
		UserID:    user.ID,
		TokenHash: "expired-session-token",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Minute),
	}
	if err := s.CreateSession(ctx, session); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	got, _, err := s.GetSessionWithUser(ctx, "expired-session-token")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if got != nil {
		t.Error("expected nil for expired session")
	}
}

func TestDeleteSession(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "delete-session@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	session := &store.Session{
		UserID:    user.ID,
		TokenHash: "delete-me",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	if err := s.CreateSession(ctx, session); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	if err := s.DeleteSession(ctx, "delete-me"); err != nil {
		t.Fatalf("failed to delete session: %v", err)
	}

	got, _, err := s.GetSessionWithUser(ctx, "delete-me")
	if err != nil {
		t.Fatalf("failed to get session after delete: %v", err)
	}
	if got != nil {
		t.Error("expected nil after deletion")
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "cleanup-sessions@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	// Create one expired and one valid session
	expired := &store.Session{
		UserID:    user.ID,
		TokenHash: "expired-session-cleanup",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	valid := &store.Session{
		UserID:    user.ID,
		TokenHash: "valid-session-cleanup",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	if err := s.CreateSession(ctx, expired); err != nil {
		t.Fatalf("failed to create expired session: %v", err)
	}
	if err := s.CreateSession(ctx, valid); err != nil {
		t.Fatalf("failed to create valid session: %v", err)
	}

	deleted, err := s.DeleteExpiredSessions(ctx)
	if err != nil {
		t.Fatalf(
			"failed to delete expired sessions: %v", err,
		)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}

	// The valid session should still exist
	got, _, err := s.GetSessionWithUser(
		ctx, "valid-session-cleanup",
	)
	if err != nil {
		t.Fatalf("failed to get valid session: %v", err)
	}
	if got == nil {
		t.Error(
			"valid session should still exist after cleanup",
		)
	}

	// Verify expired session is actually gone
	deleted, err = s.DeleteExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("second cleanup failed: %v", err)
	}
	if deleted != 0 {
		t.Errorf(
			"expected 0 deleted on second run, got %d",
			deleted,
		)
	}
}

func TestListMatchesWithSubByUser(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user1 := &store.User{Email: "wsu1@example.com"}
	user2 := &store.User{Email: "wsu2@example.com"}
	if err := s.SaveUser(ctx, user1); err != nil {
		t.Fatalf("failed to save user1: %v", err)
	}
	if err := s.SaveUser(ctx, user2); err != nil {
		t.Fatalf("failed to save user2: %v", err)
	}

	mv1 := identity.CertIdentityValue{CertSubject: "cert@example.com", Issuers: []string{"https://issuer.example.com"}}
	mv2 := identity.FingerprintValue{Fingerprint: "DEADBEEF"}
	sub1 := &store.Subscription{UserID: user1.ID, Name: "prod certs", MonitoredValue: mv1, WebhookURL: "https://hooks.example.com/1", NotificationType: store.NotificationTypeWebhook}
	sub2 := &store.Subscription{UserID: user2.ID, Name: "ci key", MonitoredValue: mv2, WebhookURL: "https://hooks.example.com/2", NotificationType: store.NotificationTypeWebhook}
	if err := s.SaveSubscription(ctx, sub1); err != nil {
		t.Fatalf("failed to save sub1: %v", err)
	}
	if err := s.SaveSubscription(ctx, sub2); err != nil {
		t.Fatalf("failed to save sub2: %v", err)
	}

	match1 := &store.Match{Origin: "o", LogIndex: 1, UUID: "a", SubscriptionID: sub1.ID}
	match2 := &store.Match{Origin: "o", LogIndex: 2, UUID: "b", SubscriptionID: sub1.ID}
	match3 := &store.Match{Origin: "o", LogIndex: 3, UUID: "c", SubscriptionID: sub2.ID}
	for _, m := range []*store.Match{match1, match2, match3} {
		if err := s.SaveMatch(ctx, m); err != nil {
			t.Fatalf("failed to save match: %v", err)
		}
	}

	// User1 sees 2 matches, each enriched with their subscription's monitored value
	results1, err := s.ListMatchesWithSubByUser(ctx, user1.ID)
	if err != nil {
		t.Fatalf("failed to list matches with sub for user1: %v", err)
	}
	if len(results1) != 2 {
		t.Fatalf("user1: expected 2 matches, got %d", len(results1))
	}
	for _, ms := range results1 {
		if ms.SubscriptionID != sub1.ID {
			t.Errorf("expected subscription ID %d, got %d", sub1.ID, ms.SubscriptionID)
		}
		if ms.SubscriptionName != "prod certs" {
			t.Errorf("expected subscription name %q, got %q", "prod certs", ms.SubscriptionName)
		}
		certID, ok := ms.MatchedIdentity.(identity.CertIdentityValue)
		if !ok {
			t.Fatalf("expected CertIdentityValue, got %T", ms.MatchedIdentity)
		}
		if certID.CertSubject != "cert@example.com" {
			t.Errorf("CertSubject mismatch: got %s", certID.CertSubject)
		}
	}

	// User2 sees 1 match enriched with a FingerprintValue
	results2, err := s.ListMatchesWithSubByUser(ctx, user2.ID)
	if err != nil {
		t.Fatalf("failed to list matches with sub for user2: %v", err)
	}
	if len(results2) != 1 {
		t.Fatalf("user2: expected 1 match, got %d", len(results2))
	}
	fp, ok := results2[0].MatchedIdentity.(identity.FingerprintValue)
	if !ok {
		t.Fatalf("expected FingerprintValue, got %T", results2[0].MatchedIdentity)
	}
	if fp.Fingerprint != "DEADBEEF" {
		t.Errorf("fingerprint mismatch: got %s", fp.Fingerprint)
	}

	// The name is live-resolved from the subscription, so a rename is
	// reflected on existing matches without touching the matches table.
	sub1.Name = "prod certs (renamed)"
	if err := s.UpdateSubscription(ctx, sub1); err != nil {
		t.Fatalf("failed to rename sub1: %v", err)
	}
	renamed, err := s.ListMatchesWithSubByUser(ctx, user1.ID)
	if err != nil {
		t.Fatalf("failed to list matches after rename: %v", err)
	}
	if len(renamed) != len(results1) {
		t.Fatalf("expected %d matches after rename, got %d", len(results1), len(renamed))
	}
	for _, ms := range renamed {
		if ms.SubscriptionName != "prod certs (renamed)" {
			t.Errorf("expected renamed name %q, got %q", "prod certs (renamed)", ms.SubscriptionName)
		}
	}

	// Unknown user sees no matches
	results3, err := s.ListMatchesWithSubByUser(ctx, 9999)
	if err != nil {
		t.Fatalf("failed to list matches with sub for unknown user: %v", err)
	}
	if len(results3) != 0 {
		t.Errorf("expected 0 matches for unknown user, got %d", len(results3))
	}
}

// Webhook failure tracking tests

func createTestUserAndSub(t *testing.T, s *Store) (*store.User, *store.Subscription) {
	t.Helper()
	ctx := context.Background()
	user := &store.User{Email: "webhook-test@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "test@example.com"},
		WebhookURL:       "https://hooks.example.com/test",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}
	return user, sub
}

func TestRecordNotificationFailure(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	_, sub := createTestUserAndSub(t, s)

	retry := time.Now().Add(time.Minute)
	count, err := s.RecordNotificationFailure(ctx, sub.ID, time.Now(), retry)
	if err != nil {
		t.Fatalf("RecordNotificationFailure() error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}

	count, err = s.RecordNotificationFailure(ctx, sub.ID, time.Now(), retry)
	if err != nil {
		t.Fatalf("RecordNotificationFailure() error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}

	subs, err := s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatalf("ListSubscriptions() error: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 subscription, got %d", len(subs))
	}
	if subs[0].LastFailureAt == nil {
		t.Error("expected LastFailureAt to be set")
	}
	if subs[0].ConsecutiveFailures != 2 {
		t.Errorf("expected ConsecutiveFailures 2, got %d", subs[0].ConsecutiveFailures)
	}
	if subs[0].NextRetryAt == nil {
		t.Error("expected NextRetryAt to be set after failure")
	}
}

// TestRecordNotificationFailure_NonexistentSubscription verifies that
// RecordNotificationFailure for a missing subscription ID returns a wrapped
// sql.ErrNoRows. Callers can rely on this contract to distinguish "sub
// was deleted between ListPendingMatches and the failure-record call"
// from generic DB errors.
func TestRecordNotificationFailure_NonexistentSubscription(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	_, err = s.RecordNotificationFailure(ctx, 9999, time.Now(), time.Now().Add(time.Minute))
	if err == nil {
		t.Fatal("expected error for nonexistent subscription, got nil")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected wrapped sql.ErrNoRows, got: %v", err)
	}
}

func TestRecordNotificationSuccess(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	_, sub := createTestUserAndSub(t, s)

	// Record some failures first
	retry := time.Now().Add(time.Minute)
	for i := 0; i < 3; i++ {
		if _, err := s.RecordNotificationFailure(ctx, sub.ID, time.Now(), retry); err != nil {
			t.Fatalf("RecordNotificationFailure() error: %v", err)
		}
	}

	if err := s.RecordNotificationSuccess(ctx, sub.ID); err != nil {
		t.Fatalf("RecordNotificationSuccess() error: %v", err)
	}

	subs, err := s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatalf("ListSubscriptions() error: %v", err)
	}
	if subs[0].ConsecutiveFailures != 0 {
		t.Errorf("expected ConsecutiveFailures 0, got %d", subs[0].ConsecutiveFailures)
	}
	if subs[0].LastFailureAt != nil {
		t.Error("expected LastFailureAt to be nil after success")
	}
	if subs[0].NextRetryAt != nil {
		t.Error("expected NextRetryAt to be nil after success")
	}
}

func TestEnableSubscription(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user, sub := createTestUserAndSub(t, s)

	// Record failures and disable
	retry := time.Now().Add(time.Minute)
	for i := 0; i < 3; i++ {
		if _, err := s.RecordNotificationFailure(ctx, sub.ID, time.Now(), retry); err != nil {
			t.Fatalf("RecordNotificationFailure() error: %v", err)
		}
	}
	if err := s.SetSubscriptionEnabled(ctx, sub.ID, user.ID, false); err != nil {
		t.Fatalf("SetSubscriptionEnabled(false) error: %v", err)
	}

	// Verify disabled
	subs, err := s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatalf("ListSubscriptions() error: %v", err)
	}
	if subs[0].DisabledAt == nil {
		t.Fatal("expected subscription to be disabled")
	}

	// Re-enable
	if err := s.SetSubscriptionEnabled(ctx, sub.ID, user.ID, true); err != nil {
		t.Fatalf("SetSubscriptionEnabled(true) error: %v", err)
	}

	subs, err = s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatalf("ListSubscriptions() error: %v", err)
	}
	if subs[0].ConsecutiveFailures != 3 {
		t.Errorf("expected ConsecutiveFailures 3 preserved after enable, got %d", subs[0].ConsecutiveFailures)
	}
	if subs[0].LastFailureAt == nil {
		t.Error("expected LastFailureAt to be preserved after enable")
	}
	if subs[0].DisabledAt != nil {
		t.Error("expected DisabledAt nil after enable")
	}
	if subs[0].NextRetryAt == nil {
		t.Error("expected NextRetryAt to be preserved after enable")
	}
}

func TestEnableSubscription_WrongUser(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	_, sub := createTestUserAndSub(t, s)

	err = s.SetSubscriptionEnabled(ctx, sub.ID, 9999, true)
	if err == nil {
		t.Fatal("expected error enabling subscription for wrong user, got nil")
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestDisableSubscription(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user, sub := createTestUserAndSub(t, s)

	// Disable it manually
	if err := s.SetSubscriptionEnabled(ctx, sub.ID, user.ID, false); err != nil {
		t.Fatalf("SetSubscriptionEnabled(false) error: %v", err)
	}

	// Verify disabled
	subs, err := s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatalf("ListSubscriptions() error: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 subscription, got %d", len(subs))
	}
	if subs[0].DisabledAt == nil {
		t.Fatal("expected subscription to be disabled")
	}
}

func TestDisableSubscription_WrongUser(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	_, sub := createTestUserAndSub(t, s)

	err = s.SetSubscriptionEnabled(ctx, sub.ID, 9999, false)
	if err == nil {
		t.Fatal("expected error disabling subscription for wrong user, got nil")
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestDisableSubscription_AlreadyDisabled(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user, sub := createTestUserAndSub(t, s)

	if err := s.SetSubscriptionEnabled(ctx, sub.ID, user.ID, false); err != nil {
		t.Fatalf("SetSubscriptionEnabled(false) error: %v", err)
	}

	subs, err := s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatalf("ListSubscriptions() error: %v", err)
	}
	if subs[0].DisabledAt == nil {
		t.Fatal("expected DisabledAt to be set after first disable")
	}
	originalDisabledAt := *subs[0].DisabledAt

	// Disabling again should be a no-op (idempotent), preserving the
	// original disabled_at timestamp.
	if err := s.SetSubscriptionEnabled(ctx, sub.ID, user.ID, false); err != nil {
		t.Fatalf("expected idempotent disable to succeed, got: %v", err)
	}

	subs, err = s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatalf("ListSubscriptions() error: %v", err)
	}
	if subs[0].DisabledAt == nil || !subs[0].DisabledAt.Equal(originalDisabledAt) {
		t.Errorf("expected DisabledAt to be preserved (%v), got %v", originalDisabledAt, subs[0].DisabledAt)
	}
}

func TestListPendingMatches_IncludesDisabled(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "pending-test@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	// Two subscriptions: one will be disabled, one will not
	subActive := &store.Subscription{
		UserID:           user.ID,
		Name:             "active",
		MonitoredValue:   identity.SubjectValue{Subject: "active@example.com"},
		WebhookURL:       "https://hooks.example.com/active",
		NotificationType: store.NotificationTypeWebhook,
	}
	subDisabled := &store.Subscription{
		UserID:           user.ID,
		Name:             "disabled",
		MonitoredValue:   identity.SubjectValue{Subject: "disabled@example.com"},
		WebhookURL:       "https://hooks.example.com/disabled",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, subActive); err != nil {
		t.Fatalf("failed to save active sub: %v", err)
	}
	if err := s.SaveSubscription(ctx, subDisabled); err != nil {
		t.Fatalf("failed to save disabled sub: %v", err)
	}

	// Add matches for both
	for _, sub := range []*store.Subscription{subActive, subDisabled} {
		match := &store.Match{
			Origin:         "o",
			LogIndex:       1,
			UUID:           "uuid",
			Subject:        "test",
			SubscriptionID: sub.ID,
		}
		if err := s.SaveMatch(ctx, match); err != nil {
			t.Fatalf("failed to save match: %v", err)
		}
	}

	// Disable one subscription
	if err := s.SetSubscriptionEnabled(ctx, subDisabled.ID, user.ID, false); err != nil {
		t.Fatalf("SetSubscriptionEnabled(false) error: %v", err)
	}

	// ListPendingMatches should return all subscription's matches
	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending match, got %d", len(pending))
	}
}

// TestListPendingMatches_ScansChannelColumns pins the JOIN query's
// column ordering against the Scan target list: a drift would scan
// notification_type into the wrong field. Uses the 'email' value (CHECK
// constraint-permitted but never produced by the handler) so the
// assertion catches a misordered scan rather than tautologically
// matching the column DEFAULT.
func TestListPendingMatches_ScansChannelColumns(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "pending-channel@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "x@example.com"},
		NotificationType: store.NotificationTypeEmail,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	match := &store.Match{
		Origin:         "o",
		LogIndex:       1,
		UUID:           "uuid",
		Subject:        "x@example.com",
		SubscriptionID: sub.ID,
	}
	if err := s.SaveMatch(ctx, match); err != nil {
		t.Fatalf("failed to save match: %v", err)
	}

	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending match, got %d", len(pending))
	}
	got := pending[0].Subscription
	if got.NotificationType != store.NotificationTypeEmail {
		t.Errorf("NotificationType: got %q, want %q", got.NotificationType, store.NotificationTypeEmail)
	}
}

func TestSaveFailedEntry_Persists(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	entry := &store.FailedEntry{
		Origin:   "rekor.sigstore.dev - 123",
		LogIndex: 42,
		UUID:     "deadbeef",
		Error:    "error extracting verifiers: boom",
	}
	if err := s.SaveFailedEntry(ctx, entry); err != nil {
		t.Fatalf("SaveFailedEntry() error: %v", err)
	}

	var (
		origin   string
		logIndex int64
		uuid     string
		errMsg   string
	)
	row := s.db.QueryRowContext(ctx,
		"SELECT origin, log_index, uuid, error FROM failed_entries",
	)
	if err := row.Scan(&origin, &logIndex, &uuid, &errMsg); err != nil {
		t.Fatalf("failed to read back failed entry: %v", err)
	}
	if origin != entry.Origin || logIndex != entry.LogIndex || uuid != entry.UUID || errMsg != entry.Error {
		t.Errorf("failed entry = (%q, %d, %q, %q), want (%q, %d, %q, %q)",
			origin, logIndex, uuid, errMsg,
			entry.Origin, entry.LogIndex, entry.UUID, entry.Error)
	}
}

func TestDeleteExpired_NothingToDelete(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	// No rows at all — should return 0, nil
	tokensDeleted, err := s.DeleteExpiredAuthTokens(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokensDeleted != 0 {
		t.Errorf("expected 0, got %d", tokensDeleted)
	}

	sessionsDeleted, err := s.DeleteExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionsDeleted != 0 {
		t.Errorf("expected 0, got %d", sessionsDeleted)
	}
}

// CASCADE DELETE tests

func TestCascadeDeleteUser_RemovesSubscriptionsAndMatches(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "cascade@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "CASC"},
		WebhookURL:       "https://hooks.example.com/cascade",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	match := &store.Match{
		Origin:         "test-origin",
		LogIndex:       42,
		UUID:           "test-uuid",
		CertSubject:    "cascade@example.com",
		SubscriptionID: sub.ID,
	}
	if err := s.SaveMatch(ctx, match); err != nil {
		t.Fatalf("failed to save match: %v", err)
	}

	// Delete user via raw SQL; cascade should remove sub and match.
	if _, err := s.db.ExecContext(ctx,
		"DELETE FROM users WHERE id = ?", user.ID); err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}

	subs, err := s.ListSubscriptionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to list subscriptions: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("expected 0 subscriptions after cascade, got %d", len(subs))
	}

	assertRowCount(ctx, t, s.db,
		"SELECT COUNT(*) FROM matches WHERE subscription_id = ?", 0, sub.ID)
}

func TestCascadeDeleteUser_RemovesSessions(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "cascade-sess@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	session := &store.Session{
		UserID:    user.ID,
		TokenHash: "cascade-session-token",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.CreateSession(ctx, session); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	if _, err := s.db.ExecContext(ctx,
		"DELETE FROM users WHERE id = ?", user.ID); err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}

	assertRowCount(ctx, t, s.db,
		"SELECT COUNT(*) FROM sessions WHERE user_id = ?", 0, user.ID)
}

func TestCascadeDeleteSubscription_RemovesMatches(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "cascade-sub@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "SUBMATCH"},
		WebhookURL:       "https://hooks.example.com/sub-cascade",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	match := &store.Match{
		Origin:         "test-origin",
		LogIndex:       99,
		UUID:           "sub-cascade-uuid",
		CertSubject:    "cascade-sub@example.com",
		SubscriptionID: sub.ID,
	}
	if err := s.SaveMatch(ctx, match); err != nil {
		t.Fatalf("failed to save match: %v", err)
	}

	if err := s.DeleteSubscription(ctx, sub.ID, user.ID); err != nil {
		t.Fatalf("failed to delete subscription: %v", err)
	}

	assertRowCount(ctx, t, s.db,
		"SELECT COUNT(*) FROM matches WHERE subscription_id = ?", 0, sub.ID)
}

// TrimMatches tests: callers use TrimMatches to evict the oldest matches
// for a subscription so its total stays within the caller-chosen cap.

func TestTrimMatches_EvictsOldest(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	subID, _ := createTestSubscription(ctx, t, s)

	// Stagger insert timestamps so the eviction order is unambiguous.
	for i, uuid := range []string{"oldest", "middle", "newest"} {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin:         "test-origin",
			LogIndex:       int64(i),
			UUID:           uuid,
			SubscriptionID: subID,
		}); err != nil {
			t.Fatalf("failed to save match %s: %v", uuid, err)
		}
		if _, err := s.db.ExecContext(ctx,
			"UPDATE matches SET created_at = ? WHERE uuid = ?",
			time.Now().UTC().Add(time.Duration(i)*time.Second), uuid,
		); err != nil {
			t.Fatalf("failed to bump created_at for %s: %v", uuid, err)
		}
	}

	if err := s.TrimMatches(ctx, subID, 2); err != nil {
		t.Fatalf("TrimMatches: %v", err)
	}

	assertRowCount(ctx, t, s.db,
		"SELECT COUNT(*) FROM matches WHERE subscription_id = ?", 2, subID)

	rows, err := s.db.QueryContext(ctx,
		"SELECT uuid FROM matches WHERE subscription_id = ? ORDER BY uuid", subID)
	if err != nil {
		t.Fatalf("failed to query surviving uuids: %v", err)
	}
	defer rows.Close()
	var survived []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			t.Fatalf("failed to scan uuid: %v", err)
		}
		survived = append(survived, u)
	}
	want := []string{"middle", "newest"}
	if !reflect.DeepEqual(survived, want) {
		t.Errorf("surviving uuids = %v, want %v", survived, want)
	}
}

func TestTrimMatches_IsolatedPerSubscription(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "two-subs@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	subA := &store.Subscription{
		UserID:           user.ID,
		Name:             "sub-a",
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "AAA"},
		WebhookURL:       "https://hooks.example.com/a",
		NotificationType: store.NotificationTypeWebhook,
	}
	subB := &store.Subscription{
		UserID:           user.ID,
		Name:             "sub-b",
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "BBB"},
		WebhookURL:       "https://hooks.example.com/b",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, subA); err != nil {
		t.Fatalf("failed to save subA: %v", err)
	}
	if err := s.SaveSubscription(ctx, subB); err != nil {
		t.Fatalf("failed to save subB: %v", err)
	}

	for i := range 2 {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin:         "origin-b",
			LogIndex:       int64(i),
			UUID:           fmt.Sprintf("b-%d", i),
			SubscriptionID: subB.ID,
		}); err != nil {
			t.Fatalf("failed to save subB match %d: %v", i, err)
		}
	}
	for i := range 5 {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin:         "origin-a",
			LogIndex:       int64(i),
			UUID:           fmt.Sprintf("a-%d", i),
			SubscriptionID: subA.ID,
		}); err != nil {
			t.Fatalf("failed to save subA match %d: %v", i, err)
		}
	}

	if err := s.TrimMatches(ctx, subA.ID, 2); err != nil {
		t.Fatalf("TrimMatches subA: %v", err)
	}

	assertRowCount(ctx, t, s.db,
		"SELECT COUNT(*) FROM matches WHERE subscription_id = ?", 2, subA.ID)
	assertRowCount(ctx, t, s.db,
		"SELECT COUNT(*) FROM matches WHERE subscription_id = ?", 2, subB.ID)
}

func TestTrimMatches_AtOrBelowMaxIsNoop(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	subID, _ := createTestSubscription(ctx, t, s)

	for i := range 3 {
		if err := s.SaveMatch(ctx, &store.Match{
			Origin:         "test-origin",
			LogIndex:       int64(i),
			UUID:           fmt.Sprintf("u-%d", i),
			SubscriptionID: subID,
		}); err != nil {
			t.Fatalf("failed to save match %d: %v", i, err)
		}
	}

	if err := s.TrimMatches(ctx, subID, 5); err != nil {
		t.Fatalf("TrimMatches with max > count: %v", err)
	}
	if err := s.TrimMatches(ctx, subID, 3); err != nil {
		t.Fatalf("TrimMatches with max == count: %v", err)
	}

	assertRowCount(ctx, t, s.db,
		"SELECT COUNT(*) FROM matches WHERE subscription_id = ?", 3, subID)
}

func TestTrimMatches_InTransaction(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	subID, _ := createTestSubscription(ctx, t, s)

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx() error: %v", err)
	}
	for i, uuid := range []string{"oldest", "middle", "newest"} {
		if err := tx.SaveMatch(ctx, &store.Match{
			Origin:         "test-origin",
			LogIndex:       int64(i),
			UUID:           uuid,
			SubscriptionID: subID,
		}); err != nil {
			t.Fatalf("tx.SaveMatch %s: %v", uuid, err)
		}
	}
	if err := tx.TrimMatches(ctx, subID, 2); err != nil {
		t.Fatalf("tx.TrimMatches: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("tx.Commit() error: %v", err)
	}

	assertRowCount(ctx, t, s.db,
		"SELECT COUNT(*) FROM matches WHERE subscription_id = ?", 2, subID)
}

// markMatchesNotifiedTestStore creates a store with a user, subscription, and n
// pending matches and returns the store and the resulting match IDs.
func markMatchesNotifiedTestStore(t *testing.T, n int) (*Store, []int64) {
	t.Helper()
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	user := &store.User{Email: "bulk-notify@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.SubjectValue{Subject: "bulk@example.com"},
		WebhookURL:       "https://hooks.example.com/bulk",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	for i := 0; i < n; i++ {
		m := &store.Match{
			Origin:         "test-origin",
			LogIndex:       int64(i + 1),
			UUID:           "u",
			Subject:        "bulk@example.com",
			SubscriptionID: sub.ID,
		}
		if err := s.SaveMatch(ctx, m); err != nil {
			t.Fatalf("failed to save match %d: %v", i, err)
		}
	}

	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != n {
		t.Fatalf("expected %d pending after seed, got %d", n, len(pending))
	}
	ids := make([]int64, len(pending))
	for i, pm := range pending {
		ids[i] = pm.ID
	}
	return s, ids
}

func TestMarkMatchesNotified_BulkMarksAll(t *testing.T) {
	ctx := context.Background()
	s, ids := markMatchesNotifiedTestStore(t, 3)

	if err := s.MarkMatchesNotified(ctx, ids); err != nil {
		t.Fatalf("MarkMatchesNotified() error: %v", err)
	}

	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected 0 pending matches after bulk notify, got %d", len(pending))
	}
}

func TestMarkMatchesNotified_OnlyMarksGivenIDs(t *testing.T) {
	ctx := context.Background()
	s, ids := markMatchesNotifiedTestStore(t, 3)

	// Mark only the first two — the third must stay pending.
	if err := s.MarkMatchesNotified(ctx, ids[:2]); err != nil {
		t.Fatalf("MarkMatchesNotified() error: %v", err)
	}

	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending match, got %d", len(pending))
	}
	if pending[0].ID != ids[2] {
		t.Errorf("expected pending match ID %d, got %d", ids[2], pending[0].ID)
	}
}

func TestMarkMatchesNotified_EmptyAndNilNoop(t *testing.T) {
	ctx := context.Background()
	s, ids := markMatchesNotifiedTestStore(t, 2)

	if err := s.MarkMatchesNotified(ctx, nil); err != nil {
		t.Errorf("MarkMatchesNotified(nil) should be no-op, got error: %v", err)
	}
	if err := s.MarkMatchesNotified(ctx, []int64{}); err != nil {
		t.Errorf("MarkMatchesNotified([]) should be no-op, got error: %v", err)
	}

	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != len(ids) {
		t.Errorf("expected %d pending after no-op calls, got %d", len(ids), len(pending))
	}
}
