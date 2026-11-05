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

// Package store provides abstractions for storing rekor-monitor state such as checkpoints.
// The interface is designed to be database-agnostic, allowing easy switching between
// SQLite, PostgreSQL, or other backends.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/transparency-dev/formats/log"
)

// ErrNotFound is returned when a requested resource does not exist
// or is not accessible by the given user.
var ErrNotFound = errors.New("not found")

// ErrDuplicateName is returned when a subscription cannot be saved because
// the owning user already has a subscription with the same name.
var ErrDuplicateName = errors.New("subscription name already in use")

// CheckpointStore defines the interface for storing and retrieving checkpoints.
// Implementations can use SQLite, PostgreSQL, or any other storage backend.
type CheckpointStore interface {
	// LoadCheckpoint loads the most recent checkpoint for the given origin.
	// Returns nil, nil if no checkpoint exists for the origin.
	LoadCheckpoint(ctx context.Context, origin string) (*log.Checkpoint, error)

	// SaveCheckpoint saves or updates a checkpoint for the given origin.
	// If a checkpoint already exists for the origin, it will be replaced.
	SaveCheckpoint(ctx context.Context, checkpoint *log.Checkpoint) error

	// HasAnyCheckpoint reports whether the store contains at least one
	// checkpoint for any origin. Used to distinguish a true first-time
	// cold start (no checkpoints at all) from a rollover to a new shard
	// while checkpoints for prior origins still exist.
	HasAnyCheckpoint(ctx context.Context) (bool, error)
}

// Match represents a discovered identity match from the log.
type Match struct {
	ID             int64      `json:"id"`
	Origin         string     `json:"origin"`
	LogIndex       int64      `json:"logIndex"`
	UUID           string     `json:"uuid"`
	CertSubject    string     `json:"certSubject"`
	Issuer         string     `json:"issuer"`
	Fingerprint    string     `json:"fingerprint"`
	Subject        string     `json:"subject"`
	OIDExtension   string     `json:"oidExtension"`
	ExtensionValue string     `json:"extensionValue"`
	SubscriptionID int64      `json:"subscriptionID"`
	NotifiedAt     *time.Time `json:"notifiedAt"`
	CreatedAt      time.Time  `json:"createdAt"`
}

// PendingMatch is a Match that has not yet been notified,
// enriched with the subscription and user information.
type PendingMatch struct {
	Match
	User         User
	Subscription Subscription
}

// MatchWithSubscription is a Match enriched with its subscription's
// name and monitored value, returned by queries that JOIN against
// subscriptions.
type MatchWithSubscription struct {
	Match
	SubscriptionName string                  `json:"subscriptionName"`
	MatchedIdentity  identity.MonitoredValue `json:"matchedIdentity"`
}

// MatchStore defines the interface for storing and retrieving identity matches.
type MatchStore interface {
	// SaveMatch saves a new match to the store.
	SaveMatch(ctx context.Context, match *Match) error

	// TrimMatches deletes the oldest matches for the given subscription so
	// that at most limit rows remain. Ordering is by created_at then id.
	TrimMatches(ctx context.Context, subscriptionID int64, limit int) error

	// ListMatchesWithSubByUser returns matches for the given user,
	// enriched with each match's subscription monitored value.
	ListMatchesWithSubByUser(ctx context.Context, userID int64) ([]*MatchWithSubscription, error)

	// ListPendingMatches returns matches that have not yet been notified,
	// ordered oldest first by match creation time.
	ListPendingMatches(ctx context.Context) ([]*PendingMatch, error)

	// MarkMatchesNotified sets notified_at to the current timestamp for the
	// given match IDs. A nil or empty slice is a no-op and returns nil.
	MarkMatchesNotified(ctx context.Context, matchIDs []int64) error
}

// FailedEntry represents a log entry that could not be parsed or
// processed during an identity search. Persisting these lets operators
// investigate parse failures after the fact instead of losing them to
// log output.
type FailedEntry struct {
	ID        int64     `json:"id"`
	Origin    string    `json:"origin"`
	LogIndex  int64     `json:"logIndex"`
	UUID      string    `json:"uuid"`
	Error     string    `json:"error"`
	CreatedAt time.Time `json:"createdAt"`
}

// FailedEntryStore defines the interface for persisting log entries that
// failed to parse or process during an identity search.
type FailedEntryStore interface {
	// SaveFailedEntry saves a failed log entry to the store.
	SaveFailedEntry(ctx context.Context, entry *FailedEntry) error
}

// User represents a registered user with an email address.
type User struct {
	ID        int64
	Email     string
	CreatedAt time.Time
}

// UserStore defines the interface for storing and retrieving users.
type UserStore interface {
	// SaveUser saves a new user to the store.
	SaveUser(ctx context.Context, user *User) error

	// GetUserByEmail returns the user with the given email, or nil if not found.
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// GetUserByID returns the user with the given ID, or nil if not found.
	GetUserByID(ctx context.Context, id int64) (*User, error)
}

type NotificationType string

const (
	NotificationTypeWebhook NotificationType = "webhook"
	NotificationTypeEmail   NotificationType = "email"
)

// Subscription links a user to a monitored value and a notification channel.
type Subscription struct {
	ID                  int64
	UserID              int64
	Name                string
	MonitoredValue      identity.MonitoredValue
	NotificationType    NotificationType
	WebhookURL          string
	ConsecutiveFailures int
	LastFailureAt       *time.Time
	DisabledAt          *time.Time
	NextRetryAt         *time.Time
	CreatedAt           time.Time
}

// SubscriptionStore defines the interface for storing and retrieving subscriptions.
type SubscriptionStore interface {
	// SaveSubscription saves a new subscription to the store.
	// Returns ErrDuplicateName if the user already has a subscription with the same name.
	SaveSubscription(ctx context.Context, sub *Subscription) error

	// UpdateSubscription updates an existing subscription's name, monitored value,
	// webhook URL, and notification type.
	// Returns ErrNotFound if the subscription does not exist or does not belong to the given user.
	// Returns ErrDuplicateName if the user already has another subscription with the same name.
	UpdateSubscription(ctx context.Context, sub *Subscription) error

	// DeleteSubscription deletes a subscription by ID, scoped to the given user.
	// Returns ErrNotFound if the subscription does not exist or does not belong to the user.
	DeleteSubscription(ctx context.Context, id, userID int64) error

	// ListSubscriptions returns all subscriptions in the store.
	ListSubscriptions(ctx context.Context) ([]*Subscription, error)

	// ListSubscriptionsByUser returns subscriptions owned by the given user.
	ListSubscriptionsByUser(ctx context.Context, userID int64) ([]*Subscription, error)

	// CountSubscriptionsByUser returns the total number of subscriptions
	// owned by the given user, including disabled rows.
	CountSubscriptionsByUser(ctx context.Context, userID int64) (int, error)

	// RecordNotificationSuccess resets all backoff/retry state (does not
	// affect disabled_at) for a subscription after a successful
	// notification delivery.
	RecordNotificationSuccess(ctx context.Context, subscriptionID int64) error

	// RecordNotificationFailure increments the failure counter, records lastFailureAt,
	// and stores the pre-computed nextRetryAt for backoff scheduling.
	// Returns the new consecutive failure count.
	RecordNotificationFailure(ctx context.Context, subscriptionID int64, lastFailureAt, nextRetryAt time.Time) (int, error)

	// SetSubscriptionEnabled enables or disables a subscription.
	// Backoff state (consecutive_failures, last_failure_at, next_retry_at) is
	// preserved across enable/disable cycles so users cannot reset the failure
	// count by toggling the subscription. Only a successful delivery resets it.
	// Returns ErrNotFound if the subscription does not exist or does not belong to the user.
	SetSubscriptionEnabled(ctx context.Context, id, userID int64, enabled bool) error
}

// AuthToken represents a magic-link authentication token.
// Tokens are keyed by email (not user ID) so that user creation
// can be deferred until the token is validated.
type AuthToken struct {
	ID        int64
	Email     string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// AuthTokenStore defines the interface for managing magic-link auth tokens.
type AuthTokenStore interface {
	// CreateAuthToken stores a new auth token.
	CreateAuthToken(ctx context.Context, token *AuthToken) error

	// ConsumeAuthToken looks up a token by its hash, validates that it
	// is unused and not expired, marks it as used, and returns it.
	// Returns nil, nil if the token is not found, already used, or expired.
	ConsumeAuthToken(ctx context.Context, tokenHash string) (*AuthToken, error)

	// DeleteExpiredAuthTokens removes auth tokens that have expired or
	// have already been used. Returns the number of deleted rows.
	DeleteExpiredAuthTokens(ctx context.Context) (int64, error)
}

// Session represents an authenticated user session.
type Session struct {
	ID        int64
	UserID    int64
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// SessionStore defines the interface for managing user sessions.
type SessionStore interface {
	// CreateSession stores a new session.
	CreateSession(ctx context.Context, session *Session) error

	// GetSessionWithUser returns the session and its associated user in a
	// single query. Returns (nil, nil, nil) if the token hash is not found or expired.
	GetSessionWithUser(ctx context.Context, tokenHash string) (*Session, *User, error)

	// DeleteSession removes a session by its token hash.
	DeleteSession(ctx context.Context, tokenHash string) error

	// DeleteExpiredSessions removes sessions that have expired.
	// Returns the number of deleted rows.
	DeleteExpiredSessions(ctx context.Context) (int64, error)
}

// Store combines checkpoint, match, failed-entry, subscription, user, auth token, and session storage capabilities.
type Store interface {
	CheckpointStore
	MatchStore
	FailedEntryStore
	SubscriptionStore
	UserStore
	AuthTokenStore
	SessionStore
	Close() error
}

// Tx represents a database transaction that provides all store operations.
type Tx interface {
	CheckpointStore
	MatchStore
	FailedEntryStore
	SubscriptionStore
	UserStore
	AuthTokenStore
	SessionStore
	Commit() error
	Rollback() error
}

// TransactionalStore is a Store that supports transactions.
type TransactionalStore interface {
	Store
	BeginTx(ctx context.Context) (Tx, error)
}
