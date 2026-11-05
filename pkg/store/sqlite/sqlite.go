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

// Package sqlite provides a SQLite implementation of the CheckpointStore and MatchStore interfaces.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	stdlog "log"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/store"
	"github.com/transparency-dev/formats/log"

	// The SQLite driver (aliased to avoid colliding with the golang-migrate
	// sqlite database driver imported above). Importing it under a name
	// still registers the "sqlite" driver via its init().
	sqlitedriver "modernc.org/sqlite"
)

// sqliteConstraintUnique is SQLite's extended result code for a UNIQUE
// constraint violation. It is part of SQLite's stable result-code ABI and
// is defined here to avoid importing the large modernc.org/sqlite/lib
// package solely for the constant.
// https://www.sqlite.org/rescode.html#constraint_unique
const sqliteConstraintUnique = 2067

//go:embed migrations/*.sql
var migrationsFS embed.FS

// dbExecutor is an interface satisfied by both *sql.DB and *sql.Tx,
// allowing the same query methods to work with or without a transaction.
type dbExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Store implements store.CheckpointStore using SQLite.
type Store struct {
	db *sql.DB
}

// Tx wraps a database transaction and provides the same methods as Store.
type Tx struct {
	tx *sql.Tx
}

// NewStore creates a new SQLite-backed checkpoint store.
// The dsn can be:
//   - A file path (e.g., "/path/to/checkpoints.db")
//   - ":memory:" for an in-memory database (useful for testing)
//   - A SQLite connection string with options
func NewStore(_ context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", configuredSQLiteDSN(dsn))
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Run database migrations
	if err := runMigrations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return &Store{db: db}, nil
}

func configuredSQLiteDSN(dsn string) string {
	var b strings.Builder
	b.WriteString(dsn)

	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}

	for _, pragma := range []string{"foreign_keys(1)", "journal_mode(WAL)"} {
		b.WriteString(sep)
		b.WriteString("_pragma=")
		b.WriteString(pragma)
		sep = "&"
	}

	return b.String()
}

// runMigrations runs all pending database migrations using the embedded FS.
func runMigrations(db *sql.DB) error {
	return runMigrationsFromFS(db, migrationsFS, "migrations")
}

// runMigrationsFromFS runs all pending database migrations from the given FS and path.
func runMigrationsFromFS(db *sql.DB, fsys fs.FS, path string) error {
	driver, err := sqlite.WithInstance(db, &sqlite.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	sourceDriver, err := iofs.New(fsys, path)
	if err != nil {
		return fmt.Errorf("failed to create migration source: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "sqlite", driver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	// Check for dirty state BEFORE running migrations
	// This detects if a previous migration attempt failed and left the database in an inconsistent state
	stdlog.Printf("Running migrations...\n")
	version, dirty, err := m.Version()
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		// ErrNilVersion is OK - it just means no migrations have been run yet
		return fmt.Errorf("failed to get migration version: %w", err)
	}
	if dirty {
		return fmt.Errorf("database is in a dirty migration state (version %d). A previous migration failed and must be manually resolved", version)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		// ErrNoChange means no migrations were needed (already up to date)
		// Any other error means a migration failed
		return fmt.Errorf("failed to run migrations: %w", err)
	}
	stdlog.Printf("Migrations completed successfully\n")

	return nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// BeginTx starts a new transaction and returns a Tx that can be used
// for transactional operations. The caller must call Commit() or Rollback().
func (s *Store) BeginTx(ctx context.Context) (store.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	return &Tx{tx: tx}, nil
}

// Commit commits the transaction.
func (t *Tx) Commit() error {
	return t.tx.Commit()
}

// Rollback aborts the transaction.
func (t *Tx) Rollback() error {
	return t.tx.Rollback()
}

// --- Internal implementations that accept dbExecutor ---

func loadCheckpoint(ctx context.Context, exec dbExecutor, origin string) (*log.Checkpoint, error) {
	query := `SELECT origin, size, hash FROM checkpoints WHERE origin = ?`

	var checkpoint log.Checkpoint
	err := exec.QueryRowContext(ctx, query, origin).Scan(
		&checkpoint.Origin,
		&checkpoint.Size,
		&checkpoint.Hash,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load checkpoint: %w", err)
	}

	return &checkpoint, nil
}

func hasAnyCheckpoint(ctx context.Context, exec dbExecutor) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM checkpoints)`

	var exists bool
	if err := exec.QueryRowContext(ctx, query).Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check for any checkpoint: %w", err)
	}
	return exists, nil
}

func saveCheckpoint(ctx context.Context, exec dbExecutor, checkpoint *log.Checkpoint) error {
	query := `
		INSERT INTO checkpoints (origin, size, hash, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(origin) DO UPDATE SET
			size = excluded.size,
			hash = excluded.hash,
			updated_at = CURRENT_TIMESTAMP
	`

	_, err := exec.ExecContext(ctx, query, checkpoint.Origin, checkpoint.Size, checkpoint.Hash)
	if err != nil {
		return fmt.Errorf("failed to save checkpoint: %w", err)
	}

	return nil
}

func saveMatch(ctx context.Context, exec dbExecutor, match *store.Match) error {
	query := `
		INSERT INTO matches (
			origin, log_index, uuid,
			cert_subject, issuer, fingerprint, subject,
			oid_extension, extension_value, subscription_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := exec.ExecContext(ctx, query,
		match.Origin,
		match.LogIndex,
		match.UUID,
		match.CertSubject,
		match.Issuer,
		match.Fingerprint,
		match.Subject,
		match.OIDExtension,
		match.ExtensionValue,
		match.SubscriptionID,
	)
	if err != nil {
		return fmt.Errorf("failed to save match: %w", err)
	}

	return nil
}

func saveFailedEntry(ctx context.Context, exec dbExecutor, entry *store.FailedEntry) error {
	query := `
		INSERT INTO failed_entries (
			origin, log_index, uuid, error
		) VALUES (?, ?, ?, ?)
	`

	_, err := exec.ExecContext(ctx, query,
		entry.Origin,
		entry.LogIndex,
		entry.UUID,
		entry.Error,
	)
	if err != nil {
		return fmt.Errorf("failed to save failed entry: %w", err)
	}

	return nil
}

// trimMatches deletes the oldest matches for subscriptionID so that at
// most limit rows remain. ORDER BY uses (created_at, id) so ties on
// CURRENT_TIMESTAMP (SQLite stores it with second precision) still
// evict in deterministic insertion order.
func trimMatches(ctx context.Context, exec dbExecutor, subscriptionID int64, limit int) error {
	if _, err := exec.ExecContext(ctx, `
		DELETE FROM matches
		WHERE id IN (
			SELECT id FROM matches
			WHERE subscription_id = ?
			ORDER BY created_at ASC, id ASC
			LIMIT MAX(0, (SELECT COUNT(*) FROM matches WHERE subscription_id = ?) - ?)
		)
	`, subscriptionID, subscriptionID, limit); err != nil {
		return fmt.Errorf("failed to trim matches for subscription %d: %w", subscriptionID, err)
	}
	return nil
}

func saveUser(ctx context.Context, exec dbExecutor, user *store.User) error {
	query := `
		INSERT INTO users (email)
		VALUES (?)
	`

	result, err := exec.ExecContext(ctx, query, user.Email)
	if err != nil {
		return fmt.Errorf("failed to save user: %w", err)
	}

	user.ID, err = result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert ID: %w", err)
	}

	return nil
}

func listPendingMatches(ctx context.Context, exec dbExecutor) ([]*store.PendingMatch, error) {
	query := `
		SELECT m.id, m.origin, m.log_index, m.uuid,
		       m.cert_subject, m.issuer, m.fingerprint, m.subject,
		       m.oid_extension, m.extension_value,
		       m.subscription_id, m.notified_at, m.created_at,
		       u.id, u.email, u.created_at,
		       s.id, s.user_id, s.name, s.webhook_url, s.notification_type,
		       s.monitored_value,
		       s.consecutive_failures, s.last_failure_at, s.disabled_at, s.next_retry_at, s.created_at
		FROM matches m
		JOIN subscriptions s ON m.subscription_id = s.id
		JOIN users u ON s.user_id = u.id
		WHERE m.notified_at IS NULL
		ORDER BY m.created_at ASC
	`

	rows, err := exec.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending matches: %w", err)
	}
	defer rows.Close()

	var pending []*store.PendingMatch
	for rows.Next() {
		var pm store.PendingMatch
		var monitoredValueJSON string
		err := rows.Scan(
			&pm.ID,
			&pm.Origin,
			&pm.LogIndex,
			&pm.UUID,
			&pm.CertSubject,
			&pm.Issuer,
			&pm.Fingerprint,
			&pm.Subject,
			&pm.OIDExtension,
			&pm.ExtensionValue,
			&pm.SubscriptionID,
			&pm.NotifiedAt,
			&pm.CreatedAt,
			&pm.User.ID,
			&pm.User.Email,
			&pm.User.CreatedAt,
			&pm.Subscription.ID,
			&pm.Subscription.UserID,
			&pm.Subscription.Name,
			&pm.Subscription.WebhookURL,
			&pm.Subscription.NotificationType,
			&monitoredValueJSON,
			&pm.Subscription.ConsecutiveFailures,
			&pm.Subscription.LastFailureAt,
			&pm.Subscription.DisabledAt,
			&pm.Subscription.NextRetryAt,
			&pm.Subscription.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan pending match: %w", err)
		}

		pm.Subscription.MonitoredValue, err = identity.ParseMatchedIdentityJSON([]byte(monitoredValueJSON))
		if err != nil {
			return nil, fmt.Errorf("failed to parse monitored value JSON: %w", err)
		}

		pending = append(pending, &pm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating pending matches: %w", err)
	}

	return pending, nil
}

func markMatchesNotified(ctx context.Context, exec dbExecutor, matchIDs []int64) error {
	if len(matchIDs) == 0 {
		return nil
	}

	placeholders := make([]string, len(matchIDs))
	args := make([]any, 0, len(matchIDs)+1)
	args = append(args, time.Now().UTC())
	for i, id := range matchIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	query := fmt.Sprintf(
		`UPDATE matches SET notified_at = ? WHERE id IN (%s)`,
		strings.Join(placeholders, ","),
	)

	if _, err := exec.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("failed to mark matches notified: %w", err)
	}
	return nil
}

func getUserByEmail(ctx context.Context, exec dbExecutor, email string) (*store.User, error) {
	query := `SELECT id, email, created_at FROM users WHERE email = ?`

	var user store.User
	err := exec.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

// isUniqueConstraintErr reports whether err is a SQLite UNIQUE constraint
// violation, matched on the driver's result code rather than its message.
// The only unique index on subscriptions is the per-user name index, so
// within subscription save/update this unambiguously means the user already
// has a subscription with the same name.
func isUniqueConstraintErr(err error) bool {
	var sqliteErr *sqlitedriver.Error
	return errors.As(err, &sqliteErr) && sqliteErr.Code() == sqliteConstraintUnique
}

func saveSubscription(ctx context.Context, exec dbExecutor, sub *store.Subscription) error {
	if err := identity.VerifyMonitoredValues([]identity.MonitoredValue{sub.MonitoredValue}); err != nil {
		return fmt.Errorf("failed to verify monitored value: %w", err)
	}

	query := `
		INSERT INTO subscriptions (user_id, name, monitored_value, webhook_url, notification_type)
		VALUES (?, ?, ?, ?, ?)
	`

	monitoredValueJSON, err := sub.MonitoredValue.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize monitored value: %w", err)
	}

	result, err := exec.ExecContext(ctx, query, sub.UserID, sub.Name, monitoredValueJSON, sub.WebhookURL, sub.NotificationType)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("subscription name %q already in use by user %d: %w", sub.Name, sub.UserID, store.ErrDuplicateName)
		}
		return fmt.Errorf("failed to save subscription: %w", err)
	}

	sub.ID, err = result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert ID: %w", err)
	}

	return nil
}

func updateSubscription(ctx context.Context, exec dbExecutor, sub *store.Subscription) error {
	if err := identity.VerifyMonitoredValues([]identity.MonitoredValue{sub.MonitoredValue}); err != nil {
		return fmt.Errorf("failed to verify monitored value: %w", err)
	}

	monitoredValueJSON, err := sub.MonitoredValue.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize monitored value: %w", err)
	}

	query := `
		UPDATE subscriptions
		SET name = ?, monitored_value = ?, webhook_url = ?, notification_type = ?
		WHERE id = ? AND user_id = ?
	`

	result, err := exec.ExecContext(ctx, query,
		sub.Name,
		monitoredValueJSON,
		sub.WebhookURL,
		sub.NotificationType,
		sub.ID, sub.UserID,
	)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("subscription name %q already in use by user %d: %w", sub.Name, sub.UserID, store.ErrDuplicateName)
		}
		return fmt.Errorf("failed to update subscription: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("subscription %d not owned by user %d: %w", sub.ID, sub.UserID, store.ErrNotFound)
	}

	return nil
}

func deleteSubscription(ctx context.Context, exec dbExecutor, id, userID int64) error {
	query := `DELETE FROM subscriptions WHERE id = ? AND user_id = ?`

	result, err := exec.ExecContext(ctx, query, id, userID)
	if err != nil {
		return fmt.Errorf("failed to delete subscription: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("subscription %d not owned by user %d: %w", id, userID, store.ErrNotFound)
	}

	return nil
}

func getUserByID(ctx context.Context, exec dbExecutor, id int64) (*store.User, error) {
	query := `SELECT id, email, created_at FROM users WHERE id = ?`

	var user store.User
	err := exec.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &user, nil
}

func listMatchesWithSubByUser(
	ctx context.Context, exec dbExecutor, userID int64,
) ([]*store.MatchWithSubscription, error) {
	query := `
		SELECT m.id, m.origin, m.log_index, m.uuid,
		       m.cert_subject, m.issuer, m.fingerprint, m.subject,
		       m.oid_extension, m.extension_value,
		       m.subscription_id, m.notified_at, m.created_at,
		       s.name, s.monitored_value
		FROM matches m
		JOIN subscriptions s ON m.subscription_id = s.id
		WHERE s.user_id = ?
		ORDER BY m.created_at DESC
	`

	rows, err := exec.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list matches with sub by user: %w", err)
	}
	defer rows.Close()

	var results []*store.MatchWithSubscription
	for rows.Next() {
		var ms store.MatchWithSubscription
		var monitoredValueJSON string
		err := rows.Scan(
			&ms.ID,
			&ms.Origin,
			&ms.LogIndex,
			&ms.UUID,
			&ms.CertSubject,
			&ms.Issuer,
			&ms.Fingerprint,
			&ms.Subject,
			&ms.OIDExtension,
			&ms.ExtensionValue,
			&ms.SubscriptionID,
			&ms.NotifiedAt,
			&ms.CreatedAt,
			&ms.SubscriptionName,
			&monitoredValueJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan match with sub: %w", err)
		}
		ms.MatchedIdentity, err = identity.ParseMatchedIdentityJSON(
			[]byte(monitoredValueJSON),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse monitored value JSON: %w", err)
		}
		results = append(results, &ms)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating matches with sub: %w", err)
	}

	return results, nil
}

// scanSubscriptionRows extracts subscriptions from query results.
func scanSubscriptionRows(rows *sql.Rows) ([]*store.Subscription, error) {
	var subs []*store.Subscription
	for rows.Next() {
		var sub store.Subscription
		var monitoredValueJSON string
		err := rows.Scan(
			&sub.ID,
			&sub.UserID,
			&sub.Name,
			&monitoredValueJSON,
			&sub.WebhookURL,
			&sub.NotificationType,
			&sub.ConsecutiveFailures,
			&sub.LastFailureAt,
			&sub.DisabledAt,
			&sub.NextRetryAt,
			&sub.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan subscription: %w", err)
		}

		sub.MonitoredValue, err = identity.ParseMatchedIdentityJSON([]byte(monitoredValueJSON))
		if err != nil {
			return nil, fmt.Errorf("failed to parse monitored value JSON: %w", err)
		}

		subs = append(subs, &sub)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating subscriptions: %w", err)
	}

	return subs, nil
}

func listSubscriptionsByUser(ctx context.Context, exec dbExecutor, userID int64) ([]*store.Subscription, error) {
	query := `
		SELECT id, user_id, name, monitored_value, webhook_url, notification_type,
		       consecutive_failures, last_failure_at, disabled_at, next_retry_at, created_at
		FROM subscriptions
		WHERE user_id = ?
		ORDER BY created_at DESC
	`

	rows, err := exec.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list subscriptions by user: %w", err)
	}
	defer rows.Close()

	return scanSubscriptionRows(rows)
}

func countSubscriptionsByUser(ctx context.Context, exec dbExecutor, userID int64) (int, error) {
	query := `SELECT COUNT(*) FROM subscriptions WHERE user_id = ?`

	var count int
	if err := exec.QueryRowContext(ctx, query, userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count subscriptions by user: %w", err)
	}
	return count, nil
}

func listSubscriptions(ctx context.Context, exec dbExecutor) ([]*store.Subscription, error) {
	query := `
		SELECT id, user_id, name, monitored_value, webhook_url, notification_type,
		       consecutive_failures, last_failure_at, disabled_at, next_retry_at, created_at
		FROM subscriptions
		ORDER BY created_at DESC
	`

	rows, err := exec.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list subscriptions: %w", err)
	}
	defer rows.Close()

	return scanSubscriptionRows(rows)
}

func createAuthToken(ctx context.Context, exec dbExecutor, token *store.AuthToken) error {
	// Invalidate any existing unused tokens for this email
	// so only the most recent magic link is valid.
	invalidate := `
		DELETE FROM auth_tokens
		WHERE email = ? AND used_at IS NULL
	`
	if _, err := exec.ExecContext(ctx, invalidate, token.Email); err != nil {
		return fmt.Errorf("failed to invalidate old tokens: %w", err)
	}

	query := `
		INSERT INTO auth_tokens (email, token_hash, expires_at)
		VALUES (?, ?, ?)
	`

	result, err := exec.ExecContext(ctx, query, token.Email, token.TokenHash, token.ExpiresAt.UTC())
	if err != nil {
		return fmt.Errorf("failed to create auth token: %w", err)
	}

	token.ID, err = result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert ID: %w", err)
	}

	return nil
}

func consumeAuthToken(ctx context.Context, exec dbExecutor, tokenHash string) (*store.AuthToken, error) {
	now := time.Now().UTC()
	query := `
		UPDATE auth_tokens
		SET used_at = ?
		WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
		RETURNING id, email, token_hash, expires_at, used_at, created_at
	`

	var token store.AuthToken
	err := exec.QueryRowContext(ctx, query, now, tokenHash, now).Scan(
		&token.ID,
		&token.Email,
		&token.TokenHash,
		&token.ExpiresAt,
		&token.UsedAt,
		&token.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to consume auth token: %w", err)
	}

	return &token, nil
}

func deleteExpiredAuthTokens(ctx context.Context, exec dbExecutor) (int64, error) {
	now := time.Now().UTC()
	query := `DELETE FROM auth_tokens WHERE expires_at <= ? OR used_at IS NOT NULL`
	result, err := exec.ExecContext(ctx, query, now)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired auth tokens: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}
	return n, nil
}

func createSession(ctx context.Context, exec dbExecutor, session *store.Session) error {
	query := `
		INSERT INTO sessions (user_id, token_hash, expires_at)
		VALUES (?, ?, ?)
	`
	result, err := exec.ExecContext(ctx, query, session.UserID, session.TokenHash, session.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	session.ID, err = result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert ID: %w", err)
	}
	return nil
}

func getSessionWithUser(ctx context.Context, exec dbExecutor, tokenHash string) (*store.Session, *store.User, error) {
	query := `
		SELECT s.id, s.user_id, s.token_hash, s.expires_at, s.created_at,
		       u.id, u.email, u.created_at
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.token_hash = ? AND s.expires_at > ?
	`
	var session store.Session
	var user store.User
	err := exec.QueryRowContext(ctx, query, tokenHash, time.Now().UTC()).Scan(
		&session.ID,
		&session.UserID,
		&session.TokenHash,
		&session.ExpiresAt,
		&session.CreatedAt,
		&user.ID,
		&user.Email,
		&user.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get session with user: %w", err)
	}
	return &session, &user, nil
}

func deleteSession(ctx context.Context, exec dbExecutor, tokenHash string) error {
	query := `DELETE FROM sessions WHERE token_hash = ?`
	_, err := exec.ExecContext(ctx, query, tokenHash)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

func deleteExpiredSessions(ctx context.Context, exec dbExecutor) (int64, error) {
	query := `DELETE FROM sessions WHERE expires_at <= ?`
	result, err := exec.ExecContext(ctx, query, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired sessions: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}
	return n, nil
}

func recordNotificationSuccess(ctx context.Context, exec dbExecutor, subscriptionID int64) error {
	query := `
		UPDATE subscriptions
		SET consecutive_failures = 0,
		    last_failure_at = NULL,
		    next_retry_at = NULL
		WHERE id = ?
	`
	_, err := exec.ExecContext(ctx, query, subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to record notification success: %w", err)
	}
	return nil
}

func recordNotificationFailure(ctx context.Context, exec dbExecutor, subscriptionID int64, lastFailureAt, nextRetryAt time.Time) (int, error) {
	query := `
		UPDATE subscriptions
		SET consecutive_failures = consecutive_failures + 1,
		    last_failure_at = ?,
		    next_retry_at = ?
		WHERE id = ?
		RETURNING consecutive_failures
	`
	var newCount int
	err := exec.QueryRowContext(ctx, query, lastFailureAt.UTC(), nextRetryAt.UTC(), subscriptionID).Scan(&newCount)
	if err != nil {
		return 0, fmt.Errorf("failed to record notification failure: %w", err)
	}
	return newCount, nil
}

func setSubscriptionEnabled(ctx context.Context, exec dbExecutor, id, userID int64, enabled bool) error {
	var (
		query string
		args  []any
	)
	if enabled {
		query = `
			UPDATE subscriptions
			SET disabled_at = NULL
			WHERE id = ? AND user_id = ?
		`
		args = []any{id, userID}
	} else {
		// COALESCE preserves the original disable timestamp on repeat
		// disables so the operation is idempotent.
		query = `
			UPDATE subscriptions
			SET disabled_at = COALESCE(disabled_at, ?)
			WHERE id = ? AND user_id = ?
		`
		args = []any{time.Now().UTC(), id, userID}
	}
	result, err := exec.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update subscription enabled state: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("subscription %d not found for user %d: %w", id, userID, store.ErrNotFound)
	}
	return nil
}

// --- Store methods (use db directly) ---

// LoadCheckpoint loads the most recent checkpoint for the given origin.
func (s *Store) LoadCheckpoint(ctx context.Context, origin string) (*log.Checkpoint, error) {
	return loadCheckpoint(ctx, s.db, origin)
}

// SaveCheckpoint saves or updates a checkpoint for the given origin.
func (s *Store) SaveCheckpoint(ctx context.Context, checkpoint *log.Checkpoint) error {
	return saveCheckpoint(ctx, s.db, checkpoint)
}

// HasAnyCheckpoint reports whether the store contains at least one checkpoint.
func (s *Store) HasAnyCheckpoint(ctx context.Context) (bool, error) {
	return hasAnyCheckpoint(ctx, s.db)
}

// SaveMatch saves a new match to the store.
func (s *Store) SaveMatch(ctx context.Context, match *store.Match) error {
	return saveMatch(ctx, s.db, match)
}

// SaveFailedEntry saves a log entry that failed to parse or process.
func (s *Store) SaveFailedEntry(ctx context.Context, entry *store.FailedEntry) error {
	return saveFailedEntry(ctx, s.db, entry)
}

// TrimMatches deletes the oldest matches for subscriptionID so that at most
// limit rows remain. Used by callers that own per-subscription retention.
func (s *Store) TrimMatches(ctx context.Context, subscriptionID int64, limit int) error {
	return trimMatches(ctx, s.db, subscriptionID, limit)
}

// SaveUser saves a new user to the store.
func (s *Store) SaveUser(ctx context.Context, user *store.User) error {
	return saveUser(ctx, s.db, user)
}

// GetUserByEmail returns the user with the given email, or nil if not found.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*store.User, error) {
	return getUserByEmail(ctx, s.db, email)
}

// ListPendingMatches returns un-notified matches joined with subscription data.
func (s *Store) ListPendingMatches(ctx context.Context) ([]*store.PendingMatch, error) {
	return listPendingMatches(ctx, s.db)
}

// MarkMatchesNotified sets notified_at for the given match IDs in a single statement.
// An empty or nil slice is a no-op.
func (s *Store) MarkMatchesNotified(ctx context.Context, matchIDs []int64) error {
	return markMatchesNotified(ctx, s.db, matchIDs)
}

// SaveSubscription saves a new subscription to the store.
func (s *Store) SaveSubscription(ctx context.Context, sub *store.Subscription) error {
	return saveSubscription(ctx, s.db, sub)
}

// UpdateSubscription updates an existing subscription.
func (s *Store) UpdateSubscription(ctx context.Context, sub *store.Subscription) error {
	return updateSubscription(ctx, s.db, sub)
}

// DeleteSubscription deletes a subscription by ID, scoped to the given user.
func (s *Store) DeleteSubscription(ctx context.Context, id, userID int64) error {
	return deleteSubscription(ctx, s.db, id, userID)
}

// ListSubscriptions returns subscriptions in the store.
func (s *Store) ListSubscriptions(ctx context.Context) ([]*store.Subscription, error) {
	return listSubscriptions(ctx, s.db)
}

// ListSubscriptionsByUser returns subscriptions owned by the given user.
func (s *Store) ListSubscriptionsByUser(ctx context.Context, userID int64) ([]*store.Subscription, error) {
	return listSubscriptionsByUser(ctx, s.db, userID)
}

// CountSubscriptionsByUser returns the total subscription count for a user.
func (s *Store) CountSubscriptionsByUser(ctx context.Context, userID int64) (int, error) {
	return countSubscriptionsByUser(ctx, s.db, userID)
}

// RecordNotificationSuccess resets all backoff/retry state (does not affect disabled_at) for a subscription.
func (s *Store) RecordNotificationSuccess(ctx context.Context, subscriptionID int64) error {
	return recordNotificationSuccess(ctx, s.db, subscriptionID)
}

// RecordNotificationFailure increments the failure counter and stores the
// last-failure and next-retry timestamps for backoff scheduling.
func (s *Store) RecordNotificationFailure(ctx context.Context, subscriptionID int64, lastFailureAt, nextRetryAt time.Time) (int, error) {
	return recordNotificationFailure(ctx, s.db, subscriptionID, lastFailureAt, nextRetryAt)
}

// SetSubscriptionEnabled enables or disables a subscription.
func (s *Store) SetSubscriptionEnabled(ctx context.Context, id, userID int64, enabled bool) error {
	return setSubscriptionEnabled(ctx, s.db, id, userID, enabled)
}

// GetUserByID returns the user with the given ID, or nil if not found.
func (s *Store) GetUserByID(ctx context.Context, id int64) (*store.User, error) {
	return getUserByID(ctx, s.db, id)
}

// ListMatchesWithSubByUser returns matches enriched with subscription monitored values.
func (s *Store) ListMatchesWithSubByUser(ctx context.Context, userID int64) ([]*store.MatchWithSubscription, error) {
	return listMatchesWithSubByUser(ctx, s.db, userID)
}

// CreateAuthToken stores a new auth token. The invalidation of old
// tokens and the insert run inside a single transaction.
func (s *Store) CreateAuthToken(ctx context.Context, token *store.AuthToken) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if err := createAuthToken(ctx, tx, token); err != nil {
		return err
	}
	return tx.Commit()
}

// ConsumeAuthToken looks up, validates, and marks an auth token as used.
func (s *Store) ConsumeAuthToken(ctx context.Context, tokenHash string) (*store.AuthToken, error) {
	return consumeAuthToken(ctx, s.db, tokenHash)
}

// DeleteExpiredAuthTokens removes expired or used auth tokens.
func (s *Store) DeleteExpiredAuthTokens(ctx context.Context) (int64, error) {
	return deleteExpiredAuthTokens(ctx, s.db)
}

// CreateSession stores a new session.
func (s *Store) CreateSession(ctx context.Context, session *store.Session) error {
	return createSession(ctx, s.db, session)
}

// GetSessionWithUser returns a valid session and its user in a single query.
func (s *Store) GetSessionWithUser(ctx context.Context, tokenHash string) (*store.Session, *store.User, error) {
	return getSessionWithUser(ctx, s.db, tokenHash)
}

// DeleteSession removes a session by its token hash.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	return deleteSession(ctx, s.db, tokenHash)
}

// DeleteExpiredSessions removes expired sessions.
func (s *Store) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	return deleteExpiredSessions(ctx, s.db)
}

// --- Tx methods (use transaction) ---

// LoadCheckpoint loads the most recent checkpoint for the given origin within the transaction.
func (t *Tx) LoadCheckpoint(ctx context.Context, origin string) (*log.Checkpoint, error) {
	return loadCheckpoint(ctx, t.tx, origin)
}

// SaveCheckpoint saves or updates a checkpoint within the transaction.
func (t *Tx) SaveCheckpoint(ctx context.Context, checkpoint *log.Checkpoint) error {
	return saveCheckpoint(ctx, t.tx, checkpoint)
}

// HasAnyCheckpoint reports whether the store contains at least one checkpoint, within the transaction.
func (t *Tx) HasAnyCheckpoint(ctx context.Context) (bool, error) {
	return hasAnyCheckpoint(ctx, t.tx)
}

// SaveMatch saves a new match within the transaction.
func (t *Tx) SaveMatch(ctx context.Context, match *store.Match) error {
	return saveMatch(ctx, t.tx, match)
}

// SaveFailedEntry saves a failed log entry within the transaction.
func (t *Tx) SaveFailedEntry(ctx context.Context, entry *store.FailedEntry) error {
	return saveFailedEntry(ctx, t.tx, entry)
}

// TrimMatches deletes the oldest matches for subscriptionID within the
// transaction so that at most limit rows remain.
func (t *Tx) TrimMatches(ctx context.Context, subscriptionID int64, limit int) error {
	return trimMatches(ctx, t.tx, subscriptionID, limit)
}

// SaveUser saves a new user within the transaction.
func (t *Tx) SaveUser(ctx context.Context, user *store.User) error {
	return saveUser(ctx, t.tx, user)
}

// GetUserByEmail returns the user with the given email within the transaction.
func (t *Tx) GetUserByEmail(ctx context.Context, email string) (*store.User, error) {
	return getUserByEmail(ctx, t.tx, email)
}

// ListPendingMatches returns un-notified matches within the transaction.
func (t *Tx) ListPendingMatches(ctx context.Context) ([]*store.PendingMatch, error) {
	return listPendingMatches(ctx, t.tx)
}

// MarkMatchesNotified sets notified_at for the given match IDs within the transaction.
// An empty or nil slice is a no-op.
func (t *Tx) MarkMatchesNotified(ctx context.Context, matchIDs []int64) error {
	return markMatchesNotified(ctx, t.tx, matchIDs)
}

// SaveSubscription saves a new subscription within the transaction.
func (t *Tx) SaveSubscription(ctx context.Context, sub *store.Subscription) error {
	return saveSubscription(ctx, t.tx, sub)
}

// UpdateSubscription updates an existing subscription within the transaction.
func (t *Tx) UpdateSubscription(ctx context.Context, sub *store.Subscription) error {
	return updateSubscription(ctx, t.tx, sub)
}

// DeleteSubscription deletes a subscription within the transaction.
func (t *Tx) DeleteSubscription(ctx context.Context, id, userID int64) error {
	return deleteSubscription(ctx, t.tx, id, userID)
}

// ListSubscriptions returns subscriptions within the transaction.
func (t *Tx) ListSubscriptions(ctx context.Context) ([]*store.Subscription, error) {
	return listSubscriptions(ctx, t.tx)
}

// ListSubscriptionsByUser returns subscriptions owned by the given user within the transaction.
func (t *Tx) ListSubscriptionsByUser(ctx context.Context, userID int64) ([]*store.Subscription, error) {
	return listSubscriptionsByUser(ctx, t.tx, userID)
}

// CountSubscriptionsByUser returns the total subscription count for a user within the transaction.
func (t *Tx) CountSubscriptionsByUser(ctx context.Context, userID int64) (int, error) {
	return countSubscriptionsByUser(ctx, t.tx, userID)
}

// RecordNotificationSuccess resets all backoff/retry state (does not affect disabled_at) for a subscription within the transaction.
func (t *Tx) RecordNotificationSuccess(ctx context.Context, subscriptionID int64) error {
	return recordNotificationSuccess(ctx, t.tx, subscriptionID)
}

// RecordNotificationFailure increments the failure counter and stores the
// last-failure and next-retry timestamps within the transaction.
func (t *Tx) RecordNotificationFailure(ctx context.Context, subscriptionID int64, lastFailureAt, nextRetryAt time.Time) (int, error) {
	return recordNotificationFailure(ctx, t.tx, subscriptionID, lastFailureAt, nextRetryAt)
}

// SetSubscriptionEnabled enables or disables a subscription within the transaction.
func (t *Tx) SetSubscriptionEnabled(ctx context.Context, id, userID int64, enabled bool) error {
	return setSubscriptionEnabled(ctx, t.tx, id, userID, enabled)
}

// GetUserByID returns the user with the given ID within the transaction.
func (t *Tx) GetUserByID(ctx context.Context, id int64) (*store.User, error) {
	return getUserByID(ctx, t.tx, id)
}

// ListMatchesWithSubByUser returns matches enriched with subscription monitored values within the transaction.
func (t *Tx) ListMatchesWithSubByUser(ctx context.Context, userID int64) ([]*store.MatchWithSubscription, error) {
	return listMatchesWithSubByUser(ctx, t.tx, userID)
}

// CreateAuthToken stores a new auth token within the transaction.
func (t *Tx) CreateAuthToken(ctx context.Context, token *store.AuthToken) error {
	return createAuthToken(ctx, t.tx, token)
}

// ConsumeAuthToken looks up, validates, and marks an auth token as used within the transaction.
func (t *Tx) ConsumeAuthToken(ctx context.Context, tokenStr string) (*store.AuthToken, error) {
	return consumeAuthToken(ctx, t.tx, tokenStr)
}

// DeleteExpiredAuthTokens removes expired or used auth tokens within the transaction.
func (t *Tx) DeleteExpiredAuthTokens(ctx context.Context) (int64, error) {
	return deleteExpiredAuthTokens(ctx, t.tx)
}

// CreateSession stores a new session within the transaction.
func (t *Tx) CreateSession(ctx context.Context, session *store.Session) error {
	return createSession(ctx, t.tx, session)
}

// GetSessionWithUser returns a valid session and its user within the transaction.
func (t *Tx) GetSessionWithUser(ctx context.Context, tokenStr string) (*store.Session, *store.User, error) {
	return getSessionWithUser(ctx, t.tx, tokenStr)
}

// DeleteSession removes a session by its token within the transaction.
func (t *Tx) DeleteSession(ctx context.Context, tokenStr string) error {
	return deleteSession(ctx, t.tx, tokenStr)
}

// DeleteExpiredSessions removes expired sessions within the transaction.
func (t *Tx) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	return deleteExpiredSessions(ctx, t.tx)
}

var (
	_ store.TransactionalStore = (*Store)(nil)
	_ store.Tx                 = (*Tx)(nil)
)
