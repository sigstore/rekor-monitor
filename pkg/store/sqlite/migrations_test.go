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
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/store"

	_ "modernc.org/sqlite"
)

const expectedVersion = 8

// minVersionWithDown is the lowest migration version required to ship a
// .down.sql. Migration 1 predates the policy and is intentionally
// up-only; everything from this version onward must round-trip.
const minVersionWithDown = 2

// migrationFileRE matches the canonical migration filename shape
// "<digits>_<name>.(up|down).sql".
var migrationFileRE = regexp.MustCompile(`^(\d+)_.+\.(up|down)\.sql$`)

func TestRunMigrations_Idempotent(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// First open: runs migrations
	s1, err := NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("first NewStore failed: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("failed to close first store: %v", err)
	}

	// Second open: migrations should be idempotent (ErrNoChange handled)
	s2, err := NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("second NewStore failed (migrations not idempotent): %v", err)
	}
	defer s2.Close()

	// Verify version and dirty state are unchanged after re-run
	version, dirty := queryMigrationState(ctx, t, s2.db)
	if version != expectedVersion {
		t.Errorf("migration version = %d, want %d", version, expectedVersion)
	}
	if dirty {
		t.Error("migration dirty flag is true after re-run, want false")
	}
}

func TestRunMigrations_SchemaCreated(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	for _, table := range []string{"checkpoints", "matches", "failed_entries", "users", "subscriptions", "auth_tokens", "sessions"} {
		assertTableExists(ctx, t, s.db, table)
	}
}

func TestRunMigrations_DirtyState(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// Create store to run initial migrations
	s, err := NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// Manually set dirty flag in schema_migrations
	_, err = s.db.ExecContext(ctx,
		"UPDATE schema_migrations SET dirty = 1",
	)
	if err != nil {
		t.Fatalf("failed to set dirty flag: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("failed to close store: %v", err)
	}

	// Reopening should fail with dirty state error
	_, err = NewStore(ctx, dbPath)
	if err == nil {
		t.Fatal("expected error for dirty migration state, got nil")
	}
	if !strings.Contains(err.Error(), "dirty migration state") {
		t.Errorf(
			"error should mention dirty migration state, got: %v",
			err,
		)
	}
}

func TestRunMigrations_IncrementalApply(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// Two initial migrations: create two tables
	twoMigrations := fstest.MapFS{
		"migrations/000001_create_items.up.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL);"),
		},
		"migrations/000002_create_tags.up.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE tags (id INTEGER PRIMARY KEY, label TEXT NOT NULL);"),
		},
	}

	// Open DB and apply first two migrations
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}

	if err := runMigrationsFromFS(db, twoMigrations, "migrations"); err != nil {
		t.Fatalf("first runMigrationsFromFS failed: %v", err)
	}

	// Verify version=2, dirty=false
	version, dirty := queryMigrationState(ctx, t, db)
	if version != 2 {
		t.Errorf("after 2 migrations: version = %d, want 2", version)
	}
	if dirty {
		t.Error("after 2 migrations: dirty = true, want false")
	}

	// Verify both tables exist
	assertTableExists(ctx, t, db, "items")
	assertTableExists(ctx, t, db, "tags")

	if err := db.Close(); err != nil {
		t.Fatalf("failed to close db: %v", err)
	}

	// Add a third migration
	threeMigrations := fstest.MapFS{
		"migrations/000001_create_items.up.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL);"),
		},
		"migrations/000002_create_tags.up.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE tags (id INTEGER PRIMARY KEY, label TEXT NOT NULL);"),
		},
		"migrations/000003_create_comments.up.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE comments (id INTEGER PRIMARY KEY, body TEXT NOT NULL);"),
		},
	}

	// Reopen and apply with the third migration added
	db2, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to reopen db: %v", err)
	}
	defer db2.Close()

	if err := runMigrationsFromFS(db2, threeMigrations, "migrations"); err != nil {
		t.Fatalf("second runMigrationsFromFS failed: %v", err)
	}

	// Verify version=3, dirty=false
	version, dirty = queryMigrationState(ctx, t, db2)
	if version != 3 {
		t.Errorf("after 3 migrations: version = %d, want 3", version)
	}
	if dirty {
		t.Error("after 3 migrations: dirty = true, want false")
	}

	// Verify new table exists
	assertTableExists(ctx, t, db2, "comments")
}

func TestRunMigrations_UpgradesV1DatabaseWithoutLosingData(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")

	initialSchema, err := migrationsFS.ReadFile("migrations/000001_initial_schema.up.sql")
	if err != nil {
		t.Fatalf("failed to read initial schema migration: %v", err)
	}

	v1Migrations := fstest.MapFS{
		"migrations/000001_initial_schema.up.sql": &fstest.MapFile{
			Data: initialSchema,
		},
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open v1 db: %v", err)
	}

	if err := runMigrationsFromFS(db, v1Migrations, "migrations"); err != nil {
		t.Fatalf("failed to apply initial migration: %v", err)
	}

	monitoredValueJSON, err := json.Marshal(identity.FingerprintValue{Fingerprint: "UPGRADE"})
	if err != nil {
		t.Fatalf("failed to marshal monitored value: %v", err)
	}

	if _, err := db.ExecContext(ctx,
		"INSERT INTO users (id, email) VALUES (1, 'upgrade@example.com')",
	); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO subscriptions (id, user_id, monitored_value, webhook_url)
		VALUES (10, 1, ?, 'https://hooks.example.com/upgrade')
	`, string(monitoredValueJSON)); err != nil {
		t.Fatalf("failed to seed subscription: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO matches (
			id, origin, log_index, uuid, cert_subject, issuer, fingerprint,
			subject, oid_extension, extension_value, subscription_id
		)
		VALUES (
			100, 'upgrade-origin', 42, 'upgrade-uuid', 'upgrade@example.com',
			'https://issuer.example.com', 'upgrade-fingerprint', 'upgrade-subject',
			'1.2.3.4', 'upgrade-extension', 10
		)
	`); err != nil {
		t.Fatalf("failed to seed match: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, expires_at)
		VALUES (1000, 1, 'upgrade-session-token', '2030-01-01 00:00:00')
	`); err != nil {
		t.Fatalf("failed to seed v1 data: %v", err)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("failed to close v1 db: %v", err)
	}

	s, err := NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("failed to open upgraded store: %v", err)
	}
	defer s.Close()

	version, dirty := queryMigrationState(ctx, t, s.db)
	if version != expectedVersion {
		t.Errorf("migration version = %d, want %d", version, expectedVersion)
	}
	if dirty {
		t.Error("migration dirty flag is true after upgrade, want false")
	}

	user, err := s.GetUserByEmail(ctx, "upgrade@example.com")
	if err != nil {
		t.Fatalf("failed to fetch upgraded user: %v", err)
	}
	if user == nil {
		t.Fatal("expected upgraded user to exist")
	}
	if user.ID != 1 {
		t.Errorf("user ID = %d, want 1", user.ID)
	}

	subs, err := s.ListSubscriptionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to list upgraded subscriptions: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("subscription count = %d, want 1", len(subs))
	}
	if subs[0].ID != 10 {
		t.Errorf("subscription ID = %d, want 10", subs[0].ID)
	}
	if subs[0].WebhookURL != "https://hooks.example.com/upgrade" {
		t.Errorf("webhook URL = %q, want %q", subs[0].WebhookURL, "https://hooks.example.com/upgrade")
	}
	// Existing v1 subscriptions must inherit the 000004 column default.
	if subs[0].NotificationType != store.NotificationTypeWebhook {
		t.Errorf("notification type = %q, want %q (migration default)",
			subs[0].NotificationType, store.NotificationTypeWebhook)
	}

	fingerprint, ok := subs[0].MonitoredValue.(identity.FingerprintValue)
	if !ok {
		t.Fatalf("monitored value type = %T, want identity.FingerprintValue", subs[0].MonitoredValue)
	}
	if fingerprint.Fingerprint != "UPGRADE" {
		t.Errorf("fingerprint = %q, want %q", fingerprint.Fingerprint, "UPGRADE")
	}

	matches, err := s.ListMatchesWithSubByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to list upgraded matches: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("match count = %d, want 1", len(matches))
	}
	if matches[0].ID != 100 {
		t.Errorf("match ID = %d, want 100", matches[0].ID)
	}
	if matches[0].SubscriptionID != 10 {
		t.Errorf("match subscription ID = %d, want 10", matches[0].SubscriptionID)
	}

	session, userFromSession, err := s.GetSessionWithUser(ctx, "upgrade-session-token")
	if err != nil {
		t.Fatalf("failed to fetch upgraded session: %v", err)
	}
	if session == nil {
		t.Fatal("expected upgraded session to exist")
	}
	if session.ID != 1000 {
		t.Errorf("session ID = %d, want 1000", session.ID)
	}
	if userFromSession == nil || userFromSession.ID != user.ID {
		t.Fatalf("session user = %+v, want user ID %d", userFromSession, user.ID)
	}

	if _, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", user.ID); err != nil {
		t.Fatalf("failed to delete upgraded user: %v", err)
	}

	subs, err = s.ListSubscriptionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to list subscriptions after upgraded-user delete: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("expected 0 subscriptions after cascade, got %d", len(subs))
	}

	assertRowCount(ctx, t, s.db, "SELECT COUNT(*) FROM matches WHERE subscription_id = ?", 0, int64(10))
	assertRowCount(ctx, t, s.db, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", 0, user.ID)
}

// assertTableExists fails the test if the given table does not exist.
func assertTableExists(
	ctx context.Context,
	t *testing.T,
	db *sql.DB,
	table string,
) {
	t.Helper()
	var name string
	err := db.QueryRowContext(ctx,
		"SELECT name FROM sqlite_master WHERE type='table' AND name=?",
		table,
	).Scan(&name)
	if err != nil {
		t.Errorf("table %q not found: %v", table, err)
	}
}

// queryMigrationState returns the version and dirty flag from schema_migrations.
func queryMigrationState(
	ctx context.Context,
	t *testing.T,
	db *sql.DB,
) (int, bool) {
	t.Helper()
	var version int
	var dirty bool
	err := db.QueryRowContext(ctx,
		"SELECT version, dirty FROM schema_migrations",
	).Scan(&version, &dirty)
	if err != nil {
		t.Fatalf("failed to query schema_migrations: %v", err)
	}
	return version, dirty
}

func assertRowCount(
	ctx context.Context,
	t *testing.T,
	db *sql.DB,
	query string,
	want int,
	args ...any,
) {
	t.Helper()

	var got int
	if err := db.QueryRowContext(ctx, query, args...).Scan(&got); err != nil {
		t.Fatalf("failed to query row count: %v", err)
	}
	if got != want {
		t.Errorf("row count = %d, want %d for query %q", got, want, query)
	}
}

// TestRunMigrations_EveryVersionHasUpAndDown enforces the policy that
// every migration ships both directions. Every version must have an
// .up.sql; the .down.sql requirement is grandfathered for versions
// below minVersionWithDown.
func TestRunMigrations_EveryVersionHasUpAndDown(t *testing.T) {
	manifest := discoverMigrations(t)
	if len(manifest.versions) == 0 {
		t.Fatal("no migrations found")
	}

	evaluatedDown := 0
	for _, v := range manifest.versions {
		if manifest.up[v] == 0 {
			t.Errorf("migration version %d missing .up.sql", v)
		}
		if v < minVersionWithDown {
			continue
		}
		evaluatedDown++
		if manifest.down[v] == 0 {
			t.Errorf("migration version %d missing .down.sql", v)
		}
	}
	if evaluatedDown == 0 {
		t.Fatalf("no migrations >= minVersionWithDown=%d found; lower the constant or add migrations", minVersionWithDown)
	}
}

// TestRunMigrations_VersionsContiguousAndUnique enforces that migration
// version numbers form a dense sequence starting at 1, and that no two
// files share the same (version, direction). Gaps would silently break
// migrate's stepwise round-trips; duplicates would let two files compete
// for the same version with whichever sorts last winning.
func TestRunMigrations_VersionsContiguousAndUnique(t *testing.T) {
	manifest := discoverMigrations(t)
	if len(manifest.versions) == 0 {
		t.Fatal("no migrations found")
	}

	for i, v := range manifest.versions {
		if want := i + 1; v != want {
			t.Errorf("versions[%d] = %d, want %d (gap or non-1 start)", i, v, want)
		}
	}

	for _, v := range manifest.versions {
		if c := manifest.up[v]; c > 1 {
			t.Errorf("version %d has %d .up.sql files, want at most 1", v, c)
		}
		if c := manifest.down[v]; c > 1 {
			t.Errorf("version %d has %d .down.sql files, want at most 1", v, c)
		}
	}
}

// TestRunMigrations_DownUpRoundTripPerVersion exercises every down file
// reachable from head. Discovered dynamically from the embedded FS, so
// new migrations are covered automatically.
func TestRunMigrations_DownUpRoundTripPerVersion(t *testing.T) {
	ctx := context.Background()
	versions := discoverMigrations(t).versions
	if len(versions) == 0 {
		t.Fatal("no migrations found")
	}

	// Versions are dense and 1-indexed (enforced by
	// TestRunMigrations_VersionsContiguousAndUnique), so the index of
	// minVersionWithDown is just minVersionWithDown - 1.
	firstWithDownIdx := minVersionWithDown - 1
	if firstWithDownIdx >= len(versions) {
		t.Skipf("no migrations >= minVersionWithDown=%d to round-trip", minVersionWithDown)
	}

	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	m := newMigrateForTest(t, db)
	if err := m.Up(); err != nil {
		t.Fatalf("Up to head failed: %v", err)
	}

	// Step down through every version that has a .down.sql, stopping just
	// above the grandfathered range. Stepping down from versions[i] must
	// land the schema at versions[i-1].
	for i := len(versions) - 1; i >= firstWithDownIdx; i-- {
		if err := m.Steps(-1); err != nil {
			t.Fatalf("Steps(-1) at version %d failed: %v", versions[i], err)
		}
		want := versions[i-1]
		version, dirty := queryMigrationState(ctx, t, db)
		if version != want {
			t.Errorf("after stepping down from %d: version = %d, want %d", versions[i], version, want)
		}
		if dirty {
			t.Errorf("after stepping down from %d: dirty = true, want false", versions[i])
		}
	}

	// Step back up to head, asserting each transition is clean.
	for i := firstWithDownIdx; i < len(versions); i++ {
		from := versions[i-1]
		if err := m.Steps(1); err != nil {
			t.Fatalf("Steps(+1) at version %d failed: %v", from, err)
		}
		version, dirty := queryMigrationState(ctx, t, db)
		if version != versions[i] {
			t.Errorf("after stepping up from %d: version = %d, want %d", from, version, versions[i])
		}
		if dirty {
			t.Errorf("after stepping up from %d: dirty = true, want false", from)
		}
	}
}

// TestRunMigrations_V3DownDropsWebhookColumns verifies that 000003's down
// removes the four webhook-failure columns while preserving subscription
// rows and their pre-existing fields.
func TestRunMigrations_V3DownDropsWebhookColumns(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	m := newMigrateForTest(t, db)
	if err := m.Migrate(3); err != nil {
		t.Fatalf("migrate to v3 failed: %v", err)
	}

	monitoredValueJSON, err := json.Marshal(identity.FingerprintValue{Fingerprint: "DOWNTEST"})
	if err != nil {
		t.Fatalf("failed to marshal monitored value: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO users (id, email) VALUES (1, 'down@example.com')`,
	); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO subscriptions
			(id, user_id, monitored_value, webhook_url,
			 consecutive_failures, last_failure_at, disabled_at, next_retry_at)
		VALUES (1, 1, ?, 'https://hooks.example.com/down',
			5, '2026-01-01 00:00:00', '2026-01-02 00:00:00', '2026-01-03 00:00:00')
	`, string(monitoredValueJSON)); err != nil {
		t.Fatalf("failed to seed subscription: %v", err)
	}

	if err := m.Steps(-1); err != nil {
		t.Fatalf("Steps(-1) failed: %v", err)
	}

	version, dirty := queryMigrationState(ctx, t, db)
	if version != 2 {
		t.Errorf("version = %d, want 2", version)
	}
	if dirty {
		t.Error("dirty = true, want false")
	}

	cols := subscriptionColumns(ctx, t, db)
	for _, c := range []string{"consecutive_failures", "last_failure_at", "disabled_at", "next_retry_at"} {
		if _, ok := cols[c]; ok {
			t.Errorf("column %q still present after down migration", c)
		}
	}
	for _, c := range []string{"id", "user_id", "monitored_value", "webhook_url", "created_at"} {
		if _, ok := cols[c]; !ok {
			t.Errorf("column %q missing after down migration", c)
		}
	}

	var (
		id         int64
		userID     int64
		monitored  string
		webhookURL string
	)
	err = db.QueryRowContext(ctx,
		`SELECT id, user_id, monitored_value, webhook_url FROM subscriptions WHERE id = 1`,
	).Scan(&id, &userID, &monitored, &webhookURL)
	if err != nil {
		t.Fatalf("subscription row missing after down: %v", err)
	}
	if id != 1 || userID != 1 {
		t.Errorf("subscription core fields = (%d, %d), want (1, 1)", id, userID)
	}
	if webhookURL != "https://hooks.example.com/down" {
		t.Errorf("webhook URL = %q, want preserved value", webhookURL)
	}
	if monitored != string(monitoredValueJSON) {
		t.Errorf("monitored_value = %q, want preserved JSON", monitored)
	}
}

// TestRunMigrations_V3DownRoundTrip migrates to v3, steps down to v2,
// then back up to v3. Verifies the schema returns to v3 with default
// values for the re-added columns and that the store still functions.
func TestRunMigrations_V3DownRoundTrip(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	m := newMigrateForTest(t, db)
	if err := m.Migrate(3); err != nil {
		t.Fatalf("migrate to v3 failed: %v", err)
	}

	monitoredValueJSON, err := json.Marshal(identity.FingerprintValue{Fingerprint: "ROUND"})
	if err != nil {
		t.Fatalf("failed to marshal monitored value: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO users (id, email) VALUES (1, 'round@example.com')`,
	); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO subscriptions
			(id, user_id, monitored_value, webhook_url, consecutive_failures)
		VALUES (1, 1, ?, 'https://hooks.example.com/round', 7)
	`, string(monitoredValueJSON)); err != nil {
		t.Fatalf("failed to seed subscription: %v", err)
	}

	if err := m.Steps(-1); err != nil {
		t.Fatalf("Steps(-1) failed: %v", err)
	}
	if err := m.Migrate(3); err != nil {
		t.Fatalf("migrate back to v3 failed: %v", err)
	}

	version, dirty := queryMigrationState(ctx, t, db)
	if version != 3 {
		t.Errorf("version = %d, want 3", version)
	}
	if dirty {
		t.Error("dirty = true after round-trip, want false")
	}

	var (
		consecutiveFailures int
		lastFailureAt       sql.NullTime
		disabledAt          sql.NullTime
		nextRetryAt         sql.NullTime
	)
	err = db.QueryRowContext(ctx, `
		SELECT consecutive_failures, last_failure_at, disabled_at, next_retry_at
		FROM subscriptions WHERE id = 1
	`).Scan(&consecutiveFailures, &lastFailureAt, &disabledAt, &nextRetryAt)
	if err != nil {
		t.Fatalf("failed to re-read subscription: %v", err)
	}
	// The down step drops the columns and the up step re-adds them with
	// their declared defaults; the seeded value of 7 does not survive.
	if consecutiveFailures != 0 {
		t.Errorf("consecutive_failures = %d after round-trip, want 0", consecutiveFailures)
	}
	if lastFailureAt.Valid || disabledAt.Valid || nextRetryAt.Valid {
		t.Errorf("nullable columns should be NULL after round-trip, got last_failure_at.Valid=%v disabled_at.Valid=%v next_retry_at.Valid=%v",
			lastFailureAt.Valid, disabledAt.Valid, nextRetryAt.Valid)
	}

	// Sanity-check that the v3 store API still works on the rebuilt schema.
	s := &Store{db: db}
	now := time.Now().UTC()
	count, err := s.RecordNotificationFailure(ctx, 1, now, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("RecordNotificationFailure after round-trip: %v", err)
	}
	if count != 1 {
		t.Errorf("RecordNotificationFailure count = %d, want 1", count)
	}
}

// TestRunMigrations_V8DownPreservesDataAndDropsName exercises the 000008
// table-rebuild with real data in both directions. The empty-database
// round-trip test covers the schema; this one verifies that the matches
// stash/restore preserves rows through both the up and the down rebuild,
// that the name column is backfilled on up and dropped on down, and that
// the backfill is deterministic across a down/up cycle.
func TestRunMigrations_V8DownPreservesDataAndDropsName(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	m := newMigrateForTest(t, db)
	if err := m.Migrate(7); err != nil {
		t.Fatalf("migrate to v7 failed: %v", err)
	}

	monitoredValueJSON, err := json.Marshal(identity.FingerprintValue{Fingerprint: "V8"})
	if err != nil {
		t.Fatalf("failed to marshal monitored value: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO users (id, email) VALUES (1, 'v8@example.com')`,
	); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO subscriptions (id, user_id, monitored_value, webhook_url, notification_type)
		VALUES (1, 1, ?, 'https://hooks.example.com/v8', 'webhook')
	`, string(monitoredValueJSON)); err != nil {
		t.Fatalf("failed to seed subscription: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO matches (id, origin, log_index, uuid, subscription_id)
		VALUES (100, 'origin', 8, 'uuid-8', 1)
	`); err != nil {
		t.Fatalf("failed to seed match: %v", err)
	}

	// Up to v8: name column added and backfilled, data preserved.
	if err := m.Migrate(8); err != nil {
		t.Fatalf("migrate to v8 failed: %v", err)
	}
	assertSubscriptionName(ctx, t, db, 1, "Subscription #1")
	assertRowCount(ctx, t, db, "SELECT COUNT(*) FROM matches WHERE id = ? AND subscription_id = ?", 1, int64(100), int64(1))

	// The per-user unique name index is actually UNIQUE after migration
	// (not merely present): a second subscription reusing the backfilled
	// (user_id, name) pair is rejected.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO subscriptions (user_id, name, monitored_value, webhook_url, notification_type)
		VALUES (1, 'Subscription #1', ?, 'https://hooks.example.com/dup', 'webhook')
	`, string(monitoredValueJSON)); err == nil {
		t.Error("expected duplicate (user_id, name) insert to fail after v8 migration, got nil")
	}

	// Down to v7: name column gone, subscription and match rows preserved.
	if err := m.Steps(-1); err != nil {
		t.Fatalf("Steps(-1) to v7 failed: %v", err)
	}
	if version, _ := queryMigrationState(ctx, t, db); version != 7 {
		t.Errorf("version = %d, want 7 after down", version)
	}
	if _, ok := subscriptionColumns(ctx, t, db)["name"]; ok {
		t.Error("name column still present after down migration")
	}
	assertRowCount(ctx, t, db, "SELECT COUNT(*) FROM subscriptions WHERE id = ? AND webhook_url = ?", 1, int64(1), "https://hooks.example.com/v8")
	assertRowCount(ctx, t, db, "SELECT COUNT(*) FROM matches WHERE id = ? AND subscription_id = ?", 1, int64(100), int64(1))

	// Up again: backfill is deterministic.
	if err := m.Migrate(8); err != nil {
		t.Fatalf("migrate back to v8 failed: %v", err)
	}
	assertSubscriptionName(ctx, t, db, 1, "Subscription #1")
}

// assertSubscriptionName fails the test unless the subscription with the
// given id has the expected name.
func assertSubscriptionName(ctx context.Context, t *testing.T, db *sql.DB, id int64, want string) {
	t.Helper()
	var got string
	if err := db.QueryRowContext(ctx, "SELECT name FROM subscriptions WHERE id = ?", id).Scan(&got); err != nil {
		t.Fatalf("failed to read subscription %d name: %v", id, err)
	}
	if got != want {
		t.Errorf("subscription %d name = %q, want %q", id, got, want)
	}
}

// newMigrateForTest builds a *migrate.Migrate over the embedded
// migrationsFS and the given database, for tests that need direct access
// to Steps/Up/Down (runMigrationsFromFS only goes up).
func newMigrateForTest(t *testing.T, db *sql.DB) *migrate.Migrate {
	t.Helper()
	driver, err := sqlite.WithInstance(db, &sqlite.Config{})
	if err != nil {
		t.Fatalf("failed to create migration driver: %v", err)
	}
	sourceDriver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("failed to create migration source: %v", err)
	}
	m, err := migrate.NewWithInstance("iofs", sourceDriver, "sqlite", driver)
	if err != nil {
		t.Fatalf("failed to create migrate instance: %v", err)
	}
	return m
}

// migrationsManifest summarizes the embedded migrations: the sorted set
// of distinct versions and how many files of each direction exist per
// version. Counts (rather than bools) let callers detect duplicate
// filenames colliding on the same (version, direction).
type migrationsManifest struct {
	versions []int
	up       map[int]int
	down     map[int]int
}

// discoverMigrations scans the embedded migrationsFS once and returns the
// sorted version list together with up/down occurrence counts. Callers
// that only need the version list ignore the maps.
func discoverMigrations(t *testing.T) migrationsManifest {
	t.Helper()
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("failed to read migrations dir: %v", err)
	}
	manifest := migrationsManifest{
		up:   map[int]int{},
		down: map[int]int{},
	}
	seen := map[int]struct{}{}
	for _, e := range entries {
		matches := migrationFileRE.FindStringSubmatch(e.Name())
		if matches == nil {
			continue
		}
		v, err := strconv.Atoi(matches[1])
		if err != nil {
			t.Fatalf("failed to parse version from %q: %v", e.Name(), err)
		}
		seen[v] = struct{}{}
		switch matches[2] {
		case "up":
			manifest.up[v]++
		case "down":
			manifest.down[v]++
		default:
			t.Fatalf("unexpected migration direction %q in %q", matches[2], e.Name())
		}
	}
	manifest.versions = make([]int, 0, len(seen))
	for v := range seen {
		manifest.versions = append(manifest.versions, v)
	}
	sort.Ints(manifest.versions)
	return manifest
}

// subscriptionColumns returns the column names of the subscriptions table.
func subscriptionColumns(ctx context.Context, t *testing.T, db *sql.DB) map[string]struct{} {
	t.Helper()
	rows, err := db.QueryContext(ctx, "PRAGMA table_info(subscriptions)")
	if err != nil {
		t.Fatalf("PRAGMA table_info failed: %v", err)
	}
	defer rows.Close()

	cols := map[string]struct{}{}
	for rows.Next() {
		// Only the column name is needed; PRAGMA table_info's other
		// fields (cid, type, notnull, dflt_value, pk) are scanned into
		// a shared placeholder.
		var (
			name    string
			discard any
		)
		if err := rows.Scan(&discard, &name, &discard, &discard, &discard, &discard); err != nil {
			t.Fatalf("failed to scan table_info row: %v", err)
		}
		cols[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("error iterating table_info: %v", err)
	}
	return cols
}
