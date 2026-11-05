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

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/auth"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/store"
	"github.com/sigstore/rekor-monitor/pkg/store/sqlite"
)

// mockEmailSender records sent emails for test assertions.
type mockEmailSender struct {
	sent []sentEmail
}

type sentEmail struct {
	To      string
	Subject string
	Body    string
}

func (m *mockEmailSender) Send(_ context.Context, to, subject, body string) error {
	m.sent = append(m.sent, sentEmail{To: to, Subject: subject, Body: body})
	return nil
}

// testMaxSubscriptionsPerUser is a generous default cap used in tests
// that don't care about subscription-limit behavior; tests covering the
// cap itself construct their own server with a tighter value.
const testMaxSubscriptionsPerUser = 100

func setupTestServer(t *testing.T) (*Server, *sqlite.Store, *mockEmailSender) {
	t.Helper()
	ctx := context.Background()
	s, err := sqlite.NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	mock := &mockEmailSender{}
	srv := NewServer(ServerConfig{
		Store:                   s,
		SMTP:                    mock,
		BaseURL:                 "http://localhost:8080",
		AllowPrivateWebhooks:    true,
		MaxSubscriptionsPerUser: testMaxSubscriptionsPerUser,
	})
	return srv, s, mock
}

// testMux returns the server's full route table for tests
// that need path-based routing (e.g. /api/subscriptions/{id}).
func testMux(t *testing.T, srv *Server) *http.ServeMux {
	t.Helper()
	mux, err := srv.newMux()
	if err != nil {
		t.Fatalf("failed to create mux: %v", err)
	}
	return mux
}

func TestHandleLanding(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.handleLanding(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Sign In") {
		t.Error("landing page should contain 'Sign In' link")
	}
}

func TestHandleLanding_NotFound(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.handleLanding(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleLogin_GET(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "email") {
		t.Error("login page should contain email form")
	}
}

func TestHandleLogin_GET_AlreadyLoggedIn(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()

	user := &store.User{Email: "loggedin@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	session := &store.Session{
		UserID:    user.ID,
		TokenHash: auth.HashToken("existing-session"),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	if err := s.CreateSession(ctx, session); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_token",
		Value: "existing-session",
	})
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != routeDashboard {
		t.Errorf("expected redirect to %s, got %s", routeDashboard, loc)
	}
}

func TestHandleLogin_POST_NewUser(t *testing.T) {
	srv, s, mock := setupTestServer(t)
	ctx := context.Background()

	form := url.Values{"email": {"newuser@example.com"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Check Your Email") {
		t.Error("should show check-email page")
	}
	if len(mock.sent) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(mock.sent))
	}
	if mock.sent[0].To != "newuser@example.com" {
		t.Errorf("email sent to %s, want newuser@example.com", mock.sent[0].To)
	}
	if !strings.Contains(mock.sent[0].Body, "/auth/callback?token=") {
		t.Error("email should contain magic link")
	}

	// User should NOT be created until the token is validated.
	user, err := s.GetUserByEmail(ctx, "newuser@example.com")
	if err != nil {
		t.Fatalf("failed to look up user: %v", err)
	}
	if user != nil {
		t.Error("user should not be created at login time")
	}
}

func TestHandleLogin_POST_ExistingUser(t *testing.T) {
	srv, s, mock := setupTestServer(t)
	ctx := context.Background()

	user := &store.User{Email: "existing@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	form := url.Values{"email": {"existing@example.com"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if len(mock.sent) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(mock.sent))
	}
}

func TestHandleLogin_POST_InvalidEmail(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	form := url.Values{"email": {"not-an-email"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleLogin_POST_EmptyEmail(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	form := url.Values{"email": {""}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAuthCallback_GETRendersConfirmPage(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	req := httptest.NewRequest(
		http.MethodGet,
		"/auth/callback?token=some-token",
		nil,
	)
	w := httptest.NewRecorder()
	srv.handleAuthCallback(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Sign In") {
		t.Error("confirm page should contain a Sign In button")
	}
	if !strings.Contains(body, "some-token") {
		t.Error("confirm page should include the token in a hidden field")
	}
}

func TestAuthCallback_GETMissingToken(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	req := httptest.NewRequest(
		http.MethodGet, "/auth/callback", nil,
	)
	w := httptest.NewRecorder()
	srv.handleAuthCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAuthCallback_POSTValidToken(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()

	tokenStr, err := auth.GenerateToken(auth.AuthTokenBytes)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	authToken := &store.AuthToken{
		Email:     "callback@example.com",
		TokenHash: auth.HashToken(tokenStr),
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
	}
	if err := s.CreateAuthToken(ctx, authToken); err != nil {
		t.Fatalf("failed to create auth token: %v", err)
	}

	form := url.Values{"token": {tokenStr}}
	req := httptest.NewRequest(
		http.MethodPost, "/auth/callback",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleAuthCallback(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Check that a session cookie was set
	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "session_token" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session_token cookie to be set")
	}
	if sessionCookie.Value == "" {
		t.Error("session_token cookie should not be empty")
	}

	// User should be created during callback
	user, err := s.GetUserByEmail(ctx, "callback@example.com")
	if err != nil {
		t.Fatalf("failed to look up user: %v", err)
	}
	if user == nil {
		t.Error("user should be created after token validation")
	}
}

func TestAuthCallback_POSTInvalidToken(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	form := url.Values{"token": {"invalid-token"}}
	req := httptest.NewRequest(
		http.MethodPost, "/auth/callback",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleAuthCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAuthCallback_POSTMissingToken(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	req := httptest.NewRequest(
		http.MethodPost, "/auth/callback",
		strings.NewReader(""),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleAuthCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAuthPoll_Unauthenticated(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	req := httptest.NewRequest(
		http.MethodGet, "/auth/poll", nil,
	)
	w := httptest.NewRecorder()
	srv.handleAuthPoll(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp struct{ Authenticated bool }
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Authenticated {
		t.Error("expected authenticated=false without session")
	}
}

func TestAuthPoll_Authenticated(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "poll@example.com", "poll-session")

	req := httptest.NewRequest(
		http.MethodGet, "/auth/poll", nil,
	)
	req.AddCookie(&http.Cookie{
		Name:  "session_token",
		Value: "poll-session",
	})
	w := httptest.NewRecorder()
	srv.handleAuthPoll(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp struct{ Authenticated bool }
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Authenticated {
		t.Error("expected authenticated=true with valid session")
	}
}

func TestDashboard_Unauthenticated(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	handler := srv.requireAuth(srv.handleDashboard)
	req := httptest.NewRequest(
		http.MethodGet, "/dashboard", nil,
	)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != routeLogin {
		t.Errorf("expected redirect to %s, got %s", routeLogin, loc)
	}
}

func TestDashboard_Authenticated(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()

	user := &store.User{Email: "dash@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	session := &store.Session{
		UserID:    user.ID,
		TokenHash: auth.HashToken("dash-session-token"),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	if err := s.CreateSession(ctx, session); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	handler := srv.requireAuth(srv.handleDashboard)
	req := httptest.NewRequest(
		http.MethodGet, "/dashboard", nil,
	)
	req.AddCookie(&http.Cookie{
		Name:  "session_token",
		Value: "dash-session-token",
	})
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Dashboard") {
		t.Error("dashboard page should contain 'Dashboard'")
	}
	if !strings.Contains(body, "dash@example.com") {
		t.Error(
			"dashboard page should contain the user's email",
		)
	}
	if !strings.Contains(body, "known-oids-data") {
		t.Error("dashboard page should embed known OID metadata for the web UI")
	}
	if !strings.Contains(body, "Issuer V2") || !strings.Contains(body, "1.3.6.1.4.1.57264.1.8") {
		t.Error("dashboard page should include known OID names and dot notation values")
	}
}

func TestLogout(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()

	user := &store.User{Email: "logout@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	session := &store.Session{
		UserID:    user.ID,
		TokenHash: auth.HashToken("logout-session"),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	if err := s.CreateSession(ctx, session); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_token",
		Value: "logout-session",
	})
	w := httptest.NewRecorder()
	srv.handleLogout(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != routeLanding {
		t.Errorf("expected redirect to %s, got %s", routeLanding, loc)
	}

	// Verify session cookie is cleared
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "session_token" && c.MaxAge != -1 {
			t.Error(
				"expected session_token cookie to be " +
					"cleared (MaxAge=-1)",
			)
		}
	}

	// Verify session is deleted from DB
	got, _, err := s.GetSessionWithUser(ctx, "logout-session")
	if err != nil {
		t.Fatalf("error checking session: %v", err)
	}
	if got != nil {
		t.Error("expected session to be deleted from DB")
	}
}

func TestLogout_MethodNotAllowed(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	req := httptest.NewRequest(
		http.MethodGet, "/logout", nil,
	)
	w := httptest.NewRecorder()
	srv.handleLogout(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestAPIMatches_Unauthenticated(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	handler := srv.requireAuth(srv.handleMatches)
	req := httptest.NewRequest(
		http.MethodGet, "/api/matches", nil,
	)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAPIMatches_Authenticated(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()

	user := createTestUserSession(t, s, "api@example.com", "api-session")

	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "TESTFP"},
		WebhookURL:       "https://hooks.example.com/matches-test",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	match := &store.Match{
		Origin:         "test-origin",
		LogIndex:       1,
		UUID:           "test-uuid",
		SubscriptionID: sub.ID,
	}
	if err := s.SaveMatch(ctx, match); err != nil {
		t.Fatalf("failed to save match: %v", err)
	}

	mux := testMux(t, srv)
	req := httptest.NewRequest(http.MethodGet, "/api/matches", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "api-session"})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var matches []struct {
		UUID            string          `json:"UUID"`
		MatchedIdentity json.RawMessage `json:"matchedIdentity"`
	}
	if err := json.NewDecoder(w.Body).Decode(&matches); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(matches[0].MatchedIdentity) == 0 || string(matches[0].MatchedIdentity) == "null" {
		t.Error("expected matchedIdentity to be set in response, got none")
	}
	if matches[0].UUID != "test-uuid" {
		t.Errorf("expected UUID test-uuid, got %s", matches[0].UUID)
	}
}

func TestAPISubscriptions_Unauthenticated(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	mux := testMux(t, srv)
	req := httptest.NewRequest(
		http.MethodGet, "/api/subscriptions", nil,
	)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestFullAuthFlow(t *testing.T) {
	srv, s, mock := setupTestServer(t)
	ctx := context.Background()

	// Step 1: POST /login with email
	form := url.Values{"email": {"flow@example.com"}}
	req := httptest.NewRequest(
		http.MethodPost, "/login",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set(
		"Content-Type", "application/x-www-form-urlencoded",
	)
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login POST: expected 200, got %d", w.Code)
	}
	if len(mock.sent) != 1 {
		t.Fatalf("expected 1 email, got %d", len(mock.sent))
	}

	// Step 2: Extract token from email body
	body := mock.sent[0].Body
	tokenIdx := strings.Index(body, "token=")
	if tokenIdx == -1 {
		t.Fatal(
			"email body does not contain token= parameter",
		)
	}
	tokenStr := body[tokenIdx+6:]
	if endIdx := strings.IndexByte(tokenStr, '"'); endIdx != -1 {
		tokenStr = tokenStr[:endIdx]
	}

	// Step 3: GET /auth/callback?token=... renders confirm page
	req = httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("/auth/callback?token=%s", tokenStr),
		nil,
	)
	w = httptest.NewRecorder()
	srv.handleAuthCallback(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf(
			"auth callback GET: expected 200, got %d", w.Code,
		)
	}

	// Step 4: POST /auth/callback to activate the token
	activateForm := url.Values{"token": {tokenStr}}
	req = httptest.NewRequest(
		http.MethodPost, "/auth/callback",
		strings.NewReader(activateForm.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	srv.handleAuthCallback(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf(
			"auth callback POST: expected 200, got %d", w.Code,
		)
	}

	// Extract session cookie
	var sessionToken string
	for _, c := range w.Result().Cookies() {
		if c.Name == "session_token" {
			sessionToken = c.Value
		}
	}
	if sessionToken == "" {
		t.Fatal("no session_token cookie set")
	}

	// Step 5: Poll should report authenticated
	req = httptest.NewRequest(
		http.MethodGet, "/auth/poll", nil,
	)
	req.AddCookie(&http.Cookie{
		Name:  "session_token",
		Value: sessionToken,
	})
	w = httptest.NewRecorder()
	srv.handleAuthPoll(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("auth poll: expected 200, got %d", w.Code)
	}
	var pollResp struct{ Authenticated bool }
	if err := json.NewDecoder(w.Body).Decode(&pollResp); err != nil {
		t.Fatalf("failed to decode poll response: %v", err)
	}
	if !pollResp.Authenticated {
		t.Error("expected authenticated=true after activation")
	}

	// Step 6: Access dashboard with session
	handler := srv.requireAuth(srv.handleDashboard)
	req = httptest.NewRequest(
		http.MethodGet, "/dashboard", nil,
	)
	req.AddCookie(&http.Cookie{
		Name:  "session_token",
		Value: sessionToken,
	})
	w = httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf(
			"dashboard: expected 200, got %d", w.Code,
		)
	}

	// Step 5: Verify user was created
	user, err := s.GetUserByEmail(ctx, "flow@example.com")
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if user == nil {
		t.Fatal("user not created")
	}

	// Step 6: Logout
	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_token",
		Value: sessionToken,
	})
	w = httptest.NewRecorder()
	srv.handleLogout(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf(
			"logout: expected 303, got %d", w.Code,
		)
	}

	// Step 7: Verify session is gone
	handler = srv.requireAuth(srv.handleDashboard)
	req = httptest.NewRequest(
		http.MethodGet, "/dashboard", nil,
	)
	req.AddCookie(&http.Cookie{
		Name:  "session_token",
		Value: sessionToken,
	})
	w = httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf(
			"dashboard after logout: expected 303 redirect,"+
				" got %d", w.Code,
		)
	}
}

// createTestUserSession creates a user and session for testing authenticated endpoints.
func createTestUserSession(
	t *testing.T, s *sqlite.Store, email, token string,
) *store.User {
	t.Helper()
	ctx := context.Background()
	user := &store.User{Email: email}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	session := &store.Session{
		UserID:    user.ID,
		TokenHash: auth.HashToken(token),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := s.CreateSession(ctx, session); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	return user
}

func TestCreateSubscription_Success(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "create-sub@example.com", "create-sub-session")

	body := `{"name":"My subscription","monitoredValue":{"type":"certIdentity","certSubject":"user@example.com","issuers":["https://accounts.google.com"]},"notificationType":"webhook","webhookURL":"https://hooks.example.com/notify"}`
	req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "create-sub-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		ID int64 `json:"ID"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.ID == 0 {
		t.Error("expected non-zero subscription ID")
	}
}

func TestCreateSubscription_AllTypes(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "types@example.com", "types-session")

	tests := []struct {
		name string
		body string
	}{
		{
			"certIdentity",
			`{"name":"cert","monitoredValue":{"type":"certIdentity","certSubject":"u@example.com"},"notificationType":"webhook","webhookURL":"https://hooks.example.com/1"}`,
		},
		{
			"fingerprint",
			`{"name":"fp","monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"notificationType":"webhook","webhookURL":"https://hooks.example.com/2"}`,
		},
		{
			"subject",
			`{"name":"subj","monitoredValue":{"type":"subject","subject":"sub@example.com"},"notificationType":"webhook","webhookURL":"https://hooks.example.com/3"}`,
		},
		{
			"oidExtension",
			`{"name":"oid","monitoredValue":{"type":"oidExtension","oid":[1,3,6,1,4,1,57264,1,1],"extensionValues":["val"]},"notificationType":"webhook","webhookURL":"https://hooks.example.com/4"}`,
		},
	}

	mux := testMux(t, srv)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "types-session"})
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusCreated {
				t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestCreateSubscription_InvalidBody(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "invalid@example.com", "invalid-session")

	req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader("{bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "invalid-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreateSubscription_MissingWebhook(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "nowh@example.com", "nowh-session")

	body := `{"name":"missing webhook","monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"notificationType":"webhook"}`
	req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "nowh-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreateSubscription_InvalidMonitoredValue(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "badval@example.com", "badval-session")

	body := `{"name":"bad value","monitoredValue":{"type":"certIdentity","certSubject":""},"notificationType":"webhook","webhookURL":"https://hooks.example.com/x"}`
	req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "badval-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreateSubscription_InvalidOID(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "badoid@example.com", "badoid-session")

	body := `{"name":"bad oid","monitoredValue":{"type":"oidExtension","oid":[1],"extensionValues":["val"]},"notificationType":"webhook","webhookURL":"https://hooks.example.com/x"}`
	req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "badoid-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Invalid monitored value") {
		t.Fatalf("expected invalid monitored value response, got %q", w.Body.String())
	}
}

func TestCreateSubscription_InvalidWebhookURL(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "badurl@example.com", "badurl-session")

	tests := []struct {
		name string
		url  string
	}{
		{"ftp scheme", `"ftp://hooks.example.com/notify"`},
		{"embedded credentials", `"https://user:pass@hooks.example.com/notify"`},
		{"fragment present", `"https://hooks.example.com/notify#frag"`},
		{"missing host", `"https:///path"`},
	}

	mux := testMux(t, srv)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"name":%q,"monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"notificationType":"webhook","webhookURL":%s}`, tt.name, tt.url)
			req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "badurl-session"})
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "Invalid webhook URL") {
				t.Errorf("expected 'Invalid webhook URL' in response, got: %s", w.Body.String())
			}
		})
	}
}

func TestCreateSubscription_Unauthenticated(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	body := `{"monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"webhookURL":"https://hooks.example.com/x"}`
	req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// newCappedServer builds a server identical to setupTestServer but with
// a caller-chosen MaxSubscriptionsPerUser, used by the cap tests.
func newCappedServer(t *testing.T, maxSubs int) (*Server, *sqlite.Store) {
	t.Helper()
	ctx := context.Background()
	s, err := sqlite.NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	srv := NewServer(ServerConfig{
		Store:                   s,
		SMTP:                    &mockEmailSender{},
		BaseURL:                 "http://localhost:8080",
		AllowPrivateWebhooks:    true,
		MaxSubscriptionsPerUser: maxSubs,
	})
	return srv, s
}

// postSubscription issues a POST /api/subscriptions with a fresh,
// uniquely-keyed body so each call can succeed independently.
func postSubscription(t *testing.T, mux *http.ServeMux, sessionToken, fingerprint string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(
		`{"name":%q,"monitoredValue":{"type":"fingerprint","fingerprint":%q},"notificationType":"webhook","webhookURL":"https://hooks.example.com/x"}`,
		fingerprint, fingerprint,
	)
	req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestCreateSubscription_underCap_201(t *testing.T) {
	srv, s := newCappedServer(t, 3)
	createTestUserSession(t, s, "under-cap@example.com", "under-cap-session")

	mux := testMux(t, srv)
	for i := range 3 {
		w := postSubscription(t, mux, "under-cap-session", fmt.Sprintf("FP%d", i))
		if w.Code != http.StatusCreated {
			t.Fatalf("post %d: expected 201, got %d: %s", i, w.Code, w.Body.String())
		}
	}
}

func TestCreateSubscription_atCap_returns409(t *testing.T) {
	srv, s := newCappedServer(t, 2)
	createTestUserSession(t, s, "at-cap@example.com", "at-cap-session")

	mux := testMux(t, srv)
	for i := range 2 {
		w := postSubscription(t, mux, "at-cap-session", fmt.Sprintf("FP%d", i))
		if w.Code != http.StatusCreated {
			t.Fatalf("post %d: expected 201, got %d: %s", i, w.Code, w.Body.String())
		}
	}

	w := postSubscription(t, mux, "at-cap-session", "FP-OVER")
	if w.Code != http.StatusConflict {
		t.Fatalf("post over cap: expected 409, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Subscription limit reached") {
		t.Errorf("expected 'Subscription limit reached' message, got %q", w.Body.String())
	}
}

func TestCreateSubscription_DuplicateName_409(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "dupname@example.com", "dupname-session")

	mux := testMux(t, srv)
	body := `{"name":"My monitor","monitoredValue":{"type":"fingerprint","fingerprint":"AAA"},"notificationType":"webhook","webhookURL":"https://hooks.example.com/1"}`
	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "dupname-session"})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	if w := post(); w.Code != http.StatusCreated {
		t.Fatalf("first create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	w := post()
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate create: expected 409, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "already have a subscription named") {
		t.Errorf("expected duplicate-name message, got %q", w.Body.String())
	}
}

func TestCreateSubscription_EmptyName_400(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "emptyname@example.com", "emptyname-session")

	body := `{"name":"   ","monitoredValue":{"type":"fingerprint","fingerprint":"AAA"},"notificationType":"webhook","webhookURL":"https://hooks.example.com/1"}`
	req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "emptyname-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "name is required") {
		t.Errorf("expected name-required message, got %q", w.Body.String())
	}
}

func TestCreateSubscription_NameTooLong_400(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "longname@example.com", "longname-session")

	mux := testMux(t, srv)
	create := func(name string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"name":%q,"monitoredValue":{"type":"fingerprint","fingerprint":"AAA"},"notificationType":"webhook","webhookURL":"https://hooks.example.com/1"}`, name)
		req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "longname-session"})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	// A name exactly at the limit is accepted; one byte over is rejected.
	if w := create(strings.Repeat("a", maxSubscriptionNameLen)); w.Code != http.StatusCreated {
		t.Fatalf("name at limit: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	w := create(strings.Repeat("b", maxSubscriptionNameLen+1))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("name over limit: expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "too long") {
		t.Errorf("expected too-long message, got %q", w.Body.String())
	}
}

func TestUpdateSubscription_HTTPSuccess(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()
	user := createTestUserSession(t, s, "update-http@example.com", "update-http-session")

	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "ORIGINAL"},
		WebhookURL:       "https://hooks.example.com/orig",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	body := `{"name":"Updated name","monitoredValue":{"type":"fingerprint","fingerprint":"UPDATED"},"notificationType":"webhook","webhookURL":"https://hooks.example.com/new"}`
	url := fmt.Sprintf("/api/subscriptions/%d", sub.ID)
	req := httptest.NewRequest(http.MethodPut, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "update-http-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateSubscription_DuplicateName_409(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()
	user := createTestUserSession(t, s, "upd-dup@example.com", "upd-dup-session")

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

	// Renaming "second" onto "first"'s name collides → 409.
	body := `{"name":"first","monitoredValue":{"type":"fingerprint","fingerprint":"BBB"},"notificationType":"webhook","webhookURL":"https://hooks.example.com/2"}`
	url := fmt.Sprintf("/api/subscriptions/%d", second.ID)
	req := httptest.NewRequest(http.MethodPut, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "upd-dup-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "already have a subscription named") {
		t.Errorf("expected duplicate-name message, got %q", w.Body.String())
	}
}

func TestUpdateSubscription_HTTPNotFound(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "upd-nf@example.com", "upd-nf-session")

	body := `{"name":"not found","monitoredValue":{"type":"fingerprint","fingerprint":"X"},"notificationType":"webhook","webhookURL":"https://hooks.example.com/x"}`
	req := httptest.NewRequest(http.MethodPut, "/api/subscriptions/9999", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "upd-nf-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateSubscription_HTTPNotOwned(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()

	ownerUser := &store.User{Email: "owner-upd@example.com"}
	if err := s.SaveUser(ctx, ownerUser); err != nil {
		t.Fatalf("failed to save owner user: %v", err)
	}

	sub := &store.Subscription{
		UserID:           ownerUser.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "OWNED"},
		WebhookURL:       "https://hooks.example.com/owned",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	createTestUserSession(t, s, "attacker@example.com", "attacker-session")

	body := `{"name":"hijacked","monitoredValue":{"type":"fingerprint","fingerprint":"HIJACKED"},"notificationType":"webhook","webhookURL":"https://evil.com"}`
	url := fmt.Sprintf("/api/subscriptions/%d", sub.ID)
	req := httptest.NewRequest(http.MethodPut, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "attacker-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateSubscription_HTTPUnauthenticated(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	body := `{"monitoredValue":{"type":"fingerprint","fingerprint":"X"},"notificationType":"webhook","webhookURL":"https://hooks.example.com/x"}`
	req := httptest.NewRequest(http.MethodPut, "/api/subscriptions/1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestDeleteSubscription_HTTPSuccess(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()
	user := createTestUserSession(t, s, "del-sub@example.com", "del-sub-session")

	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "TO-DELETE"},
		WebhookURL:       "https://hooks.example.com/del",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	url := fmt.Sprintf("/api/subscriptions/%d", sub.ID)
	req := httptest.NewRequest(http.MethodDelete, url, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "del-sub-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	// Verify it's actually gone.
	subs, err := s.ListSubscriptionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to list subscriptions: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("expected 0 subscriptions, got %d", len(subs))
	}
}

func TestDeleteSubscription_HTTPNotFound(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "del-nf@example.com", "del-nf-session")

	req := httptest.NewRequest(http.MethodDelete, "/api/subscriptions/9999", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "del-nf-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteSubscription_HTTPNotOwned(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()

	ownerUser := &store.User{Email: "owner-del@example.com"}
	if err := s.SaveUser(ctx, ownerUser); err != nil {
		t.Fatalf("failed to save owner user: %v", err)
	}

	sub := &store.Subscription{
		UserID:           ownerUser.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "OWNED"},
		WebhookURL:       "https://hooks.example.com/owned",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	createTestUserSession(t, s, "attacker-del@example.com", "attacker-del-session")

	url := fmt.Sprintf("/api/subscriptions/%d", sub.ID)
	req := httptest.NewRequest(http.MethodDelete, url, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "attacker-del-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteSubscription_HTTPUnauthenticated(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/subscriptions/1", nil)

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestUpdateSubscription_HTTPInvalidID(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "upd-id@example.com", "upd-id-session")

	body := `{"name":"invalid id","monitoredValue":{"type":"fingerprint","fingerprint":"X"},"notificationType":"webhook","webhookURL":"https://hooks.example.com/x"}`
	mux := testMux(t, srv)

	for _, path := range []string{
		"/api/subscriptions/abc",
		"/api/subscriptions/0",
		"/api/subscriptions/-1",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "upd-id-session"})
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestDeleteSubscription_HTTPInvalidID(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "del-id@example.com", "del-id-session")

	mux := testMux(t, srv)

	for _, path := range []string{
		"/api/subscriptions/abc",
		"/api/subscriptions/0",
		"/api/subscriptions/-1",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, path, nil)
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "del-id-session"})
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestListSubscriptions_Authenticated(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()

	user := createTestUserSession(t, s, "list-subs@example.com", "list-subs-session")

	// Create another user with their own subscription (must not appear in the response).
	other := &store.User{Email: "other-list@example.com"}
	if err := s.SaveUser(ctx, other); err != nil {
		t.Fatalf("failed to save other user: %v", err)
	}
	otherSub := &store.Subscription{
		UserID:           other.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "OTHER"},
		WebhookURL:       "https://hooks.example.com/other",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, otherSub); err != nil {
		t.Fatalf("failed to save other subscription: %v", err)
	}

	// No subscriptions for our user yet.
	mux := testMux(t, srv)
	req := httptest.NewRequest(http.MethodGet, routeAPISubscriptions, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "list-subs-session"})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	type subJSON struct {
		ID         int64  `json:"ID"`
		WebhookURL string `json:"WebhookURL"`
	}
	var subs []subJSON
	if err := json.NewDecoder(w.Body).Decode(&subs); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("expected 0 subscriptions for new user, got %d", len(subs))
	}

	// Add a subscription for our user.
	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "MINE"},
		WebhookURL:       "https://hooks.example.com/mine",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	req = httptest.NewRequest(http.MethodGet, routeAPISubscriptions, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "list-subs-session"})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if err := json.NewDecoder(w.Body).Decode(&subs); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(subs) != 1 {
		t.Errorf("expected 1 subscription, got %d", len(subs))
	}
	if subs[0].WebhookURL != "https://hooks.example.com/mine" {
		t.Errorf("expected WebhookURL https://hooks.example.com/mine, got %s", subs[0].WebhookURL)
	}
}

// Enable subscription endpoint tests

func TestEnableSubscription_HTTPSuccess(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()
	user := createTestUserSession(t, s, "enable@example.com", "enable-session")

	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "DISABLED"},
		WebhookURL:       "https://hooks.example.com/disabled",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	// Disable it
	if err := s.SetSubscriptionEnabled(ctx, sub.ID, user.ID, false); err != nil {
		t.Fatalf("SetSubscriptionEnabled(false) error: %v", err)
	}

	// Verify disabled
	subs, _ := s.ListSubscriptionsByUser(ctx, user.ID)
	if subs[0].DisabledAt == nil {
		t.Fatal("expected subscription to be disabled")
	}

	// POST /api/subscriptions/{id}/enable
	url := fmt.Sprintf("/api/subscriptions/%d/enable", sub.ID)
	req := httptest.NewRequest(http.MethodPost, url, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "enable-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	// Verify re-enabled
	subs, _ = s.ListSubscriptionsByUser(ctx, user.ID)
	if subs[0].DisabledAt != nil {
		t.Error("expected DisabledAt nil after enable")
	}
	if subs[0].ConsecutiveFailures != 0 {
		t.Errorf("expected ConsecutiveFailures 0 (preserved), got %d", subs[0].ConsecutiveFailures)
	}
}

func TestEnableSubscription_HTTPNotFound(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "enable-nf@example.com", "enable-nf-session")

	req := httptest.NewRequest(http.MethodPost, "/api/subscriptions/9999/enable", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "enable-nf-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEnableSubscription_HTTPNotOwned(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()

	owner := &store.User{Email: "enable-owner@example.com"}
	if err := s.SaveUser(ctx, owner); err != nil {
		t.Fatalf("failed to save owner: %v", err)
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

	createTestUserSession(t, s, "enable-attacker@example.com", "enable-attacker-session")

	url := fmt.Sprintf("/api/subscriptions/%d/enable", sub.ID)
	req := httptest.NewRequest(http.MethodPost, url, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "enable-attacker-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEnableSubscription_HTTPUnauthenticated(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/subscriptions/1/enable", nil)
	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestEnableSubscription_HTTPInvalidID(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "enable-bad@example.com", "enable-bad-session")

	mux := testMux(t, srv)
	for _, path := range []string{
		"/api/subscriptions/abc/enable",
		"/api/subscriptions/0/enable",
		"/api/subscriptions/-1/enable",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "enable-bad-session"})
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

// Disable subscription endpoint tests

func TestDisableSubscription_HTTPSuccess(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()
	user := createTestUserSession(t, s, "disable@example.com", "disable-session")

	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "TODISABLE"},
		WebhookURL:       "https://hooks.example.com/disable",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	// Verify not disabled
	subs, _ := s.ListSubscriptionsByUser(ctx, user.ID)
	if subs[0].DisabledAt != nil {
		t.Fatal("expected subscription to not be disabled initially")
	}

	// POST /api/subscriptions/{id}/disable
	url := fmt.Sprintf("/api/subscriptions/%d/disable", sub.ID)
	req := httptest.NewRequest(http.MethodPost, url, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "disable-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	// Verify disabled
	subs, _ = s.ListSubscriptionsByUser(ctx, user.ID)
	if subs[0].DisabledAt == nil {
		t.Error("expected DisabledAt to be set after disable")
	}
}

func TestDisableSubscription_HTTPNotFound(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "disable-nf@example.com", "disable-nf-session")

	req := httptest.NewRequest(http.MethodPost, "/api/subscriptions/9999/disable", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "disable-nf-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDisableSubscription_HTTPNotOwned(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()

	owner := &store.User{Email: "disable-owner@example.com"}
	if err := s.SaveUser(ctx, owner); err != nil {
		t.Fatalf("failed to save owner: %v", err)
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

	createTestUserSession(t, s, "disable-attacker@example.com", "disable-attacker-session")

	url := fmt.Sprintf("/api/subscriptions/%d/disable", sub.ID)
	req := httptest.NewRequest(http.MethodPost, url, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "disable-attacker-session"})

	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDisableSubscription_HTTPUnauthenticated(t *testing.T) {
	srv, _, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/subscriptions/1/disable", nil)
	mux := testMux(t, srv)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestDisableSubscription_ThenEnable(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()
	user := createTestUserSession(t, s, "toggle@example.com", "toggle-session")

	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "TOGGLE"},
		WebhookURL:       "https://hooks.example.com/toggle",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	// Pre-record failures so we can verify backoff state survives the
	// disable→enable round-trip (users must not be able to reset the
	// failure counter by toggling the subscription off and on).
	originalRetry := time.Now().UTC().Add(15 * time.Minute)
	for i := 0; i < 3; i++ {
		if _, err := s.RecordNotificationFailure(ctx, sub.ID, time.Now(), originalRetry); err != nil {
			t.Fatalf("RecordNotificationFailure() error: %v", err)
		}
	}

	mux := testMux(t, srv)

	// Disable
	disableURL := fmt.Sprintf("/api/subscriptions/%d/disable", sub.ID)
	req := httptest.NewRequest(http.MethodPost, disableURL, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "toggle-session"})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("disable: expected 204, got %d", w.Code)
	}

	subs, _ := s.ListSubscriptionsByUser(ctx, user.ID)
	if subs[0].DisabledAt == nil {
		t.Fatal("expected disabled after disable call")
	}

	// Enable
	enableURL := fmt.Sprintf("/api/subscriptions/%d/enable", sub.ID)
	req = httptest.NewRequest(http.MethodPost, enableURL, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "toggle-session"})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("enable: expected 204, got %d", w.Code)
	}

	subs, _ = s.ListSubscriptionsByUser(ctx, user.ID)
	if subs[0].DisabledAt != nil {
		t.Error("expected not disabled after enable call")
	}
	if subs[0].ConsecutiveFailures != 3 {
		t.Errorf("expected ConsecutiveFailures preserved as 3, got %d", subs[0].ConsecutiveFailures)
	}
	if subs[0].NextRetryAt == nil || !subs[0].NextRetryAt.Equal(originalRetry) {
		t.Errorf("expected NextRetryAt preserved (%v), got %v", originalRetry, subs[0].NextRetryAt)
	}
	if subs[0].LastFailureAt == nil {
		t.Error("expected LastFailureAt preserved across enable/disable")
	}
}

// Verify the list subscriptions API includes failure tracking fields
func TestListSubscriptions_IncludesFailureState(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()
	user := createTestUserSession(t, s, "list-fail@example.com", "list-fail-session")

	sub := &store.Subscription{
		UserID:           user.ID,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "FAILTEST"},
		WebhookURL:       "https://hooks.example.com/failtest",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("failed to save subscription: %v", err)
	}

	// Record some failures
	retry := time.Now().Add(time.Minute)
	for i := 0; i < 2; i++ {
		if _, err := s.RecordNotificationFailure(ctx, sub.ID, time.Now(), retry); err != nil {
			t.Fatalf("RecordNotificationFailure() error: %v", err)
		}
	}

	mux := testMux(t, srv)
	req := httptest.NewRequest(http.MethodGet, routeAPISubscriptions, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "list-fail-session"})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var subs []struct {
		ID                  int64   `json:"ID"`
		ConsecutiveFailures int     `json:"ConsecutiveFailures"`
		LastFailureAt       *string `json:"LastFailureAt"`
		DisabledAt          *string `json:"DisabledAt"`
	}
	if err := json.NewDecoder(w.Body).Decode(&subs); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 subscription, got %d", len(subs))
	}
	if subs[0].ConsecutiveFailures != 2 {
		t.Errorf("expected ConsecutiveFailures 2 in JSON, got %d", subs[0].ConsecutiveFailures)
	}
	if subs[0].LastFailureAt == nil {
		t.Error("expected LastFailureAt to be present in JSON")
	}
	if subs[0].DisabledAt != nil {
		t.Error("expected DisabledAt to be null (not yet at threshold)")
	}
}

func TestRunCleanup(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	ctx := context.Background()

	user := &store.User{Email: "cleanup@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	// Create expired token and session
	expiredToken := &store.AuthToken{
		Email:     "cleanup@example.com",
		TokenHash: auth.HashToken("expired-token-cleanup"),
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	if err := s.CreateAuthToken(ctx, expiredToken); err != nil {
		t.Fatalf("failed to create expired token: %v", err)
	}

	expiredSession := &store.Session{
		UserID:    user.ID,
		TokenHash: auth.HashToken("expired-session-cleanup"),
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	if err := s.CreateSession(ctx, expiredSession); err != nil {
		t.Fatalf(
			"failed to create expired session: %v", err,
		)
	}

	// Create valid session that should survive cleanup
	validSession := &store.Session{
		UserID:    user.ID,
		TokenHash: auth.HashToken("valid-session-cleanup"),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	if err := s.CreateSession(ctx, validSession); err != nil {
		t.Fatalf(
			"failed to create valid session: %v", err,
		)
	}

	// Run cleanup
	srv.runCleanup(ctx)

	// Valid session should still work
	got, _, err := s.GetSessionWithUser(
		ctx, auth.HashToken("valid-session-cleanup"),
	)
	if err != nil {
		t.Fatalf("error getting valid session: %v", err)
	}
	if got == nil {
		t.Error("valid session should survive cleanup")
	}

	// Running cleanup again should find nothing to delete
	srv.runCleanup(ctx)
}

// setupRateLimitedServer creates a server with tight rate limits for testing.
func setupRateLimitedServer(t *testing.T) (*Server, *sqlite.Store, *mockEmailSender) {
	t.Helper()
	ctx := context.Background()
	s, err := sqlite.NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	mock := &mockEmailSender{}
	srv := NewServer(ServerConfig{
		Store:                s,
		SMTP:                 mock,
		BaseURL:              "http://localhost:8080",
		AllowPrivateWebhooks: true,
		IPLimiter:            NewRateLimiter(2, 1*time.Minute),
		LoginEmailLimiter:    NewRateLimiter(1, 1*time.Minute),
		PollIPLimiter:        NewRateLimiter(2, 1*time.Minute),
		AuthEmailLimiter:     NewRateLimiter(2, 1*time.Minute),
	})
	return srv, s, mock
}

func TestHandleLoginPost_RateLimitByIP(t *testing.T) {
	srv, _, _ := setupRateLimitedServer(t)
	handler := srv.requireIPRateLimit(srv.ipLimiter, srv.handleLoginPost)

	makeReq := func() *httptest.ResponseRecorder {
		form := url.Values{"email": {"test@example.com"}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()
		handler(w, req)
		return w
	}

	// First 2 requests (burst) should succeed.
	for i := range 2 {
		w := makeReq()
		if w.Code == http.StatusTooManyRequests {
			t.Errorf("request %d should not be rate limited", i)
		}
	}

	// Third request should be rate limited with Retry-After.
	w := makeReq()
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429 response")
	}
}

func TestHandleLoginPost_RateLimitByEmail(t *testing.T) {
	srv, _, mock := setupRateLimitedServer(t)

	var reqCount int
	makeReq := func(email string) *httptest.ResponseRecorder {
		reqCount++
		form := url.Values{"email": {email}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// Use different IPs so the IP limiter doesn't trigger.
		req.RemoteAddr = fmt.Sprintf("10.0.0.%d:12345", reqCount)
		w := httptest.NewRecorder()
		srv.handleLoginPost(w, req)
		return w
	}

	// First request sends an email.
	w := makeReq("limit@example.com")
	if w.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w.Code)
	}
	if len(mock.sent) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(mock.sent))
	}

	// Second request should be silently dropped (still 200, no extra email).
	w = makeReq("limit@example.com")
	if w.Code != http.StatusOK {
		t.Errorf("rate-limited request should return 200, got %d", w.Code)
	}
	if len(mock.sent) != 1 {
		t.Errorf("expected still 1 email sent (silent drop), got %d", len(mock.sent))
	}
}

func TestAuthCallback_GETRateLimitByIP(t *testing.T) {
	srv, _, _ := setupRateLimitedServer(t)
	handler := srv.requireIPRateLimit(srv.ipLimiter, srv.handleAuthCallback)

	makeReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?token=sometoken", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()
		handler(w, req)
		return w
	}

	// First 2 requests (burst) should not return 429.
	for i := range 2 {
		w := makeReq()
		if w.Code == http.StatusTooManyRequests {
			t.Errorf("request %d should not be rate limited", i)
		}
	}

	// Third request should be rate limited.
	w := makeReq()
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

func TestAuthCallback_POSTRateLimitByIP(t *testing.T) {
	srv, _, _ := setupRateLimitedServer(t)
	handler := srv.requireIPRateLimit(srv.ipLimiter, srv.handleAuthCallback)

	makeReq := func() *httptest.ResponseRecorder {
		form := url.Values{"token": {"sometoken"}}
		req := httptest.NewRequest(http.MethodPost, "/auth/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.0.0.2:12345"
		w := httptest.NewRecorder()
		handler(w, req)
		return w
	}

	// First 2 requests (burst) should not return 429.
	for i := range 2 {
		w := makeReq()
		if w.Code == http.StatusTooManyRequests {
			t.Errorf("request %d should not be rate limited", i)
		}
	}

	// Third request should be rate limited.
	w := makeReq()
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429 response")
	}
}

func TestAuthPoll_RateLimitByIP(t *testing.T) {
	srv, _, _ := setupRateLimitedServer(t)
	handler := srv.requireIPRateLimit(srv.pollIPLimiter, srv.handleAuthPoll)

	makeReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/auth/poll", nil)
		req.RemoteAddr = "10.0.0.3:12345"
		w := httptest.NewRecorder()
		handler(w, req)
		return w
	}

	// First 2 requests (burst) should not return 429.
	for i := range 2 {
		w := makeReq()
		if w.Code == http.StatusTooManyRequests {
			t.Errorf("request %d should not be rate limited", i)
		}
	}

	// Third request should be rate limited.
	w := makeReq()
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429 response")
	}
}

// TestRequireEmailRateLimit_NoUserInContext_FailsClosed guards the
// programmer-error branch in requireEmailRateLimit: if the middleware
// is wired without requireAuth in front of it, it must respond 500
// rather than silently skipping the rate limit.
func TestRequireEmailRateLimit_NoUserInContext_FailsClosed(t *testing.T) {
	srv, _, _ := setupTestServer(t)
	rl := NewRateLimiter(10, 1*time.Minute)

	called := false
	handler := srv.requireEmailRateLimit(rl, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	if called {
		t.Error("next handler must not be called when user context is missing")
	}
}

// TestRequireAuthRateLimited_AuthFailureDoesNotConsumeEmailLimit verifies
// the middleware ordering inside requireAuthRateLimited: requireAuth runs
// before requireEmailRateLimit, so requests that fail authentication must
// not consume the per-email budget. We exercise this by sending several
// unauthenticated requests through the chain (which should be rejected at
// the auth step) and then confirming an authenticated user still has the
// full email budget available.
func TestRequireAuthRateLimited_AuthFailureDoesNotConsumeEmailLimit(t *testing.T) {
	ctx := context.Background()
	s, err := sqlite.NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	user := &store.User{Email: "auth-order@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	session := &store.Session{
		UserID:    user.ID,
		TokenHash: auth.HashToken("auth-order-session"),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	if err := s.CreateSession(ctx, session); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	const emailLimit = 2
	srv := NewServer(ServerConfig{
		Store:            s,
		SMTP:             &mockEmailSender{},
		BaseURL:          "http://localhost:8080",
		IPLimiter:        NewRateLimiter(50, 1*time.Minute),
		AuthEmailLimiter: NewRateLimiter(emailLimit, 1*time.Minute),
	})

	handler := srv.requireAuthRateLimited(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// 5 unauthenticated requests — should be rejected by requireAuth
	// (303 redirect to /login) and never reach the email limiter.
	for i := range 5 {
		req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		req.RemoteAddr = "10.0.0.20:12345"
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("unauthenticated request %d unexpectedly rate limited", i)
		}
	}

	makeAuth := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		req.RemoteAddr = "10.0.0.20:12345"
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "auth-order-session"})
		w := httptest.NewRecorder()
		handler(w, req)
		return w
	}

	// The full email budget must still be available.
	for i := range emailLimit {
		w := makeAuth()
		if w.Code != http.StatusOK {
			t.Errorf("authenticated request %d expected 200, got %d", i, w.Code)
		}
	}

	// Budget exhausted — next authenticated request should 429.
	w := makeAuth()
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after exhausting email budget, got %d", w.Code)
	}
}

// TestRequireAuthRateLimited_IPLimitFor429 verifies that the per-IP
// rate limiter applies on authenticated routes (the outermost wrap
// in requireAuthRateLimited).
func TestRequireAuthRateLimited_IPLimitFor429(t *testing.T) {
	ctx := context.Background()
	s, err := sqlite.NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	user := &store.User{Email: "ip-limit@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}
	session := &store.Session{
		UserID:    user.ID,
		TokenHash: auth.HashToken("ip-limit-session"),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	if err := s.CreateSession(ctx, session); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	const ipLimit = 2
	srv := NewServer(ServerConfig{
		Store:     s,
		SMTP:      &mockEmailSender{},
		BaseURL:   "http://localhost:8080",
		IPLimiter: NewRateLimiter(ipLimit, 1*time.Minute),
		// No email limiter, so the only relevant cap is per-IP.
	})

	handler := srv.requireAuthRateLimited(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	makeReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		req.RemoteAddr = "10.0.0.30:12345"
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "ip-limit-session"})
		w := httptest.NewRecorder()
		handler(w, req)
		return w
	}

	for i := range ipLimit {
		w := makeReq()
		if w.Code != http.StatusOK {
			t.Errorf("authenticated request %d expected 200, got %d", i, w.Code)
		}
	}

	w := makeReq()
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after exhausting IP budget, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429 response")
	}
}

// TestCreateSubscription_EmailType_IgnoresClientSuppliedEmail pins the
// server's invariant that an email subscription's recipient is sourced
// from the authenticated user record, not the request body. The
// subscriptionRequest type has no notificationEmail field; the JSON
// decoder silently drops the key if a client sends it. Dispatch later
// uses pm.User.Email (see notify_test.go), closing both the
// spam-dispatcher vector and the per-recipient rate-limit bypass via
// aliasing.
func TestCreateSubscription_EmailType_IgnoresClientSuppliedEmail(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "third-party address in body is ignored",
			body: `{"name":"email sub","monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"notificationType":"email","notificationEmail":"victim@example.com"}`,
		},
		{
			name: "aliased form of own email in body is ignored",
			body: `{"name":"email sub","monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"notificationType":"email","notificationEmail":"  Email-Sub@Example.COM  "}`,
		},
		{
			name: "syntactically invalid value in body is ignored",
			body: `{"name":"email sub","monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"notificationType":"email","notificationEmail":"not-an-email"}`,
		},
		{
			name: "missing field is fine",
			body: `{"name":"email sub","monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"notificationType":"email"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, s, _ := setupTestServer(t)
			user := createTestUserSession(t, s, "email-sub@example.com", "email-sub-session")

			req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "email-sub-session"})

			mux := testMux(t, srv)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusCreated {
				t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
			}

			subs, err := s.ListSubscriptionsByUser(context.Background(), user.ID)
			if err != nil {
				t.Fatalf("failed to list subscriptions: %v", err)
			}
			if len(subs) != 1 {
				t.Fatalf("expected 1 subscription, got %d", len(subs))
			}
			if subs[0].NotificationType != store.NotificationTypeEmail {
				t.Errorf("notification type = %q, want %q", subs[0].NotificationType, store.NotificationTypeEmail)
			}
		})
	}
}

// TestCreateSubscription_EmailType_ZeroesWebhookURL pins that an email
// subscription doesn't retain a client-supplied webhookURL — the
// stored row carries data only for the active channel. The dispatcher
// gates on NotificationType today, but stale text in WebhookURL would
// still surface in /api/subscriptions JSON. The malformed-URL cases
// also pin the documented control-flow split: validateWebhookURL runs
// only inside the webhook branch of parseSubscriptionBody, so an
// email subscription must accept (and silently drop) a malformed
// webhookURL rather than rejecting the request with 400.
func TestCreateSubscription_EmailType_ZeroesWebhookURL(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "well-formed webhookURL",
			body: `{"name":"zero unused","monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"notificationType":"email","webhookURL":"https://hooks.example.com/leak"}`,
		},
		{
			name: "malformed webhookURL (not a url)",
			body: `{"name":"zero unused","monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"notificationType":"email","webhookURL":"not a url"}`,
		},
		{
			name: "dangerous-scheme webhookURL",
			body: `{"name":"zero unused","monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"notificationType":"email","webhookURL":"javascript:alert(1)"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, s, _ := setupTestServer(t)
			user := createTestUserSession(t, s, "zero-unused@example.com", "zero-unused-session")

			req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "zero-unused-session"})

			mux := testMux(t, srv)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusCreated {
				t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
			}

			subs, err := s.ListSubscriptionsByUser(context.Background(), user.ID)
			if err != nil {
				t.Fatalf("failed to list subscriptions: %v", err)
			}
			if len(subs) != 1 {
				t.Fatalf("expected 1 subscription, got %d", len(subs))
			}
			if subs[0].NotificationType != store.NotificationTypeEmail {
				t.Errorf("notification type = %q, want %q", subs[0].NotificationType, store.NotificationTypeEmail)
			}
			if subs[0].WebhookURL != "" {
				t.Errorf("webhook URL = %q, want empty", subs[0].WebhookURL)
			}
		})
	}
}

// TestCreateSubscription_InvalidNotificationType pins that a
// notificationType the server doesn't recognize is rejected with 400.
// An unknown value ("sms") and an empty/omitted value are both invalid:
// the channel is required, so there is no implicit default.
func TestCreateSubscription_InvalidNotificationType(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "unknown type",
			body: `{"name":"bad type","monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"notificationType":"sms"}`,
		},
		{
			name: "empty type",
			body: `{"name":"bad type","monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"notificationType":""}`,
		},
		{
			name: "omitted type",
			body: `{"name":"bad type","monitoredValue":{"type":"fingerprint","fingerprint":"DEADBEEF"},"webhookURL":"https://hooks.example.com/x"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, s, _ := setupTestServer(t)
			createTestUserSession(t, s, "bad-type@example.com", "bad-type-session")

			req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "bad-type-session"})

			mux := testMux(t, srv)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

// TestUpdateSubscription_SwitchNotificationType covers webhook<->email
// transitions in both directions. The email->webhook direction matters
// most: validateWebhookURL has to rerun on a field that was empty while
// the subscription was email-only, and a missing/malformed URL must
// reject the update rather than silently produce an unreachable
// webhook subscription.
func TestUpdateSubscription_SwitchNotificationType(t *testing.T) {
	tests := []struct {
		name              string
		seedType          store.NotificationType
		seedWebhookURL    string
		body              string
		wantStatus        int
		wantNotifType     store.NotificationType
		wantWebhookURL    string
		wantErrorContains string
	}{
		{
			name:           "webhook to email succeeds and ignores any client-supplied email",
			seedType:       store.NotificationTypeWebhook,
			seedWebhookURL: "https://hooks.example.com/orig",
			body:           `{"name":"switch","monitoredValue":{"type":"fingerprint","fingerprint":"ORIGINAL"},"notificationType":"email","notificationEmail":"victim@example.com"}`,
			wantStatus:     http.StatusOK,
			wantNotifType:  store.NotificationTypeEmail,
		},
		{
			name:           "email to webhook with valid URL succeeds",
			seedType:       store.NotificationTypeEmail,
			body:           `{"name":"switch","monitoredValue":{"type":"fingerprint","fingerprint":"ORIGINAL"},"notificationType":"webhook","webhookURL":"https://hooks.example.com/new"}`,
			wantStatus:     http.StatusOK,
			wantNotifType:  store.NotificationTypeWebhook,
			wantWebhookURL: "https://hooks.example.com/new",
		},
		{
			name:              "email to webhook with missing URL returns 400",
			seedType:          store.NotificationTypeEmail,
			body:              `{"name":"switch","monitoredValue":{"type":"fingerprint","fingerprint":"ORIGINAL"},"notificationType":"webhook"}`,
			wantStatus:        http.StatusBadRequest,
			wantErrorContains: "Invalid webhook URL",
		},
		{
			name:              "email to webhook with malformed URL returns 400",
			seedType:          store.NotificationTypeEmail,
			body:              `{"name":"switch","monitoredValue":{"type":"fingerprint","fingerprint":"ORIGINAL"},"notificationType":"webhook","webhookURL":"not a url"}`,
			wantStatus:        http.StatusBadRequest,
			wantErrorContains: "Invalid webhook URL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, s, _ := setupTestServer(t)
			ctx := context.Background()
			user := createTestUserSession(t, s, "switch-type@example.com", "switch-type-session")

			sub := &store.Subscription{
				UserID:           user.ID,
				Name:             "switch",
				MonitoredValue:   identity.FingerprintValue{Fingerprint: "ORIGINAL"},
				NotificationType: tc.seedType,
				WebhookURL:       tc.seedWebhookURL,
			}
			if err := s.SaveSubscription(ctx, sub); err != nil {
				t.Fatalf("failed to save subscription: %v", err)
			}

			url := fmt.Sprintf("/api/subscriptions/%d", sub.ID)
			req := httptest.NewRequest(http.MethodPut, url, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "switch-type-session"})

			mux := testMux(t, srv)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("expected %d, got %d: %s", tc.wantStatus, w.Code, w.Body.String())
			}
			if tc.wantErrorContains != "" {
				if !strings.Contains(w.Body.String(), tc.wantErrorContains) {
					t.Errorf("expected response body to contain %q, got %q", tc.wantErrorContains, w.Body.String())
				}
				return
			}

			subs, err := s.ListSubscriptionsByUser(ctx, user.ID)
			if err != nil {
				t.Fatalf("failed to list subscriptions: %v", err)
			}
			if len(subs) != 1 {
				t.Fatalf("expected 1 subscription, got %d", len(subs))
			}
			if subs[0].NotificationType != tc.wantNotifType {
				t.Errorf("notification type = %q, want %q", subs[0].NotificationType, tc.wantNotifType)
			}
			if subs[0].WebhookURL != tc.wantWebhookURL {
				t.Errorf("webhook URL = %q, want %q", subs[0].WebhookURL, tc.wantWebhookURL)
			}
		})
	}
}
