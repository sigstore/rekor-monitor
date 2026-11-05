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
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/auth"
	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/store"
)

//go:embed static templates
var content embed.FS

// EmailSender is the interface for sending emails. The concrete smtp.Sender
// satisfies this interface; tests can provide a no-op or recording mock.
type EmailSender interface {
	Send(ctx context.Context, to, subject, body string) error
}

// contextKey is an unexported type for context keys in this package.
type contextKey int

const userContextKey contextKey = 0

const sessionCookieName = "session_token"

const sessionCookieMaxAgeHours = 24 * time.Hour

type namedOIDOption struct {
	Name string `json:"name"`
	OID  string `json:"oid"`
}

type dashboardData struct {
	Email     string
	KnownOIDs []namedOIDOption
}

// Route paths.
const (
	routeLanding                     = "/"
	routeLogin                       = "/login"
	routeAuthCallback                = "/auth/callback"
	routeAuthPoll                    = "/auth/poll"
	routeLogout                      = "/logout"
	routeDashboard                   = "/dashboard"
	routeAPIMatches                  = "/api/matches"
	routeAPISubscriptions            = "/api/subscriptions"
	routeAPISubscriptionsByID        = "/api/subscriptions/{id}"
	routeAPISubscriptionsByIDEnable  = "/api/subscriptions/{id}/enable"
	routeAPISubscriptionsByIDDisable = "/api/subscriptions/{id}/disable"
)

// UserFromContext extracts the authenticated user from the request context.
func UserFromContext(ctx context.Context) (*store.User, error) {
	u, ok := ctx.Value(userContextKey).(*store.User)
	if !ok {
		return nil, fmt.Errorf("no authenticated user in context")
	}
	return u, nil
}

// Server represents the web server for rekor-watch.
type Server struct {
	store                   store.TransactionalStore
	smtp                    EmailSender
	baseURL                 string
	allowPrivateWebhooks    bool
	maxSubscriptionsPerUser int
	httpServer              *http.Server
	dashTmpl                *template.Template
	emailLinkTmpl           *template.Template
	confirmLoginTmpl        *template.Template
	checkEmailTmpl          *template.Template
	knownOIDs               []namedOIDOption

	ipLimiter         *RateLimiter
	loginEmailLimiter *RateLimiter
	pollIPLimiter     *RateLimiter
	authEmailLimiter  *RateLimiter

	trustProxyHeaders bool
}

// ServerConfig holds the configuration for the web server.
type ServerConfig struct {
	Store                store.TransactionalStore
	SMTP                 EmailSender
	BaseURL              string
	AllowPrivateWebhooks bool
	TrustProxyHeaders    bool

	// MaxSubscriptionsPerUser caps how many subscriptions a single user
	// may own (counted across both enabled and disabled rows).
	// Enforced on POST /api/subscriptions; PUT/DELETE remain unaffected
	// so users above the cap can still drain organically.
	MaxSubscriptionsPerUser int

	// Rate limiters below. Nil means no limiting for that scope.

	// IPLimiter applies a per-IP cap to /login, /auth/callback, and all
	// authenticated routes (dashboard + /api/*). It guards every request
	// path that does real work, except the long-polled /auth/poll.
	IPLimiter *RateLimiter
	// LoginEmailLimiter applies a per-email cap to /login submissions to
	// throttle magic-link emails for a single address (limit reached
	// rendering still shows the check-email page to avoid leaking whether
	// the address is registered).
	LoginEmailLimiter *RateLimiter
	// PollIPLimiter applies a per-IP cap specifically to /auth/poll, which
	// the confirm-login page hits every few seconds for up to 15 minutes
	// and therefore needs a more flexible budget than IPLimiter.
	PollIPLimiter *RateLimiter
	// AuthEmailLimiter applies a per-email cap (keyed by the authenticated
	// user's email) to the dashboard and /api/* routes.
	AuthEmailLimiter *RateLimiter
}

// NewServer creates a new web server.
func NewServer(cfg ServerConfig) *Server {
	data, err := content.ReadFile("templates/dashboard.html")
	if err != nil {
		panic(fmt.Sprintf("failed to read dashboard template: %v", err))
	}
	tmpl, err := template.New("dashboard").Parse(string(data))
	if err != nil {
		panic(fmt.Sprintf("failed to parse dashboard template: %v", err))
	}

	emailData, err := content.ReadFile("templates/magic_link_email.html")
	if err != nil {
		panic(fmt.Sprintf("failed to read magic link email template: %v", err))
	}
	emailTmpl, err := template.New("magic_link_email").Parse(string(emailData))
	if err != nil {
		panic(fmt.Sprintf("failed to parse magic link email template: %v", err))
	}

	confirmData, err := content.ReadFile("templates/confirm_login.html")
	if err != nil {
		panic(fmt.Sprintf("failed to read confirm login template: %v", err))
	}
	confirmTmpl, err := template.New("confirm_login").Parse(string(confirmData))
	if err != nil {
		panic(fmt.Sprintf("failed to parse confirm login template: %v", err))
	}

	checkEmailData, err := content.ReadFile("templates/check_email.html")
	if err != nil {
		panic(fmt.Sprintf("failed to read check email template: %v", err))
	}
	checkEmailTmpl, err := template.New("check_email").Parse(string(checkEmailData))
	if err != nil {
		panic(fmt.Sprintf("failed to parse check email template: %v", err))
	}

	named := extensions.AllNamedOIDs()
	knownOIDs := make([]namedOIDOption, 0, len(named))
	for _, namedOID := range named {
		knownOIDs = append(knownOIDs, namedOIDOption{
			Name: namedOID.Name,
			OID:  namedOID.OID.String(),
		})
	}

	return &Server{
		store:                   cfg.Store,
		smtp:                    cfg.SMTP,
		baseURL:                 strings.TrimRight(cfg.BaseURL, "/"),
		allowPrivateWebhooks:    cfg.AllowPrivateWebhooks,
		maxSubscriptionsPerUser: cfg.MaxSubscriptionsPerUser,
		trustProxyHeaders:       cfg.TrustProxyHeaders,
		dashTmpl:                tmpl,
		emailLinkTmpl:           emailTmpl,
		confirmLoginTmpl:        confirmTmpl,
		checkEmailTmpl:          checkEmailTmpl,
		knownOIDs:               knownOIDs,
		ipLimiter:               cfg.IPLimiter,
		loginEmailLimiter:       cfg.LoginEmailLimiter,
		pollIPLimiter:           cfg.PollIPLimiter,
		authEmailLimiter:        cfg.AuthEmailLimiter,
	}
}

// newMux builds the HTTP route table. It is used by Start and by tests.
func (s *Server) newMux() (*http.ServeMux, error) {
	mux := http.NewServeMux()

	// Serve static files
	staticFS, err := fs.Sub(content, "static")
	if err != nil {
		return nil, fmt.Errorf("failed to create static filesystem: %w", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Public routes
	mux.HandleFunc(routeLanding, s.handleLanding)

	// Public routes with IP rate limiting
	mux.HandleFunc(routeLogin,
		s.requireIPRateLimit(s.ipLimiter, s.handleLogin))
	mux.HandleFunc(routeAuthCallback,
		s.requireIPRateLimit(s.ipLimiter, s.handleAuthCallback))
	mux.HandleFunc(routeAuthPoll,
		s.requireIPRateLimit(s.pollIPLimiter, s.handleAuthPoll))

	// Authenticated routes with IP + email rate limiting
	mux.HandleFunc(routeLogout, s.requireAuthRateLimited(s.handleLogout))
	mux.HandleFunc(routeDashboard, s.requireAuthRateLimited(s.handleDashboard))
	mux.HandleFunc(routeAPIMatches, s.requireAuthRateLimited(s.handleMatches))
	mux.HandleFunc("GET "+routeAPISubscriptions, s.requireAuthRateLimited(s.handleListSubscriptions))
	mux.HandleFunc("POST "+routeAPISubscriptions, s.requireAuthRateLimited(s.handleCreateSubscription))
	mux.HandleFunc("PUT "+routeAPISubscriptionsByID, s.requireAuthRateLimited(s.handleUpdateSubscription))
	mux.HandleFunc("DELETE "+routeAPISubscriptionsByID, s.requireAuthRateLimited(s.handleDeleteSubscription))
	mux.HandleFunc("POST "+routeAPISubscriptionsByIDEnable, s.requireAuthRateLimited(s.handleEnableSubscription))
	mux.HandleFunc("POST "+routeAPISubscriptionsByIDDisable, s.requireAuthRateLimited(s.handleDisableSubscription))

	return mux, nil
}

// Start binds the web server to the given port and serves in the
// background. It returns immediately after the listener is
// established, so callers can detect port conflicts synchronously.
// The server shuts down gracefully when ctx is cancelled.
func (s *Server) Start(ctx context.Context, port int) error {
	mux, err := s.newMux()
	if err != nil {
		return err
	}

	s.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("web server failed to listen on port %d: %w", port, err)
	}

	// Graceful shutdown when ctx is cancelled
	go func() {
		<-ctx.Done()
		log.Println("Shutting down web server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("Web server shutdown error: %v", err)
		}
	}()

	log.Printf("Web server listening on http://localhost:%d", port)
	go func() {
		if err := s.httpServer.Serve(ln); err != http.ErrServerClosed {
			log.Printf("Web server error: %v", err)
		}
	}()

	// Start background cleanup of expired tokens and sessions
	go s.cleanupLoop(ctx)

	return nil
}

// cleanupLoop periodically deletes expired auth tokens and sessions.
// It runs every hour until ctx is cancelled.
func (s *Server) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.runCleanup(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// runCleanup deletes expired auth tokens and sessions from the database,
// and removes stale rate limiter entries.
func (s *Server) runCleanup(ctx context.Context) {
	tokensDeleted, err := s.store.DeleteExpiredAuthTokens(ctx)
	if err != nil {
		log.Printf("Error cleaning up expired auth tokens: %v", err)
	} else if tokensDeleted > 0 {
		log.Printf("Cleaned up %d expired auth token(s)", tokensDeleted)
	}

	sessionsDeleted, err := s.store.DeleteExpiredSessions(ctx)
	if err != nil {
		log.Printf("Error cleaning up expired sessions: %v", err)
	} else if sessionsDeleted > 0 {
		log.Printf("Cleaned up %d expired session(s)", sessionsDeleted)
	}

	for _, rl := range []*RateLimiter{s.ipLimiter, s.loginEmailLimiter, s.pollIPLimiter, s.authEmailLimiter} {
		if rl != nil {
			rl.Cleanup()
		}
	}
}

// writeRateLimited sends a 429 response with a Retry-After header.
func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int(retryAfter.Seconds()) + 1 // round up
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	http.Error(w, "Too many requests", http.StatusTooManyRequests)
}

// serveStaticTemplate reads an embedded template file and writes it as HTML.
func serveStaticTemplate(w http.ResponseWriter, name string) {
	data, err := content.ReadFile(name)
	if err != nil {
		http.Error(w, "Failed to load page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(data); err != nil {
		log.Printf("Error writing %s response: %v", name, err)
	}
}

// setSessionCookie sets or clears the session cookie.
func setSessionCookie(w http.ResponseWriter, token string, maxAgeDuration time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAgeDuration.Seconds()),
		Secure:   true,
	})
}

func deleteSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Secure:   true,
	})
}

// authenticatedUser returns the user behind the session cookie, or nil
// if there is no cookie, the session is invalid, or the user is missing.
func (s *Server) authenticatedUser(r *http.Request) *store.User {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	session, user, err := s.store.GetSessionWithUser(
		r.Context(), auth.HashToken(cookie.Value),
	)
	if err != nil {
		log.Printf("Error validating session: %v", err)
		return nil
	}
	if session == nil || user == nil {
		return nil
	}
	return user
}

// requireAuth is middleware that validates the session cookie and injects
// the authenticated user into the request context. Returns 401 for API
// requests and redirects to /login for page requests.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := s.authenticatedUser(r)
		if user == nil {
			s.authFailed(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey, user)
		next(w, r.WithContext(ctx))
	}
}

// requireIPRateLimit is middleware that rejects requests when the
// per-IP rate limit is exceeded, returning 429 with Retry-After.
func (s *Server) requireIPRateLimit(
	rl *RateLimiter, next http.HandlerFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if rl != nil {
			ip := s.clientIP(r)
			if ok, retryAfter := rl.Allow(ip); !ok {
				//nolint:gosec // G706: %q escapes control chars, preventing log injection
				log.Printf("IP rate limit exceeded: ip=%q path=%q retryAfter=%s",
					ip, r.URL.Path, retryAfter)
				writeRateLimited(w, retryAfter)
				return
			}
		}
		next(w, r)
	}
}

// requireAuthRateLimited composes the standard middleware stack for
// authenticated routes: per-IP rate limit, then session auth, then
// per-email rate limit.
func (s *Server) requireAuthRateLimited(next http.HandlerFunc) http.HandlerFunc {
	return s.requireIPRateLimit(s.ipLimiter,
		s.requireAuth(
			s.requireEmailRateLimit(s.authEmailLimiter, next)))
}

// requireEmailRateLimit is middleware that rejects requests when the
// per-email rate limit is exceeded. It extracts the email from the
// authenticated user in the request context, so it must be chained
// after requireAuth.
func (s *Server) requireEmailRateLimit(
	rl *RateLimiter, next http.HandlerFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if rl != nil {
			user, err := UserFromContext(r.Context())
			if err != nil {
				// No user in context means this middleware was wired
				// without requireAuth in front of it. Fail closed
				// rather than silently skipping the rate limit.
				log.Printf("requireEmailRateLimit: no user in context: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if ok, retryAfter := rl.Allow(user.Email); !ok {
				//nolint:gosec // G706: %q escapes control chars, preventing log injection
				log.Printf("Email rate limit exceeded: email=%q path=%q retryAfter=%s",
					user.Email, r.URL.Path, retryAfter)
				writeRateLimited(w, retryAfter)
				return
			}
		}
		next(w, r)
	}
}

// authFailed returns 401 for API routes, redirects to /login for pages.
func (s *Server) authFailed(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, routeLogin, http.StatusSeeOther)
}

// handleLanding serves the public landing page.
func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != routeLanding {
		http.NotFound(w, r)
		return
	}

	// Redirect authenticated users to the dashboard.
	if user := s.authenticatedUser(r); user != nil {
		http.Redirect(w, r, routeDashboard, http.StatusSeeOther)
		return
	}

	serveStaticTemplate(w, "templates/landing.html")
}

// handleLogin serves the login form (GET) or processes login (POST).
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// If already logged in, redirect to dashboard.
		if user := s.authenticatedUser(r); user != nil {
			http.Redirect(w, r, routeDashboard, http.StatusSeeOther)
			return
		}

		serveStaticTemplate(w, "templates/login.html")

	case http.MethodPost:
		s.handleLoginPost(w, r)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLoginPost processes the login form submission.
func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit for login form
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// Validate email format
	if _, err := mail.ParseAddress(email); err != nil {
		http.Error(w, "Invalid email address", http.StatusBadRequest)
		return
	}

	// Per-email rate limit: silently show check-email page to avoid
	// leaking whether the email address is registered.
	if s.loginEmailLimiter != nil {
		if allowed, retryAfter := s.loginEmailLimiter.Allow(email); !allowed {
			//nolint:gosec // G706: %q escapes control chars, preventing log injection
			log.Printf("Email rate limit exceeded: email=%q path=%q retryAfter=%s",
				email, r.URL.Path, retryAfter)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := s.checkEmailTmpl.Execute(w, nil); err != nil {
				log.Printf("Error rendering check email page: %v", err)
			}
			return
		}
	}

	// Generate auth token keyed by email (user creation is
	// deferred until the token is validated in the callback).
	tokenStr, err := auth.GenerateToken(auth.AuthTokenBytes)
	if err != nil {
		log.Printf("Error generating auth token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	authToken := &store.AuthToken{
		Email:     email,
		TokenHash: auth.HashToken(tokenStr),
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
	}
	if err := s.store.CreateAuthToken(r.Context(), authToken); err != nil {
		log.Printf("Error saving auth token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Send magic link email
	magicLink := fmt.Sprintf("%s%s?token=%s", s.baseURL, routeAuthCallback, tokenStr)
	var emailBody bytes.Buffer
	if err := s.emailLinkTmpl.Execute(&emailBody, struct{ MagicLink string }{magicLink}); err != nil {
		log.Printf("Error rendering magic link email: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := s.smtp.Send(r.Context(), email, "Sign in to Rekor Watch", emailBody.String()); err != nil {
		log.Printf("Error sending magic link email: %v", err)
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		return
	}

	// Show check-email page
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.checkEmailTmpl.Execute(w, nil); err != nil {
		log.Printf("Error rendering check email page: %v", err)
	}
}

// handleAuthCallback handles the magic-link flow in two steps:
//   - GET  renders a confirmation page with a "Sign In" button.
//   - POST consumes the token, creates a session, and redirects to the dashboard.
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleAuthCallbackConfirm(w, r)
	case http.MethodPost:
		s.handleAuthCallbackActivate(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAuthCallbackConfirm renders the confirmation page so the user must
// explicitly click "Sign In" to activate the magic-link token.
func (s *Server) handleAuthCallbackConfirm(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.confirmLoginTmpl.Execute(w, struct{ Token string }{tokenStr}); err != nil {
		log.Printf("Error rendering confirm login page: %v", err)
	}
}

// handleAuthCallbackActivate consumes the magic-link token, creates a
// session, and redirects to the dashboard.
func (s *Server) handleAuthCallbackActivate(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.FormValue("token")
	if tokenStr == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	authToken, err := s.store.ConsumeAuthToken(r.Context(), auth.HashToken(tokenStr))
	if err != nil {
		log.Printf("Error consuming auth token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if authToken == nil {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	// Find or create the user now that the email is verified.
	user, err := s.store.GetUserByEmail(r.Context(), authToken.Email)
	if err != nil {
		log.Printf("Error looking up user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		user = &store.User{Email: authToken.Email}
		if err := s.store.SaveUser(r.Context(), user); err != nil {
			log.Printf("Error creating user: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	// Create session
	sessionToken, err := auth.GenerateToken(auth.SessionTokenBytes)
	if err != nil {
		log.Printf("Error generating session token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	session := &store.Session{
		UserID:    user.ID,
		TokenHash: auth.HashToken(sessionToken),
		ExpiresAt: time.Now().UTC().Add(sessionCookieMaxAgeHours),
	}
	if err := s.store.CreateSession(r.Context(), session); err != nil {
		log.Printf("Error creating session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	setSessionCookie(w, sessionToken, sessionCookieMaxAgeHours)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true}`)
}

// handleAuthPoll lets the check-email page detect when the session cookie has
// been set (i.e. the user confirmed the magic link in another tab).
func (s *Server) handleAuthPoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authenticated := s.authenticatedUser(r) != nil

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"authenticated":%t}`, authenticated)
}

// handleLogout deletes the session and clears the cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if err := s.store.DeleteSession(r.Context(), auth.HashToken(cookie.Value)); err != nil {
			log.Printf("Error deleting session: %v", err)
		}
	}

	deleteSessionCookie(w)

	http.Redirect(w, r, routeLanding, http.StatusSeeOther)
}

// handleDashboard serves the authenticated dashboard page.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := userFromRequest(w, r)
	if user == nil {
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.dashTmpl.Execute(w, dashboardData{
		Email:     user.Email,
		KnownOIDs: s.knownOIDs,
	}); err != nil {
		log.Printf("Error executing dashboard template: %v", err)
	}
}

// handleMatches returns matches scoped to the authenticated user.
func (s *Server) handleMatches(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := userFromRequest(w, r)
	if user == nil {
		return
	}
	matches, err := s.store.ListMatchesWithSubByUser(r.Context(), user.ID)
	if err != nil {
		log.Printf("Error listing matches: %v", err)
		http.Error(w, "Failed to fetch matches", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(matches); err != nil {
		log.Printf("Error encoding matches response: %v", err)
	}
}

// userFromRequest extracts the authenticated user from the request context.
// Returns nil and writes an HTTP 500 error on failure.
func userFromRequest(w http.ResponseWriter, r *http.Request) *store.User {
	user, err := UserFromContext(r.Context())
	if err != nil {
		log.Printf("Error getting user from context: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return nil
	}
	return user
}

// subscriptionIDFromPath extracts and validates the {id} path value.
func subscriptionIDFromPath(r *http.Request) (int64, error) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid subscription ID: %w", err)
	}
	if id <= 0 {
		return 0, fmt.Errorf("invalid subscription ID: must be positive")
	}
	return id, nil
}

// handleListSubscriptions returns subscriptions for the authenticated user.
func (s *Server) handleListSubscriptions(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(w, r)
	if user == nil {
		return
	}
	subs, err := s.store.ListSubscriptionsByUser(r.Context(), user.ID)
	if err != nil {
		log.Printf("Error listing subscriptions: %v", err)
		http.Error(w, "Failed to fetch subscriptions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(subs); err != nil {
		log.Printf("Error encoding subscriptions response: %v", err)
	}
}

// maxSubscriptionNameLen caps the length of a subscription name (in bytes)
// to keep card titles and stored labels reasonable.
const maxSubscriptionNameLen = 200

// subscriptionRequest is the common JSON body for create and update.
type subscriptionRequest struct {
	Name             string                 `json:"name"`
	MonitoredValue   json.RawMessage        `json:"monitoredValue"`
	NotificationType store.NotificationType `json:"notificationType"`
	WebhookURL       string                 `json:"webhookURL"`
}

// parseSubscriptionBody decodes, validates, and returns the parsed request.
// Returns nil and writes an HTTP error on failure.
//
// Email subscriptions are always delivered to the authenticated user's
// verified address (pm.User.Email at dispatch time). The request body
// has no notificationEmail field: the contact address is owned by the
// user record, not per-subscription. This keeps the user from
// directing notifications at a third-party mailbox (which would let
// them use this server as a spam dispatcher) and ensures the
// per-recipient rate limiter keys on a single normalized address per
// user.
func (s *Server) parseSubscriptionBody(w http.ResponseWriter, r *http.Request) (*subscriptionRequest, identity.MonitoredValue) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req subscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return nil, nil
		}
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return nil, nil
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		http.Error(w, "Subscription name is required", http.StatusBadRequest)
		return nil, nil
	}
	if len(req.Name) > maxSubscriptionNameLen {
		http.Error(w, fmt.Sprintf("Subscription name too long (max %d characters)", maxSubscriptionNameLen), http.StatusBadRequest)
		return nil, nil
	}

	switch req.NotificationType {
	case store.NotificationTypeWebhook:
		if err := validateWebhookURL(req.WebhookURL, s.allowPrivateWebhooks); err != nil {
			http.Error(w, fmt.Sprintf("Invalid webhook URL: %v", err), http.StatusBadRequest)
			return nil, nil
		}
	case store.NotificationTypeEmail:
		// Zero the unused webhook URL so the stored row only carries
		// data for the active channel — stale text in WebhookURL would
		// otherwise surface in /api/subscriptions JSON.
		req.WebhookURL = ""
	default:
		http.Error(w, "Invalid notification type: must be 'webhook' or 'email'", http.StatusBadRequest)
		return nil, nil
	}

	mv, err := identity.ParseMatchedIdentityJSON(req.MonitoredValue)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid monitored value: %v", err), http.StatusBadRequest)
		return nil, nil
	}
	if err := mv.Verify(); err != nil {
		http.Error(w, fmt.Sprintf("Invalid monitored value: %v", err), http.StatusBadRequest)
		return nil, nil
	}

	return &req, mv
}

// handleCreateSubscription creates a new subscription for the authenticated user.
//
// The count + insert run inside a single transaction so two concurrent
// POSTs from the same user at the boundary cannot both succeed.
func (s *Server) handleCreateSubscription(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(w, r)
	if user == nil {
		return
	}

	req, mv := s.parseSubscriptionBody(w, r)
	if req == nil {
		return
	}

	sub := &store.Subscription{
		UserID:           user.ID,
		Name:             req.Name,
		MonitoredValue:   mv,
		NotificationType: req.NotificationType,
		WebhookURL:       req.WebhookURL,
	}

	tx, err := s.store.BeginTx(r.Context())
	if err != nil {
		log.Printf("Error beginning transaction: %v", err)
		http.Error(w, "Failed to create subscription", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback() //nolint:errcheck

	count, err := tx.CountSubscriptionsByUser(r.Context(), user.ID)
	if err != nil {
		log.Printf("Error counting subscriptions: %v", err)
		http.Error(w, "Failed to create subscription", http.StatusInternalServerError)
		return
	}
	if count >= s.maxSubscriptionsPerUser {
		http.Error(w, fmt.Sprintf("Subscription limit reached (max %d per user)", s.maxSubscriptionsPerUser), http.StatusConflict)
		return
	}

	if err := tx.SaveSubscription(r.Context(), sub); err != nil {
		if errors.Is(err, store.ErrDuplicateName) {
			http.Error(w, fmt.Sprintf("You already have a subscription named %q", sub.Name), http.StatusConflict)
			return
		}
		log.Printf("Error saving subscription: %v", err)
		http.Error(w, "Failed to create subscription", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("Error committing subscription: %v", err)
		http.Error(w, "Failed to create subscription", http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(sub)
	if err != nil {
		log.Printf("Error encoding subscription response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if _, err := w.Write(data); err != nil {
		log.Printf("Error writing subscription response: %v", err)
	}
}

// handleUpdateSubscription updates an existing subscription for the authenticated user.
func (s *Server) handleUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(w, r)
	if user == nil {
		return
	}

	id, err := subscriptionIDFromPath(r)
	if err != nil {
		http.Error(w, "Invalid subscription ID", http.StatusBadRequest)
		return
	}

	req, mv := s.parseSubscriptionBody(w, r)
	if req == nil {
		return
	}

	sub := &store.Subscription{
		ID:               id,
		UserID:           user.ID,
		Name:             req.Name,
		MonitoredValue:   mv,
		NotificationType: req.NotificationType,
		WebhookURL:       req.WebhookURL,
	}
	if err := s.store.UpdateSubscription(r.Context(), sub); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "Subscription not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, store.ErrDuplicateName) {
			http.Error(w, fmt.Sprintf("You already have a subscription named %q", sub.Name), http.StatusConflict)
			return
		}
		log.Printf("Error updating subscription: %v", err)
		http.Error(w, "Failed to update subscription", http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(sub)
	if err != nil {
		log.Printf("Error encoding subscription response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(data); err != nil {
		log.Printf("Error writing subscription response: %v", err)
	}
}

// handleDeleteSubscription deletes a subscription for the authenticated user.
func (s *Server) handleDeleteSubscription(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(w, r)
	if user == nil {
		return
	}

	id, err := subscriptionIDFromPath(r)
	if err != nil {
		http.Error(w, "Invalid subscription ID", http.StatusBadRequest)
		return
	}

	if err := s.store.DeleteSubscription(r.Context(), id, user.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "Subscription not found", http.StatusNotFound)
			return
		}
		log.Printf("Error deleting subscription: %v", err)
		http.Error(w, "Failed to delete subscription", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleDisableSubscription manually disables a subscription for the authenticated user.
func (s *Server) handleDisableSubscription(w http.ResponseWriter, r *http.Request) {
	s.setSubscriptionEnabled(w, r, false)
}

// handleEnableSubscription re-enables a disabled subscription for the authenticated user.
func (s *Server) handleEnableSubscription(w http.ResponseWriter, r *http.Request) {
	s.setSubscriptionEnabled(w, r, true)
}

func (s *Server) setSubscriptionEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	user := userFromRequest(w, r)
	if user == nil {
		return
	}

	id, err := subscriptionIDFromPath(r)
	if err != nil {
		http.Error(w, "Invalid subscription ID", http.StatusBadRequest)
		return
	}

	if err := s.store.SetSubscriptionEnabled(r.Context(), id, user.ID, enabled); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "Subscription not found", http.StatusNotFound)
			return
		}
		action := "enabling"
		if !enabled {
			action = "disabling"
		}
		log.Printf("Error %s subscription: %v", action, err)
		http.Error(w, "Failed to update subscription", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
