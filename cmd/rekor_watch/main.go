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
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"net/http"

	"github.com/sigstore/rekor-monitor/cmd/rekor_watch/web"
	"github.com/sigstore/rekor-monitor/pkg/email"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	safenet "github.com/sigstore/rekor-monitor/pkg/net"
	"github.com/sigstore/rekor-monitor/pkg/store/sqlite"
	rmutil "github.com/sigstore/rekor-monitor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/root"
	"sigs.k8s.io/release-utils/version"
)

// Default values for monitoring job parameters
const (
	TUFRepository = "staging"
	// The monitor config is not published by TUF yet, so it is read from a file
	// shipped in this repository. The default tracks TUFRepository.
	// See https://github.com/trailofbits/rekor-watch/issues/38
	defaultMonitorConfigPath = "targets/staging/monitor_config.json"
	defaultDBPath            = "rekor_watch.db"
	defaultWebPort           = 8080
	defaultBaseURL           = "http://localhost:8080"
	defaultSMTPHost          = "localhost"
	defaultSMTPPort          = 1025
	defaultSMTPFrom          = "rekor-watch@localhost"
	defaultSMTPHelo          = "rekor-watch.sigstore.org"
	defaultInterval          = 5 * time.Minute

	// Subscription cap defaults.
	defaultMaxSubscriptionsPerUser = 20

	// Match cap defaults. The cap is per-subscription; older matches are
	// evicted FIFO when the cap is exceeded.
	defaultMaxMatchesPerSubscription = 1000

	// Rate limiting defaults.
	defaultIPRate           = 60
	defaultIPWindow         = 1 * time.Minute
	defaultLoginEmailRate   = 20
	defaultLoginEmailWindow = 15 * time.Minute
	defaultPollIPRate       = 100
	defaultPollIPWindow     = 1 * time.Minute
	defaultAuthEmailRate    = 60
	defaultAuthEmailWindow  = 1 * time.Minute
)

// Environment variable names for configuration overrides
const (
	envInterval             = "REKOR_WATCH_INTERVAL"
	envUserAgent            = "REKOR_WATCH_USER_AGENT_STRING"
	envTUFRepository        = "REKOR_WATCH_TUF_REPOSITORY"
	envTUFRootPath          = "REKOR_WATCH_TUF_ROOT_PATH"
	envMonitorConfig        = "REKOR_WATCH_MONITOR_CONFIG"
	envCARoots              = "REKOR_WATCH_CA_ROOTS"
	envCAIntermediates      = "REKOR_WATCH_CA_INTERMEDIATES"
	envHTTPSChain           = "REKOR_WATCH_HTTPS_CHAIN"
	envDBPath               = "REKOR_WATCH_DB_PATH"
	envWebPort              = "REKOR_WATCH_WEB_PORT"
	envBaseURL              = "REKOR_WATCH_BASE_URL"
	envSMTPHost             = "REKOR_WATCH_SMTP_HOST"
	envSMTPPort             = "REKOR_WATCH_SMTP_PORT"
	envSMTPFrom             = "REKOR_WATCH_SMTP_FROM"
	envSMTPUsername         = "REKOR_WATCH_SMTP_USERNAME"
	envSMTPPassword         = "REKOR_WATCH_SMTP_PASSWORD" //nolint:gosec // G101: env var name, not a credential
	envSMTPUseTLS           = "REKOR_WATCH_SMTP_USE_TLS"
	envSMTPHELO             = "REKOR_WATCH_SMTP_HELO"
	envSMTPAuthType         = "REKOR_WATCH_SMTP_AUTH_TYPE"
	envAllowPrivateWebhooks = "REKOR_WATCH_ALLOW_PRIVATE_WEBHOOKS"

	envMaxSubscriptionsPerUser   = "REKOR_WATCH_MAX_SUBSCRIPTIONS_PER_USER"
	envMaxMatchesPerSubscription = "REKOR_WATCH_MAX_MATCHES_PER_SUBSCRIPTION"

	envRateLimitEnabled          = "REKOR_WATCH_RATE_LIMIT_ENABLED"
	envRateLimitIPRate           = "REKOR_WATCH_RATE_LIMIT_IP_RATE"
	envRateLimitIPWindow         = "REKOR_WATCH_RATE_LIMIT_IP_WINDOW" //nolint:gosec // G101: env var name, not a credential
	envRateLimitLoginEmailRate   = "REKOR_WATCH_RATE_LIMIT_LOGIN_EMAIL_RATE"
	envRateLimitLoginEmailWindow = "REKOR_WATCH_RATE_LIMIT_LOGIN_EMAIL_WINDOW"
	envRateLimitPollIPRate       = "REKOR_WATCH_RATE_LIMIT_POLL_IP_RATE"
	envRateLimitPollIPWindow     = "REKOR_WATCH_RATE_LIMIT_POLL_IP_WINDOW" //nolint:gosec // G101: env var name, not a credential
	envRateLimitAuthEmailRate    = "REKOR_WATCH_RATE_LIMIT_AUTH_EMAIL_RATE"
	envRateLimitAuthEmailWindow  = "REKOR_WATCH_RATE_LIMIT_AUTH_EMAIL_WINDOW"
	envTrustProxyHeaders         = "REKOR_WATCH_TRUST_PROXY_HEADERS"
)

// envUsage appends the environment variable name to a flag usage string.
func envUsage(envKey, usage string) string {
	return fmt.Sprintf("%s (env: %s)", usage, envKey)
}

// envOrDefault returns the environment variable value if set, otherwise the fallback.
func envOrDefault(envKey, fallback string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return fallback
}

// envOrDefaultInt returns the environment variable value as an int if set, otherwise the fallback.
func envOrDefaultInt(envKey string, fallback int) int {
	if v := os.Getenv(envKey); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
		log.Fatalf("Warning: %s env variable does not contain a number", envKey)
	}
	return fallback
}

// envOrDefaultBool returns the environment variable value as a bool if set, otherwise the fallback.
func envOrDefaultBool(envKey string, fallback bool) bool {
	if v := os.Getenv(envKey); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
		log.Fatalf("Warning: %s env variable does not contain a bool\n", envKey)
	}
	return fallback
}

// validateMaxSubscriptionsPerUser rejects non-positive caps. Zero/negative
// would either disable the cap silently or insert junk rows; the design
// chooses to fail closed at startup.
func validateMaxSubscriptionsPerUser(v int) error {
	if v <= 0 {
		return fmt.Errorf("--max-subscriptions-per-user must be > 0, got %d", v)
	}
	return nil
}

// validateMaxMatchesPerSubscription rejects non-positive caps for the same
// reason as the subscription cap: silently disabling the cap by passing 0
// is too easy to miss.
func validateMaxMatchesPerSubscription(v int) error {
	if v <= 0 {
		return fmt.Errorf("--max-matches-per-subscription must be > 0, got %d", v)
	}
	return nil
}

// envOrDefaultDuration returns the environment variable value as a time.Duration if set, otherwise the fallback.
func envOrDefaultDuration(envKey string, fallback time.Duration) time.Duration {
	if v := os.Getenv(envKey); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		log.Fatalf("Warning: %s env variable does not contain a valid duration", envKey)
	}
	return fallback
}

func mainWithReturn() int {
	log.Println("Starting rekor-watch...")

	interval := flag.Duration("interval", envOrDefaultDuration(envInterval, defaultInterval), envUsage(envInterval, "Length of interval between each periodical consistency check"))
	userAgentString := flag.String("user-agent", envOrDefault(envUserAgent, ""), envUsage(envUserAgent, "details to include in the user agent string"))
	tufRepository := flag.String("tuf-repository", envOrDefault(envTUFRepository, TUFRepository), envUsage(envTUFRepository, "TUF repository to use. Can be 'default', 'staging' or a custom TUF repository URL."))
	tufRootPath := flag.String("tuf-root-path", envOrDefault(envTUFRootPath, ""), envUsage(envTUFRootPath, "path to the trusted root file (passed out of bounds), if custom TUF repository is used"))
	monitorConfigPath := flag.String("monitor-config", envOrDefault(envMonitorConfig, defaultMonitorConfigPath), envUsage(envMonitorConfig, "path to the monitor config file (a protojson-encoded dev.sigstore.monitor.v1.MonitorConfig) listing the logs to monitor"))
	caRootsFilePath := flag.String("ca-roots", envOrDefault(envCARoots, ""), envUsage(envCARoots, "path to a bundle file of CA certificates in PEM format"))
	caIntermediatesFilePath := flag.String("ca-intermediates", envOrDefault(envCAIntermediates, ""), envUsage(envCAIntermediates, "path to a bundle file of CA intermediate certificates in PEM format. The flag must be used together with --ca-roots"))
	httpsChainPath := flag.String("https-cert-chain", envOrDefault(envHTTPSChain, ""), envUsage(envHTTPSChain, "path to a list of CA certificates in PEM format for the HTTPS connection to the log server"))
	dbPath := flag.String("db", envOrDefault(envDBPath, defaultDBPath), envUsage(envDBPath, "path to SQLite database file for storing checkpoints (use :memory: for in-memory)"))
	webPort := flag.Int("web-port", envOrDefaultInt(envWebPort, defaultWebPort), envUsage(envWebPort, "port for web UI server (0 to disable)"))
	baseURL := flag.String("base-url", envOrDefault(envBaseURL, defaultBaseURL), envUsage(envBaseURL, "base URL for the web server (used in magic link emails)"))
	smtpHost := flag.String("smtp-host", envOrDefault(envSMTPHost, defaultSMTPHost), envUsage(envSMTPHost, "SMTP server host"))
	smtpPort := flag.Int("smtp-port", envOrDefaultInt(envSMTPPort, defaultSMTPPort), envUsage(envSMTPPort, "SMTP server port"))
	smtpFrom := flag.String("smtp-from", envOrDefault(envSMTPFrom, defaultSMTPFrom), envUsage(envSMTPFrom, "SMTP sender address"))
	smtpUsername := flag.String("smtp-username", envOrDefault(envSMTPUsername, ""), envUsage(envSMTPUsername, "SMTP username for authentication"))
	smtpPassword := flag.String("smtp-password", "", envUsage(envSMTPPassword, "SMTP password for authentication"))
	smtpUseTLS := flag.Bool("smtp-use-tls", envOrDefaultBool(envSMTPUseTLS, false), envUsage(envSMTPUseTLS, "use TLS for SMTP connection"))
	smtpHELO := flag.String("smtp-helo", envOrDefault(envSMTPHELO, defaultSMTPHelo), envUsage(envSMTPHELO, "SMTP HELO domain"))
	smtpAuthType := flag.String("smtp-auth-type", envOrDefault(envSMTPAuthType, "PLAIN"), envUsage(envSMTPAuthType, "SMTP authentication type (PLAIN, XOAUTH2)"))
	maxSubscriptionsPerUser := flag.Int("max-subscriptions-per-user", envOrDefaultInt(envMaxSubscriptionsPerUser, defaultMaxSubscriptionsPerUser), envUsage(envMaxSubscriptionsPerUser, "maximum subscriptions a single user may own (must be > 0)"))
	maxMatchesPerSubscription := flag.Int("max-matches-per-subscription", envOrDefaultInt(envMaxMatchesPerSubscription, defaultMaxMatchesPerSubscription), envUsage(envMaxMatchesPerSubscription, "maximum matches retained per subscription; older matches are evicted FIFO when exceeded (must be > 0)"))
	flag.Parse()

	if err := validateMaxSubscriptionsPerUser(*maxSubscriptionsPerUser); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}
	if err := validateMaxMatchesPerSubscription(*maxMatchesPerSubscription); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	if *smtpPassword == "" {
		*smtpPassword = os.Getenv(envSMTPPassword)
	}

	log.Printf("Configuration: interval=%v, tufRepository=%s, monitorConfig=%s, dbPath=%s, webPort=%d", *interval, *tufRepository, *monitorConfigPath, *dbPath, *webPort)

	if *caIntermediatesFilePath != "" && *caRootsFilePath == "" {
		log.Fatalf("ca-intermediates must be used together with --ca-roots")
	}

	finalUserAgent := strings.TrimSpace(fmt.Sprintf("%s/%s (%s; %s) %s",
		"rekor-watch",
		version.GetVersionInfo().GitVersion,
		runtime.GOOS,
		runtime.GOARCH,
		*userAgentString,
	))
	log.Printf("User-Agent: %s", finalUserAgent)

	ctx := context.Background()

	log.Printf("Initializing TUF client with repository: %s", *tufRepository)
	tufClient, err := rmutil.GetTUFClient(*tufRepository, *tufRootPath)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("TUF client initialized successfully")

	log.Println("Fetching trusted root from TUF...")
	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Trusted root fetched successfully")

	log.Println("Configuring trusted CAs...")
	newCARootsFile, newCAIntermediatesFile, cleanupTrustedCAs, err := rmutil.ConfigureTrustedCAs(*caRootsFilePath, *caIntermediatesFilePath, trustedRoot)
	if err != nil {
		log.Fatal(err)
	}
	*caRootsFilePath = newCARootsFile
	*caIntermediatesFilePath = newCAIntermediatesFile
	defer cleanupTrustedCAs()
	log.Printf("Trusted CAs configured: roots=%s, intermediates=%s", newCARootsFile, newCAIntermediatesFile)

	// Initialize SQLite store for checkpoints and matches
	log.Printf("Initializing SQLite store at: %s", *dbPath)
	dbStore, err := sqlite.NewStore(ctx, *dbPath)
	if err != nil {
		log.Printf("Failed to initialize database store: %v", err)
		return 1
	}
	defer dbStore.Close()
	log.Println("SQLite store initialized successfully")

	smtpSender, err := email.NewSender(email.Config{
		Host:         *smtpHost,
		Port:         *smtpPort,
		From:         *smtpFrom,
		Username:     *smtpUsername,
		SMTPPassword: *smtpPassword,
		SMTPHELO:     *smtpHELO,
		UseTLS:       *smtpUseTLS,
		SMTPAuthType: *smtpAuthType,
	})
	if err != nil {
		log.Printf("Failed to initialize SMTP sender: %v", err)
		return 1
	}

	allowPrivateWebhooks := envOrDefaultBool(envAllowPrivateWebhooks, false)

	if *webPort > 0 {
		webCfg := web.ServerConfig{
			Store:                   dbStore,
			SMTP:                    smtpSender,
			BaseURL:                 *baseURL,
			AllowPrivateWebhooks:    allowPrivateWebhooks,
			TrustProxyHeaders:       envOrDefaultBool(envTrustProxyHeaders, false),
			MaxSubscriptionsPerUser: *maxSubscriptionsPerUser,
		}

		if envOrDefaultBool(envRateLimitEnabled, true) {
			ipRate := envOrDefaultInt(envRateLimitIPRate, defaultIPRate)
			ipWin := envOrDefaultDuration(envRateLimitIPWindow, defaultIPWindow)
			loginEmailRate := envOrDefaultInt(envRateLimitLoginEmailRate, defaultLoginEmailRate)
			loginEmailWin := envOrDefaultDuration(envRateLimitLoginEmailWindow, defaultLoginEmailWindow)
			pollIPRate := envOrDefaultInt(envRateLimitPollIPRate, defaultPollIPRate)
			pollIPWin := envOrDefaultDuration(envRateLimitPollIPWindow, defaultPollIPWindow)
			authEmailRate := envOrDefaultInt(envRateLimitAuthEmailRate, defaultAuthEmailRate)
			authEmailWin := envOrDefaultDuration(envRateLimitAuthEmailWindow, defaultAuthEmailWindow)

			webCfg.IPLimiter = web.NewRateLimiter(ipRate, ipWin)
			webCfg.LoginEmailLimiter = web.NewRateLimiter(loginEmailRate, loginEmailWin)
			webCfg.PollIPLimiter = web.NewRateLimiter(pollIPRate, pollIPWin)
			webCfg.AuthEmailLimiter = web.NewRateLimiter(authEmailRate, authEmailWin)

			log.Printf("Rate limiting enabled: IP %d req/%v, login-email %d req/%v, poll-IP %d req/%v, auth-email %d req/%v",
				ipRate, ipWin, loginEmailRate, loginEmailWin, pollIPRate, pollIPWin, authEmailRate, authEmailWin)
		} else {
			log.Println("Rate limiting disabled")
		}

		webServer := web.NewServer(webCfg)
		if err := webServer.Start(ctx, *webPort); err != nil {
			log.Printf("Failed to start web server: %v", err)
			return 1
		}
	}

	searchOpts := []identity.SearchOption{
		identity.WithCARootsFile(newCARootsFile),
		identity.WithCAIntermediatesFile(newCAIntermediatesFile),
	}

	log.Println("Starting Rekor v2 main loop...")
	tracker, err := newShardTracker(ctx, tufClient, *monitorConfigPath, finalUserAgent, *httpsChainPath)
	if err != nil {
		log.Printf("error getting Rekor shards: %v\n", err)
		return 1
	}
	mon := &monitor{
		tracker:    tracker,
		store:      dbStore,
		searchOpts: searchOpts,
		maxMatches: *maxMatchesPerSubscription,
	}
	// Rate-limit outbound notifications to 5 per second per destination
	// host to avoid overwhelming subscriber endpoints.
	notificationLimiter := web.NewRateLimiter(5, 1*time.Second)
	notif := newNotifier(dbStore, finalUserAgent, newWebhookClient(allowPrivateWebhooks), notificationLimiter, smtpSender)
	notifyFn := func(ctx context.Context) error { return notif.runOnce(ctx, time.Now()) }
	return monitorLoop(ctx, *interval, mon.runOnce, notifyFn)
}

// IterationFunc is a function that performs a single monitoring iteration.
// Returns nil on success, error on failure.
type IterationFunc func(ctx context.Context) error

// monitorLoop runs the monitoring loop with the given iteration function.
// It handles the ticker, signal handling, and graceful shutdown.
// After each iteration, notifyFn is called to deliver pending notifications.
func monitorLoop(ctx context.Context, interval time.Duration, iterationFn, notifyFn IterationFunc) int {
	// Set up signal handling for graceful shutdown
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run the monitoring loop
	for {
		log.Printf("New monitor run at %s", time.Now().Format(time.RFC3339))

		if err := iterationFn(ctx); err != nil {
			log.Printf("Monitoring iteration failed: %v", err)
			// Continue to next iteration on error
		} else {
			log.Println("Monitoring iteration completed successfully")
		}

		if err := notifyFn(ctx); err != nil {
			log.Printf("Notification delivery failed: %v", err)
		}

		log.Printf("Waiting %v until next iteration...", interval)
		select {
		case <-ticker.C:
			continue
		case <-ctx.Done():
			log.Println("Shutting down gracefully...")
			return 0
		}
	}
}

// newWebhookClient returns the HTTP client used for outbound webhook
// delivery. With allowPrivate set, SSRF protection is disabled so the client
// can reach loopback/private addresses (intended for local testing).
func newWebhookClient(allowPrivate bool) *http.Client {
	if allowPrivate {
		log.Printf("WARNING: %s is set — SSRF protection disabled\n", envAllowPrivateWebhooks)
		return &http.Client{}
	}
	return safenet.NewSafeHTTPClient()
}

func main() {
	os.Exit(mainWithReturn())
}
