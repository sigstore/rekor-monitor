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
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// maxEntries is the maximum number of tracked keys per limiter.
const maxEntries = 10000

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter is a keyed rate limiter. Each key gets its own token bucket
// via golang.org/x/time/rate. When the map is full, stale entries are
// swept; if every entry is still fresh the new key is rejected.
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	limit   int
	window  time.Duration
}

// NewRateLimiter creates a keyed rate limiter allowing limit requests
// per window for each key. limit must be > 0.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if limit <= 0 {
		panic("ratelimit: limit must be > 0")
	}
	return &RateLimiter{
		entries: make(map[string]*entry),
		limit:   limit,
		window:  window,
	}
}

// Allow reports whether a request for the given key should be allowed.
// If denied, retryAfter indicates how long the caller should wait.
func (rl *RateLimiter) Allow(key string) (allowed bool, retryAfter time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	if e, ok := rl.entries[key]; ok {
		e.lastSeen = now
		r := e.limiter.ReserveN(now, 1)
		if d := r.DelayFrom(now); d > 0 {
			r.Cancel()
			return false, d
		}
		return true, 0
	}

	// New key — make room if full.
	if len(rl.entries) >= maxEntries {
		rl.sweepStale(now)
		if len(rl.entries) >= maxEntries {
			return false, rl.window
		}
	}

	e := &entry{
		limiter:  rate.NewLimiter(rate.Every(rl.window/time.Duration(rl.limit)), rl.limit),
		lastSeen: now,
	}
	e.limiter.AllowN(now, 1)
	rl.entries[key] = e
	return true, 0
}

// Cleanup removes entries not seen within the window.
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.sweepStale(time.Now())
}

// sweepStale removes entries not seen within the window.
// Must be called with rl.mu held.
func (rl *RateLimiter) sweepStale(now time.Time) {
	for k, e := range rl.entries {
		if now.Sub(e.lastSeen) >= rl.window {
			delete(rl.entries, k)
		}
	}
}

// parseIP trims whitespace and returns the IP string only if it's valid.
func parseIP(s string) string {
	s = strings.TrimSpace(s)
	if net.ParseIP(s) != nil {
		return s
	}
	return ""
}

// clientIP extracts the client IP address from the request. When
// s.trustProxyHeaders is true it checks proxy headers before falling
// back to RemoteAddr. Trusting proxy headers without a trusted reverse
// proxy allows clients to spoof their IP.
//
// X-Real-IP is checked first because it is a single value set by the
// reverse proxy itself. X-Forwarded-For is an append-chain — we take
// the rightmost (last) entry, which is the one the trusted proxy appended
// (the client's real IP as seen by the proxy). Earlier entries in the
// chain may be client-supplied and spoofable.
func (s *Server) clientIP(r *http.Request) string {
	if s.trustProxyHeaders {
		if ip := parseIP(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}

		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the rightmost entry — the one appended by the trusted proxy.
			parts := strings.Split(xff, ",")
			if ip := parseIP(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}

	// RemoteAddr is host:port; strip the port.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
