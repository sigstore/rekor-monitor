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
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(3, 1*time.Minute)

	for i := range 3 {
		if allowed, _ := rl.Allow("key"); !allowed {
			t.Errorf("request %d should be allowed", i)
		}
	}

	allowed, retryAfter := rl.Allow("key")
	if allowed {
		t.Error("request after limit should be denied")
	}
	if retryAfter <= 0 {
		t.Error("retryAfter should be positive when denied")
	}
}

func TestRateLimiter_DifferentKeys(t *testing.T) {
	rl := NewRateLimiter(1, 1*time.Minute)

	if allowed, _ := rl.Allow("a"); !allowed {
		t.Error("first request for key 'a' should be allowed")
	}
	if allowed, _ := rl.Allow("a"); allowed {
		t.Error("second request for key 'a' should be denied")
	}

	if allowed, _ := rl.Allow("b"); !allowed {
		t.Error("first request for key 'b' should be allowed")
	}
}

func TestRateLimiter_FullRejectsNewKeys(t *testing.T) {
	rl := NewRateLimiter(1, 1*time.Hour)

	for i := range maxEntries {
		rl.Allow(fmt.Sprintf("key%d", i))
	}

	allowed, retryAfter := rl.Allow("newkey")
	if allowed {
		t.Error("new key should be rejected when full and all entries fresh")
	}
	if retryAfter != 1*time.Hour {
		t.Errorf("retryAfter should be the window duration, got %v", retryAfter)
	}
}

func TestRateLimiter_FullEvictsStale(t *testing.T) {
	rl := NewRateLimiter(1, 1*time.Minute)

	for i := range maxEntries {
		rl.Allow(fmt.Sprintf("key%d", i))
	}

	// Make all entries stale.
	rl.mu.Lock()
	for _, e := range rl.entries {
		e.lastSeen = time.Now().Add(-2 * time.Minute)
	}
	rl.mu.Unlock()

	if allowed, _ := rl.Allow("newkey"); !allowed {
		t.Error("new key should be allowed after stale entries are swept")
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	rl := NewRateLimiter(1, 1*time.Minute)

	rl.Allow("old")
	rl.Allow("new")

	rl.mu.Lock()
	rl.entries["old"].lastSeen = time.Now().Add(-2 * time.Minute)
	rl.mu.Unlock()

	rl.Cleanup()

	rl.mu.Lock()
	_, hasOld := rl.entries["old"]
	_, hasNew := rl.entries["new"]
	rl.mu.Unlock()

	if hasOld {
		t.Error("stale entry should have been cleaned up")
	}
	if !hasNew {
		t.Error("fresh entry should still exist")
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name              string
		trustProxyHeaders bool
		xff               string
		xRealIP           string
		remoteAddr        string
		want              string
	}{
		{
			name:              "trusted: X-Forwarded-For single",
			trustProxyHeaders: true,
			xff:               "1.2.3.4",
			remoteAddr:        "9.9.9.9:1234",
			want:              "1.2.3.4",
		},
		{
			name:              "trusted: X-Forwarded-For multiple takes rightmost",
			trustProxyHeaders: true,
			xff:               "spoofed.by.client, 1.2.3.4",
			remoteAddr:        "9.9.9.9:1234",
			want:              "1.2.3.4",
		},
		{
			name:              "trusted: X-Real-IP",
			trustProxyHeaders: true,
			xRealIP:           "10.0.0.1",
			remoteAddr:        "9.9.9.9:1234",
			want:              "10.0.0.1",
		},
		{
			name:              "trusted: X-Real-IP takes precedence over XFF",
			trustProxyHeaders: true,
			xff:               "1.1.1.1",
			xRealIP:           "2.2.2.2",
			remoteAddr:        "3.3.3.3:80",
			want:              "2.2.2.2",
		},
		{
			name:       "untrusted: ignores X-Forwarded-For",
			xff:        "1.2.3.4",
			remoteAddr: "9.9.9.9:1234",
			want:       "9.9.9.9",
		},
		{
			name:       "untrusted: ignores X-Real-IP",
			xRealIP:    "10.0.0.1",
			remoteAddr: "9.9.9.9:1234",
			want:       "9.9.9.9",
		},
		{
			name:              "trusted: invalid X-Real-IP falls through to RemoteAddr",
			trustProxyHeaders: true,
			xRealIP:           "not-an-ip",
			remoteAddr:        "9.9.9.9:1234",
			want:              "9.9.9.9",
		},
		{
			name:              "trusted: invalid XFF falls through to RemoteAddr",
			trustProxyHeaders: true,
			xff:               "garbage, also-garbage",
			remoteAddr:        "9.9.9.9:1234",
			want:              "9.9.9.9",
		},
		{
			name:              "trusted: invalid X-Real-IP with valid XFF uses XFF",
			trustProxyHeaders: true,
			xRealIP:           "not-an-ip",
			xff:               "1.2.3.4",
			remoteAddr:        "9.9.9.9:1234",
			want:              "1.2.3.4",
		},
		{
			name:       "RemoteAddr with port",
			remoteAddr: "192.168.1.1:5000",
			want:       "192.168.1.1",
		},
		{
			name:       "RemoteAddr without port",
			remoteAddr: "192.168.1.1",
			want:       "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &Server{trustProxyHeaders: tt.trustProxyHeaders}
			r := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     http.Header{},
			}
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			got := srv.clientIP(r)
			if got != tt.want {
				t.Errorf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
