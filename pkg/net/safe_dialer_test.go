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

package net

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// IsBlocked unit tests
// ---------------------------------------------------------------------------

func TestIsBlocked(t *testing.T) {
	tests := []struct {
		ip      string
		blocked bool
	}{
		// Loopback
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"127.255.255.255", true},

		// RFC 1918
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},

		// RFC 6598 shared address space (CGNAT / Tailscale)
		{"100.64.0.0", true},
		{"100.64.0.1", true},
		{"100.100.100.100", true},
		{"100.127.255.255", true},

		// Link-local / cloud IMDS
		{"169.254.0.1", true},
		{"169.254.169.254", true}, // AWS/GCP/Azure IMDS

		// Unspecified
		{"0.0.0.0", true},

		// Multicast — not global unicast
		{"224.0.0.1", true},
		{"239.255.255.255", true},

		// Broadcast — not global unicast
		{"255.255.255.255", true},

		// IPv6 loopback
		{"::1", true},

		// IPv6 unique-local (fc00::/7)
		{"fc00::1", true},
		{"fd00::1", true},
		{"fd12:3456:789a::1", true},

		// IPv6 link-local
		{"fe80::1", true},
		{"fe80::dead:beef", true},

		// IPv6 multicast
		{"ff02::1", true},
		{"ff0e::1", true},

		// IPv6 unspecified
		{"::", true},

		// Public addresses — must NOT be blocked
		{"1.1.1.1", false},
		{"8.8.8.8", false},
		{"8.8.4.4", false},
		{"93.184.216.34", false}, // example.com
		{"104.16.0.0", false},    // Cloudflare
		// Public IPv6
		{"2606:4700:4700::1111", false}, // Cloudflare DNS
		{"2001:4860:4860::8888", false}, // Google DNS
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("invalid IP in test table: %q", tt.ip)
		}
		got := IsBlocked(ip)
		if got != tt.blocked {
			t.Errorf("IsBlocked(%q) = %v, want %v", tt.ip, got, tt.blocked)
		}
	}
}

// ---------------------------------------------------------------------------
// safeDialContext — blocked cases (connection is refused before TCP dial)
// ---------------------------------------------------------------------------

func TestSafeDialContext_Blocked(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		// Literal loopback IPs
		{"loopback 127.0.0.1", "127.0.0.1:80"},
		{"loopback 127.0.0.2", "127.0.0.2:80"},

		// Hostname that resolves to loopback
		{"localhost hostname", "localhost:80"},

		// RFC 1918
		{"private 10.0.0.1", "10.0.0.1:80"},
		{"private 172.16.0.1", "172.16.0.1:80"},
		{"private 192.168.1.1", "192.168.1.1:80"},

		// RFC 6598 CGNAT
		{"CGNAT 100.64.0.1", "100.64.0.1:80"},
		{"CGNAT 100.100.100.100", "100.100.100.100:80"},

		// Cloud IMDS
		{"IMDS 169.254.169.254", "169.254.169.254:80"},
		{"link-local 169.254.0.1", "169.254.0.1:80"},

		// IPv6 blocked
		{"IPv6 loopback ::1", "[::1]:80"},
		{"IPv6 link-local fe80::1", "[fe80::1]:80"},
		{"IPv6 unique-local fc00::1", "[fc00::1]:80"},
		{"IPv6 unique-local fd00::1", "[fd00::1]:80"},
	}

	dialer := &net.Dialer{}
	dial := safeDialContext(dialer)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := dial(context.Background(), "tcp", tt.addr)
			if err == nil {
				conn.Close()
				t.Fatal("expected blocked connection, got nil error")
			}
			if !strings.Contains(err.Error(), "safenet:") {
				t.Errorf("expected safenet error, got: %v", err)
			}
		})
	}
}

// TestSafeDialContext_MalformedAddr verifies a parse-level error is returned
// when the addr has no port component.
func TestSafeDialContext_MalformedAddr(t *testing.T) {
	dialer := &net.Dialer{}
	dial := safeDialContext(dialer)

	_, err := dial(context.Background(), "tcp", "no-port-here")
	if err == nil {
		t.Fatal("expected error for malformed addr, got nil")
	}
	if !strings.Contains(err.Error(), "safenet:") {
		t.Errorf("expected safenet error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NewSafeHTTPClient — end-to-end via http.Client
// ---------------------------------------------------------------------------

// TestNewSafeHTTPClient_BlocksHTTPToLoopback confirms that an http.Client
// from NewSafeHTTPClient cannot reach a server on 127.0.0.1 or via "localhost".
func TestNewSafeHTTPClient_BlocksHTTPToLoopback(t *testing.T) {
	// Bind a real TCP listener on loopback so the port is open;
	// the safe client must reject the connection before it is established.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	client := NewSafeHTTPClient()

	for _, host := range []string{"127.0.0.1", "localhost"} {
		url := fmt.Sprintf("http://%s/", net.JoinHostPort(host, fmt.Sprintf("%d", port))) // DevSkim: ignore DS137138 - intentional HTTP in test
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			t.Errorf("GET %s: expected SSRF error, got HTTP %d", url, resp.StatusCode)
			continue
		}
		if !strings.Contains(err.Error(), "safenet:") {
			t.Errorf("GET %s: expected safenet error, got: %v", url, err)
		}
	}
}
