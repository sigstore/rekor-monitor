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
	"net/http"
	"time"
)

// cgnatBlock is the shared address space defined in RFC 6598
// (100.64.0.0/10), used for Carrier-grade NAT.
// Go's net.IP.IsPrivate() does not cover this range.
var cgnatBlock = mustParseCIDR("100.64.0.0/10")

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// IsBlocked reports whether ip is not a publicly-routable unicast address.
// It permits only addresses that are global unicast and not RFC-1918 /
// IPv6 unique-local (which Go considers global unicast per RFC 4291),
// and also blocks the RFC 6598 shared address space (100.64.0.0/10).
func IsBlocked(ip net.IP) bool {
	return !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnatBlock.Contains(ip)
}

// safeDialContext returns a DialContext that blocks connections to non-public
// addresses (loopback, link-local, RFC-1918, multicast) to prevent SSRF.
// The hostname is resolved once and the connection is dialed to the resolved
// IP directly, preventing DNS-rebinding attacks.
func safeDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("safenet: failed to parse address %q: %w", addr, err)
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("safenet: failed to resolve host %q: %w", host, err)
		}

		safe := make([]net.IPAddr, 0, len(ips))
		for _, ip := range ips {
			if !IsBlocked(ip.IP) {
				safe = append(safe, ip)
			}
		}

		if len(safe) == 0 {
			return nil, fmt.Errorf(
				"safenet: connections to private/link-local addresses are not permitted (host %q resolved to blocked IPs only)",
				host,
			)
		}

		// Try each safe address in order; return on the first successful
		// connection. Iterating the pre-resolved IPs avoids a second DNS
		// lookup on each attempt, preventing DNS-rebinding between tries.
		var lastErr error
		for _, ip := range safe {
			var conn net.Conn
			conn, lastErr = dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if lastErr == nil {
				return conn, nil
			}
		}
		return nil, lastErr
	}
}

// NewSafeHTTPClient returns an http.Client whose transport blocks connections
// to loopback, RFC-1918, and link-local addresses to prevent SSRF.
func NewSafeHTTPClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	defaultTimeout := 30 * time.Second
	t.DialContext = safeDialContext(&net.Dialer{
		Timeout:   defaultTimeout,
		KeepAlive: defaultTimeout,
	})
	return &http.Client{Transport: t, Timeout: defaultTimeout}
}
