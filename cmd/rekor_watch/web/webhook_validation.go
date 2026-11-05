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
	"net"
	"net/url"

	safenet "github.com/sigstore/rekor-monitor/pkg/net"
)

const maxWebhookURLLength = 2048

// validateWebhookURL checks that rawURL is a well-formed, safe webhook
// destination. When allowPrivate is false it also resolves the hostname
// and rejects URLs whose addresses are all private/loopback.
//
// Note: this check is best-effort (DNS can change between validation and
// delivery). The safe dialer's IsBlocked check at connection time remains
// the authoritative SSRF guard; this just gives users early feedback.
func validateWebhookURL(rawURL string, allowPrivate bool) error {
	if rawURL == "" {
		return fmt.Errorf("webhookURL is required")
	}

	if len(rawURL) > maxWebhookURLLength {
		return fmt.Errorf("webhook URL exceeds maximum length of %d characters", maxWebhookURLLength)
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("webhook URL is not a valid URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("webhook URL scheme must be http or https, got %q", u.Scheme)
	}

	if u.Hostname() == "" {
		return fmt.Errorf("webhook URL must include a hostname")
	}

	if u.User != nil {
		return fmt.Errorf("webhook URL must not contain embedded credentials")
	}

	if u.Fragment != "" {
		return fmt.Errorf("webhook URL must not contain a fragment")
	}

	if !allowPrivate {
		ips, err := net.LookupIP(u.Hostname())
		if err != nil {
			return fmt.Errorf("webhook URL hostname %q could not be resolved: %w", u.Hostname(), err)
		}
		allBlocked := true
		for _, ip := range ips {
			if !safenet.IsBlocked(ip) {
				allBlocked = false
				break
			}
		}
		if allBlocked {
			return fmt.Errorf("webhook URL hostname %q resolves to a private/loopback address", u.Hostname())
		}
	}

	return nil
}
