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
	"strings"
	"testing"
)

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		allowPrivate bool
		wantErr      string // empty means no error expected
	}{
		// Valid URLs
		{
			name:         "valid https URL",
			url:          "https://hooks.example.com/notify",
			allowPrivate: true,
			wantErr:      "",
		},
		{
			name:         "valid http URL",
			url:          "http://hooks.example.com/notify", // DevSkim: ignore DS137138 - intentional HTTP in test
			allowPrivate: true,
			wantErr:      "",
		},
		{
			name:         "valid https with port",
			url:          "https://hooks.example.com:8443/notify",
			allowPrivate: true,
			wantErr:      "",
		},
		{
			name:         "valid https with path and query",
			url:          "https://hooks.example.com/webhook?token=abc",
			allowPrivate: true,
			wantErr:      "",
		},

		// Bad scheme
		{
			name:         "ftp scheme rejected",
			url:          "ftp://hooks.example.com/notify",
			allowPrivate: true,
			wantErr:      "scheme must be http or https",
		},
		{
			name:         "javascript scheme rejected",
			url:          "javascript:alert(1)", //nolint:gosec // test case
			allowPrivate: true,
			wantErr:      "scheme must be http or https",
		},
		{
			name:         "empty scheme rejected",
			url:          "://hooks.example.com",
			allowPrivate: true,
			wantErr:      "not a valid URL",
		},

		// Missing host
		{
			name:         "no hostname",
			url:          "https:///path",
			allowPrivate: true,
			wantErr:      "must include a hostname",
		},

		// Embedded credentials
		{
			name:         "userinfo rejected",
			url:          "https://user:pass@hooks.example.com/notify",
			allowPrivate: true,
			wantErr:      "must not contain embedded credentials",
		},
		{
			name:         "user only rejected",
			url:          "https://user@hooks.example.com/notify",
			allowPrivate: true,
			wantErr:      "must not contain embedded credentials",
		},

		// Fragment
		{
			name:         "fragment rejected",
			url:          "https://hooks.example.com/notify#section",
			allowPrivate: true,
			wantErr:      "must not contain a fragment",
		},

		// Length exceeded
		{
			name:         "URL too long",
			url:          "https://hooks.example.com/" + strings.Repeat("a", maxWebhookURLLength),
			allowPrivate: true,
			wantErr:      "exceeds maximum length",
		},

		// Private IP rejection
		{
			name:         "localhost rejected when not allowed",
			url:          "https://localhost/notify",
			allowPrivate: false,
			wantErr:      "resolves to a private/loopback address",
		},
		{
			name:         "127.0.0.1 rejected when not allowed",
			url:          "https://127.0.0.1/notify",
			allowPrivate: false,
			wantErr:      "resolves to a private/loopback address",
		},

		// Private IP allowed
		{
			name:         "localhost allowed when private allowed",
			url:          "https://localhost/notify",
			allowPrivate: true,
			wantErr:      "",
		},
		{
			name:         "127.0.0.1 allowed when private allowed",
			url:          "https://127.0.0.1/notify",
			allowPrivate: true,
			wantErr:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWebhookURL(tt.url, tt.allowPrivate)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}
