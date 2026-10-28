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

package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	safenet "github.com/sigstore/rekor-monitor/pkg/net"
)

// WebhookSender POSTs JSON payloads to a subscription's webhook URL.
type WebhookSender struct {
	userAgent  string
	httpClient *http.Client
}

// NewWebhookSender returns a WebhookSender that uses the provided httpClient
// for all outbound requests. If httpClient is nil a safe (SSRF-protected)
// client is created automatically.
func NewWebhookSender(userAgent string, httpClient *http.Client) *WebhookSender {
	if httpClient == nil {
		httpClient = safenet.NewSafeHTTPClient()
	}
	return &WebhookSender{
		userAgent:  userAgent,
		httpClient: httpClient,
	}
}

// Send posts the payload as JSON to the given webhook URL.
func (s *WebhookSender) Send(ctx context.Context, url string, payload NotificationPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to build notification body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) //nolint:errcheck
		resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
