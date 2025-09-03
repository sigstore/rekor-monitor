// Copyright 2025 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestStartMetricsServer verifies that the metrics server starts and serves the /metrics endpoint.
func TestStartMetricsServer(t *testing.T) {
	port := 9465
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go func() {
		if err := StartMetricsServer(ctx, port); err != nil {
			t.Errorf("StartMetricsServer failed: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
	if err != nil {
		t.Fatalf("Failed to query /metrics: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "log_index_verification_total") ||
		!strings.Contains(string(body), "log_index_verification_failure") {
		t.Errorf("metrics missing:\n%s", body)
	}

	// Cancel context to shutdown server
	cancel()
	time.Sleep(50 * time.Millisecond)

	_, err = http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
	if err == nil {
		t.Error("Expected connection error after shutdown, but request succeeded")
	}
}

// TestIncLogIndexVerificationTotal verifies that the total verification counter increments correctly.
func TestIncLogIndexVerificationTotal(t *testing.T) {
	port := 9471
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go StartMetricsServer(ctx, port)
	time.Sleep(100 * time.Millisecond)

	// Increment
	IncLogIndexVerificationTotal()

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "log_index_verification_total 1") {
		t.Errorf("expected counter incremented, got:\n%s", body)
	}
}

// TestIncLogIndexVerificationFailure verifies that the failure counter increments correctly.
func TestIncLogIndexVerificationFailure(t *testing.T) {
	port := 9472 // unique port to avoid conflicts
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go StartMetricsServer(ctx, port)
	time.Sleep(100 * time.Millisecond)

	// Increment the failure counter
	IncLogIndexVerificationFailure()

	// Fetch metrics
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
	if err != nil {
		t.Fatalf("Failed to query /metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	b := string(body)

	// Assert counter incremented
	if !strings.Contains(b, "log_index_verification_failure 1") {
		t.Errorf("expected failure counter incremented, got:\n%s", b)
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
