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
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestStartMetricsServer verifies that the metrics server starts and serves the /metrics endpoint.
func TestStartMetricsServer(t *testing.T) {
	// Use a unique port to avoid conflicts
	port := 9465
	go func() {
		if err := StartMetricsServer(port); err != nil {
			t.Errorf("StartMetricsServer failed: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
	if err != nil {
		t.Fatalf("Failed to query /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if !contains(string(body), "log_index_verification_total") {
		t.Errorf("Expected metric log_index_verification_total in response, not found")
	}
	if !contains(string(body), "log_index_verification_failure") {
		t.Errorf("Expected metric log_index_verification_failure in response, not found")
	}

	// Send SIGTERM to trigger graceful shutdown
	signalChan := GetSignalChan()
	signalChan <- os.Interrupt

	time.Sleep(100 * time.Millisecond)

	_, err = http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
	if err == nil {
		t.Error("Expected connection error after shutdown, but request succeeded")
	}
}

// TestIncLogIndexVerificationTotal verifies that the total verification counter increments correctly.
func TestIncLogIndexVerificationTotal(t *testing.T) {
	// Reset registry to isolate test
	InitRegistryForTesting()

	initialValue := testutil.ToFloat64(GetLogIndexVerificationTotal())

	IncLogIndexVerificationTotal()

	newValue := testutil.ToFloat64(GetLogIndexVerificationTotal())
	if newValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f (initial: %f)", newValue, initialValue)
	}
}

// TestIncLogIndexVerificationFailure verifies that the failure counter increments correctly.
func TestIncLogIndexVerificationFailure(t *testing.T) {
	InitRegistryForTesting()

	initialValue := testutil.ToFloat64(GetLogIndexVerificationFailure())

	IncLogIndexVerificationFailure()

	newValue := testutil.ToFloat64(GetLogIndexVerificationFailure())
	if newValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f (initial: %f)", newValue, initialValue)
	}
}

// TestGetSignalChan verifies that GetSignalChan returns a non-nil channel.
func TestGetSignalChan(t *testing.T) {
	signalChan := GetSignalChan()
	if signalChan == nil {
		t.Error("Expected non-nil signal channel, got nil")
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
