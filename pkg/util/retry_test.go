// Copyright 2025 The Sigstore Authors.
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

package util

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

type HTTPError struct {
	Code int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP error with status code %d", e.Code)
}

func (e *HTTPError) StatusCode() int {
	return e.Code
}

type HTTP2Error struct {
	Message string
}

func (e *HTTP2Error) Error() string {
	return e.Message
}

func TestRetry(t *testing.T) {
	t.Run("retry_with_recoverable_error", func(t *testing.T) {
		attempts := 0
		result, err := Retry(context.Background(), func() (any, error) {
			attempts++
			if attempts < 3 {
				return nil, WrapError(&HTTPError{Code: http.StatusInternalServerError})
			}
			return "success after retries", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "success after retries" {
			t.Fatalf("expected 'success after retries', got %v", result)
		}
		if attempts != 3 {
			t.Fatalf("expected 3 attempts, got %d", attempts)
		}
	})

	t.Run("retry_with_http2_goaway_error", func(t *testing.T) {
		attempts := 0
		result, err := Retry(context.Background(), func() (any, error) {
			attempts++
			if attempts < 3 {
				return nil, WrapError(&HTTP2Error{Message: "http2: server sent GOAWAY"})
			}
			return "success after retries", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "success after retries" {
			t.Fatalf("expected 'success after retries', got %v", result)
		}
		if attempts != 3 {
			t.Fatalf("expected 3 attempts, got %d", attempts)
		}
	})

	t.Run("stop_retry_on_non_retryable_error", func(t *testing.T) {
		attempts := 0
		result, err := Retry(context.Background(), func() (any, error) {
			attempts++
			return nil, WrapError(errors.New("non-retryable error"))
		})
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if result != nil {
			t.Fatalf("expected nil result, got %v", result)
		}
		if attempts != 1 {
			t.Fatalf("expected 1 attempt, got %d", attempts)
		}
	})

	t.Run("max_attempts_reached", func(t *testing.T) {
		attempts := 0
		result, err := Retry(context.Background(), func() (any, error) {
			attempts++
			return nil, WrapError(&HTTPError{Code: http.StatusInternalServerError})
		}, WithMaxAttempts(3))

		if err == nil {
			t.Fatalf("expected error after max attempts, got nil")
		}
		if err.Error() != "retry cancelled after 3 attempts: context deadline exceeded" {
			t.Fatalf("expected context deadline exceeded, got %v", err)
		}

		if result != nil {
			t.Fatalf("expected nil result, got %v", result)
		}
		if attempts != 3 {
			t.Fatalf("expected 3 attempts, got %d", attempts)
		}
	})

	t.Run("context_cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		attempts := 0
		go func() {
			time.Sleep(1 * time.Second)
			cancel()
		}()
		_, err := Retry(ctx, func() (any, error) {
			attempts++
			return nil, WrapError(errors.New("temporary error"))
		})
		if err == nil {
			t.Fatalf("expected error due to context cancellation, got nil")
		}
		if attempts < 1 {
			t.Fatalf("expected at least 1 attempt, got %d", attempts)
		}
	})

	t.Run("validate_retry_configuration", func(t *testing.T) {
		invalidConfig := func() *RetryConfig {
			return &RetryConfig{
				MaxAttempts: 0,
			}
		}
		err := validateRetryConfig(invalidConfig())
		if err == nil {
			t.Fatalf("expected validation error, got nil")
		}

		validConfig := func() *RetryConfig {
			return &RetryConfig{
				MaxAttempts:     5,
				InitialInterval: 1 * time.Second,
				MaxInterval:     5 * time.Second,
				Multiplier:      1.5,
				MaxElapsedTime:  30 * time.Second,
			}
		}
		err = validateRetryConfig(validConfig())
		if err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})
}
