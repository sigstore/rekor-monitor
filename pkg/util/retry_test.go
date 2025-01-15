// Copyright 2022 The Sigstore Authors.
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
	"strings"
	"testing"
	"time"
)

func TestRetry(t *testing.T) {
	t.Run("successful execution without retry", func(t *testing.T) {
		attempts := 0
		f := func() (any, error) {
			attempts++
			return "success", nil
		}

		result, err := Retry(context.Background(), f)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if attempts != 1 {
			t.Errorf("Expected 1 attempt, got %d", attempts)
		}
		if result != "success" {
			t.Errorf("Expected 'success', got %v", result)
		}
	})

	t.Run("successful execution after retries", func(t *testing.T) {
		attempts := 0
		f := func() (any, error) {
			attempts++
			if attempts < 3 {
				return nil, RetryeError{Err: errors.New("error getting entries by index range")}
			}
			return "success", nil
		}

		result, err := Retry(context.Background(), f)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if attempts != 3 {
			t.Errorf("Expected 3 attempts, got %d", attempts)
		}
		if result != "success" {
			t.Errorf("Expected 'success', got %v", result)
		}
	})

	t.Run("max attempts exceeded", func(t *testing.T) {
		attempts := 0
		f := func() (any, error) {
			attempts++
			return nil, RetryeError{Err: errors.New("error getting entries by index range")}
		}

		_, err := Retry(context.Background(), f)
		if err == nil {
			t.Error("Expected error, got nil")
		}
		if attempts != 5 { // default max attempts
			t.Errorf("Expected 5 attempts, got %d", attempts)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		attempts := 0
		ctx, cancel := context.WithCancel(context.Background())
		f := func() (any, error) {
			attempts++
			cancel() // cancle after first attempt
			return nil, RetryeError{Err: errors.New("error getting entries by index range")}
		}

		_, err := Retry(ctx, f)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Expected context.Canceled error, got %v", err)
		}
		if attempts != 1 {
			t.Errorf("Expected 1 attempt, got %d", attempts)
		}
	})

	t.Run("max elapsed time exceeded", func(t *testing.T) {
		attempts := 0
		f := func() (any, error) {
			attempts++
			time.Sleep(200 * time.Millisecond)
			return nil, RetryeError{Err: errors.New("error getting entries by index range")}
		}

		_, err := Retry(context.Background(), f,
			WithMaxElapsedTime(500*time.Millisecond),
			WithInitialInterval(100*time.Millisecond))

		if err == nil {
			t.Error("Expected error, got nil")
		}
		if !strings.Contains(err.Error(), "max elapsed time exceeded") {
			t.Errorf("Expected max elapsed time error, got %v", err)
		}
	})
}

func TestRetryConfig(t *testing.T) {
	t.Run("custom configuration", func(t *testing.T) {
		attempts := 0
		f := func() (any, error) {
			attempts++
			return nil, RetryeError{Err: errors.New("error getting entries by index range")}
		}

		_, err := Retry(context.Background(), f,
			WithMaxAttempts(3),
			WithInitialInterval(100*time.Millisecond),
			WithMaxInterval(200*time.Millisecond),
			WithMultiplier(2.0),
			WithMaxElapsedTime(1*time.Second))

		if err == nil {
			t.Error("Expected error, got nil")
		}
		if attempts != 3 {
			t.Errorf("Expected 3 attempts, got %d", attempts)
		}
	})
}

func TestRetryeError(t *testing.T) {
	t.Run("retryable error messages", func(t *testing.T) {
		testCases := []struct {
			name        string
			err         error
			shouldRetry bool
		}{
			{
				name:        "error getting entries",
				err:         errors.New("error getting entries by index range"),
				shouldRetry: true,
			},
			{
				name:        "non-retryable error",
				err:         errors.New("other error"),
				shouldRetry: false,
			},
			{
				name:        "nil error",
				err:         nil,
				shouldRetry: false,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				rerr := RetryeError{Err: tc.err}
				if rerr.ShouldRetry() != tc.shouldRetry {
					t.Errorf("Expected ShouldRetry() to return %v for error: %v",
						tc.shouldRetry, tc.err)
				}
			})
		}
	})
}
