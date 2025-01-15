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
	"fmt"
	"strings"
	"time"
)

type RetryConfig struct {
	MaxAttempts     int
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
	MaxElapsedTime  time.Duration
}

func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:     5,
		InitialInterval: 1 * time.Second,
		MaxInterval:     5 * time.Second,
		Multiplier:      1.5,
		MaxElapsedTime:  30 * time.Second,
	}
}

type RetryableError interface {
	ShouldRetry() bool
}

type RetryeError struct {
	Err error
}

func (r RetryeError) Error() string {
	return r.Err.Error()
}

func (r RetryeError) ShouldRetry() bool {
	if r.Err == nil {
		return false
	}

	// add all specific error messages that should trigger retry
	retryableErrors := []string{
		"error getting entries by index range",
	}

	errMsg := r.Err.Error()
	for _, msg := range retryableErrors {
		if strings.Contains(errMsg, msg) {
			return true
		}
	}
	return false
}

func WrapError(err error) error {
	if err == nil {
		return nil
	}
	return RetryeError{Err: err}
}

// Retry will call the provided function until it returns without an error or the context is cancelled.
func Retry(ctx context.Context, f func() (any, error), opts ...func(*RetryConfig)) (any, error) {
	config := DefaultRetryConfig()
	for _, opt := range opts {
		opt(config)
	}

	var lastErr error
	startTime := time.Now()
	currentInterval := config.InitialInterval

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		if time.Since(startTime) > config.MaxElapsedTime {
			if lastErr != nil {
				return nil, fmt.Errorf("max elapsed time exceeded after %d attempts, last error: %w",
					attempt-1, lastErr)
			}
			return nil, fmt.Errorf("max elapsed time exceeded after %d attempts", attempt-1)
		}

		resp, err := f()
		if err == nil {
			return resp, nil
		}

		lastErr = err

		if retryableErr, ok := err.(RetryableError); ok {
			if !retryableErr.ShouldRetry() {
				return nil, err
			}
		}

		if attempt == config.MaxAttempts {
			return nil, fmt.Errorf("max attempts (%d) reached, last error: %w", config.MaxAttempts, err)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(currentInterval):
			currentInterval = time.Duration(float64(currentInterval) * config.Multiplier)
			if currentInterval > config.MaxInterval {
				currentInterval = config.MaxInterval
			}
		}
	}

	return nil, fmt.Errorf("unexpected state")
}

func WithMaxAttempts(attempts int) func(*RetryConfig) {
	return func(c *RetryConfig) {
		if attempts > 0 {
			c.MaxAttempts = attempts
		}
	}
}

func WithInitialInterval(interval time.Duration) func(*RetryConfig) {
	return func(c *RetryConfig) {
		if interval > 0 {
			c.InitialInterval = interval
		}
	}
}

func WithMaxInterval(interval time.Duration) func(*RetryConfig) {
	return func(c *RetryConfig) {
		if interval > 0 {
			c.MaxInterval = interval
		}
	}
}

func WithMultiplier(multiplier float64) func(*RetryConfig) {
	return func(c *RetryConfig) {
		if multiplier > 1 {
			c.Multiplier = multiplier
		}
	}
}

func WithMaxElapsedTime(duration time.Duration) func(*RetryConfig) {
	return func(c *RetryConfig) {
		if duration > 0 {
			c.MaxElapsedTime = duration
		}
	}
}
