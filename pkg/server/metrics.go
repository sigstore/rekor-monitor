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

package server

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	registry = prometheus.NewRegistry()

	logIndexVerificationTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "log_index_verification_total",
		Help: "Total number of log consistency check attempts.",
	})
	logIndexVerificationFailure = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "log_index_verification_failure",
		Help: "Total number of failed log consistency check attempts.",
	})

	signalChan = make(chan os.Signal, 1)
)

func init() {
	registry.MustRegister(logIndexVerificationTotal, logIndexVerificationFailure)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
}

// InitRegistryForTesting resets the registry for test isolation.
// This is only used in tests to ensure a clean state.
func InitRegistryForTesting() {
	registry = prometheus.NewRegistry()
	registry.MustRegister(logIndexVerificationTotal, logIndexVerificationFailure)
}

// GetLogIndexVerificationTotal returns the total verification counter for testing.
func GetLogIndexVerificationTotal() prometheus.Counter {
	return logIndexVerificationTotal
}

// GetLogIndexVerificationFailure returns the failure counter for testing.
func GetLogIndexVerificationFailure() prometheus.Counter {
	return logIndexVerificationFailure
}

// IncLogIndexVerificationTotal increments the total verification counter
func IncLogIndexVerificationTotal() {
	logIndexVerificationTotal.Inc()
}

// IncLogIndexVerificationFailure increments the failure counter
func IncLogIndexVerificationFailure() {
	logIndexVerificationFailure.Inc()
}

// GetSignalChan returns the signal channel for handling SIGINT/SIGTERM.
func GetSignalChan() chan os.Signal {
	return signalChan
}

// StartMetricsServer starts the metrics server
func StartMetricsServer(port int) error {
	http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	portStr := strconv.Itoa(port)
	log.Printf("Starting Prometheus metrics server on :%s", portStr)

	server := &http.Server{
		Addr:              ":" + portStr,
		Handler:           nil,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start Prometheus metrics server: %v", err)
		}
	}()

	// Handle graceful shutdown
	go func() {
		sig := <-signalChan
		log.Println("Shutting down metrics server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Metrics server shutdown error: %v", err)
		}
		signalChan <- sig
	}()

	return nil
}
