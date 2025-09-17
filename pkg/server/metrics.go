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
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	reg *prometheus.Registry

	// custom metrics
	logIndexVerificationTotal   prometheus.Counter
	logIndexVerificationFailure prometheus.Counter

	// system
	signalChan chan os.Signal
}

// Singleton instance
func getMetrics() *metrics {
	return _initMetricsFunc()
}

var _initMetricsFunc = sync.OnceValue[*metrics](func() *metrics {
	m := metrics{
		reg:        prometheus.NewRegistry(),
		signalChan: make(chan os.Signal, 1),
	}
	f := promauto.With(m.reg)

	m.logIndexVerificationTotal = f.NewCounter(prometheus.CounterOpts{
		Name: "log_index_verification_total",
		Help: "Total number of log consistency check attempts.",
	})
	m.logIndexVerificationFailure = f.NewCounter(prometheus.CounterOpts{
		Name: "log_index_verification_failure",
		Help: "Total number of failed log consistency check attempts.",
	})

	// subscribe to termination signals
	signal.Notify(m.signalChan, os.Interrupt, syscall.SIGTERM)

	return &m
})

// IncLogIndexVerificationTotal increments the total verification counter
func IncLogIndexVerificationTotal() {
	getMetrics().logIndexVerificationTotal.Inc()
}

// IncLogIndexVerificationFailure increments the failure counter
func IncLogIndexVerificationFailure() {
	getMetrics().logIndexVerificationFailure.Inc()
}

// GetSignalChan returns the signal channel for handling SIGINT/SIGTERM.
func GetSignalChan() chan os.Signal {
	return getMetrics().signalChan
}

// GetLogIndexVerificationTotal returns the total verification counter.
func GetLogIndexVerificationTotal() prometheus.Counter {
	return getMetrics().logIndexVerificationTotal
}

// GetLogIndexVerificationFailure returns the failure counter.
func GetLogIndexVerificationFailure() prometheus.Counter {
	return getMetrics().logIndexVerificationFailure
}

// StartMetricsServer starts the metrics server
func StartMetricsServer(ctx context.Context, port int) error {
	m := getMetrics()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{}))

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("failed to start Prometheus metrics server: %w", err)
		} else {
			errCh <- nil
		}
	}()

	// Shutdown when context is cancelled
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	// Short wait to let the server start before returning
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}
