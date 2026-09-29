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

package v2

import (
	"testing"
	"time"

	monitor_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/monitor/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
)

type fakeTrustedMaterial struct {
	root.BaseTrustedMaterial
	rekorLogs map[string]*root.TransparencyLog
}

func (f *fakeTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog {
	return f.rekorLogs
}

func rekorLog(readURL string, majorAPIVersion uint32, origin string) *monitor_v1.TransparencyLogMonitorConfig {
	return &monitor_v1.TransparencyLogMonitorConfig{
		ReadUrl:         readURL,
		LogOrigin:       origin,
		MajorApiVersion: majorAPIVersion,
	}
}

func TestShardTargetsFromMonitorConfig(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	day := func(d int) time.Time { return time.Date(2026, 1, d, 0, 0, 0, 0, time.UTC) }

	trustedRoot := &fakeTrustedMaterial{rekorLogs: map[string]*root.TransparencyLog{
		// Retired before now, but still expected among the targets: entries
		// already in it have to stay verifiable.
		"key-old": {BaseURL: "https://old.rekor.example.dev", ValidityPeriodStart: day(1), ValidityPeriodEnd: day(10)},
		"key-new": {BaseURL: "https://new.rekor.example.dev", ValidityPeriodStart: day(10)},
		// Not yet serving entries, so not a shard to monitor.
		"key-future": {BaseURL: "https://future.rekor.example.dev", ValidityPeriodStart: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
	}}

	config := &monitor_v1.MonitorConfig{
		RekorLogs: []*monitor_v1.TransparencyLogMonitorConfig{
			rekorLog("https://old.rekor.example.dev", 2, "old.rekor.example.dev"),
			rekorLog("https://future.rekor.example.dev", 2, "future.rekor.example.dev"),
			// A read URL that differs from the origin is the case the monitor
			// config exists for: writes go to a load balancer that does not
			// serve reads.
			rekorLog("https://read.rekor.example.dev", 2, "new.rekor.example.dev"),
			// v1 logs are not tiled, so they are not v2 shards.
			rekorLog("https://v1.rekor.example.dev", 1, "old.rekor.example.dev"),
		},
	}

	targets, err := ShardTargetsFromMonitorConfig(config, trustedRoot, now)
	if err != nil {
		t.Fatalf("ShardTargetsFromMonitorConfig returned error: %v", err)
	}

	wantOrigins := []string{"new.rekor.example.dev", "old.rekor.example.dev"}
	if len(targets) != len(wantOrigins) {
		t.Fatalf("got %d targets, want %d: %+v", len(targets), len(wantOrigins), targets)
	}
	for i, want := range wantOrigins {
		if targets[i].Origin != want {
			t.Errorf("target %d origin = %q, want %q (targets must be ordered newest first)", i, targets[i].Origin, want)
		}
	}

	// The read URL comes from the monitor config, the validity from the
	// trusted root entry for the same origin.
	if targets[0].ReadURL != "https://read.rekor.example.dev" {
		t.Errorf("latest target read URL = %q, want the monitor config read URL", targets[0].ReadURL)
	}
	if !targets[0].ValidityStart.Equal(day(10)) || !targets[0].ValidityEnd.IsZero() {
		t.Errorf("latest target validity = (%v, %v), want (%v, zero)", targets[0].ValidityStart, targets[0].ValidityEnd, day(10))
	}
	if !targets[1].ValidityEnd.Equal(day(10)) {
		t.Errorf("retired target validity end = %v, want %v", targets[1].ValidityEnd, day(10))
	}
}

func TestShardTargetsFromMonitorConfigRejectsDuplicateOrigins(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	trustedRoot := &fakeTrustedMaterial{rekorLogs: map[string]*root.TransparencyLog{
		"key-one": {BaseURL: "https://known.rekor.example.dev", ValidityPeriodStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		"key-two": {BaseURL: "https://known.rekor.example.dev", ValidityPeriodStart: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
	}}
	config := &monitor_v1.MonitorConfig{RekorLogs: []*monitor_v1.TransparencyLogMonitorConfig{
		rekorLog("https://known.rekor.example.dev", 2, "known.rekor.example.dev"),
	}}

	if _, err := ShardTargetsFromMonitorConfig(config, trustedRoot, now); err == nil {
		t.Fatal("expected an error for duplicate trusted-root origins, got nil")
	}
}

func TestShardTargetsFromMonitorConfigErrors(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	trustedRoot := &fakeTrustedMaterial{rekorLogs: map[string]*root.TransparencyLog{
		"key": {BaseURL: "https://known.rekor.example.dev", ValidityPeriodStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
	}}

	tests := []struct {
		name   string
		config *monitor_v1.MonitorConfig
	}{
		{
			// Without a trusted root entry there is no key to verify the
			// log's checkpoints, so it cannot be monitored.
			name: "log missing from the trusted root",
			config: &monitor_v1.MonitorConfig{RekorLogs: []*monitor_v1.TransparencyLogMonitorConfig{
				rekorLog("https://unknown.rekor.example.dev", 2, "unknown.rekor.example.dev"),
			}},
		},
		{
			name: "no v2 logs",
			config: &monitor_v1.MonitorConfig{RekorLogs: []*monitor_v1.TransparencyLogMonitorConfig{
				rekorLog("https://known.rekor.example.dev", 1, "known.rekor.example.dev"),
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ShardTargetsFromMonitorConfig(tt.config, trustedRoot, now); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}
