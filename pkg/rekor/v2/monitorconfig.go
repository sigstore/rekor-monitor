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
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"slices"
	"time"

	monitor_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/monitor/v1"
	"github.com/sigstore/rekor-monitor/pkg/tiles"
	"github.com/sigstore/rekor-monitor/pkg/util"
	tiles_client "github.com/sigstore/rekor-tiles/v2/pkg/client"
	"github.com/sigstore/rekor-tiles/v2/pkg/client/read"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// ShardTarget is a Rekor v2 shard from a monitor config. Origin is separate
// from ReadURL because checkpoints retain their origin when served elsewhere.
type ShardTarget struct {
	ReadURL string
	Origin  string
	// ValidityStart and ValidityEnd delimit the shard's validity period. A zero
	// ValidityEnd means the shard has not been retired.
	ValidityStart time.Time
	ValidityEnd   time.Time
}

// ShardTargetsFromMonitorConfig returns current and retired v2 logs, newest first.
func ShardTargetsFromMonitorConfig(config *monitor_v1.MonitorConfig, trustedRoot root.TrustedMaterial, now time.Time) ([]ShardTarget, error) {
	var targets []ShardTarget
	for _, logConfig := range config.GetRekorLogs() {
		if logConfig.GetMajorApiVersion() != 2 {
			continue
		}
		origin := logConfig.GetLogOrigin()
		logInstance, err := findLogByOrigin(trustedRoot, origin, now)
		if err != nil {
			return nil, err
		}
		if logInstance == nil {
			continue
		}
		targets = append(targets, ShardTarget{
			ReadURL:       logConfig.GetReadUrl(),
			Origin:        origin,
			ValidityStart: logInstance.ValidityPeriodStart,
			ValidityEnd:   logInstance.ValidityPeriodEnd,
		})
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("error fetching Rekor shards: no v2 shards found in monitor config")
	}

	slices.SortFunc(targets, func(a, b ShardTarget) int {
		return b.ValidityStart.Compare(a.ValidityStart)
	})
	return targets, nil
}

// GetRekorShardsForTargets builds clients for targets ordered newest first.
func GetRekorShardsForTargets(ctx context.Context, trustedRoot *root.TrustedRoot, targets []ShardTarget, userAgent, certChain string) (map[string]ShardInfo, string, error) {
	if len(targets) == 0 {
		return nil, "", fmt.Errorf("failed to find any Rekor v2 shards")
	}

	clientOpts := []tiles_client.Option{tiles_client.WithUserAgent(userAgent)}
	var tlsConfig *tls.Config
	if certChain != "" {
		var err error
		tlsConfig, err = util.TLSConfigForCA(certChain)
		if err != nil {
			return nil, "", fmt.Errorf("getting TLS config: %w", err)
		}
		clientOpts = append(clientOpts, tiles_client.WithTLSConfig(tlsConfig))
	}

	rekorShards := make(map[string]ShardInfo)
	latestShardOrigin := targets[0].Origin
	for _, target := range targets {
		parsedURL, err := url.Parse(target.ReadURL)
		if err != nil {
			return nil, "", fmt.Errorf("error parsing Rekor url: %v", err)
		}

		verifier, err := GetLogVerifier(ctx, parsedURL, trustedRoot, userAgent, tlsConfig)
		if err != nil {
			return nil, "", err
		}

		rekorClient, err := read.NewReader(target.ReadURL, target.Origin, verifier, clientOpts...)
		if err != nil {
			return nil, "", fmt.Errorf("getting Rekor client: %v", err)
		}

		checkpoint, _, err := rekorClient.ReadCheckpoint(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get current checkpoint for log '%v': %v", target.Origin, err)
		}

		rekorShards[checkpoint.Origin] = ShardInfo{&rekorClient, &verifier, target.ValidityEnd}
	}
	return rekorShards, latestShardOrigin, nil
}

func findLogByOrigin(trustedRoot root.TrustedMaterial, origin string, now time.Time) (*root.TransparencyLog, error) {
	var match *root.TransparencyLog
	for _, logInstance := range trustedRoot.RekorLogs() {
		logOrigin, err := tiles.GetOrigin(logInstance.BaseURL)
		if err != nil || logOrigin != origin {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("log origin %q appears more than once in the trusted root", origin)
		}
		match = logInstance
	}

	if match == nil {
		return nil, fmt.Errorf("log %q in monitor config is not in the trusted root", origin)
	}
	if match.ValidityPeriodStart.IsZero() || match.ValidityPeriodStart.After(now) {
		return nil, nil
	}
	return match, nil
}
