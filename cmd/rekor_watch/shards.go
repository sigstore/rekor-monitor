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

package main

import (
	"context"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/monitorconfig"
	rekor_v2 "github.com/sigstore/rekor-monitor/pkg/rekor/v2"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// shardTracker follows the active Rekor v2 shard and switches to a new one when
// the log rolls over. Its refresh steps are function fields so the rollover
// logic can be tested without TUF or network access.
type shardTracker struct {
	shards            map[string]rekor_v2.ShardInfo
	latestShardOrigin string
	targets           []rekor_v2.ShardTarget

	refreshTargets func() ([]rekor_v2.ShardTarget, error)
	fetchShards    func(context.Context, []rekor_v2.ShardTarget) (map[string]rekor_v2.ShardInfo, string, error)
}

func newShardTracker(ctx context.Context, tufClient *tuf.Client, monitorConfigPath, userAgent, httpsChainPath string) (*shardTracker, error) {
	t := &shardTracker{
		refreshTargets: func() ([]rekor_v2.ShardTarget, error) {
			config, err := monitorconfig.LoadFromFile(monitorConfigPath)
			if err != nil {
				return nil, err
			}
			if err := tufClient.Refresh(); err != nil {
				return nil, fmt.Errorf("refreshing TUF client: %w", err)
			}
			trustedRoot, err := root.GetTrustedRoot(tufClient)
			if err != nil {
				return nil, fmt.Errorf("getting trusted root: %w", err)
			}
			return rekor_v2.ShardTargetsFromMonitorConfig(config, trustedRoot, time.Now())
		},
		fetchShards: func(ctx context.Context, targets []rekor_v2.ShardTarget) (map[string]rekor_v2.ShardInfo, string, error) {
			trustedRoot, err := root.GetTrustedRoot(tufClient)
			if err != nil {
				return nil, "", fmt.Errorf("getting trusted root: %w", err)
			}
			return rekor_v2.GetRekorShardsForTargets(ctx, trustedRoot, targets, userAgent, httpsChainPath)
		},
	}

	// The tracker starts with no shards, so refresh fetches the initial set
	// (and errors if the log has no v2 shards).
	if err := t.refresh(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

// refresh re-fetches the shards when the active shard set changes. On any error
// it leaves the existing shards untouched, so a transient TUF/network failure
// does not drop the shards already being followed.
func (t *shardTracker) refresh(ctx context.Context) error {
	targets, err := t.refreshTargets()
	if err != nil {
		return fmt.Errorf("refreshing shard targets: %w", err)
	}

	if slices.Equal(t.targets, targets) {
		return nil
	}

	shards, latestShardOrigin, err := t.fetchShards(ctx, targets)
	if err != nil {
		return fmt.Errorf("fetching updated shards: %w", err)
	}

	log.Printf("Rekor shards updated: %d shards, latest shard origin %q (was %q)", len(shards), latestShardOrigin, t.latestShardOrigin)
	t.shards = shards
	t.latestShardOrigin = latestShardOrigin
	t.targets = slices.Clone(targets)
	return nil
}
