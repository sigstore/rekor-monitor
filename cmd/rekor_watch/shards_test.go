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
	"errors"
	"testing"

	rekor_v2 "github.com/sigstore/rekor-monitor/pkg/rekor/v2"
)

func shardSet(origins ...string) map[string]rekor_v2.ShardInfo {
	m := make(map[string]rekor_v2.ShardInfo, len(origins))
	for _, o := range origins {
		m[o] = rekor_v2.ShardInfo{}
	}
	return m
}

func TestShardTrackerRefresh_ReadURLChange(t *testing.T) {
	oldTarget := rekor_v2.ShardTarget{ReadURL: "https://old.example.dev", Origin: "origin-A"}
	newTarget := rekor_v2.ShardTarget{ReadURL: "https://new.example.dev", Origin: "origin-A"}
	fetched := false
	tr := &shardTracker{
		shards:            shardSet("origin-A"),
		latestShardOrigin: "origin-A",
		targets:           []rekor_v2.ShardTarget{oldTarget},
		refreshTargets: func() ([]rekor_v2.ShardTarget, error) {
			return []rekor_v2.ShardTarget{newTarget}, nil
		},
		fetchShards: func(_ context.Context, targets []rekor_v2.ShardTarget) (map[string]rekor_v2.ShardInfo, string, error) {
			fetched = true
			return shardSet("origin-A"), targets[0].Origin, nil
		},
	}

	if err := tr.refresh(context.Background()); err != nil {
		t.Fatalf("refresh returned error: %v", err)
	}
	if !fetched {
		t.Fatal("fetchShards was not called after the read URL changed")
	}
	if tr.targets[0] != newTarget {
		t.Fatalf("stored target = %+v, want %+v", tr.targets[0], newTarget)
	}
}

func TestShardTrackerRefresh_NoUpdate(t *testing.T) {
	fetched := false
	targets := []rekor_v2.ShardTarget{{Origin: "origin-A"}}
	tr := &shardTracker{
		shards:            shardSet("origin-A"),
		latestShardOrigin: "origin-A",
		targets:           targets,
		refreshTargets: func() ([]rekor_v2.ShardTarget, error) {
			return targets, nil
		},
		fetchShards: func(context.Context, []rekor_v2.ShardTarget) (map[string]rekor_v2.ShardInfo, string, error) {
			fetched = true
			return nil, "", nil
		},
	}

	if err := tr.refresh(context.Background()); err != nil {
		t.Fatalf("refresh returned error: %v", err)
	}
	if fetched {
		t.Fatal("fetchShards was called even though no update was needed")
	}
	if tr.latestShardOrigin != "origin-A" {
		t.Fatalf("latestShardOrigin changed to %q, want origin-A", tr.latestShardOrigin)
	}
	if _, ok := tr.shards["origin-A"]; !ok || len(tr.shards) != 1 {
		t.Fatalf("shards changed unexpectedly: %v", keys(tr.shards))
	}
}

func TestShardTrackerRefresh_Update(t *testing.T) {
	wantTargets := []rekor_v2.ShardTarget{{Origin: "origin-B"}, {Origin: "origin-A"}}
	var fetchTargets []rekor_v2.ShardTarget

	tr := &shardTracker{
		shards:            shardSet("origin-A"),
		latestShardOrigin: "origin-A",
		targets:           []rekor_v2.ShardTarget{{Origin: "origin-A"}},
		refreshTargets: func() ([]rekor_v2.ShardTarget, error) {
			return wantTargets, nil
		},
		fetchShards: func(_ context.Context, targets []rekor_v2.ShardTarget) (map[string]rekor_v2.ShardInfo, string, error) {
			fetchTargets = targets
			return shardSet("origin-A", "origin-B"), "origin-B", nil
		},
	}

	if err := tr.refresh(context.Background()); err != nil {
		t.Fatalf("refresh returned error: %v", err)
	}
	if len(fetchTargets) != len(wantTargets) || fetchTargets[0].Origin != "origin-B" {
		t.Fatal("refreshed target order was not passed to fetchShards")
	}
	if len(tr.targets) != len(wantTargets) || tr.targets[0].Origin != "origin-B" {
		t.Fatal("refreshed targets were not stored after a successful fetch")
	}
	if tr.latestShardOrigin != "origin-B" {
		t.Fatalf("latestShardOrigin = %q, want origin-B", tr.latestShardOrigin)
	}
	if _, ok := tr.shards["origin-B"]; !ok || len(tr.shards) != 2 {
		t.Fatalf("shards not updated: %v", keys(tr.shards))
	}
}

func TestShardTrackerRefresh_TargetsError(t *testing.T) {
	tr := &shardTracker{
		shards:            shardSet("origin-A"),
		latestShardOrigin: "origin-A",
		targets:           []rekor_v2.ShardTarget{{Origin: "origin-A"}},
		refreshTargets: func() ([]rekor_v2.ShardTarget, error) {
			return nil, errors.New("boom")
		},
		fetchShards: func(context.Context, []rekor_v2.ShardTarget) (map[string]rekor_v2.ShardInfo, string, error) {
			t.Fatal("fetchShards must not run after a target refresh error")
			return nil, "", nil
		},
	}

	if err := tr.refresh(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
	assertUnchanged(t, tr)
}

func TestShardTrackerRefresh_FetchError(t *testing.T) {
	tr := &shardTracker{
		shards:            shardSet("origin-A"),
		latestShardOrigin: "origin-A",
		targets:           []rekor_v2.ShardTarget{{Origin: "origin-A"}},
		refreshTargets: func() ([]rekor_v2.ShardTarget, error) {
			return []rekor_v2.ShardTarget{{Origin: "origin-B"}}, nil
		},
		fetchShards: func(context.Context, []rekor_v2.ShardTarget) (map[string]rekor_v2.ShardInfo, string, error) {
			return nil, "", errors.New("boom")
		},
	}

	if err := tr.refresh(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
	assertUnchanged(t, tr)
}

func assertUnchanged(t *testing.T, tr *shardTracker) {
	t.Helper()
	if tr.latestShardOrigin != "origin-A" {
		t.Fatalf("latestShardOrigin changed to %q, want origin-A", tr.latestShardOrigin)
	}
	if _, ok := tr.shards["origin-A"]; !ok || len(tr.shards) != 1 {
		t.Fatalf("shards mutated on failure: %v", keys(tr.shards))
	}
	if len(tr.targets) != 1 || tr.targets[0].Origin != "origin-A" {
		t.Fatalf("targets mutated on failure: %+v", tr.targets)
	}
}

func keys(m map[string]rekor_v2.ShardInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
