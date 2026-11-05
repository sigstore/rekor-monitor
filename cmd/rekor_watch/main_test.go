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
	"testing"

	"github.com/transparency-dev/formats/log"
)

func TestDecideSearchRange(t *testing.T) {
	tests := []struct {
		name             string
		prev             *log.Checkpoint
		current          *log.Checkpoint
		hasAnyCheckpoint bool
		wantStart        int64
		wantEnd          int64
		wantSearch       bool
	}{
		{
			// Fresh deploy with no checkpoints anywhere: preserve the
			// "monitor going forward only" contract, do not back-search history.
			name:             "first-time deploy does not back-search",
			prev:             nil,
			current:          &log.Checkpoint{Size: 42},
			hasAnyCheckpoint: false,
			wantSearch:       false,
		},
		{
			// Rollover to a new shard that already holds entries: back-search
			// it so pre-existing entries still match subscriptions. The range
			// (-1, Size-1] must include index 0.
			name:             "rollover back-searches the whole new shard",
			prev:             nil,
			current:          &log.Checkpoint{Size: 7},
			hasAnyCheckpoint: true,
			wantStart:        -1,
			wantEnd:          6,
			wantSearch:       true,
		},
		{
			// Rollover to an empty new shard: nothing to back-search yet.
			name:             "rollover to empty shard does not search",
			prev:             nil,
			current:          &log.Checkpoint{Size: 0},
			hasAnyCheckpoint: true,
			wantSearch:       false,
		},
		{
			// Known shard that grew: incremental scan of the new entries only.
			name:       "incremental scan of new entries",
			prev:       &log.Checkpoint{Size: 10},
			current:    &log.Checkpoint{Size: 15},
			wantStart:  9,
			wantEnd:    14,
			wantSearch: true,
		},
		{
			// Known shard that did not grow: no-op, skip the scan.
			name:       "no growth is a no-op",
			prev:       &log.Checkpoint{Size: 10},
			current:    &log.Checkpoint{Size: 10},
			wantSearch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, search := decideSearchRange(tt.prev, tt.current, tt.hasAnyCheckpoint)
			if search != tt.wantSearch {
				t.Fatalf("search = %v, want %v", search, tt.wantSearch)
			}
			if !search {
				return
			}
			if start != tt.wantStart || end != tt.wantEnd {
				t.Errorf("range = (%d, %d], want (%d, %d]", start, end, tt.wantStart, tt.wantEnd)
			}
		})
	}
}
