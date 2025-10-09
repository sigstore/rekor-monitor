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

package v2

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"time"

	tiles_client "github.com/sigstore/rekor-tiles/v2/pkg/client"
	"github.com/sigstore/rekor-tiles/v2/pkg/client/read"
	"github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"google.golang.org/protobuf/encoding/protojson"
)

type ShardInfo struct {
	client      *read.Client
	verifier    *signature.Verifier
	validityEnd time.Time
}

type Entry struct {
	ProtoEntry *protobuf.Entry
	Index      int64
}

func RefreshSigningConfig(tufClient *tuf.Client) (*root.SigningConfig, error) {
	err := tufClient.Refresh()
	if err != nil {
		return nil, fmt.Errorf("error refreshing TUF client: %v", err)
	}

	signingConfig, err := root.GetSigningConfig(tufClient)
	if err != nil {
		return nil, fmt.Errorf("error getting SigningConfig target: %v", err)
	}
	return signingConfig, nil
}

func filterV2Shards(rekorServices []root.Service) []root.Service {
	// First we sort and filter the Rekor services so that they're ordered from
	// newest to oldest. We filter them so that we:
	// - only include the v2 logs.
	// - only include shards that are (or were) valid. No shards that will be valid in the future
	sortedServices := make([]root.Service, len(rekorServices))
	copy(sortedServices, rekorServices)
	slices.SortFunc(sortedServices, func(i, j root.Service) int {
		return i.ValidityPeriodStart.Compare(j.ValidityPeriodStart)
	})

	var rekorV2Services []root.Service
	now := time.Now()
	for _, s := range slices.Backward(sortedServices) {
		if s.MajorAPIVersion == 2 && !s.ValidityPeriodStart.IsZero() && s.ValidityPeriodStart.Before(now) {
			rekorV2Services = append(rekorV2Services, s)
		}
	}

	return rekorV2Services
}

func ShardsNeedUpdating(currentShards map[string]ShardInfo, newSigningConfig *root.SigningConfig) (bool, error) {
	newShards := newSigningConfig.RekorLogURLs()
	newV2Shards := filterV2Shards(newShards)

	if len(newV2Shards) == 0 {
		return false, fmt.Errorf("error fetching Rekor shards: no v2 shards found in SigningConfig")
	}

	if len(currentShards) != len(newV2Shards) {
		// Shards were added/removed, need to update
		return true, nil
	}

	for _, newShard := range newV2Shards {
		newShardURL, err := url.Parse(newShard.URL)
		if err != nil {
			return false, fmt.Errorf("error parsing rekor shard URL: %v", err)
		}
		newShardOrigin, err := getOrigin(newShardURL)
		if err != nil {
			return false, err
		}

		matchingShard, ok := currentShards[newShardOrigin]
		switch {
		case !ok:
			// The shard in the new SigningConfig is not present
			// in the existing shards, so we need to update
			return true, nil
		case matchingShard.validityEnd != newShard.ValidityPeriodEnd:
			// The newest shard in the SigningConfig is present in
			// the existing shards, but the end validity time changed
			return true, nil
		}
	}

	// All the shards in the new SigningConfig are present in
	// the existing shards, and they have the same validity end time
	return false, nil
}

func GetRekorShards(ctx context.Context, trustedRoot *root.TrustedRoot, rekorServices []root.Service, userAgent string) (map[string]ShardInfo, string, error) {
	rekorV2Services := filterV2Shards(rekorServices)
	if len(rekorV2Services) == 0 {
		return nil, "", fmt.Errorf("failed to find any Rekor v2 shards")
	}

	rekorShards := make(map[string]ShardInfo)
	latestShardOrigin := ""
	for _, service := range rekorV2Services {
		parsedURL, err := url.Parse(service.URL)
		if err != nil {
			return nil, "", fmt.Errorf("error parsing Rekor url: %v", err)
		}
		origin, err := getOrigin(parsedURL)
		if err != nil {
			return nil, "", err
		}

		// The services in rekorV2Services are ordered from newest to oldest,
		// so we store the origin of the first one as the origin
		// of the latest shard
		if latestShardOrigin == "" {
			latestShardOrigin = origin
		}
		verifier, err := GetLogVerifier(ctx, parsedURL, trustedRoot, userAgent)
		if err != nil {
			return nil, "", err
		}

		rekorClient, err := read.NewReader(service.URL, origin, verifier, tiles_client.WithUserAgent(userAgent))
		if err != nil {
			return nil, "", fmt.Errorf("getting Rekor client: %v", err)
		}

		// ReadCheckpoint fetches and verifies the current checkpoint
		// We verify the checkpoints of all v2 shards
		checkpoint, _, err := rekorClient.ReadCheckpoint(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get current checkpoint for log '%v': %v", origin, err)
		}

		rekorShards[checkpoint.Origin] = ShardInfo{&rekorClient, &verifier, service.ValidityPeriodEnd}
	}
	return rekorShards, latestShardOrigin, nil
}

func getOrigin(shardURL *url.URL) (string, error) {
	prefixLen := len(shardURL.Scheme) + len("://")
	if prefixLen >= len(shardURL.String()) {
		return "", fmt.Errorf("error getting origin from URL %v", shardURL)
	}
	origin := shardURL.String()[len(shardURL.Scheme)+len("://"):]
	return origin, nil
}

// GetTileIndex gets the index of the tile a checkpoint belongs to.
func getTileIndex(checkpointIndex int64) int64 {
	treeSize := checkpointIndex + 1
	fullTilesCount := treeSize / layout.TileWidth

	if treeSize%layout.TileWidth == 0 {
		return fullTilesCount - 1
	}
	return fullTilesCount
}

func getEntriesFromTile(ctx context.Context, shard ShardInfo, fullTileIndex int64, partialTileWidth uint8) ([]Entry, error) {
	client := *shard.client
	bundleBytes, err := client.ReadEntryBundle(ctx, uint64(fullTileIndex), partialTileWidth) //nolint: gosec // G115
	if err != nil {
		return nil, fmt.Errorf("failed to fetch entry bundle")
	}
	var bundle api.EntryBundle
	err = bundle.UnmarshalText(bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse entry bundle")
	}
	var entries []Entry
	for i, entryBytes := range bundle.Entries {
		logEntry := protobuf.Entry{}
		err = protojson.Unmarshal(entryBytes, &logEntry)
		if err != nil {
			return nil, fmt.Errorf("failed to parse entry")
		}
		entries = append(entries, Entry{ProtoEntry: &logEntry, Index: fullTileIndex*layout.TileWidth + int64(i)})
	}
	return entries, nil
}

// GetEntriesByIndexRange fetches all entries by log index, from (start, end]
// If start == end, it doesn't return any entries
// Returns error if start > end
func GetEntriesByIndexRange(ctx context.Context, shard ShardInfo, start, end int64) ([]Entry, error) {
	if start > end {
		return nil, fmt.Errorf("start (%d) must be less than or equal to end (%d)", start, end)
	}

	var entries []Entry
	if start == end {
		return entries, nil
	}

	startTileIndex := getTileIndex(start)
	startLogSize := start + 1
	endTileIndex := getTileIndex(end)
	endLogSize := end + 1

	// If the start and end tiles are different, first we get any remaining unread
	// entries from the start tile
	if startTileIndex < endTileIndex {
		partialBundleSize := startLogSize % layout.TileWidth
		// A partial bundle size of 0 means the start tile was read in full,
		// so no need to read it again. Otherwise, we've only read the tile
		// partially, and we need to read the remaining entries.
		if partialBundleSize > 0 {
			allStartEntries, err := getEntriesFromTile(ctx, shard, startTileIndex, 0)
			if err != nil {
				return nil, fmt.Errorf("error getting bundle for tile: %d. Error: %v", startTileIndex, err)
			}
			unreadEntries := allStartEntries[partialBundleSize:]
			entries = append(entries, unreadEntries...)
		}
	}

	// We get all the entries from the full tiles in (start, end)
	for i := startTileIndex + 1; i < endTileIndex; i++ {
		currentEntries, err := getEntriesFromTile(ctx, shard, i, 0)
		if err != nil {
			return nil, fmt.Errorf("error getting bundle for tile: %d. Error: %v", i, err)
		}
		entries = append(entries, currentEntries...)
	}

	// Finally, we get all the entries available in the last tile
	partialBundleSize := uint8(endLogSize % layout.TileWidth) //nolint: gosec // G115
	endEntries, err := getEntriesFromTile(ctx, shard, endTileIndex, partialBundleSize)
	if err != nil {
		return nil, fmt.Errorf("error getting bundle for tile: %d, width: %d. Error: %v", endTileIndex, partialBundleSize, err)
	}
	entries = append(entries, endEntries...)

	return entries, nil
}
