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

package tiles

import (
	"context"
	"fmt"
	"net/url"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/note"
)

type Client interface {
	ReadCheckpoint(ctx context.Context) (*log.Checkpoint, *note.Note, error)
	ReadTile(ctx context.Context, level, index uint64, p uint8) ([]byte, error)
	ReadEntryBundle(ctx context.Context, index uint64, p uint8) ([]byte, error)
}

func GetOrigin(origin, shardURL string) (string, error) {
	if origin != "" {
		return origin, nil
	}
	parsedURL, err := url.Parse(shardURL)
	if err != nil {
		return "", fmt.Errorf("parsing URL: %w", err)
	}
	prefixLen := len(parsedURL.Scheme) + len("://")
	if prefixLen >= len(parsedURL.String()) {
		return "", fmt.Errorf("error getting origin from URL %s", shardURL)
	}
	origin = parsedURL.String()[len(parsedURL.Scheme)+len("://"):]
	return origin, nil
}

// GetTileIndex gets the index of the tile a checkpoint belongs to.
func GetTileIndex(checkpointIndex int64) int64 {
	treeSize := checkpointIndex + 1
	fullTilesCount := treeSize / layout.TileWidth

	if treeSize%layout.TileWidth == 0 {
		return fullTilesCount - 1
	}
	return fullTilesCount
}
