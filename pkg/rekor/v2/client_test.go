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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/sigstore/rekor-tiles/v2/pkg/client/read"
	"github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
)

// mockReadClient implements read.Client for testing
type mockReadClient struct {
	// entries maps tile index to a list of entries in that tile
	entries map[int64][]Entry
}

var _ read.Client = (*mockReadClient)(nil)

func (m *mockReadClient) ReadCheckpoint(_ context.Context) (*log.Checkpoint, *note.Note, error) {
	return nil, nil, nil
}

func (m *mockReadClient) ReadTile(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
	return nil, nil
}

// ReadEntryBundle returns entries for a given tile index
// If partialWidth > 0, it returns only the first partialWidth entries
func (m *mockReadClient) ReadEntryBundle(_ context.Context, tileIndex uint64, partialWidth uint8) ([]byte, error) {
	tileEntries, ok := m.entries[int64(tileIndex)]
	if !ok {
		return nil, fmt.Errorf("tile %d not found", tileIndex)
	}

	// Determine how many entries to return
	count := len(tileEntries)
	if partialWidth > 0 && int(partialWidth) < count {
		count = int(partialWidth)
	}

	// Build an entry bundle in the tlog-tiles format:
	// Each entry is: 2-byte size (big-endian uint16) + entry data
	var buf bytes.Buffer
	for i := 0; i < count; i++ {
		entryBytes, err := protojson.Marshal(tileEntries[i].ProtoEntry)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal entry: %v", err)
		}
		// Write 2-byte size prefix
		size := uint16(len(entryBytes))
		if err := binary.Write(&buf, binary.BigEndian, size); err != nil {
			return nil, fmt.Errorf("failed to write size: %v", err)
		}
		// Write entry data
		if _, err := buf.Write(entryBytes); err != nil {
			return nil, fmt.Errorf("failed to write entry: %v", err)
		}
	}

	return buf.Bytes(), nil
}

// createMockEntry creates a minimal Entry for testing
func createMockEntry(index int64) Entry {
	return Entry{
		ProtoEntry: &protobuf.Entry{
			Kind: "hashedrekord",
		},
		Index: index,
	}
}

// createMockShardWithEntries creates a ShardInfo with mock entries
// The entries are organized by tile and indexed correctly
func createMockShardWithEntries(maxIndex int64) ShardInfo {
	mockClient := &mockReadClient{
		entries: make(map[int64][]Entry),
	}

	// Populate tiles with entries
	for i := int64(0); i <= maxIndex; i++ {
		tileIndex := i / layout.TileWidth
		entry := createMockEntry(i)

		if mockClient.entries[tileIndex] == nil {
			mockClient.entries[tileIndex] = make([]Entry, 0, layout.TileWidth)
		}
		mockClient.entries[tileIndex] = append(mockClient.entries[tileIndex], entry)
	}

	var client read.Client = mockClient
	return ShardInfo{
		client: &client,
	}
}

func TestGetTileIndex(t *testing.T) {
	tests := []struct {
		name           string
		checkpointIdx  int64
		expectedTileId int64
	}{
		{
			name:           "first entry",
			checkpointIdx:  0,
			expectedTileId: 0,
		},
		{
			name:           "last entry of first tile",
			checkpointIdx:  layout.TileWidth - 1,
			expectedTileId: 0,
		},
		{
			name:           "first entry of second tile",
			checkpointIdx:  layout.TileWidth,
			expectedTileId: 1,
		},
		{
			name:           "middle of second tile",
			checkpointIdx:  layout.TileWidth + 100,
			expectedTileId: 1,
		},
		{
			name:           "large index",
			checkpointIdx:  1344291,
			expectedTileId: 1344292 / layout.TileWidth, // 5251
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTileIndex(tt.checkpointIdx)
			if result != tt.expectedTileId {
				t.Errorf("getTileIndex(%d) = %d, want %d", tt.checkpointIdx, result, tt.expectedTileId)
			}
		})
	}
}

func TestGetEntriesByIndexRange_StartEqualsEnd(t *testing.T) {
	shard := createMockShardWithEntries(100)

	// When start == end, should return 0 entries
	result, err := GetEntriesByIndexRange(context.Background(), shard, 42, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(result))
	}
}

func TestGetEntriesByIndexRange_StartGreaterThanEnd(t *testing.T) {
	shard := createMockShardWithEntries(100)

	// When start > end, should return error
	_, err := GetEntriesByIndexRange(context.Background(), shard, 50, 40)
	if err == nil {
		t.Fatal("expected error when start > end")
	}
	if !strings.Contains(err.Error(), "less than or equal to") {
		t.Fatalf("expected error about start being less than end, got: %v", err)
	}
}

func TestGetEntriesByIndexRange_SingleEntry(t *testing.T) {
	shard := createMockShardWithEntries(100)

	// Range (42, 43] should return exactly entry 43
	result, err := GetEntriesByIndexRange(context.Background(), shard, 42, 43)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}
	if result[0].Index != 43 {
		t.Fatalf("expected entry with index 43, got %d", result[0].Index)
	}
}

func TestGetEntriesByIndexRange_SameTile(t *testing.T) {
	// Range where both start and end are within the same tile
	shard := createMockShardWithEntries(300)

	// Range (35, 37] should return entries 36 and 37 only (both in tile 0)
	result, err := GetEntriesByIndexRange(context.Background(), shard, 35, 37)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}

	expectedIndices := []int64{36, 37}
	for i, expected := range expectedIndices {
		if result[i].Index != expected {
			t.Errorf("result[%d].Index = %d, want %d", i, result[i].Index, expected)
		}
	}

	// Verify that no entries before index 36 are included
	for _, entry := range result {
		if entry.Index <= 35 {
			t.Errorf("found entry with index %d, which should not be included (start=35)", entry.Index)
		}
	}
}

func TestGetEntriesByIndexRange_SameTile_LargeIndex(t *testing.T) {
	// Range within same tile using large indices (both in tile 5251)
	maxIndex := int64(1344293)
	shard := createMockShardWithEntries(maxIndex)

	// Range (1344291, 1344292] should return exactly entry 1344292
	result, err := GetEntriesByIndexRange(context.Background(), shard, 1344291, 1344292)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}
	if result[0].Index != 1344292 {
		t.Fatalf("expected entry with index 1344292, got %d", result[0].Index)
	}

	// Verify no entries outside the requested range are included
	for _, entry := range result {
		if entry.Index <= 1344291 {
			t.Errorf("found entry %d which is <= start index 1344291", entry.Index)
		}
	}
}

func TestGetEntriesByIndexRange_CrossTiles(t *testing.T) {
	// Test crossing from tile 0 to tile 1
	// Tile 0: indices 0-255
	// Tile 1: indices 256-511
	shard := createMockShardWithEntries(300)

	// Range (250, 260] should return entries 251-260
	result, err := GetEntriesByIndexRange(context.Background(), shard, 250, 260)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedCount := 10 // entries 251, 252, ..., 260
	if len(result) != expectedCount {
		t.Fatalf("expected %d entries, got %d", expectedCount, len(result))
	}

	for i, entry := range result {
		expectedIndex := int64(251 + i)
		if entry.Index != expectedIndex {
			t.Errorf("result[%d].Index = %d, want %d", i, entry.Index, expectedIndex)
		}
	}
}

func TestGetEntriesByIndexRange_MultipleFullTiles(t *testing.T) {
	// Test spanning multiple full tiles
	// Create enough entries to span 3 full tiles plus partial
	maxIndex := int64(layout.TileWidth*3 + 50) // 818 entries
	shard := createMockShardWithEntries(maxIndex)

	// Range from middle of tile 0 to middle of tile 2
	// (100, 600] should return 500 entries (101-600)
	start := int64(100)
	end := int64(600)
	result, err := GetEntriesByIndexRange(context.Background(), shard, start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedCount := int(end - start) // 500
	if len(result) != expectedCount {
		t.Fatalf("expected %d entries, got %d", expectedCount, len(result))
	}

	// Verify all indices are correct and in order
	for i, entry := range result {
		expectedIndex := start + 1 + int64(i) // 101, 102, ..., 600
		if entry.Index != expectedIndex {
			t.Errorf("result[%d].Index = %d, want %d", i, entry.Index, expectedIndex)
		}
	}

	// Verify no entries outside range
	for _, entry := range result {
		if entry.Index <= start || entry.Index > end {
			t.Errorf("entry %d is outside range (%d, %d]", entry.Index, start, end)
		}
	}
}

func TestGetEntriesByIndexRange_FullTile(t *testing.T) {
	// Test getting exactly one full tile worth of entries
	shard := createMockShardWithEntries(int64(layout.TileWidth) + 10)

	// Range (0, 256] should return entries 1-256 (a full tile worth minus first entry)
	result, err := GetEntriesByIndexRange(context.Background(), shard, 0, int64(layout.TileWidth))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedCount := layout.TileWidth // 256
	if len(result) != expectedCount {
		t.Fatalf("expected %d entries, got %d", expectedCount, len(result))
	}

	for i, entry := range result {
		expectedIndex := int64(1 + i) // 1, 2, ..., 256
		if entry.Index != expectedIndex {
			t.Errorf("result[%d].Index = %d, want %d", i, entry.Index, expectedIndex)
		}
	}
}

func TestGetEntriesByIndexRange_StartAtTileBoundary(t *testing.T) {
	// Test when start is at the last index of a tile
	shard := createMockShardWithEntries(300)

	// Tile 0 ends at index 255
	// Range (255, 260] should return entries 256-260 (all in tile 1)
	result, err := GetEntriesByIndexRange(context.Background(), shard, 255, 260)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedCount := 5 // entries 256, 257, 258, 259, 260
	if len(result) != expectedCount {
		t.Fatalf("expected %d entries, got %d", expectedCount, len(result))
	}

	for i, entry := range result {
		expectedIndex := int64(256 + i)
		if entry.Index != expectedIndex {
			t.Errorf("result[%d].Index = %d, want %d", i, entry.Index, expectedIndex)
		}
	}
}

func TestGetEntriesByIndexRange_EndAtTileBoundary(t *testing.T) {
	// Test when end is at the last index of a tile
	shard := createMockShardWithEntries(300)

	// Tile 0 ends at index 255
	// Range (250, 255] should return entries 251-255
	result, err := GetEntriesByIndexRange(context.Background(), shard, 250, 255)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedCount := 5 // entries 251, 252, 253, 254, 255
	if len(result) != expectedCount {
		t.Fatalf("expected %d entries, got %d", expectedCount, len(result))
	}

	for i, entry := range result {
		expectedIndex := int64(251 + i)
		if entry.Index != expectedIndex {
			t.Errorf("result[%d].Index = %d, want %d", i, entry.Index, expectedIndex)
		}
	}
}
