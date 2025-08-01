// Copyright 2022 The Sigstore Authors.
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

package v1

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/sigstore/rekor-monitor/pkg/rekor/mock"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
)

func TestGetLogInfo(t *testing.T) {
	logInfo := &models.LogInfo{}
	treeSize := int64(1234)
	logInfo.TreeSize = &treeSize

	var mClient client.Rekor
	mClient.Tlog = &mock.TlogClient{
		LogInfo: logInfo,
	}
	result, err := GetLogInfo(context.Background(), &mClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if treeSize != *result.TreeSize {
		t.Fatalf("expected tree size: %v, got: %v", treeSize, *result.TreeSize)
	}
}

func TestGetEntriesByIndexRange(t *testing.T) {
	maxIndex := 100
	var logEntries []*models.LogEntry

	// the contents of the LogEntryAnon don't matter
	// test will verify the indices returned by looking at the map keys
	for i := 0; i <= maxIndex; i++ {
		lea := models.LogEntryAnon{}
		data := models.LogEntry{
			fmt.Sprint(i): lea,
		}
		logEntries = append(logEntries, &data)
	}

	var mClient client.Rekor
	mClient.Entries = &mock.EntriesClient{
		Entries: logEntries,
	}

	// should return 1 through 100 for index range
	result, err := GetEntriesByIndexRange(context.TODO(), &mClient, 0, maxIndex)
	if err != nil {
		t.Fatalf("unexpected error getting entries: %v", err)
	}
	if len(result) != 100 {
		t.Fatalf("expected 100 entries, got %d", len(result))
	}
	index := 0
	for i := 1; i <= 100; i++ {
		if !reflect.DeepEqual(result[index], *logEntries[i]) {
			t.Fatalf("entries should be equal for index %d, log index %d", index, i)
		}
		index++
	}

	// should return 42 through 67 for index range
	result, err = GetEntriesByIndexRange(context.TODO(), &mClient, 41, 67)
	if err != nil {
		t.Fatalf("unexpected error getting entries: %v", err)
	}
	if len(result) != 26 {
		t.Fatalf("expected 26 entries, got %d", len(result))
	}
	index = 0
	for i := 42; i <= 67; i++ {
		if !reflect.DeepEqual(result[index], *logEntries[i]) {
			t.Fatalf("entries should be equal for index %d, log index %d", index, i)
		}
		index++
	}

	// should return index 42
	result, err = GetEntriesByIndexRange(context.TODO(), &mClient, 42, 42)
	if err != nil {
		t.Fatalf("unexpected error getting entries: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}
	if !reflect.DeepEqual(result[0], *logEntries[42]) {
		t.Fatalf("entries should be equal for index 0, log index 42")
	}

	// failure: start greater than end
	_, err = GetEntriesByIndexRange(context.TODO(), &mClient, 11, 10)
	if err == nil || !strings.Contains(err.Error(), "less than or equal to") {
		t.Fatalf("expected error with start greater than end index, got %v", err)
	}
}

func Test_min(t *testing.T) {
	tests := []struct {
		a      int
		b      int
		result int
	}{
		{
			a:      1,
			b:      1,
			result: 1,
		},
		{
			a:      2,
			b:      1,
			result: 1,
		},
		{
			a:      10,
			b:      11,
			result: 10,
		},
	}

	for _, tt := range tests {
		m := computeMin(tt.a, tt.b)
		if m != tt.result {
			t.Errorf("expected min value of %d for inputs(%d,%d), got %d", tt.result, tt.a, tt.b, m)
		}
	}
}
