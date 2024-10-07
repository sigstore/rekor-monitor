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

package rekor

import (
	"context"
	"fmt"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/pubkey"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// GetPublicKey fetches the current public key from Rekor
func GetPublicKey(ctx context.Context, rekorClient *client.Rekor) ([]byte, error) {
	p := pubkey.NewGetPublicKeyParamsWithContext(ctx)
	pubkeyResp, err := rekorClient.Pubkey.GetPublicKey(p)
	if err != nil {
		return nil, err
	}
	return []byte(pubkeyResp.Payload), nil
}

// GetLogInfo fetches a stable checkpoint for each log shard
func GetLogInfo(ctx context.Context, rekorClient *client.Rekor) (*models.LogInfo, error) {
	p := tlog.NewGetLogInfoParamsWithContext(ctx)

	logInfoResp, err := rekorClient.Tlog.GetLogInfo(p)
	if err != nil {
		return nil, err
	}
	return logInfoResp.GetPayload(), nil
}

// GetEntriesByIndexRange fetches all entries by log index, from (start, end]
// If start == end, returns a single entry for that index
// Returns error if start > end
func GetEntriesByIndexRange(ctx context.Context, rekorClient *client.Rekor, start, end int) ([]models.LogEntry, error) {
	if start > end {
		return nil, fmt.Errorf("start (%d) must be less than or equal to end (%d)", start, end)
	}

	// handle case where we initialize log monitor
	if start == end {
		start--
	}

	var logEntries []models.LogEntry
	for i := start + 1; i <= end; i += 10 {
		var logIndices []*int64
		min := min(i+10, end+1)
		for j := i; j < min; j++ {
			j := int64(j)
			logIndices = append(logIndices, &j)
		}
		slq := models.SearchLogQuery{}
		slq.LogIndexes = logIndices

		p := entries.NewSearchLogQueryParamsWithContext(ctx)
		p.SetEntry(&slq)

		resp, err := rekorClient.Entries.SearchLogQuery(p)
		if err != nil {
			return nil, err
		}
		logEntries = append(logEntries, resp.Payload...)
	}
	return logEntries, nil
}

// min calculates the minimum of two integers. Preferred over math.Min due to verbose type conversions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
