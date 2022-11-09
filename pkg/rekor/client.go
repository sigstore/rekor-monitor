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

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// GetEntriesByIndexRange fetches all entries by log index, from [start, end]
func GetEntriesByIndexRange(ctx context.Context, rekorClient *client.Rekor, start, end int) ([]models.LogEntry, error) {
	var logEntries []models.LogEntry
	for i := start; i <= end; i++ {
		params := entries.NewGetLogEntryByIndexParamsWithContext(ctx)
		params.SetLogIndex(int64(i))
		resp, err := rekorClient.Entries.GetLogEntryByIndex(params)
		if err != nil {
			return nil, err
		}
		logEntries = append(logEntries, resp.Payload)
	}
	return logEntries, nil
}
