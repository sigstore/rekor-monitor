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

package mock

import (
	"errors"

	"github.com/go-openapi/runtime"

	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// EntriesClient is a client that implements entries.ClientService for Rekor
// To use:
// var mClient client.Rekor
// mClient.Entries = &logEntry
type EntriesClient struct {
	Entries []*models.LogEntry
}

func (m *EntriesClient) CreateLogEntry(_ *entries.CreateLogEntryParams, _ ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	return nil, errors.New("not implemented")
}

func (m *EntriesClient) GetLogEntryByIndex(_ *entries.GetLogEntryByIndexParams, _ ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	return nil, errors.New("not implemented")
}

func (m *EntriesClient) GetLogEntryByUUID(_ *entries.GetLogEntryByUUIDParams, _ ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	return nil, errors.New("not implemented")
}

func (m *EntriesClient) SearchLogQuery(params *entries.SearchLogQueryParams, _ ...entries.ClientOption) (*entries.SearchLogQueryOK, error) {
	resp := []models.LogEntry{}
	if m.Entries != nil {
		for _, i := range params.Entry.LogIndexes {
			resp = append(resp, *m.Entries[*i])
		}
	}
	return &entries.SearchLogQueryOK{
		Payload: resp,
	}, nil
}

// TODO: Implement mock
func (m *EntriesClient) SetTransport(_ runtime.ClientTransport) {
}
