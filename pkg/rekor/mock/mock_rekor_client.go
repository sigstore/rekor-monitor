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
	"github.com/go-openapi/strfmt"

	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/pubkey"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// EntriesClient is a client that implements entries.ClientService for Rekor
// To use:
// var mClient client.Rekor
// mClient.Entries = &mock.EntriesClient{Entries: <logEntries>, ETag: <etag>, Location: <location>, LogEntry: <logEntry>}
type EntriesClient struct {
	Entries  []*models.LogEntry
	ETag     string
	Location strfmt.URI
	LogEntry models.LogEntry
}

func (m *EntriesClient) CreateLogEntry(_ *entries.CreateLogEntryParams, _ ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	return &entries.CreateLogEntryCreated{
		ETag:     m.ETag,
		Location: m.Location,
		Payload:  m.LogEntry,
	}, nil
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

func (m *EntriesClient) SetTransport(_ runtime.ClientTransport) {}

// TlogClient is a client that implements tlog.ClientService for Rekor
// To use:
// var mClient client.Rekor
// mClient.Entries = &mock.TlogClient{LogInfo: <loginfo>, ConsistencyProof: <consistencyproof>}
type TlogClient struct {
	LogInfo          *models.LogInfo
	ConsistencyProof *models.ConsistencyProof
}

func (m *TlogClient) GetLogInfo(_ *tlog.GetLogInfoParams, _ ...tlog.ClientOption) (*tlog.GetLogInfoOK, error) {
	return &tlog.GetLogInfoOK{
		Payload: m.LogInfo,
	}, nil
}

func (m *TlogClient) GetLogProof(_ *tlog.GetLogProofParams, _ ...tlog.ClientOption) (*tlog.GetLogProofOK, error) {
	return &tlog.GetLogProofOK{
		Payload: m.ConsistencyProof,
	}, nil
}

func (m *TlogClient) SetTransport(_ runtime.ClientTransport) {}

// PubkeyClient is a client that implements pubkey.ClientService for Rekor
// To use:
// var mClient client.Rekor
// mClient.Entries = &mock.PubkeyClient{PEMPubKey: <string>}
type PubkeyClient struct {
	PEMPubKey string
}

func (m *PubkeyClient) GetPublicKey(_ *pubkey.GetPublicKeyParams, _ ...pubkey.ClientOption) (*pubkey.GetPublicKeyOK, error) {
	return &pubkey.GetPublicKeyOK{
		Payload: m.PEMPubKey,
	}, nil
}

func (m *PubkeyClient) SetTransport(_ runtime.ClientTransport) {}
