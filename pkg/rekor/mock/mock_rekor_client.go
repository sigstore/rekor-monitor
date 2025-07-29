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
	"fmt"

	"github.com/go-openapi/runtime"

	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/pubkey"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// EntriesClient is a client that implements entries.ClientService for Rekor
// To use:
// var mClient client.Rekor
// mClient.Entries = &mock.EntriesClient{Entries: <logEntries>, ETag: <etag>, Location: <location>, LogEntry: <logEntry>}
type EntriesClient struct {
	Entries  []*models.LogEntry
	LogEntry models.LogEntry
	Error    error
}

func (m *EntriesClient) CreateLogEntry(_ *entries.CreateLogEntryParams, _ ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return &entries.CreateLogEntryCreated{
		Payload: m.LogEntry,
	}, nil
}

func (m *EntriesClient) GetLogEntryByIndex(_ *entries.GetLogEntryByIndexParams, _ ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	return nil, errors.New("not implemented")
}

func (m *EntriesClient) GetLogEntryByUUID(_ *entries.GetLogEntryByUUIDParams, _ ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	return nil, errors.New("not implemented")
}

func (m *EntriesClient) SearchLogQuery(params *entries.SearchLogQueryParams, _ ...entries.ClientOption) (*entries.SearchLogQueryOK, error) {
	if m.Error != nil {
		return nil, m.Error
	}
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
	Error            error
}

func (m *TlogClient) GetLogInfo(_ *tlog.GetLogInfoParams, _ ...tlog.ClientOption) (*tlog.GetLogInfoOK, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return &tlog.GetLogInfoOK{
		Payload: m.LogInfo,
	}, nil
}

func (m *TlogClient) GetLogProof(_ *tlog.GetLogProofParams, _ ...tlog.ClientOption) (*tlog.GetLogProofOK, error) {
	if m.Error != nil {
		return nil, m.Error
	}
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

type TrustedRoot struct {
	ctLogs    map[string]*root.TransparencyLog
	rekorLogs map[string]*root.TransparencyLog
}

func NewTrustedRoot(ctLogs map[string]*root.TransparencyLog, rekorLogs map[string]*root.TransparencyLog) *TrustedRoot {
	return &TrustedRoot{
		ctLogs:    ctLogs,
		rekorLogs: rekorLogs,
	}
}

func (tr *TrustedRoot) RekorLogs() map[string]*root.TransparencyLog {
	return tr.rekorLogs
}

func (tr *TrustedRoot) CTLogs() map[string]*root.TransparencyLog {
	return tr.ctLogs
}

func (tr *TrustedRoot) TimestampingAuthorities() []root.TimestampingAuthority {
	return nil
}

func (tr *TrustedRoot) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return nil
}

func (tr *TrustedRoot) PublicKeyVerifier(string) (root.TimeConstrainedVerifier, error) {
	return nil, fmt.Errorf("public key verifier not found")
}
