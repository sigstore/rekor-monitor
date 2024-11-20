// Copyright 2024 The Sigstore Authors.
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

package ct

import (
	"context"
	"fmt"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
)

func GetCTLogEntries(logClient *ctclient.LogClient, startIndex int, endIndex int) ([]ct.LogEntry, error) {
	entries, err := logClient.GetEntries(context.Background(), int64(startIndex), int64(endIndex))
	if err != nil {
		return nil, fmt.Errorf("error retrieving certificate transparency log entries: %v", err)
	}
	return entries, nil
}

func ScanEntryCertSubject(logEntry ct.LogEntry, monitoredCertIDs []identity.CertificateIdentity) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	for _, monitoredCertID := range monitoredCertIDs {
		match, sub, iss, err := identity.CertMatchesPolicy(logEntry.X509Cert, monitoredCertID.CertSubject, monitoredCertID.Issuers)
		if err != nil {
			return nil, fmt.Errorf("error with policy matching  at index %d: %w", logEntry.Index, err)
		} else if match {
			matchedEntries = append(matchedEntries, identity.LogEntry{
				CertSubject: sub,
				Issuer:      iss,
				Index:       logEntry.Index,
			})
		}
	}
	return matchedEntries, nil
}

func ScanEntryOIDExtensions(logEntry ct.LogEntry, monitoredOIDMatchers []extensions.OIDExtension) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	cert := logEntry.X509Cert
	for _, monitoredOID := range monitoredOIDMatchers {
		match, _, extValue, err := identity.OIDMatchesPolicy(cert, monitoredOID.ObjectIdentifier, monitoredOID.ExtensionValues)
		if err != nil {
			return nil, fmt.Errorf("error with policy matching at index %d: %w", logEntry.Index, err)
		}
		if match {
			matchedEntries = append(matchedEntries, identity.LogEntry{
				Index:          logEntry.Index,
				OIDExtension:   monitoredOID.ObjectIdentifier,
				ExtensionValue: extValue,
			})
		}
	}
	return matchedEntries, nil
}

func MatchedIndices(logEntries []ct.LogEntry, mvs identity.MonitoredValues) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	for _, entry := range logEntries {
		matchedCertSubjectEntries, err := ScanEntryCertSubject(entry, mvs.CertificateIdentities)
		if err != nil {
			return nil, err
		}
		matchedEntries = append(matchedEntries, matchedCertSubjectEntries...)

		matchedOIDEntries, err := ScanEntryOIDExtensions(entry, mvs.OIDMatchers)
		if err != nil {
			return nil, err
		}
		matchedEntries = append(matchedEntries, matchedOIDEntries...)
	}

	return matchedEntries, nil
}

func IdentitySearch(client *ctclient.LogClient, startIndex int, endIndex int, mvs identity.MonitoredValues) ([]identity.LogEntry, error) {
	retrievedEntries, err := GetCTLogEntries(client, startIndex, endIndex)
	if err != nil {
		return nil, err
	}
	matchedEntries, err := MatchedIndices(retrievedEntries, mvs)
	if err != nil {
		return nil, err
	}
	return matchedEntries, nil
}
