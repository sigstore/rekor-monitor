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
	"github.com/sigstore/rekor-monitor/pkg/util/file"
)

func GetCTLogEntries(ctx context.Context, logClient *ctclient.LogClient, startIndex int, endIndex int) ([]ct.LogEntry, error) {
	entries, err := logClient.GetEntries(ctx, int64(startIndex), int64(endIndex))
	if err != nil {
		return nil, fmt.Errorf("error retrieving certificate transparency log entries: %v", err)
	}
	return entries, nil
}

func ScanEntryCertSubject(logEntry ct.LogEntry, monitoredCertIDs []identity.CertificateIdentity) (identity.MatchedEntries, error) {
	cert := logEntry.X509Cert
	if cert == nil && logEntry.Precert != nil {
		cert = logEntry.Precert.TBSCertificate
	}

	if cert == nil {
		return identity.MatchedEntries{}, fmt.Errorf("unsupported CT log entry at index %d", logEntry.Index)
	}
	matchedEntries := identity.NewMatchedEntries()
	for _, monitoredCertID := range monitoredCertIDs {
		match, sub, iss, err := identity.CertMatchesPolicy(cert, monitoredCertID.CertSubject, monitoredCertID.Issuers)
		if err != nil {
			return identity.MatchedEntries{}, fmt.Errorf("error with policy matching  at index %d: %w", logEntry.Index, err)
		} else if match {
			matchedEntries.Add(identity.LogEntry{
				CertSubject: sub,
				Issuer:      iss,
				Index:       logEntry.Index,
			})
		}
	}
	return matchedEntries, nil
}

func ScanEntryOIDExtensions(logEntry ct.LogEntry, monitoredOIDMatchers []extensions.OIDExtension) (identity.MatchedEntries, error) {
	cert := logEntry.X509Cert
	if cert == nil && logEntry.Precert != nil {
		cert = logEntry.Precert.TBSCertificate
	}

	if cert == nil {
		return identity.MatchedEntries{}, fmt.Errorf("unsupported CT log entry at index %d", logEntry.Index)
	}
	matchedEntries := identity.NewMatchedEntries()
	for _, monitoredOID := range monitoredOIDMatchers {
		match, _, extValue, err := identity.OIDMatchesPolicy(cert, monitoredOID.ObjectIdentifier, monitoredOID.ExtensionValues)
		if err != nil {
			return identity.MatchedEntries{}, fmt.Errorf("error with policy matching at index %d: %w", logEntry.Index, err)
		}
		if match {
			matchedEntries.Add(identity.LogEntry{
				Index:          logEntry.Index,
				OIDExtension:   monitoredOID.ObjectIdentifier,
				ExtensionValue: extValue,
			})
		}
	}
	return matchedEntries, nil
}

func MatchedIndices(logEntries []ct.LogEntry, mvs identity.MonitoredValues) (identity.MatchedEntries, []identity.FailedLogEntry, error) {
	matchedEntries := identity.NewMatchedEntries()
	failedEntries := []identity.FailedLogEntry{}
	for _, entry := range logEntries {
		matchedCertSubjectEntries, err := ScanEntryCertSubject(entry, mvs.CertificateIdentities)
		if err != nil {
			failedEntries = append(failedEntries, identity.FailedLogEntry{
				Index: entry.Index,
				Error: fmt.Sprintf("error matching certificate subjects: %v", err),
			})
			continue
		}
		matchedEntries.Merge(matchedCertSubjectEntries)

		matchedOIDEntries, err := ScanEntryOIDExtensions(entry, mvs.OIDMatchers)
		if err != nil {
			failedEntries = append(failedEntries, identity.FailedLogEntry{
				Index: entry.Index,
				Error: fmt.Sprintf("error matching OID extensions: %v", err),
			})
			continue
		}
		matchedEntries.Merge(matchedOIDEntries)
	}

	return matchedEntries, failedEntries, nil
}

func IdentitySearch(ctx context.Context, client *ctclient.LogClient, startIndex int, endIndex int, monitoredValues identity.MonitoredValues, outputIdentitiesFile string, idMetadataFile *string) (identity.MatchedEntries, []identity.FailedLogEntry, error) {
	entries, err := GetCTLogEntries(ctx, client, startIndex, endIndex)
	if err != nil {
		return identity.MatchedEntries{}, nil, err
	}
	matchedEntries, failedEntries, err := MatchedIndices(entries, monitoredValues)
	if err != nil {
		return identity.MatchedEntries{}, nil, err
	}

	err = file.WriteMatchedIdentityEntries(outputIdentitiesFile, matchedEntries, idMetadataFile, endIndex)
	if err != nil {
		return identity.MatchedEntries{}, nil, err
	}

	return matchedEntries, failedEntries, nil
}
