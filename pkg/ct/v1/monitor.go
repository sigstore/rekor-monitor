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

package v1

import (
	"context"
	"fmt"
	"os"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/sigstore/rekor-monitor/pkg/ct/common"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
)

func GetCTLogEntries(ctx context.Context, logClient *ctclient.LogClient, startIndex int64, endIndex int64) ([]ct.LogEntry, error) {
	entries, err := logClient.GetEntries(ctx, startIndex, endIndex)
	if err != nil {
		return nil, fmt.Errorf("error retrieving certificate transparency log entries: %v", err)
	}
	return entries, nil
}

func ScanEntryCertSubject(logEntry ct.LogEntry, monitoredCertID identity.CertIdentityValue) ([]identity.LogEntry, error) {
	cert := logEntry.X509Cert
	if cert == nil && logEntry.Precert != nil {
		cert = logEntry.Precert.TBSCertificate
	}

	if cert == nil {
		return nil, fmt.Errorf("unsupported CT log entry at index %d", logEntry.Index)
	}
	return common.ScanEntryCertSubject(cert, logEntry.Index, monitoredCertID)
}

func ScanEntryOIDExtension(logEntry ct.LogEntry, monitoredOID identity.OIDMatcherValue) ([]identity.LogEntry, error) {
	cert := logEntry.X509Cert
	if cert == nil && logEntry.Precert != nil {
		cert = logEntry.Precert.TBSCertificate
	}

	if cert == nil {
		return nil, fmt.Errorf("unsupported CT log entry at index %d", logEntry.Index)
	}
	return common.ScanEntryOIDExtension(cert, logEntry.Index, monitoredOID)
}

func rawCert(logEntry ct.LogEntry) []byte {
	if logEntry.X509Cert == nil {
		return nil
	}
	return logEntry.X509Cert.Raw
}

func rawPrecert(logEntry ct.LogEntry) []byte {
	if logEntry.Precert == nil || logEntry.Precert.TBSCertificate == nil {
		return nil
	}
	return logEntry.Precert.TBSCertificate.Raw
}

func MatchedIndices(logEntries []ct.LogEntry, mvs identity.MonitoredValues, caRoots string, caIntermediates string) ([]identity.LogEntry, []identity.FailedLogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	failedEntries := []identity.FailedLogEntry{}
	for _, entry := range logEntries {
		err := common.ValidateCertificateChain(rawCert(entry), rawPrecert(entry), caRoots, caIntermediates)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error validating chain for log entry at index %d: %v\n", entry.Index, err)
			continue
		}

		// Iterate over each monitored value and match accordingly
		for _, mv := range mvs {
			switch v := mv.(type) {
			case identity.CertIdentityValue:
				matchedCertSubjectEntries, err := ScanEntryCertSubject(entry, v)
				if err != nil {
					failedEntries = append(failedEntries, identity.FailedLogEntry{
						Index: entry.Index,
						Error: fmt.Sprintf("error matching certificate subjects: %v", err),
					})
					continue
				}
				matchedEntries = append(matchedEntries, matchedCertSubjectEntries...)
			case identity.OIDMatcherValue:
				matchedOIDEntries, err := ScanEntryOIDExtension(entry, v)
				if err != nil {
					failedEntries = append(failedEntries, identity.FailedLogEntry{
						Index: entry.Index,
						Error: fmt.Sprintf("error matching OID extensions: %v", err),
					})
					continue
				}
				matchedEntries = append(matchedEntries, matchedOIDEntries...)
			}
		}
	}

	return matchedEntries, failedEntries, nil
}

func IdentitySearch(ctx context.Context, client *ctclient.LogClient, monitoredValues identity.MonitoredValues, startIndex, endIndex int64, opts ...identity.SearchOption) ([]identity.MonitoredIdentity, []identity.FailedLogEntry, error) {
	o := identity.MakeIdentitySearchOptions(opts...)

	entries, err := GetCTLogEntries(ctx, client, startIndex, endIndex)
	if err != nil {
		return nil, nil, err
	}
	matchedEntries, failedEntries, err := MatchedIndices(entries, monitoredValues, o.CARootsFile, o.CAIntermediatesFile)
	if err != nil {
		return nil, nil, err
	}

	err = file.WriteMatchedIdentityEntries(o.OutputIdentitiesFile, o.OutputIdentitiesFormat, matchedEntries, o.IdentityMetadataFile, endIndex)
	if err != nil {
		return nil, nil, err
	}

	monitoredIdentities := identity.CreateMonitoredIdentities(matchedEntries)
	return monitoredIdentities, failedEntries, nil
}
