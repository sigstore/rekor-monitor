// Copyright 2026 The Sigstore Authors.
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
	"context"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/sigstore/rekor-monitor/pkg/ct/common"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/tiles"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
)

func ScanEntryCertSubject(logEntry Entry, monitoredCertID identity.CertIdentityValue) ([]identity.LogEntry, error) {
	var cert *x509.Certificate
	var err error
	if logEntry.Entry.IsPrecert {
		cert, err = x509.ParseCertificate(logEntry.Entry.Precertificate)
		if err != nil {
			return nil, fmt.Errorf("error parsing precert: %w", err)
		}
	} else {
		cert, err = x509.ParseCertificate(logEntry.Entry.Certificate)
		if err != nil {
			return nil, fmt.Errorf("error parsing cert: %w", err)
		}
	}
	return common.ScanEntryCertSubject(cert, logEntry.Index, monitoredCertID)
}

func ScanEntryOIDExtension(logEntry Entry, monitoredOID identity.OIDMatcherValue) ([]identity.LogEntry, error) {
	var cert *x509.Certificate
	var err error
	if logEntry.Entry.IsPrecert {
		cert, err = x509.ParseCertificate(logEntry.Entry.Precertificate)
		if err != nil {
			return nil, fmt.Errorf("error parsing precert: %w", err)
		}
	} else {
		cert, err = x509.ParseCertificate(logEntry.Entry.Certificate)
		if err != nil {
			return nil, fmt.Errorf("error parsing cert: %w", err)
		}
	}
	return common.ScanEntryOIDExtension(cert, logEntry.Index, monitoredOID)
}

func MatchedIndices(logEntries []Entry, mvs identity.MonitoredValues, caRoots string, caIntermediates string) ([]identity.LogEntry, []identity.FailedLogEntry, error) {
	if err := identity.VerifyMonitoredValues(mvs); err != nil {
		return nil, nil, err
	}

	matchedEntries := []identity.LogEntry{}
	failedEntries := []identity.FailedLogEntry{}

	for _, entry := range logEntries {
		err := common.ValidateCertificateChain(entry.Entry.Certificate, entry.Entry.Precertificate, caRoots, caIntermediates)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error validating chain for log entry at index %d: %v\n", entry.Index, err)
			continue
		}

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

func IdentitySearch(ctx context.Context, client *Client, monitoredValues identity.MonitoredValues, startIndex, endIndex int64, opts ...identity.SearchOption) ([]identity.MonitoredIdentity, []identity.FailedLogEntry, error) {
	o := identity.MakeIdentitySearchOptions(opts...)
	entries, err := tiles.GetEntriesByIndexRange(ctx, client, startIndex, endIndex, getEntriesFromTile)
	if err != nil {
		return nil, nil, fmt.Errorf("getting entries by index range: %w", err)
	}
	matchedEntries, failedEntries, err := MatchedIndices(entries, monitoredValues, o.CARootsFile, o.CAIntermediatesFile)
	if err != nil {
		return nil, nil, fmt.Errorf("looking for matching entries: %w", err)
	}
	err = file.WriteMatchedIdentityEntries(o.OutputIdentitiesFile, o.OutputIdentitiesFormat, matchedEntries, o.IdentityMetadataFile, endIndex)
	if err != nil {
		return nil, nil, err
	}

	monitoredIdentities := identity.CreateMonitoredIdentities(matchedEntries)
	return monitoredIdentities, failedEntries, nil
}
