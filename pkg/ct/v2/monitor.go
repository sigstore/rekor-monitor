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

	google_x509 "github.com/google/certificate-transparency-go/x509"
	"github.com/sigstore/rekor-monitor/pkg/ct/common"
	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/notifications"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
)

func ScanEntryCertSubject(logEntry Entry, monitoredCertIDs []identity.CertificateIdentity) ([]identity.LogEntry, error) {
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
	return common.ScanEntryCertSubject(cert, logEntry.Index, monitoredCertIDs)
}

func ScanEntryOIDExtensions(logEntry Entry, monitoredOIDMatchers []extensions.OIDExtension) ([]identity.LogEntry, error) {
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
	return common.ScanEntryOIDExtensions(cert, logEntry.Index, monitoredOIDMatchers)
}

func MatchedIndices(logEntries []Entry, mvs identity.MonitoredValues, caRoots string, caIntermediates string) ([]identity.LogEntry, []identity.FailedLogEntry, error) {
	if err := identity.VerifyMonitoredValues(mvs); err != nil {
		return nil, nil, err
	}

	var matchedEntries []identity.LogEntry
	var failedEntries []identity.FailedLogEntry

	for _, entry := range logEntries {
		if entry.Entry.Certificate != nil {
			cert, err := x509.ParseCertificate(entry.Entry.Certificate)
			if err == nil {
				if err = identity.ValidateCertificateChain([]*x509.Certificate{cert}, caRoots, caIntermediates); err != nil {
					fmt.Fprintf(os.Stderr, "error validating certificate chain for log entry at index %d: %v\n", entry.Index, err)
					continue
				}
			}
		} else if entry.Entry.Precertificate != nil {
			cert, err := google_x509.ParseCertificate(entry.Entry.Precertificate)
			if err == nil {
				if err = identity.ValidatePreCertificateChain([]*google_x509.Certificate{cert}, caRoots, caIntermediates); err != nil {
					fmt.Fprintf(os.Stderr, "error validating pre-certificate chain for log entry at index %d: %v\n", entry.Index, err)
					continue
				}
			}
		}
		matchedCertSubjectEntries, err := ScanEntryCertSubject(entry, mvs.CertificateIdentities)
		if err != nil {
			failedEntries = append(failedEntries, identity.FailedLogEntry{
				Index: entry.Index,
				Error: fmt.Sprintf("error matching certificate subjects: %v", err),
			})
			continue
		}
		matchedEntries = append(matchedEntries, matchedCertSubjectEntries...)

		matchedOIDEntries, err := ScanEntryOIDExtensions(entry, mvs.OIDMatchers)
		if err != nil {
			failedEntries = append(failedEntries, identity.FailedLogEntry{
				Index: entry.Index,
				Error: fmt.Sprintf("error matching OID extensions: %v", err),
			})
			continue
		}
		matchedEntries = append(matchedEntries, matchedOIDEntries...)
	}

	return matchedEntries, failedEntries, nil
}

func IdentitySearch(ctx context.Context, client *Client, config *notifications.IdentityMonitorConfiguration, monitoredValues identity.MonitoredValues) ([]identity.MonitoredIdentity, []identity.FailedLogEntry, error) {
	entries, err := GetEntriesByIndexRange(ctx, client, *config.StartIndex, *config.EndIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("getting entries by index range: %w", err)
	}
	matchedEntries, failedEntries, err := MatchedIndices(entries, monitoredValues, config.CARootsFile, config.CAIntermediatesFile)
	if err != nil {
		return nil, nil, fmt.Errorf("looking for matching entries: %w", err)
	}
	err = file.WriteMatchedIdentityEntries(config.OutputIdentitiesFile, config.OutputIdentitiesFormat, matchedEntries, config.IdentityMetadataFile, *config.EndIndex)
	if err != nil {
		return nil, nil, err
	}

	identities := identity.CreateIdentitiesList(monitoredValues)
	monitoredIdentities := identity.CreateMonitoredIdentities(matchedEntries, identities)
	return monitoredIdentities, failedEntries, nil
}
