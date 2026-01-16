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
	"crypto/x509"
	"fmt"
	"os"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	google_x509 "github.com/google/certificate-transparency-go/x509"
	"github.com/sigstore/rekor-monitor/pkg/ct/common"
	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/notifications"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
)

func GetCTLogEntries(ctx context.Context, logClient *ctclient.LogClient, startIndex int64, endIndex int64) ([]ct.LogEntry, error) {
	entries, err := logClient.GetEntries(ctx, startIndex, endIndex)
	if err != nil {
		return nil, fmt.Errorf("error retrieving certificate transparency log entries: %v", err)
	}
	return entries, nil
}

func ScanEntryCertSubject(logEntry ct.LogEntry, monitoredCertIDs []identity.CertificateIdentity) ([]identity.LogEntry, error) {
	cert := logEntry.X509Cert
	if cert == nil && logEntry.Precert != nil {
		cert = logEntry.Precert.TBSCertificate
	}

	if cert == nil {
		return nil, fmt.Errorf("unsupported CT log entry at index %d", logEntry.Index)
	}
	return common.ScanEntryCertSubject(cert, logEntry.Index, monitoredCertIDs)
}

func ScanEntryOIDExtensions(logEntry ct.LogEntry, monitoredOIDMatchers []extensions.OIDExtension) ([]identity.LogEntry, error) {
	cert := logEntry.X509Cert
	if cert == nil && logEntry.Precert != nil {
		cert = logEntry.Precert.TBSCertificate
	}

	if cert == nil {
		return nil, fmt.Errorf("unsupported CT log entry at index %d", logEntry.Index)
	}
	return common.ScanEntryOIDExtensions(cert, logEntry.Index, monitoredOIDMatchers)
}

func MatchedIndices(logEntries []ct.LogEntry, mvs identity.MonitoredValues, caRoots string, caIntermediates string) ([]identity.LogEntry, []identity.FailedLogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	failedEntries := []identity.FailedLogEntry{}
	for _, entry := range logEntries {
		if entry.X509Cert != nil {
			cert, err := x509.ParseCertificate(entry.X509Cert.Raw)
			if err == nil {
				if err = identity.ValidateCertificateChain([]*x509.Certificate{cert}, caRoots, caIntermediates); err != nil {
					fmt.Fprintf(os.Stderr, "error validating certificate chain for log entry at index %d: %v\n", entry.Index, err)
					continue
				}
			}
		} else if entry.Precert != nil {
			cert, err := google_x509.ParseCertificate(entry.Precert.Submitted.Data)
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

func IdentitySearch(ctx context.Context, client *ctclient.LogClient, config *notifications.IdentityMonitorConfiguration, monitoredValues identity.MonitoredValues) ([]identity.MonitoredIdentity, []identity.FailedLogEntry, error) {
	entries, err := GetCTLogEntries(ctx, client, *config.StartIndex, *config.EndIndex)
	if err != nil {
		return nil, nil, err
	}
	matchedEntries, failedEntries, err := MatchedIndices(entries, monitoredValues, config.CARootsFile, config.CAIntermediatesFile)
	if err != nil {
		return nil, nil, err
	}

	err = file.WriteMatchedIdentityEntries(config.OutputIdentitiesFile, config.OutputIdentitiesFormat, matchedEntries, config.IdentityMetadataFile, *config.EndIndex)
	if err != nil {
		return nil, nil, err
	}

	identities := identity.CreateIdentitiesList(monitoredValues)
	monitoredIdentities := identity.CreateMonitoredIdentities(matchedEntries, identities)
	return monitoredIdentities, failedEntries, nil
}
