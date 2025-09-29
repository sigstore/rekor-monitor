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
	"crypto/x509"
	"fmt"
	"os"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	google_x509 "github.com/google/certificate-transparency-go/x509"
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
	matchedEntries := []identity.LogEntry{}
	for _, monitoredCertID := range monitoredCertIDs {
		match, sub, iss, err := identity.CertMatchesPolicy(cert, monitoredCertID.CertSubject, monitoredCertID.Issuers)
		if err != nil {
			return nil, fmt.Errorf("error with policy matching  at index %d: %w", logEntry.Index, err)
		} else if match {
			matchedEntries = append(matchedEntries, identity.LogEntry{
				MatchedIdentity:     monitoredCertID.CertSubject,
				MatchedIdentityType: identity.MatchedIdentityTypeCertSubject,
				CertSubject:         sub,
				Issuer:              iss,
				Index:               logEntry.Index,
			})
		}
	}
	return matchedEntries, nil
}

func ScanEntryOIDExtensions(logEntry ct.LogEntry, monitoredOIDMatchers []extensions.OIDExtension) ([]identity.LogEntry, error) {
	cert := logEntry.X509Cert
	if cert == nil && logEntry.Precert != nil {
		cert = logEntry.Precert.TBSCertificate
	}

	if cert == nil {
		return nil, fmt.Errorf("unsupported CT log entry at index %d", logEntry.Index)
	}
	matchedEntries := []identity.LogEntry{}
	for _, monitoredOID := range monitoredOIDMatchers {
		match, _, extValue, err := identity.OIDMatchesPolicy(cert, monitoredOID.ObjectIdentifier, monitoredOID.ExtensionValues)
		if err != nil {
			return nil, fmt.Errorf("error with policy matching at index %d: %w", logEntry.Index, err)
		}
		if match {
			matchedEntries = append(matchedEntries, identity.LogEntry{
				MatchedIdentity:     extValue,
				MatchedIdentityType: identity.MatchedIdentityTypeExtensionValue,
				Index:               logEntry.Index,
				OIDExtension:        monitoredOID.ObjectIdentifier,
				ExtensionValue:      extValue,
			})
		}
	}
	return matchedEntries, nil
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

	err = file.WriteMatchedIdentityEntries(config.OutputIdentitiesFile, matchedEntries, config.IdentityMetadataFile, *config.EndIndex)
	if err != nil {
		return nil, nil, err
	}

	identities := identity.CreateIdentitiesList(monitoredValues)
	monitoredIdentities := identity.CreateMonitoredIdentities(matchedEntries, identities)
	return monitoredIdentities, failedEntries, nil
}
