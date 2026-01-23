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

package v1

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"

	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/util"

	// required imports to call init methods
	_ "github.com/sigstore/rekor/pkg/types/alpine/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/cose/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/helm/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	_ "github.com/sigstore/rekor/pkg/types/jar/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rfc3161/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/tuf/v0.0.1"
)

func MatchLogEntryFingerprint(logEntryAnon models.LogEntryAnon, uuid string, entryFingerprints []string, monitoredFp identity.FingerprintValue) []identity.LogEntry {
	matchedEntries := []identity.LogEntry{}
	for _, fp := range entryFingerprints {
		if fp == monitoredFp.Fingerprint {
			matchedEntries = append(matchedEntries, identity.LogEntry{
				MatchedIdentity: monitoredFp,
				Fingerprint:     fp,
				Index:           *logEntryAnon.LogIndex,
				UUID:            uuid,
			})
		}
	}
	return matchedEntries
}

func MatchLogEntryCertificateIdentity(logEntryAnon models.LogEntryAnon, uuid string, entryCertificates []*x509.Certificate, monitoredCertID identity.CertIdentityValue) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	for _, cert := range entryCertificates {
		match, sub, iss, err := identity.CertMatchesPolicy(cert, monitoredCertID.CertSubject, monitoredCertID.Issuers)
		if err != nil {
			return nil, fmt.Errorf("error with policy matching for UUID %s at index %d: %w", uuid, logEntryAnon.LogIndex, err)
		} else if match {
			matchedEntries = append(matchedEntries, identity.LogEntry{
				MatchedIdentity: monitoredCertID,
				CertSubject:     sub,
				Issuer:          iss,
				Index:           *logEntryAnon.LogIndex,
				UUID:            uuid,
			})
		}
	}
	return matchedEntries, nil
}

func MatchLogEntrySubject(logEntryAnon models.LogEntryAnon, uuid string, entrySubjects []string, monitoredSub identity.SubjectValue) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	regex, err := regexp.Compile(monitoredSub.Subject)
	if err != nil {
		return nil, fmt.Errorf("error compiling regex for UUID %s at index %d: %w", uuid, logEntryAnon.LogIndex, err)
	}
	for _, sub := range entrySubjects {
		if regex.MatchString(sub) {
			matchedEntries = append(matchedEntries, identity.LogEntry{
				MatchedIdentity: monitoredSub,
				Subject:         sub,
				Index:           *logEntryAnon.LogIndex,
				UUID:            uuid,
			})
		}
	}
	return matchedEntries, nil
}

func MatchLogEntryOID(logEntryAnon models.LogEntryAnon, uuid string, entryCertificates []*x509.Certificate, monitoredOID identity.OIDMatcherValue) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	for _, cert := range entryCertificates {
		match, oid, extValue, err := identity.OIDMatchesPolicy(cert, monitoredOID.OID, monitoredOID.ExtensionValues)
		if err != nil {
			return nil, fmt.Errorf("error with policy matching for UUID %s at index %d: %w", uuid, logEntryAnon.LogIndex, err)
		}
		if match {
			matchedEntries = append(matchedEntries, identity.LogEntry{
				MatchedIdentity: monitoredOID,
				Index:           *logEntryAnon.LogIndex,
				UUID:            uuid,
				OIDExtension:    oid,
				ExtensionValue:  extValue,
			})
		}
	}
	return matchedEntries, nil
}

// MatchedIndices returns a list of log indices that contain the requested identities.
func MatchedIndices(logEntries []models.LogEntry, mvs identity.MonitoredValues, caRoots string, caIntermediates string) ([]identity.LogEntry, []identity.FailedLogEntry, error) {
	if err := identity.VerifyMonitoredValues(mvs); err != nil {
		return nil, nil, err
	}

	var matchedEntries []identity.LogEntry
	var failedEntries []identity.FailedLogEntry

	for _, entries := range logEntries {
		for uuid, entry := range entries {
			verifiers, err := extractVerifiers(&entry)
			if err != nil {
				failedEntries = append(failedEntries, identity.FailedLogEntry{
					Index: *entry.LogIndex,
					UUID:  uuid,
					Error: fmt.Sprintf("error extracting verifiers: %v", err),
				})
				continue
			}
			subjects, certs, fps, err := extractAllIdentities(verifiers)
			if err != nil {
				failedEntries = append(failedEntries, identity.FailedLogEntry{
					Index: *entry.LogIndex,
					UUID:  uuid,
					Error: fmt.Sprintf("error extracting identities: %v", err),
				})
				continue
			}

			// Validate that the certificate chain up to a trusted CA
			if err := identity.ValidateCertificateChain(certs, caRoots, caIntermediates); err != nil {
				fmt.Fprintf(os.Stderr, "Certificate chain for log entry (UUID: %s, Index: %d) could not be verified against trusted CAs, skipping the entry: %v\n", uuid, *entry.LogIndex, err)
				continue
			}

			// Iterate over each monitored value and match accordingly
			for _, mv := range mvs {
				switch v := mv.(type) {
				case identity.FingerprintValue:
					matchedFingerprintEntries := MatchLogEntryFingerprint(entry, uuid, fps, v)
					matchedEntries = append(matchedEntries, matchedFingerprintEntries...)
				case identity.SubjectValue:
					matchedSubjectEntries, err := MatchLogEntrySubject(entry, uuid, subjects, v)
					if err != nil {
						failedEntries = append(failedEntries, identity.FailedLogEntry{
							Index: *entry.LogIndex,
							UUID:  uuid,
							Error: fmt.Sprintf("error matching subjects: %v", err),
						})
						continue
					}
					matchedEntries = append(matchedEntries, matchedSubjectEntries...)
				case identity.CertIdentityValue:
					matchedCertIDEntries, err := MatchLogEntryCertificateIdentity(entry, uuid, certs, v)
					if err != nil {
						failedEntries = append(failedEntries, identity.FailedLogEntry{
							Index: *entry.LogIndex,
							UUID:  uuid,
							Error: fmt.Sprintf("error matching certificate identities: %v", err),
						})
						continue
					}
					matchedEntries = append(matchedEntries, matchedCertIDEntries...)
				case identity.OIDMatcherValue:
					matchedOIDEntries, err := MatchLogEntryOID(entry, uuid, certs, v)
					if err != nil {
						failedEntries = append(failedEntries, identity.FailedLogEntry{
							Index: *entry.LogIndex,
							UUID:  uuid,
							Error: fmt.Sprintf("error matching object identifier extensions and values: %v", err),
						})
						continue
					}
					matchedEntries = append(matchedEntries, matchedOIDEntries...)
				}
			}
		}
	}

	return matchedEntries, failedEntries, nil
}

// extractVerifiers extracts a set of keys or certificates that can verify an
// artifact signature from a Rekor entry
func extractVerifiers(e *models.LogEntryAnon) ([]pki.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}

	return eimpl.Verifiers()
}

// extractAllIdentities gets all certificates, email addresses, and key fingerprints
// from a list of verifiers
func extractAllIdentities(verifiers []pki.PublicKey) ([]string, []*x509.Certificate, []string, error) {
	var subjects []string
	var certificates []*x509.Certificate
	var fps []string

	for _, v := range verifiers {
		// append all verifier subjects (email or SAN)
		subjects = append(subjects, v.Subjects()...)
		ids, err := v.Identities()
		if err != nil {
			return nil, nil, nil, err
		}
		// append all certificate and key fingerprints
		for _, i := range ids {
			fps = append(fps, i.Fingerprint)
			if cert, ok := i.Crypto.(*x509.Certificate); ok {
				certificates = append(certificates, cert)
			}
		}
	}
	return subjects, certificates, fps, nil
}

// GetCheckpointIndex fetches the index of a checkpoint and returns it.
func GetCheckpointIndex(logInfo *models.LogInfo, checkpoint *util.SignedCheckpoint) int64 {
	// Get log size of inactive shards
	totalSize := int64(0)
	for _, s := range logInfo.InactiveShards {
		totalSize += *s.TreeSize
	}
	index := int64(checkpoint.Size) + totalSize - 1 //nolint: gosec // G115

	return index
}

func IdentitySearch(ctx context.Context, rekorClient *client.Rekor, monitoredValues identity.MonitoredValues, startIndex, endIndex int64, opts ...identity.SearchOption) ([]identity.MonitoredIdentity, []identity.FailedLogEntry, error) {
	o := identity.MakeIdentitySearchOptions(opts...)

	entries, err := GetEntriesByIndexRange(ctx, rekorClient, startIndex, endIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting entries by index range: %v", err)
	}
	matchedEntries, failedEntries, err := MatchedIndices(entries, monitoredValues, o.CARootsFile, o.CAIntermediatesFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error matching indices: %v", err)
	}

	err = file.WriteMatchedIdentityEntries(o.OutputIdentitiesFile, o.OutputIdentitiesFormat, matchedEntries, o.IdentityMetadataFile, endIndex)
	if err != nil {
		return nil, nil, err
	}

	monitoredIdentities := identity.CreateMonitoredIdentities(matchedEntries)
	return monitoredIdentities, failedEntries, nil
}
