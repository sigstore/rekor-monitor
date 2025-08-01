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
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
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

func MatchLogEntryFingerprints(logEntryAnon models.LogEntryAnon, uuid string, entryFingerprints []string, monitoredFingerprints []string) []identity.LogEntry {
	matchedEntries := []identity.LogEntry{}
	for _, monitoredFp := range monitoredFingerprints {
		for _, fp := range entryFingerprints {
			if fp == monitoredFp {
				matchedEntries = append(matchedEntries, identity.LogEntry{
					Fingerprint: fp,
					Index:       *logEntryAnon.LogIndex,
					UUID:        uuid,
				})
			}
		}
	}
	return matchedEntries
}

func MatchLogEntryCertificateIdentities(logEntryAnon models.LogEntryAnon, uuid string, entryCertificates []*x509.Certificate, monitoredCertIDs []identity.CertificateIdentity) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	for _, monitoredCertID := range monitoredCertIDs {
		for _, cert := range entryCertificates {
			match, sub, iss, err := identity.CertMatchesPolicy(cert, monitoredCertID.CertSubject, monitoredCertID.Issuers)
			if err != nil {
				return nil, fmt.Errorf("error with policy matching for UUID %s at index %d: %w", uuid, logEntryAnon.LogIndex, err)
			} else if match {
				matchedEntries = append(matchedEntries, identity.LogEntry{
					CertSubject: sub,
					Issuer:      iss,
					Index:       *logEntryAnon.LogIndex,
					UUID:        uuid,
				})
			}
		}
	}
	return matchedEntries, nil
}

func MatchLogEntrySubjects(logEntryAnon models.LogEntryAnon, uuid string, entrySubjects []string, monitoredSubjects []string) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	for _, monitoredSub := range monitoredSubjects {
		regex, err := regexp.Compile(monitoredSub)
		if err != nil {
			return nil, fmt.Errorf("error compiling regex for UUID %s at index %d: %w", uuid, logEntryAnon.LogIndex, err)
		}
		for _, sub := range entrySubjects {
			if regex.MatchString(sub) {
				matchedEntries = append(matchedEntries, identity.LogEntry{
					Subject: sub,
					Index:   *logEntryAnon.LogIndex,
					UUID:    uuid,
				})
			}
		}
	}
	return matchedEntries, nil
}

func MatchLogEntryOIDs(logEntryAnon models.LogEntryAnon, uuid string, entryCertificates []*x509.Certificate, monitoredOIDMatchers []extensions.OIDExtension) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	for _, monitoredOID := range monitoredOIDMatchers {
		for _, cert := range entryCertificates {
			match, oid, extValue, err := identity.OIDMatchesPolicy(cert, monitoredOID.ObjectIdentifier, monitoredOID.ExtensionValues)
			if err != nil {
				return nil, fmt.Errorf("error with policy matching for UUID %s at index %d: %w", uuid, logEntryAnon.LogIndex, err)
			}
			if match {
				matchedEntries = append(matchedEntries, identity.LogEntry{
					Index:          *logEntryAnon.LogIndex,
					UUID:           uuid,
					OIDExtension:   oid,
					ExtensionValue: extValue,
				})
			}
		}
	}
	return matchedEntries, nil
}

// MatchedIndices returns a list of log indices that contain the requested identities.
func MatchedIndices(logEntries []models.LogEntry, mvs identity.MonitoredValues) ([]identity.LogEntry, error) {
	if err := verifyMonitoredValues(mvs); err != nil {
		return nil, err
	}

	var matchedEntries []identity.LogEntry

	for _, entries := range logEntries {
		for uuid, entry := range entries {
			entry := entry

			verifiers, err := extractVerifiers(&entry)
			if err != nil {
				return nil, fmt.Errorf("error extracting verifiers for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
			}
			subjects, certs, fps, err := extractAllIdentities(verifiers)
			if err != nil {
				return nil, fmt.Errorf("error extracting identities for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
			}

			matchedFingerprintEntries := MatchLogEntryFingerprints(entry, uuid, fps, mvs.Fingerprints)
			matchedEntries = append(matchedEntries, matchedFingerprintEntries...)

			matchedSubjectEntries, err := MatchLogEntrySubjects(entry, uuid, subjects, mvs.Subjects)
			if err != nil {
				return nil, fmt.Errorf("error matching subjects for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
			}
			matchedEntries = append(matchedEntries, matchedSubjectEntries...)

			matchedCertIDEntries, err := MatchLogEntryCertificateIdentities(entry, uuid, certs, mvs.CertificateIdentities)
			if err != nil {
				return nil, fmt.Errorf("error matching certificate identities for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
			}
			matchedEntries = append(matchedEntries, matchedCertIDEntries...)

			matchedOIDEntries, err := MatchLogEntryOIDs(entry, uuid, certs, mvs.OIDMatchers)
			if err != nil {
				return nil, fmt.Errorf("error matching object identifier extensions and values for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
			}
			matchedEntries = append(matchedEntries, matchedOIDEntries...)
		}
	}

	return matchedEntries, nil
}

// verifyMonitoredValues checks that monitored values are valid
func verifyMonitoredValues(mvs identity.MonitoredValues) error {
	if !identity.MonitoredValuesExist(mvs) {
		return errors.New("no identities provided to monitor")
	}
	for _, certID := range mvs.CertificateIdentities {
		if len(certID.CertSubject) == 0 {
			return errors.New("certificate subject empty")
		}
		// issuers can be empty
		for _, iss := range certID.Issuers {
			if len(iss) == 0 {
				return errors.New("issuer empty")
			}
		}
	}
	for _, fp := range mvs.Fingerprints {
		if len(fp) == 0 {
			return errors.New("fingerprint empty")
		}
	}
	for _, sub := range mvs.Subjects {
		if len(sub) == 0 {
			return errors.New("subject empty")
		}
	}
	err := verifyMonitoredOIDs(mvs)
	if err != nil {
		return err
	}
	return nil
}

// verifyMonitoredOIDs checks that monitored OID extensions and matching values are valid
func verifyMonitoredOIDs(mvs identity.MonitoredValues) error {
	for _, oidMatcher := range mvs.OIDMatchers {
		if len(oidMatcher.ObjectIdentifier) == 0 {
			return errors.New("oid extension empty")
		}
		if len(oidMatcher.ExtensionValues) == 0 {
			return errors.New("oid matched values empty")
		}
		for _, extensionValue := range oidMatcher.ExtensionValues {
			if len(extensionValue) == 0 {
				return errors.New("oid matched value empty")
			}
		}
	}
	return nil
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
func GetCheckpointIndex(logInfo *models.LogInfo, checkpoint *util.SignedCheckpoint) int {
	// Get log size of inactive shards
	totalSize := 0
	for _, s := range logInfo.InactiveShards {
		totalSize += int(*s.TreeSize)
	}
	index := int(checkpoint.Size) + totalSize - 1 //nolint: gosec // G115

	return index
}

func IdentitySearch(startIndex int, endIndex int, rekorClient *client.Rekor, monitoredValues identity.MonitoredValues, outputIdentitiesFile string, idMetadataFile *string) ([]identity.MonitoredIdentity, error) {
	entries, err := GetEntriesByIndexRange(context.Background(), rekorClient, startIndex, endIndex)
	if err != nil {
		return nil, fmt.Errorf("error getting entries by index range: %v", err)
	}

	idEntries, err := MatchedIndices(entries, monitoredValues)
	if err != nil {
		return nil, fmt.Errorf("error finding log indices: %v", err)
	}

	if len(idEntries) > 0 {
		for _, idEntry := range idEntries {
			fmt.Fprintf(os.Stderr, "Found %s\n", idEntry.String())

			if err := file.WriteIdentity(outputIdentitiesFile, idEntry); err != nil {
				return nil, fmt.Errorf("failed to write entry: %v", err)
			}
		}
	}

	// TODO: idMetadataFile currently takes in a string pointer to not cause a regression in the current reusable monitoring workflow.
	// Once the reusable monitoring workflow is split into a consistency check and identity search, idMetadataFile should always take in a string value.
	if idMetadataFile != nil {
		idMetadata := file.IdentityMetadata{
			LatestIndex: endIndex,
		}
		err = file.WriteIdentityMetadata(*idMetadataFile, idMetadata)
		if err != nil {
			return nil, fmt.Errorf("failed to write id metadata: %v", err)
		}
	}

	identities := identity.CreateIdentitiesList(monitoredValues)
	monitoredIdentities := identity.CreateMonitoredIdentities(idEntries, identities)
	return monitoredIdentities, nil
}
