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

package rekor

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
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
	"github.com/sigstore/sigstore/pkg/cryptoutils"

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

var (
	certExtensionOIDCIssuer   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	certExtensionOIDCIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// MatchedIndices returns a list of log indices that contain the requested identities.
func MatchedIndices(logEntries []models.LogEntry, mvs identity.MonitoredValues) ([]identity.RekorLogEntry, error) {
	allOIDMatchers, err := extensions.MergeOIDMatchers(mvs.OIDMatchers, mvs.FulcioExtensions, mvs.CustomExtensions)
	if err != nil {
		return nil, err
	}
	// TODO: OIDMatchers should be preprocessed and merged before being passed into MatchedIndices
	mvs.OIDMatchers = allOIDMatchers
	if err := verifyMonitoredValues(mvs); err != nil {
		return nil, err
	}

	var matchedEntries []identity.RekorLogEntry

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

			for _, monitoredFp := range mvs.Fingerprints {
				for _, fp := range fps {
					if fp == monitoredFp {
						matchedEntries = append(matchedEntries, identity.RekorLogEntry{
							Fingerprint: fp,
							Index:       *entry.LogIndex,
							UUID:        uuid,
						})
					}
				}
			}

			for _, monitoredCertID := range mvs.CertificateIdentities {
				for _, cert := range certs {
					match, sub, iss, err := certMatchesPolicy(cert, monitoredCertID.CertSubject, monitoredCertID.Issuers)
					if err != nil {
						return nil, fmt.Errorf("error with policy matching for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
					} else if match {
						matchedEntries = append(matchedEntries, identity.RekorLogEntry{
							CertSubject: sub,
							Issuer:      iss,
							Index:       *entry.LogIndex,
							UUID:        uuid,
						})
					}
				}
			}

			for _, monitoredSub := range mvs.Subjects {
				regex, err := regexp.Compile(monitoredSub)
				if err != nil {
					return nil, fmt.Errorf("error compiling regex for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
				}
				for _, sub := range subjects {
					if regex.MatchString(sub) {
						matchedEntries = append(matchedEntries, identity.RekorLogEntry{
							Subject: sub,
							Index:   *entry.LogIndex,
							UUID:    uuid,
						})
					}
				}
			}

			for _, monitoredOID := range mvs.OIDMatchers {
				for _, cert := range certs {
					match, oid, extValue, err := oidMatchesPolicy(cert, monitoredOID.ObjectIdentifier, monitoredOID.ExtensionValues)
					if err != nil {
						return nil, fmt.Errorf("error with policy matching for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
					}
					if match {
						matchedEntries = append(matchedEntries, identity.RekorLogEntry{
							Index:          *entry.LogIndex,
							UUID:           uuid,
							OIDExtension:   oid,
							ExtensionValue: extValue,
						})
					}
				}
			}
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

// getExtension gets a certificate extension by OID where the extension value is an
// ASN.1-encoded string
func getExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (string, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oid) {
			continue
		}
		var extValue string
		rest, err := asn1.Unmarshal(ext.Value, &extValue)
		if err != nil {
			return "", fmt.Errorf("%w", err)
		}
		if len(rest) != 0 {
			return "", fmt.Errorf("unmarshalling extension had rest for oid %v", oid)
		}
		return extValue, nil
	}
	return "", nil
}

// getDeprecatedExtension gets a certificate extension by OID where the extension value is a raw string
func getDeprecatedExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (string, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return string(ext.Value), nil
		}
	}
	return "", nil
}

// certMatchesPolicy returns true if a certificate contains a given subject and optionally a given issuer
// expectedSub and expectedIssuers can be regular expressions
// certMatchesPolicy also returns the matched subject and issuer on success
func certMatchesPolicy(cert *x509.Certificate, expectedSub string, expectedIssuers []string) (bool, string, string, error) {
	sans := cryptoutils.GetSubjectAlternateNames(cert)
	var issuer string
	var err error
	issuer, err = getExtension(cert, certExtensionOIDCIssuerV2)
	if err != nil || issuer == "" {
		// fallback to deprecated issuer extension
		issuer, err = getDeprecatedExtension(cert, certExtensionOIDCIssuer)
		if err != nil || issuer == "" {
			return false, "", "", err
		}
	}
	subjectMatches := false
	regex, err := regexp.Compile(expectedSub)
	if err != nil {
		return false, "", "", fmt.Errorf("malformed subject regex: %w", err)
	}
	matchedSub := ""
	for _, sub := range sans {
		if regex.MatchString(sub) {
			subjectMatches = true
			matchedSub = sub
		}
	}
	// allow any issuer
	if len(expectedIssuers) == 0 {
		return subjectMatches, matchedSub, issuer, nil
	}

	issuerMatches := false
	for _, expectedIss := range expectedIssuers {
		regex, err := regexp.Compile(expectedIss)
		if err != nil {
			return false, "", "", fmt.Errorf("malformed issuer regex: %w", err)
		}
		if regex.MatchString(issuer) {
			issuerMatches = true
		}
	}
	return subjectMatches && issuerMatches, matchedSub, issuer, nil
}

// oidMatchesPolicy returns if a certificate contains both a given OID field and a matching value associated with that field
// if true, it returns the OID extension and extension value that were matched on
func oidMatchesPolicy(cert *x509.Certificate, oid asn1.ObjectIdentifier, extensionValues []string) (bool, asn1.ObjectIdentifier, string, error) {
	extValue, err := getExtension(cert, oid)
	if err != nil {
		return false, nil, "", fmt.Errorf("error getting extension value: %w", err)
	}
	if extValue == "" {
		return false, nil, "", nil
	}

	for _, extensionValue := range extensionValues {
		if extValue == extensionValue {
			return true, oid, extValue, nil
		}
	}

	return false, nil, "", nil
}

func GetPrevCurrentCheckpoints(client *client.Rekor, logInfoFile string) (*util.SignedCheckpoint, *util.SignedCheckpoint, error) {
	logInfo, err := GetLogInfo(context.Background(), client)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting log info: %v", err)
	}

	checkpoint, err := ReadLatestCheckpoint(logInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading checkpoint: %v", err)
	}

	var prevCheckpoint *util.SignedCheckpoint
	prevCheckpoint, err = file.ReadLatestCheckpoint(logInfoFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading checkpoint log: %v", err)
	}

	return prevCheckpoint, checkpoint, nil
}

// GetCheckpointIndices fetches the start and end indexes between two checkpoints and returns them.
func GetCheckpointIndices(logInfo *models.LogInfo, prevCheckpoint *util.SignedCheckpoint, checkpoint *util.SignedCheckpoint) (int, int) {
	// Get log size of inactive shards
	totalSize := 0
	for _, s := range logInfo.InactiveShards {
		totalSize += int(*s.TreeSize)
	}
	startIndex := int(prevCheckpoint.Size) + totalSize - 1 //nolint: gosec // G115, log will never be large enough to overflow
	endIndex := int(checkpoint.Size) + totalSize - 1       //nolint: gosec // G115

	return startIndex, endIndex
}

func IdentitySearch(startIndex int, endIndex int, rekorClient *client.Rekor, monitoredValues identity.MonitoredValues, outputIdentitiesFile string, idMetadataFile *string) error {

	entries, err := GetEntriesByIndexRange(context.Background(), rekorClient, startIndex, endIndex)
	if err != nil {
		return fmt.Errorf("error getting entries by index range: %v", err)
	}
	idEntries, err := MatchedIndices(entries, monitoredValues)
	if err != nil {
		return fmt.Errorf("error finding log indices: %v", err)
	}

	if len(idEntries) > 0 {
		for _, idEntry := range idEntries {
			fmt.Fprintf(os.Stderr, "Found %s\n", idEntry.String())

			if err := file.WriteIdentity(outputIdentitiesFile, idEntry); err != nil {
				return fmt.Errorf("failed to write entry: %v", err)
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
			return fmt.Errorf("failed to write id metadata: %v", err)
		}
	}

	return nil
}

// writeIdentitiesBetweenCheckpoints monitors for given identities between two checkpoints and writes any found identities to file.
func writeIdentitiesBetweenCheckpoints(logInfo *models.LogInfo, prevCheckpoint *util.SignedCheckpoint, checkpoint *util.SignedCheckpoint, monitoredValues identity.MonitoredValues, rekorClient *client.Rekor, outputIdentitiesFile string) error {
	// Get log size of inactive shards
	startIndex, endIndex := GetCheckpointIndices(logInfo, prevCheckpoint, checkpoint)

	// Search for identities in the log range
	if identity.MonitoredValuesExist(monitoredValues) {
		err := IdentitySearch(startIndex, endIndex, rekorClient, monitoredValues, outputIdentitiesFile, nil)
		if err != nil {
			return fmt.Errorf("error monitoring for identities: %v", err)
		}
	}
	return nil
}
