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

package v2

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"regexp"

	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/verifier"
	"github.com/sigstore/rekor-tiles/pkg/verifier/certificate"
	"github.com/sigstore/rekor-tiles/pkg/verifier/publickey"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func MatchLogEntryFingerprints(entry Entry, entryFingerprints []string, monitoredFingerprints []string) []identity.LogEntry {
	matchedEntries := []identity.LogEntry{}
	for _, monitoredFp := range monitoredFingerprints {
		for _, fp := range entryFingerprints {
			if fp == monitoredFp {
				matchedEntries = append(matchedEntries, identity.LogEntry{
					Fingerprint: fp,
					Index:       int64(entry.Index),
				})
			}
		}
	}
	return matchedEntries
}

func MatchLogEntryCertificateIdentities(entry Entry, entryCertificates []*x509.Certificate, monitoredCertIDs []identity.CertificateIdentity) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	for _, monitoredCertID := range monitoredCertIDs {
		for _, cert := range entryCertificates {
			match, sub, iss, err := identity.CertMatchesPolicy(cert, monitoredCertID.CertSubject, monitoredCertID.Issuers)
			if err != nil {
				return nil, fmt.Errorf("error with policy matching at index %d: %w", entry.Index, err)
			} else if match {
				matchedEntries = append(matchedEntries, identity.LogEntry{
					CertSubject: sub,
					Issuer:      iss,
					Index:       int64(entry.Index),
				})
			}
		}
	}
	return matchedEntries, nil
}

func MatchLogEntrySubjects(entry Entry, entrySubjects []string, monitoredSubjects []string) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	for _, monitoredSub := range monitoredSubjects {
		regex, err := regexp.Compile(monitoredSub)
		if err != nil {
			return nil, fmt.Errorf("error compiling regex at index %d: %w", entry.Index, err)
		}
		for _, sub := range entrySubjects {
			if regex.MatchString(sub) {
				matchedEntries = append(matchedEntries, identity.LogEntry{
					Subject: sub,
					Index:   int64(entry.Index),
				})
			}
		}
	}
	return matchedEntries, nil
}

func MatchLogEntryOIDs(entry Entry, entryCertificates []*x509.Certificate, monitoredOIDMatchers []extensions.OIDExtension) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	for _, monitoredOID := range monitoredOIDMatchers {
		for _, cert := range entryCertificates {
			match, oid, extValue, err := identity.OIDMatchesPolicy(cert, monitoredOID.ObjectIdentifier, monitoredOID.ExtensionValues)
			if err != nil {
				return nil, fmt.Errorf("error with policy matching at index %d: %w", entry.Index, err)
			}
			if match {
				matchedEntries = append(matchedEntries, identity.LogEntry{
					Index:          int64(entry.Index),
					OIDExtension:   oid,
					ExtensionValue: extValue,
				})
			}
		}
	}
	return matchedEntries, nil
}

// extractVerifiers extracts a set of keys or certificates that can verify an
// artifact signature from a Rekor entry
func extractVerifiers(e *protobuf.Entry) ([]verifier.Verifier, error) {
	spec := e.GetSpec()
	if spec == nil {
		return nil, fmt.Errorf("Entry without spec")
	}
	var protoVerifiers []*protobuf.Verifier
	switch e.GetKind() {
	case "dsse":
		dsseEntry := spec.GetDsseV002()
		for _, s := range dsseEntry.GetSignatures() {
			protoVerifiers = append(protoVerifiers, s.GetVerifier())
		}
	case "hashedrekord":
		hashedRekordEntry := spec.GetHashedRekordV002()
		protoVerifiers = append(protoVerifiers, hashedRekordEntry.GetSignature().GetVerifier())
	default:
		return nil, fmt.Errorf("entry kind not supported: %s", e.GetKind())
	}

	var verifiers []verifier.Verifier
	for _, pv := range protoVerifiers {
		if pubKey := pv.GetPublicKey(); pubKey != nil {
			v, err := publickey.NewVerifier(bytes.NewReader(pubKey.GetRawBytes()))
			if err != nil {
				return nil, fmt.Errorf("error reading public key from entry: %v", err)
			}
			verifiers = append(verifiers, v)
		} else if cert := pv.GetX509Certificate(); cert != nil {
			v, err := certificate.NewVerifier(bytes.NewReader(cert.GetRawBytes()))
			if err != nil {
				return nil, fmt.Errorf("error reading certificate from entry: %v", err)
			}
			verifiers = append(verifiers, v)
		} else {
			return nil, fmt.Errorf("must contain either a public key or X.509 certificate")
		}
	}

	return verifiers, nil
}

// extractAllIdentities gets all certificates, email addresses, and key fingerprints
// from a list of verifiers
func extractAllIdentities(verifiers []verifier.Verifier) ([]string, []*x509.Certificate, []string, error) {
	var subjects []string
	var certificates []*x509.Certificate
	var fps []string

	for _, v := range verifiers {
		identity, err := v.Identity()
		if err != nil {
			return nil, nil, nil, err
		}
		fps = append(fps, identity.Fingerprint)
		if cert, ok := identity.Crypto.(*x509.Certificate); ok {
			certificates = append(certificates, cert)
			// append all verifier subjects (email or SAN)
			subjects = append(subjects, cryptoutils.GetSubjectAlternateNames(cert)...)
		}

	}
	return subjects, certificates, fps, nil
}

// MatchedIndices returns a list of log entries that contain the requested identities.
func MatchedIndices(logEntries []Entry, mvs identity.MonitoredValues, trustedCAs []string) ([]identity.LogEntry, []identity.FailedLogEntry, error) {
	if err := identity.VerifyMonitoredValues(mvs); err != nil {
		return nil, nil, err
	}

	var matchedEntries []identity.LogEntry
	var failedEntries []identity.FailedLogEntry

	for _, entry := range logEntries {
		verifiers, err := extractVerifiers(entry.ProtoEntry)
		if err != nil {
			failedEntries = append(failedEntries, identity.FailedLogEntry{
				Index: int64(entry.Index),
				Error: fmt.Sprintf("error extracting verifiers: %v", err),
			})
			continue
		}
		subjects, certs, fps, err := extractAllIdentities(verifiers)
		if err != nil {
			failedEntries = append(failedEntries, identity.FailedLogEntry{
				Index: int64(entry.Index),
				Error: fmt.Sprintf("error extracting identities: %v", err),
			})
			continue
		}

		// Validate that the certificate chain up to a trusted CA
		if err := identity.ValidateCertificateChain(certs, trustedCAs); err != nil {
			fmt.Fprintf(os.Stderr, "Certificate chain for log entry (Index: %d) could not be verified against trusted CAs, skipping the entry: %v\n", entry.Index, err)
			continue
		}

		matchedFingerprintEntries := MatchLogEntryFingerprints(entry, fps, mvs.Fingerprints)
		matchedEntries = append(matchedEntries, matchedFingerprintEntries...)

		matchedSubjectEntries, err := MatchLogEntrySubjects(entry, subjects, mvs.Subjects)
		if err != nil {
			failedEntries = append(failedEntries, identity.FailedLogEntry{
				Index: int64(entry.Index),
				Error: fmt.Sprintf("error matching subjects: %v", err),
			})
			continue
		}
		matchedEntries = append(matchedEntries, matchedSubjectEntries...)

		matchedCertIDEntries, err := MatchLogEntryCertificateIdentities(entry, certs, mvs.CertificateIdentities)
		if err != nil {
			failedEntries = append(failedEntries, identity.FailedLogEntry{
				Index: int64(entry.Index),
				Error: fmt.Sprintf("error matching certificate identities: %v", err),
			})
			continue
		}
		matchedEntries = append(matchedEntries, matchedCertIDEntries...)

		matchedOIDEntries, err := MatchLogEntryOIDs(entry, certs, mvs.OIDMatchers)
		if err != nil {
			failedEntries = append(failedEntries, identity.FailedLogEntry{
				Index: int64(entry.Index),
				Error: fmt.Sprintf("error matching object identifier extensions and values: %v", err),
			})
			continue
		}
		matchedEntries = append(matchedEntries, matchedOIDEntries...)
	}

	return matchedEntries, failedEntries, nil
}

func IdentitySearch(ctx context.Context, startIndex int64, endIndex int64, rekorShards map[string]ShardInfo, latestShardOrigin string, monitoredValues identity.MonitoredValues, outputIdentitiesFile string, idMetadataFile *string, trustedCAs []string) ([]identity.MonitoredIdentity, []identity.FailedLogEntry, error) {
	// TODO: handle sharding
	activeShard := rekorShards[latestShardOrigin]
	entries, err := GetEntriesByIndexRange(ctx, activeShard, startIndex, endIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting entries by index range: %v", err)
	}

	matchedEntries, failedEntries, err := MatchedIndices(entries, monitoredValues, trustedCAs)
	if err != nil {
		return nil, nil, fmt.Errorf("error matching indices: %v", err)
	}

	err = file.WriteMatchedIdentityEntries(outputIdentitiesFile, matchedEntries, idMetadataFile, endIndex)
	if err != nil {
		return nil, nil, err
	}

	identities := identity.CreateIdentitiesList(monitoredValues)
	monitoredIdentities := identity.CreateMonitoredIdentities(matchedEntries, identities)
	return monitoredIdentities, failedEntries, nil
}
