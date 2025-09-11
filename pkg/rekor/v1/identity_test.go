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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/test"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	subject = "subject@example.com"
	issuer  = "oidc-issuer@domain.com"
)

func TestMatchedIndicesForCertificates(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCA()
	leafCert, leafKey, _ := test.GenerateLeafCert(subject, issuer, rootCert, rootKey)

	signer, err := signature.LoadECDSASignerVerifier(leafKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pemCert, _ := cryptoutils.MarshalCertificateToPEM(leafCert)

	payload := []byte{1, 2, 3, 4}
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}

	hashedrekord := &hashedrekord_v001.V001Entry{}
	hash := sha256.Sum256(payload)
	pe, err := hashedrekord.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(hash[:]),
		SignatureBytes: sig,
		PublicKeyBytes: [][]byte{pemCert},
		PKIFormat:      "x509",
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := types.UnmarshalEntry(pe)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := entry.Canonicalize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	integratedTime := time.Now()
	logIndex := 1234
	uuid := "123-456-123"
	logEntryAnon := models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: swag.Int64(integratedTime.Unix()),
		LogIndex:       swag.Int64(int64(logIndex)),
	}
	logEntry := models.LogEntry{uuid: logEntryAnon}

	//  match to subject with certificate in hashedrekord
	matches, failedEntries, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: subject,
			},
		}}, []string{})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}
	if matches[0].CertSubject != subject {
		t.Fatalf("mismatched subjects: %s %s", matches[0].CertSubject, subject)
	}
	if matches[0].Issuer != issuer {
		t.Fatalf("mismatched issuers: %s %s", matches[0].Issuer, issuer)
	}
	if matches[0].Index != int64(logIndex) {
		t.Fatalf("mismatched log indices: %d %d", matches[0].Index, logIndex)
	}
	if matches[0].UUID != uuid {
		t.Fatalf("mismatched UUIDs: %s %s", matches[0].UUID, uuid)
	}

	// match to subject and issuer with certificate in hashedrekord
	matches, failedEntries, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: subject,
				Issuers:     []string{issuer},
			},
		}}, []string{})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}

	// match with regex subject and regex issuer with certificate in hashedrekord
	matches, failedEntries, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: ".*ubje.*",
				Issuers:     []string{".+@domain.com"},
			},
		}}, []string{})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}

	// match to regex subject and issuer with certificate in rekord
	{
		rekord := &rekord_v001.V001Entry{}
		pe, err := rekord.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
			ArtifactBytes:  payload,
			SignatureBytes: sig,
			PublicKeyBytes: [][]byte{pemCert},
			PKIFormat:      "x509",
		})
		if err != nil {
			t.Fatal(err)
		}
		entry, err := types.UnmarshalEntry(pe)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := entry.Canonicalize(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		integratedTime := time.Now()
		logIndex := 1234
		uuid := "123-456-123"
		logEntryAnon := models.LogEntryAnon{
			Body:           base64.StdEncoding.EncodeToString(leaf),
			IntegratedTime: swag.Int64(integratedTime.Unix()),
			LogIndex:       swag.Int64(int64(logIndex)),
		}
		logEntry := models.LogEntry{uuid: logEntryAnon}

		matches, failedEntries, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
			CertificateIdentities: []identity.CertificateIdentity{
				{
					CertSubject: ".*ubje.*",
					Issuers:     []string{".+@domain.com"},
				},
			}}, []string{})
		if err != nil {
			t.Fatalf("expected error matching IDs, got %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("expected 1 match, got %d", len(matches))
		}
		if len(failedEntries) != 0 {
			t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
		}
	}

	testedMonitoredValues := []identity.MonitoredValues{
		{
			CertificateIdentities: []identity.CertificateIdentity{
				{
					CertSubject: subject,
					Issuers:     []string{"other"},
				},
			},
		},
		{
			CertificateIdentities: []identity.CertificateIdentity{
				{
					CertSubject: "other",
				},
			},
		},
	}
	for _, monitoredValues := range testedMonitoredValues {
		matches, failedEntries, err := MatchedIndices([]models.LogEntry{logEntry}, monitoredValues, []string{})
		if err != nil {
			t.Fatalf("expected error matching IDs, got %v", err)
		}
		if len(matches) != 0 {
			t.Fatalf("expected 0 matches, got %d", len(matches))
		}
		if len(failedEntries) != 0 {
			t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
		}
	}
}

// Test verifies that certificates containing only the deprecated
// extensions can still be monitored
func TestMatchedIndicesForDeprecatedCertificates(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCA()
	leafCert, leafKey, _ := test.GenerateDeprecatedLeafCert(subject, issuer, rootCert, rootKey)

	signer, err := signature.LoadECDSASignerVerifier(leafKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pemCert, _ := cryptoutils.MarshalCertificateToPEM(leafCert)

	payload := []byte{1, 2, 3, 4}
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}

	hashedrekord := &hashedrekord_v001.V001Entry{}
	hash := sha256.Sum256(payload)
	pe, err := hashedrekord.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(hash[:]),
		SignatureBytes: sig,
		PublicKeyBytes: [][]byte{pemCert},
		PKIFormat:      "x509",
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := types.UnmarshalEntry(pe)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := entry.Canonicalize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	integratedTime := time.Now()
	logIndex := 1234
	uuid := "123-456-123"
	logEntryAnon := models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: swag.Int64(integratedTime.Unix()),
		LogIndex:       swag.Int64(int64(logIndex)),
	}
	logEntry := models.LogEntry{uuid: logEntryAnon}

	//  match to subject with certificate in hashedrekord
	matches, failedEntries, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: subject,
				Issuers:     []string{issuer},
			},
		}}, []string{})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}
	if matches[0].CertSubject != subject {
		t.Fatalf("mismatched subjects: %s %s", matches[0].CertSubject, subject)
	}
	if matches[0].Issuer != issuer {
		t.Fatalf("mismatched issuers: %s %s", matches[0].Issuer, issuer)
	}
}

func TestMatchedIndicesForFingerprints(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pemKey, err := cryptoutils.MarshalPublicKeyToPEM(key.Public())
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte{1, 2, 3, 4}
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}

	hashedrekord := &hashedrekord_v001.V001Entry{}
	hash := sha256.Sum256(payload)
	pe, err := hashedrekord.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(hash[:]),
		SignatureBytes: sig,
		PublicKeyBytes: [][]byte{pemKey},
		PKIFormat:      "x509",
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := types.UnmarshalEntry(pe)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := entry.Canonicalize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	integratedTime := time.Now()
	logIndex := 1234
	uuid := "123-456-123"
	logEntryAnon := models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: swag.Int64(integratedTime.Unix()),
		LogIndex:       swag.Int64(int64(logIndex)),
	}
	logEntry := models.LogEntry{uuid: logEntryAnon}

	derKey, err := cryptoutils.MarshalPublicKeyToDER(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(derKey)
	fp := hex.EncodeToString(digest[:])

	//  match to key fingerprint in hashedrekord
	matches, failedEntries, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		Fingerprints: []string{
			fp,
		}}, []string{})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}
	if matches[0].Fingerprint != fp {
		t.Fatalf("mismatched fingerprints: %s %s", matches[0].Fingerprint, fp)
	}
	if matches[0].Index != int64(logIndex) {
		t.Fatalf("mismatched log indices: %d %d", matches[0].Index, logIndex)
	}
	if matches[0].UUID != uuid {
		t.Fatalf("mismatched UUIDs: %s %s", matches[0].UUID, uuid)
	}

	// no match with different fingerprints
	matches, failedEntries, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		Fingerprints: []string{
			"other-fp",
		}}, []string{})
	if err != nil {
		t.Fatalf("expected error matching fingerprints, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}
}

func TestMatchedIndicesForSubjects(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCA()
	leafCert, leafKey, _ := test.GenerateLeafCert(subject, issuer, rootCert, rootKey)

	signer, err := signature.LoadECDSASignerVerifier(leafKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pemCert, _ := cryptoutils.MarshalCertificateToPEM(leafCert)

	payload := []byte{1, 2, 3, 4}
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}

	hashedrekord := &hashedrekord_v001.V001Entry{}
	hash := sha256.Sum256(payload)
	pe, err := hashedrekord.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(hash[:]),
		SignatureBytes: sig,
		PublicKeyBytes: [][]byte{pemCert},
		PKIFormat:      "x509",
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := types.UnmarshalEntry(pe)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := entry.Canonicalize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	integratedTime := time.Now()
	logIndex := 1234
	uuid := "123-456-123"
	logEntryAnon := models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: swag.Int64(integratedTime.Unix()),
		LogIndex:       swag.Int64(int64(logIndex)),
	}
	logEntry := models.LogEntry{uuid: logEntryAnon}

	//  match to subject with certificate in hashedrekord
	matches, failedEntries, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		Subjects: []string{
			subject,
		}}, []string{})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}
	if matches[0].Subject != subject {
		t.Fatalf("mismatched subjects: %s %s", matches[0].Subject, subject)
	}
	if matches[0].Index != int64(logIndex) {
		t.Fatalf("mismatched log indices: %d %d", matches[0].Index, logIndex)
	}
	if matches[0].UUID != uuid {
		t.Fatalf("mismatched UUIDs: %s %s", matches[0].UUID, uuid)
	}

	// no match with different subjects
	matches, failedEntries, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		Subjects: []string{
			"other-sub",
		}}, []string{})
	if err != nil {
		t.Fatalf("expected error matching subjects, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}
}

func TestMatchedIndicesForOIDMatchers(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}
	extValueString := "test cert value"
	extValue, err := asn1.Marshal(extValueString)
	if err != nil {
		t.Fatal(err)
	}
	extension := pkix.Extension{
		Id:       oid,
		Critical: false,
		Value:    extValue,
	}

	rootCert, rootKey, _ := test.GenerateRootCA()
	leafCert, leafKey, _ := test.GenerateLeafCert(subject, issuer, rootCert, rootKey, extension)

	signer, err := signature.LoadECDSASignerVerifier(leafKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pemCert, _ := cryptoutils.MarshalCertificateToPEM(leafCert)

	payload := []byte{1, 2, 3, 4}
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}

	hashedrekord := &hashedrekord_v001.V001Entry{}
	hash := sha256.Sum256(payload)
	pe, err := hashedrekord.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(hash[:]),
		SignatureBytes: sig,
		PublicKeyBytes: [][]byte{pemCert},
		PKIFormat:      "x509",
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := types.UnmarshalEntry(pe)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := entry.Canonicalize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	integratedTime := time.Now()
	logIndex := 1234
	uuid := "123-456-123"
	logEntryAnon := models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: swag.Int64(integratedTime.Unix()),
		LogIndex:       swag.Int64(int64(logIndex)),
	}
	logEntry := models.LogEntry{uuid: logEntryAnon}

	// match to oid with matching extension value
	matches, failedEntries, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		OIDMatchers: []extensions.OIDExtension{
			{
				ObjectIdentifier: oid,
				ExtensionValues:  []string{extValueString},
			},
		}}, []string{})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}
	if matches[0].Index != int64(logIndex) {
		t.Fatalf("mismatched log indices: %d %d", matches[0].Index, logIndex)
	}
	if matches[0].UUID != uuid {
		t.Fatalf("mismatched UUIDs: %s %s", matches[0].UUID, uuid)
	}

	testedMonitoredValues := []identity.MonitoredValues{
		{
			OIDMatchers: []extensions.OIDExtension{
				{
					ObjectIdentifier: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9},
					ExtensionValues:  []string{"wrong"},
				},
			},
		},
		{
			OIDMatchers: []extensions.OIDExtension{
				{
					ObjectIdentifier: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 14},
					ExtensionValues:  []string{"test cert value"},
				},
			},
		},
	}
	for _, monitoredValues := range testedMonitoredValues {
		matches, failedEntries, err = MatchedIndices([]models.LogEntry{logEntry}, monitoredValues, []string{})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(matches) != 0 {
			t.Fatalf("expected no matches, got %d", len(matches))
		}
		if len(failedEntries) != 0 {
			t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
		}
	}
}

func TestMatchedIndicesForFulcioOIDMatchers(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}
	extValueString := "test cert value"
	extValue, err := asn1.Marshal(extValueString)
	if err != nil {
		t.Fatal(err)
	}
	extension := pkix.Extension{
		Id:       oid,
		Critical: false,
		Value:    extValue,
	}

	rootCert, rootKey, _ := test.GenerateRootCA()
	leafCert, leafKey, _ := test.GenerateLeafCert(subject, issuer, rootCert, rootKey, extension)

	signer, err := signature.LoadECDSASignerVerifier(leafKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pemCert, _ := cryptoutils.MarshalCertificateToPEM(leafCert)

	payload := []byte{1, 2, 3, 4}
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}

	hashedrekord := &hashedrekord_v001.V001Entry{}
	hash := sha256.Sum256(payload)
	pe, err := hashedrekord.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(hash[:]),
		SignatureBytes: sig,
		PublicKeyBytes: [][]byte{pemCert},
		PKIFormat:      "x509",
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := types.UnmarshalEntry(pe)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := entry.Canonicalize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	integratedTime := time.Now()
	logIndex := 1234
	uuid := "123-456-123"
	logEntryAnon := models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: swag.Int64(integratedTime.Unix()),
		LogIndex:       swag.Int64(int64(logIndex)),
	}
	logEntry := models.LogEntry{uuid: logEntryAnon}

	// match to oid with matching extension value
	oidMatchers := extensions.OIDMatchers{
		FulcioExtensions: extensions.FulcioExtensions{
			BuildSignerURI: []string{extValueString},
		},
	}
	renderedOIDMatchers, err := oidMatchers.RenderOIDMatchers()
	if err != nil {
		t.Fatalf("received error rendering OID matchers: %v", err)
	}
	matches, failedEntries, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		OIDMatchers: renderedOIDMatchers,
	}, []string{})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}
	if matches[0].Index != int64(logIndex) {
		t.Fatalf("mismatched log indices: %d %d", matches[0].Index, logIndex)
	}
	if matches[0].UUID != uuid {
		t.Fatalf("mismatched UUIDs: %s %s", matches[0].UUID, uuid)
	}

	// no match to oid with different oid extension field
	oidMatchers = extensions.OIDMatchers{
		FulcioExtensions: extensions.FulcioExtensions{
			BuildSignerDigest: []string{extValueString},
		},
	}
	renderedOIDMatchers, err = oidMatchers.RenderOIDMatchers()
	if err != nil {
		t.Fatalf("received error rendering OID matchers: %v", err)
	}
	matches, failedEntries, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		OIDMatchers: renderedOIDMatchers,
	}, []string{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}
}

func TestMatchedIndicesForCustomOIDMatchers(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}
	extValueString := "test cert value"
	extValue, err := asn1.Marshal(extValueString)
	if err != nil {
		t.Fatal(err)
	}
	extension := pkix.Extension{
		Id:       oid,
		Critical: false,
		Value:    extValue,
	}

	rootCert, rootKey, _ := test.GenerateRootCA()
	leafCert, leafKey, _ := test.GenerateLeafCert(subject, issuer, rootCert, rootKey, extension)

	signer, err := signature.LoadECDSASignerVerifier(leafKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pemCert, _ := cryptoutils.MarshalCertificateToPEM(leafCert)

	payload := []byte{1, 2, 3, 4}
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}

	hashedrekord := &hashedrekord_v001.V001Entry{}
	hash := sha256.Sum256(payload)
	pe, err := hashedrekord.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(hash[:]),
		SignatureBytes: sig,
		PublicKeyBytes: [][]byte{pemCert},
		PKIFormat:      "x509",
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := types.UnmarshalEntry(pe)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := entry.Canonicalize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	integratedTime := time.Now()
	logIndex := 1234
	uuid := "123-456-123"
	logEntryAnon := models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: swag.Int64(integratedTime.Unix()),
		LogIndex:       swag.Int64(int64(logIndex)),
	}
	logEntry := models.LogEntry{uuid: logEntryAnon}

	// match to oid with matching extension value
	oidMatchers := extensions.OIDMatchers{
		CustomExtensions: []extensions.CustomExtension{
			{
				ObjectIdentifier: "1.3.6.1.4.1.57264.1.9",
				ExtensionValues:  []string{extValueString},
			},
		},
	}
	renderedOIDMatchers, err := oidMatchers.RenderOIDMatchers()
	if err != nil {
		t.Fatalf("received error rendering OID matchers: %v", err)
	}
	matches, failedEntries, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		OIDMatchers: renderedOIDMatchers}, []string{})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}
	if matches[0].Index != int64(logIndex) {
		t.Fatalf("mismatched log indices: %d %d", matches[0].Index, logIndex)
	}
	if matches[0].UUID != uuid {
		t.Fatalf("mismatched UUIDs: %s %s", matches[0].UUID, uuid)
	}

	oidMatchers = extensions.OIDMatchers{
		CustomExtensions: []extensions.CustomExtension{
			{
				ObjectIdentifier: "1.3.6.1.4.1.57264.1.9",
				ExtensionValues:  []string{"wrong"},
			},
			{
				ObjectIdentifier: "1.3.6.1.4.1.57264.1.16",
				ExtensionValues:  []string{extValueString},
			},
		},
	}
	renderedOIDMatchers, err = oidMatchers.RenderOIDMatchers()
	if err != nil {
		t.Fatalf("received error rendering OID matchers: %v", err)
	}
	matches, failedEntries, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		OIDMatchers: renderedOIDMatchers}, []string{})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}
}

func TestMatchedIndicesFailures(t *testing.T) {
	monitoredValuesTests := map[string]struct {
		input       identity.MonitoredValues
		errorString string
	}{
		"no monitored values": {
			input:       identity.MonitoredValues{},
			errorString: "no identities provided to monitor",
		},
		"cert subject empty": {
			input: identity.MonitoredValues{
				CertificateIdentities: []identity.CertificateIdentity{
					{
						CertSubject: "",
					},
				},
			},
			errorString: "certificate subject empty",
		},
		"empty issuer": {
			input: identity.MonitoredValues{CertificateIdentities: []identity.CertificateIdentity{
				{
					CertSubject: "s",
					Issuers:     []string{""},
				},
			}},
			errorString: "issuer empty",
		},
		"empty subject": {
			input:       identity.MonitoredValues{Subjects: []string{""}},
			errorString: "subject empty",
		},
		"empty fingerprint": {
			input:       identity.MonitoredValues{Fingerprints: []string{""}},
			errorString: "fingerprint empty",
		},
		"empty oid extension": {
			input: identity.MonitoredValues{OIDMatchers: []extensions.OIDExtension{{
				ObjectIdentifier: asn1.ObjectIdentifier{},
				ExtensionValues:  []string{""},
			}}},
			errorString: "oid extension empty",
		},
		"empty oid matched values": {
			input: identity.MonitoredValues{OIDMatchers: []extensions.OIDExtension{{
				ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
				ExtensionValues:  []string{},
			}}},
			errorString: "oid matched values empty",
		},
		"empty oid matched value": {
			input: identity.MonitoredValues{OIDMatchers: []extensions.OIDExtension{{
				ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
				ExtensionValues:  []string{""},
			}}},
			errorString: "oid matched value empty",
		},
		"empty oid field": {
			input: identity.MonitoredValues{OIDMatchers: []extensions.OIDExtension{{
				ObjectIdentifier: asn1.ObjectIdentifier{},
				ExtensionValues:  []string{""},
			}}},
			errorString: "oid extension empty",
		},
	}

	for name, testCase := range monitoredValuesTests {
		t.Run(name, func(t *testing.T) {
			_, _, err := MatchedIndices(nil, testCase.input, []string{})
			if err == nil || !strings.Contains(err.Error(), testCase.errorString) {
				t.Fatalf("expected error %v, received %v", testCase.errorString, err)
			}
		})
	}
}

func TestMatchedIndicesWithTrustedCAs(t *testing.T) {
	// Create trusted CA
	trustedRootCert, trustedRootKey, err := test.GenerateRootCA()
	if err != nil {
		t.Fatal(err)
	}

	// Create untrusted CA
	untrustedRootCert, untrustedRootKey, err := test.GenerateRootCA()
	if err != nil {
		t.Fatal(err)
	}

	// Create leaf certificates signed by both CAs
	trustedSubject := "trusted@example.com"
	untrustedSubject := "untrusted@example.com"
	issuer := "oidc-issuer@domain.com"

	trustedLeafCert, trustedLeafKey, err := test.GenerateLeafCert(trustedSubject, issuer, trustedRootCert, trustedRootKey)
	if err != nil {
		t.Fatal(err)
	}

	untrustedLeafCert, untrustedLeafKey, err := test.GenerateLeafCert(untrustedSubject, issuer, untrustedRootCert, untrustedRootKey)
	if err != nil {
		t.Fatal(err)
	}

	// Create temporary files for the trusted CA
	trustedCAFile, err := os.CreateTemp("", "trusted-ca-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(trustedCAFile.Name())

	trustedCAPEM, err := cryptoutils.MarshalCertificateToPEM(trustedRootCert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trustedCAFile.Write(trustedCAPEM); err != nil {
		t.Fatal(err)
	}
	trustedCAFile.Close()

	// Create log entries for both certificates
	createLogEntry := func(cert *x509.Certificate, key *ecdsa.PrivateKey, subject string, uuid string) models.LogEntry {
		signer, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		pemCert, _ := cryptoutils.MarshalCertificateToPEM(cert)

		payload := []byte{1, 2, 3, 4}
		sig, err := signer.SignMessage(bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}

		hashedrekord := &hashedrekord_v001.V001Entry{}
		hash := sha256.Sum256(payload)
		pe, err := hashedrekord.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
			ArtifactHash:   hex.EncodeToString(hash[:]),
			SignatureBytes: sig,
			PublicKeyBytes: [][]byte{pemCert},
			PKIFormat:      "x509",
		})
		if err != nil {
			t.Fatal(err)
		}
		entry, err := types.UnmarshalEntry(pe)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := entry.Canonicalize(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		integratedTime := time.Now()
		logIndex := int64(1234)
		logEntryAnon := models.LogEntryAnon{
			Body:           base64.StdEncoding.EncodeToString(leaf),
			IntegratedTime: swag.Int64(integratedTime.Unix()),
			LogIndex:       swag.Int64(logIndex),
		}
		return models.LogEntry{uuid: logEntryAnon}
	}

	trustedLogEntry := createLogEntry(trustedLeafCert, trustedLeafKey, trustedSubject, "trusted-uuid")
	untrustedLogEntry := createLogEntry(untrustedLeafCert, untrustedLeafKey, untrustedSubject, "untrusted-uuid")

	// Test with trusted CAs provided - should only match trusted certificate
	matches, failedEntries, err := MatchedIndices([]models.LogEntry{trustedLogEntry, untrustedLogEntry}, identity.MonitoredValues{
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: ".*@example.com",
				Issuers:     []string{issuer},
			},
		},
	}, []string{trustedCAFile.Name()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only match the trusted certificate
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].CertSubject != trustedSubject {
		t.Fatalf("expected subject %s, got %s", trustedSubject, matches[0].CertSubject)
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}

	// Test with no trusted CAs provided - should match both certificates
	matches, failedEntries, err = MatchedIndices([]models.LogEntry{trustedLogEntry, untrustedLogEntry}, identity.MonitoredValues{
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: ".*@example.com",
				Issuers:     []string{issuer},
			},
		},
	}, []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should match both certificates
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	if len(failedEntries) != 0 {
		t.Fatalf("expected 0 failed entries, got %d", len(failedEntries))
	}

	// Verify both subjects are present
	subjects := make(map[string]bool)
	for _, match := range matches {
		subjects[match.CertSubject] = true
	}
	if !subjects[trustedSubject] || !subjects[untrustedSubject] {
		t.Fatalf("expected both subjects to be present, got %v", subjects)
	}
}

func TestGetCheckpointIndex(t *testing.T) {
	shardTreeSize := int64(1)
	inactiveShard := models.InactiveShardLogInfo{
		TreeSize: &shardTreeSize,
	}
	inactiveShards := []*models.InactiveShardLogInfo{&inactiveShard}
	emptyInactiveShards := []*models.InactiveShardLogInfo{}
	logInfo := &models.LogInfo{
		InactiveShards: inactiveShards,
	}
	emptyLogInfo := &models.LogInfo{
		InactiveShards: emptyInactiveShards,
	}
	checkpoint := &util.SignedCheckpoint{
		Checkpoint: util.Checkpoint{
			Size: 2,
		},
	}
	getCheckpointIndicesTests := map[string]struct {
		inputLogInfo     *models.LogInfo
		inputCheckpoint  *util.SignedCheckpoint
		expectedEndIndex int64
	}{
		"populated inactive shards": {
			inputLogInfo:     logInfo,
			inputCheckpoint:  checkpoint,
			expectedEndIndex: 2,
		},
		"empty inactive shards": {
			inputLogInfo:     emptyLogInfo,
			inputCheckpoint:  checkpoint,
			expectedEndIndex: 1,
		},
	}
	for testCaseName, testCase := range getCheckpointIndicesTests {
		expectedEndIndex := testCase.expectedEndIndex
		resultEndIndex := GetCheckpointIndex(testCase.inputLogInfo, testCase.inputCheckpoint)
		if resultEndIndex != expectedEndIndex {
			t.Errorf("%s failed: expected %d index, received %d", testCaseName, expectedEndIndex, resultEndIndex)
		}
	}
}
