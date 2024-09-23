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
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func TestMatchedIndicesForCertificates(t *testing.T) {
	subject := "subject"
	issuer := "oidc-issuer@domain.com"

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
	matches, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: subject,
			},
		}})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
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
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: subject,
				Issuers:     []string{issuer},
			},
		}})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	// match with regex subject and regex issuer with certificate in hashedrekord
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: ".*ubje.*",
				Issuers:     []string{".+@domain.com"},
			},
		}})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
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

		matches, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
			CertificateIdentities: []identity.CertificateIdentity{
				{
					CertSubject: ".*ubje.*",
					Issuers:     []string{".+@domain.com"},
				},
			}})
		if err != nil {
			t.Fatalf("expected error matching IDs, got %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("expected 1 match, got %d", len(matches))
		}
	}

	// no match with same subject, other issuer
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: subject,
				Issuers:     []string{"other"},
			},
		}})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}

	// no match with different subject
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: "other",
			},
		}})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

// Test verifies that certificates containing only the deprecated
// extensions can still be monitored
func TestMatchedIndicesForDeprecatedCertificates(t *testing.T) {
	subject := "subject"
	issuer := "oidc-issuer@domain.com"

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
	matches, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: subject,
				Issuers:     []string{issuer},
			},
		}})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
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
	matches, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		Fingerprints: []string{
			fp,
		}})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
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
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		Fingerprints: []string{
			"other-fp",
		}})
	if err != nil {
		t.Fatalf("expected error matching fingerprints, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestMatchedIndicesForSubjects(t *testing.T) {
	subject := "subject@example.com"
	issuer := "oidc-issuer@domain.com"

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
	matches, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		Subjects: []string{
			subject,
		}})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
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
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		Subjects: []string{
			"other-sub",
		}})
	if err != nil {
		t.Fatalf("expected error matching subjects, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestMatchedIndicesForOIDMatchers(t *testing.T) {
	subject := "subject"
	issuer := "oidc-issuer@domain.com"

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
	matches, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		OIDMatchers: []extensions.OIDMatcher{
			{
				ObjectIdentifier: oid,
				ExtensionValues:  []string{extValueString},
			},
		}})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Index != int64(logIndex) {
		t.Fatalf("mismatched log indices: %d %d", matches[0].Index, logIndex)
	}
	if matches[0].UUID != uuid {
		t.Fatalf("mismatched UUIDs: %s %s", matches[0].UUID, uuid)
	}

	// no match to oid with different extension value
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		OIDMatchers: []extensions.OIDMatcher{
			{
				ObjectIdentifier: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9},
				ExtensionValues:  []string{"wrong"},
			},
		}})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}

	// no match to oid with different oid extension field
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		OIDMatchers: []extensions.OIDMatcher{
			{
				ObjectIdentifier: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 14},
				ExtensionValues:  []string{"test cert value"},
			},
		}})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}
}

func TestMatchedIndicesForFulcioOIDMatchers(t *testing.T) {
	subject := "subject"
	issuer := "oidc-issuer@domain.com"

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
	matches, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		FulcioExtensions: extensions.FulcioExtensions{
			BuildSignerURI: []string{extValueString},
		}})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Index != int64(logIndex) {
		t.Fatalf("mismatched log indices: %d %d", matches[0].Index, logIndex)
	}
	if matches[0].UUID != uuid {
		t.Fatalf("mismatched UUIDs: %s %s", matches[0].UUID, uuid)
	}

	// no match to oid with different extension value
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		OIDMatchers: []extensions.OIDMatcher{
			{
				ObjectIdentifier: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9},
				ExtensionValues:  []string{"wrong"},
			},
		}})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}

	// no match to oid with different oid extension field
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		FulcioExtensions: extensions.FulcioExtensions{
			BuildSignerDigest: []string{extValueString},
		}})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}
}

func TestMatchedIndicesForCustomOIDMatchers(t *testing.T) {
	subject := "subject"
	issuer := "oidc-issuer@domain.com"

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
	matches, err := MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		CustomExtensions: []extensions.CustomExtension{
			{
				ObjectIdentifier: "1.3.6.1.4.1.57264.1.9",
				ExtensionValues:  []string{extValueString},
			},
		}})
	if err != nil {
		t.Fatalf("expected error matching IDs, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Index != int64(logIndex) {
		t.Fatalf("mismatched log indices: %d %d", matches[0].Index, logIndex)
	}
	if matches[0].UUID != uuid {
		t.Fatalf("mismatched UUIDs: %s %s", matches[0].UUID, uuid)
	}

	// no match to oid with different extension value
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		CustomExtensions: []extensions.CustomExtension{
			{
				ObjectIdentifier: "1.3.6.1.4.1.57264.1.9",
				ExtensionValues:  []string{"wrong"},
			},
		}})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}

	// no match to oid with different oid extension field
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, identity.MonitoredValues{
		CustomExtensions: []extensions.CustomExtension{
			{
				ObjectIdentifier: "1.3.6.1.4.1.57264.1.16",
				ExtensionValues:  []string{extValueString},
			},
		}})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}
}

func TestMatchedIndicesFailures(t *testing.T) {
	// failure: no monitored values
	_, err := MatchedIndices(nil, identity.MonitoredValues{})
	if err == nil || !strings.Contains(err.Error(), "no identities provided to monitor") {
		t.Fatalf("expected error with no identities, got %v", err)
	}

	// failure: certificate subject empty
	_, err = MatchedIndices(nil, identity.MonitoredValues{CertificateIdentities: []identity.CertificateIdentity{
		{
			CertSubject: "",
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "certificate subject empty") {
		t.Fatalf("expected error with empty cert subject, got %v", err)
	}

	// failure: issuer empty
	_, err = MatchedIndices(nil, identity.MonitoredValues{CertificateIdentities: []identity.CertificateIdentity{
		{
			CertSubject: "s",
			Issuers:     []string{""},
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "issuer empty") {
		t.Fatalf("expected error with empty issuer, got %v", err)
	}

	// failure: subject empty
	_, err = MatchedIndices(nil, identity.MonitoredValues{Subjects: []string{""}})
	if err == nil || !strings.Contains(err.Error(), "subject empty") {
		t.Fatalf("expected error with empty subject, got %v", err)
	}

	// failure: fingerprint empty
	_, err = MatchedIndices(nil, identity.MonitoredValues{Fingerprints: []string{""}})
	if err == nil || !strings.Contains(err.Error(), "fingerprint empty") {
		t.Fatalf("expected error with empty fingerprint, got %v", err)
	}

	// failure: oid extension empty
	_, err = MatchedIndices(nil, identity.MonitoredValues{OIDMatchers: []extensions.OIDMatcher{{
		ObjectIdentifier: asn1.ObjectIdentifier{},
		ExtensionValues:  []string{""},
	}}})
	if err == nil || !strings.Contains(err.Error(), "could not parse object identifier: empty input") {
		t.Fatalf("expected error with empty oid extension, got %v", err)
	}

	// failure: oid matched values list empty
	_, err = MatchedIndices(nil, identity.MonitoredValues{OIDMatchers: []extensions.OIDMatcher{{
		ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
		ExtensionValues:  []string{},
	}}})
	if err == nil || !strings.Contains(err.Error(), "oid matched values empty") {
		t.Fatalf("expected error with empty oid matched values list, got %v", err)
	}

	// failure: oid matched value string empty
	_, err = MatchedIndices(nil, identity.MonitoredValues{OIDMatchers: []extensions.OIDMatcher{{
		ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
		ExtensionValues:  []string{""},
	}}})
	if err == nil || !strings.Contains(err.Error(), "oid matched value empty") {
		t.Fatalf("expected error with empty oid matched value string, got %v", err)
	}
}

func TestMatchedIndicesFailuresOIDExtensionEmpty(t *testing.T) {
	// failure: oid extension empty
	_, err := MatchedIndices(nil, identity.MonitoredValues{OIDMatchers: []extensions.OIDMatcher{{
		ObjectIdentifier: asn1.ObjectIdentifier{},
		ExtensionValues:  []string{""},
	}}})
	if err == nil || !strings.Contains(err.Error(), "could not parse object identifier: empty input") {
		t.Fatalf("expected error with empty oid extension, got %v", err)
	}
}

func TestMatchedIndicesFailuresOIDExtensionValuesEmpty(t *testing.T) {
	// failure: oid extension values list empty
	_, err := MatchedIndices(nil, identity.MonitoredValues{OIDMatchers: []extensions.OIDMatcher{{
		ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
		ExtensionValues:  []string{},
	}}})
	if err == nil || !strings.Contains(err.Error(), "oid matched values empty") {
		t.Fatalf("expected error with empty oid matched values list, got %v", err)
	}
}

func TestMatchedIndicesFailuresOIDExtensionValueEmpty(t *testing.T) {
	// failure: oid extension value string empty
	_, err := MatchedIndices(nil, identity.MonitoredValues{OIDMatchers: []extensions.OIDMatcher{{
		ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
		ExtensionValues:  []string{""},
	}}})
	if err == nil || !strings.Contains(err.Error(), "oid matched value empty") {
		t.Fatalf("expected error with empty oid matched value string, got %v", err)
	}
}

func mockCertificateWithExtension(oid asn1.ObjectIdentifier, value string) (*x509.Certificate, error) {
	extValue, err := asn1.Marshal(value)
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{
		Extensions: []pkix.Extension{
			{
				Id:       oid,
				Critical: false,
				Value:    extValue,
			},
		},
	}
	return cert, nil
}

// Test when OID is present but the value does not match
func TestOIDDoesNotMatch(t *testing.T) {
	cert, err := mockCertificateWithExtension(asn1.ObjectIdentifier{2, 5, 29, 17}, "test cert value")
	if err != nil {
		t.Errorf("Expected nil got %v", err)
	}
	oid := asn1.ObjectIdentifier{2, 5, 29, 17}
	extensionValues := []string{"wrong value"}

	matches, _, _, err := oidMatchesPolicy(cert, oid, extensionValues)
	if matches || err != nil {
		t.Errorf("Expected false without error, got %v, error %v", matches, err)
	}
}

// Test when OID is not present in the certificate
func TestOIDNotPresent(t *testing.T) {
	cert := &x509.Certificate{} // No extensions
	oid := asn1.ObjectIdentifier{2, 5, 29, 17}
	extensionValues := []string{"wrong value"}

	matches, _, _, err := oidMatchesPolicy(cert, oid, extensionValues)
	if matches || err != nil {
		t.Errorf("Expected false with nil, got %v, error %v", matches, err)
	}
}

// Test when OID is present and matches value
func TestOIDMatchesValue(t *testing.T) {
	cert, err := mockCertificateWithExtension(asn1.ObjectIdentifier{2, 5, 29, 17}, "test cert value")
	if err != nil {
		t.Errorf("Expected nil got %v", err)
	}
	oid := asn1.ObjectIdentifier{2, 5, 29, 17}
	extValueString := "test cert value"
	extensionValues := []string{extValueString}

	matches, matchedOID, extValue, err := oidMatchesPolicy(cert, oid, extensionValues)
	if !matches || err != nil {
		t.Errorf("Expected true, got %v, error %v", matches, err)
	}
	if matchedOID.String() != oid.String() {
		t.Errorf("Expected oid to equal 2.5.29.17, got %s", matchedOID.String())
	}
	if extValue != extValueString {
		t.Errorf("Expected string to equal 'test cert value', got %s", extValue)
	}
}
