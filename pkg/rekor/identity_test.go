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
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/rekor/mock"
	"github.com/sigstore/rekor-monitor/pkg/test"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"golang.org/x/mod/sumdb/note"
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
		matches, err := MatchedIndices([]models.LogEntry{logEntry}, monitoredValues)
		if err != nil {
			t.Fatalf("expected error matching IDs, got %v", err)
		}
		if len(matches) != 0 {
			t.Fatalf("expected 0 matches, got %d", len(matches))
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

	testedMonitoredValues := []identity.MonitoredValues{
		{
			OIDMatchers: []extensions.OIDMatcher{
				{
					ObjectIdentifier: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9},
					ExtensionValues:  []string{"wrong"},
				},
			},
		},
		{
			OIDMatchers: []extensions.OIDMatcher{
				{
					ObjectIdentifier: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 14},
					ExtensionValues:  []string{"test cert value"},
				},
			},
		},
	}
	for _, monitoredValues := range testedMonitoredValues {
		matches, err = MatchedIndices([]models.LogEntry{logEntry}, monitoredValues)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(matches) != 0 {
			t.Fatalf("expected no matches, got %d", len(matches))
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

	testedMonitoredValues := []identity.MonitoredValues{
		{
			CustomExtensions: []extensions.CustomExtension{
				{
					ObjectIdentifier: "1.3.6.1.4.1.57264.1.9",
					ExtensionValues:  []string{"wrong"},
				},
			},
		},
		{
			CustomExtensions: []extensions.CustomExtension{
				{
					ObjectIdentifier: "1.3.6.1.4.1.57264.1.16",
					ExtensionValues:  []string{extValueString},
				},
			},
		},
	}
	for _, monitoredValues := range testedMonitoredValues {
		matches, err = MatchedIndices([]models.LogEntry{logEntry}, monitoredValues)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(matches) != 0 {
			t.Fatalf("expected no matches, got %d", len(matches))
		}
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
			input: identity.MonitoredValues{OIDMatchers: []extensions.OIDMatcher{{
				ObjectIdentifier: asn1.ObjectIdentifier{},
				ExtensionValues:  []string{""},
			}}},
			errorString: "could not parse object identifier: empty input",
		},
		"empty oid matched values": {
			input: identity.MonitoredValues{OIDMatchers: []extensions.OIDMatcher{{
				ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
				ExtensionValues:  []string{},
			}}},
			errorString: "oid matched values empty",
		},
		"empty oid matched value": {
			input: identity.MonitoredValues{OIDMatchers: []extensions.OIDMatcher{{
				ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
				ExtensionValues:  []string{""},
			}}},
			errorString: "oid matched value empty",
		},
		"empty oid field": {
			input: identity.MonitoredValues{OIDMatchers: []extensions.OIDMatcher{{
				ObjectIdentifier: asn1.ObjectIdentifier{},
				ExtensionValues:  []string{""},
			}}},
			errorString: "could not parse object identifier: empty input",
		},
	}

	for name, testCase := range monitoredValuesTests {
		t.Run(name, func(t *testing.T) {
			_, err := MatchedIndices(nil, testCase.input)
			if err == nil || !strings.Contains(err.Error(), testCase.errorString) {
				t.Fatalf("expected error %v, received %v", testCase.errorString, err)
			}
		})
	}
}

func TestGetCheckpointIndices(t *testing.T) {
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
	prevCheckpoint := &util.SignedCheckpoint{
		Checkpoint: util.Checkpoint{
			Size: 1,
		},
	}
	checkpoint := &util.SignedCheckpoint{
		Checkpoint: util.Checkpoint{
			Size: 2,
		},
	}
	getCheckpointIndicesTests := map[string]struct {
		inputLogInfo        *models.LogInfo
		inputPrevCheckpoint *util.SignedCheckpoint
		inputCheckpoint     *util.SignedCheckpoint
		expectedStartIndex  int
		expectedEndIndex    int
	}{
		"populated inactive shards": {
			inputLogInfo:        logInfo,
			inputPrevCheckpoint: prevCheckpoint,
			inputCheckpoint:     checkpoint,
			expectedStartIndex:  1,
			expectedEndIndex:    2,
		},
		"empty inactive shards": {
			inputLogInfo:        emptyLogInfo,
			inputPrevCheckpoint: prevCheckpoint,
			inputCheckpoint:     checkpoint,
			expectedStartIndex:  0,
			expectedEndIndex:    1,
		},
	}
	for testCaseName, testCase := range getCheckpointIndicesTests {
		expectedStartIndex := testCase.expectedStartIndex
		expectedEndIndex := testCase.expectedEndIndex
		resultStartIndex, resultEndIndex := GetCheckpointIndices(testCase.inputLogInfo, testCase.inputPrevCheckpoint, testCase.inputCheckpoint)
		if resultStartIndex != expectedStartIndex || resultEndIndex != expectedEndIndex {
			t.Errorf("%s failed: expected %d, %d indices, received %d, %d indices", testCaseName, expectedStartIndex, expectedEndIndex, resultStartIndex, resultEndIndex)
		}
	}
}

func TestGetPrevCurrentCheckpoints(t *testing.T) {
	// generate checkpoint
	root, _ := hex.DecodeString("1a341bc342ff4e567387de9789ab14000b147124317841489172419874198147")
	expectedCheckpoint, err := util.CreateSignedCheckpoint(util.Checkpoint{
		Origin: "origin",
		Size:   uint64(123),
		Hash:   root,
	})
	expectedCheckpoint.Signatures = []note.Signature{{Name: "name", Hash: 1, Base64: "adbadbadb"}}
	if err != nil {
		t.Fatal(err)
	}
	checkpointBytes, err := expectedCheckpoint.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Errorf("error marshalling checkpoint: %v", err)
	}
	checkpointString := string(checkpointBytes)

	var mClient client.Rekor
	mClient.Tlog = &mock.TlogClient{
		LogInfo: &models.LogInfo{
			SignedTreeHead: &checkpointString,
		},
	}

	tempDir := t.TempDir()
	tempLogInfoFile, err := os.CreateTemp(tempDir, "")
	if err != nil {
		t.Errorf("failed to create temp log file: %v", err)
	}
	tempLogInfoFileName := tempLogInfoFile.Name()
	defer os.Remove(tempLogInfoFileName)
	file.WriteCheckpoint(expectedCheckpoint, tempLogInfoFileName)

	prevCheckpoint, currentCheckpoint, err := GetPrevCurrentCheckpoints(&mClient, tempLogInfoFileName)
	if err != nil {
		t.Errorf("expected nil, received %v", err)
	}

	if prevCheckpoint.Checkpoint.String() != expectedCheckpoint.Checkpoint.String() {
		t.Errorf("expected prev checkpoint %s, received %s", expectedCheckpoint.Checkpoint, prevCheckpoint.Checkpoint)
	}

	if currentCheckpoint.Checkpoint.String() != expectedCheckpoint.Checkpoint.String() {
		t.Errorf("expected current checkpoint %s, received %s", expectedCheckpoint.Checkpoint, currentCheckpoint.Checkpoint)
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

// Test monitoring for identities using mock Rekor client
func TestWriteIdentitiesBetweenCheckpoints(t *testing.T) {
	maxIndex := 2
	var logEntries []*models.LogEntry

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

	for i := 0; i <= maxIndex; i++ {
		lea := models.LogEntryAnon{
			Body:     base64.StdEncoding.EncodeToString(leaf),
			LogIndex: swag.Int64(int64(i)),
		}
		data := models.LogEntry{
			fmt.Sprint(i): lea,
		}
		logEntries = append(logEntries, &data)
	}

	var mClient client.Rekor
	mClient.Entries = &mock.EntriesClient{
		Entries: logEntries,
	}
	testLogInfo := &models.LogInfo{}
	mClient.Tlog = &mock.TlogClient{
		LogInfo: testLogInfo,
	}

	logInfo, err := GetLogInfo(context.Background(), &mClient)
	if err != nil {
		t.Errorf("failed fetching log info: %v", err)
	}
	prevCheckpoint := &util.SignedCheckpoint{
		Checkpoint: util.Checkpoint{
			Size: 0,
		},
	}
	checkpoint := &util.SignedCheckpoint{
		Checkpoint: util.Checkpoint{
			Size: 1,
		},
	}
	monitoredValues := identity.MonitoredValues{
		Subjects: []string{
			subject,
		},
	}
	tempDir := t.TempDir()
	tempOutputIdentitiesFile, err := os.CreateTemp(tempDir, "")
	if err != nil {
		t.Errorf("failed to create temp output identities file: %v", err)
	}
	tempOutputIdentitiesFileName := tempOutputIdentitiesFile.Name()
	defer os.Remove(tempOutputIdentitiesFileName)

	err = writeIdentitiesBetweenCheckpoints(logInfo, prevCheckpoint, checkpoint, monitoredValues, &mClient, tempOutputIdentitiesFileName)
	if err != nil {
		t.Errorf("failed write identities between checkpoints: %v", err)
	}

	tempOutputIdentities, err := os.ReadFile(tempOutputIdentitiesFileName)
	if err != nil {
		t.Errorf("error reading from output identities file: %v", err)
	}
	tempOutputIdentitiesString := string(tempOutputIdentities)
	if !strings.Contains(tempOutputIdentitiesString, subject) {
		t.Errorf("expected to find subject %s, did not", subject)
	}
}
