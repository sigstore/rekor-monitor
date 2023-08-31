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
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/swag"
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
	h := sha256.Sum256(payload)
	pe, err := hashedrekord.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(h[:]),
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
	e := models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: swag.Int64(integratedTime.Unix()),
		LogIndex:       swag.Int64(int64(logIndex)),
	}
	logEntry := models.LogEntry{uuid: e}

	//  match to subject with certificate in hashedrekord
	matches, err := MatchedIndices([]models.LogEntry{logEntry}, MonitoredValues{
		CertificateIdentities: []CertificateIdentity{
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
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, MonitoredValues{
		CertificateIdentities: []CertificateIdentity{
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
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, MonitoredValues{
		CertificateIdentities: []CertificateIdentity{
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
		e := models.LogEntryAnon{
			Body:           base64.StdEncoding.EncodeToString(leaf),
			IntegratedTime: swag.Int64(integratedTime.Unix()),
			LogIndex:       swag.Int64(int64(logIndex)),
		}
		logEntry := models.LogEntry{uuid: e}

		matches, err := MatchedIndices([]models.LogEntry{logEntry}, MonitoredValues{
			CertificateIdentities: []CertificateIdentity{
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
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, MonitoredValues{
		CertificateIdentities: []CertificateIdentity{
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
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, MonitoredValues{
		CertificateIdentities: []CertificateIdentity{
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
	h := sha256.Sum256(payload)
	pe, err := hashedrekord.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(h[:]),
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
	e := models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: swag.Int64(integratedTime.Unix()),
		LogIndex:       swag.Int64(int64(logIndex)),
	}
	logEntry := models.LogEntry{uuid: e}

	derKey, err := cryptoutils.MarshalPublicKeyToDER(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(derKey)
	fp := hex.EncodeToString(digest[:])

	//  match to key fingerprint in hashedrekord
	matches, err := MatchedIndices([]models.LogEntry{logEntry}, MonitoredValues{
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
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, MonitoredValues{
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
	h := sha256.Sum256(payload)
	pe, err := hashedrekord.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(h[:]),
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
	e := models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: swag.Int64(integratedTime.Unix()),
		LogIndex:       swag.Int64(int64(logIndex)),
	}
	logEntry := models.LogEntry{uuid: e}

	//  match to subject with certificate in hashedrekord
	matches, err := MatchedIndices([]models.LogEntry{logEntry}, MonitoredValues{
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
	matches, err = MatchedIndices([]models.LogEntry{logEntry}, MonitoredValues{
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

func TestMatchedIndicesFailures(t *testing.T) {
	// failure: no monitored values
	_, err := MatchedIndices(nil, MonitoredValues{})
	if err == nil || !strings.Contains(err.Error(), "no identities provided to monitor") {
		t.Fatalf("expected error with no identities, got %v", err)
	}

	// failure: certificate subject empty
	_, err = MatchedIndices(nil, MonitoredValues{CertificateIdentities: []CertificateIdentity{
		{
			CertSubject: "",
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "certificate subject empty") {
		t.Fatalf("expected error with empty cert subject, got %v", err)
	}

	// failure: issuer empty
	_, err = MatchedIndices(nil, MonitoredValues{CertificateIdentities: []CertificateIdentity{
		{
			CertSubject: "s",
			Issuers:     []string{""},
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "issuer empty") {
		t.Fatalf("expected error with empty issuer, got %v", err)
	}

	// failure: subject empty
	_, err = MatchedIndices(nil, MonitoredValues{Subjects: []string{""}})
	if err == nil || !strings.Contains(err.Error(), "subject empty") {
		t.Fatalf("expected error with empty subject, got %v", err)
	}

	// failure: fingerprint empty
	_, err = MatchedIndices(nil, MonitoredValues{Fingerprints: []string{""}})
	if err == nil || !strings.Contains(err.Error(), "fingerprint empty") {
		t.Fatalf("expected error with empty fingerprint, got %v", err)
	}
}
