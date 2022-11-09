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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor-monitor/pkg/test"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	alpine_v001 "github.com/sigstore/rekor/pkg/types/alpine/v0.0.1"
	cose_v001 "github.com/sigstore/rekor/pkg/types/cose/v0.0.1"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	helm_v001 "github.com/sigstore/rekor/pkg/types/helm/v0.0.1"
	intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	intoto_v002 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	jar_v001 "github.com/sigstore/rekor/pkg/types/jar/v0.0.1"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	rfc3161_v001 "github.com/sigstore/rekor/pkg/types/rfc3161/v0.0.1"
	rpm_v001 "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	tuf_v001 "github.com/sigstore/rekor/pkg/types/tuf/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestMatchedIdentities(t *testing.T) {
	// create multiple log entries
	var logEntries []models.LogEntry
	logEntries = append(logEntries, generateLogEntry(t, &hashedrekord_v001.V001Entry{}, "subject1", "issuer1"))
	logEntries = append(logEntries, generateLogEntry(t, &hashedrekord_v001.V001Entry{}, "subject2", "issuer1"))
	logEntries = append(logEntries, generateLogEntry(t, &hashedrekord_v001.V001Entry{}, "subject2", "issuer2"))
	logEntries = append(logEntries, generateLogEntry(t, &hashedrekord_v001.V001Entry{}, "subject10", "issuer10"))
	logEntries = append(logEntries, generateLogEntry(t, &hashedrekord_v001.V001Entry{}, "unmatchedSub", "unmatchedIss"))

	matchedIDs, err := MatchedIndices(logEntries, Identities{[]Identity{
		// exact match
		{Subject: "subject1", Issuers: []string{"issuer1"}},
		// match two entries for each issuer
		{Subject: "subject2"},
		// ignore without subject
		{Issuers: []string{"issuer10"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(matchedIDs) != 3 {
		t.Fatalf("expected 3 matched IDs, got %d", len(matchedIDs))
	}
	if matchedIDs[0].Subject != "subject1" || matchedIDs[0].Issuer != "issuer1" {
		t.Fatalf("expected subject1/issuer1, got %v", matchedIDs[0])
	}
	if matchedIDs[1].Subject != "subject2" || matchedIDs[1].Issuer != "issuer1" {
		t.Fatalf("expected subject2/issuer1, got %v", matchedIDs[1])
	}
	if matchedIDs[2].Subject != "subject2" || matchedIDs[2].Issuer != "issuer2" {
		t.Fatalf("expected subject2/issuer2, got %v", matchedIDs[2])
	}
}

func Test_extractCerts(t *testing.T) {
	tests := []struct {
		ei types.EntryImpl
	}{
		// TODO: Test for all types
		// {
		// 	ei: &alpine_v001.V001Entry{},
		// },
		// {
		// 	ei: &cose_v001.V001Entry{},
		// },
		{
			ei: &hashedrekord_v001.V001Entry{},
		},
		// {
		// 	ei: &helm_v001.V001Entry{},
		// },
		// {
		// 	ei: &intoto_v001.V001Entry{},
		// },
		// {
		// 	ei: &intoto_v002.V002Entry{},
		// },
		// {
		// 	ei: &jar_v001.V001Entry{},
		// },
		{
			ei: &rekord_v001.V001Entry{},
		},
		// {
		// 	ei: &rfc3161_v001.V001Entry{},
		// },
		// {
		// 	ei: &rpm_v001.V001Entry{},
		// },
		// {
		// 	ei: &tuf_v001.V001Entry{},
		// },
	}

	for _, tc := range tests {
		logEntry := generateLogEntry(t, tc.ei, "subject", "oidc-issuer")
		var entry models.LogEntryAnon
		for _, e := range logEntry {
			entry = e
			// only one entry in logEntry
			break
		}
		certs, err := extractCertificates(&entry)
		if err != nil {
			t.Errorf("expected no error extracting certificates, got %v", err)
		}
		if len(certs) != 1 {
			t.Errorf("unexpected number of certs, expected 1, got %d", len(certs))
		}
	}
}

// TODO: Finish support for other entry types
func generateLogEntry(t *testing.T, ei types.EntryImpl, subect, oidcIssuer string) models.LogEntry {
	rootCert, rootKey, _ := test.GenerateRootCA()
	subCert, subKey, _ := test.GenerateSubordinateCA(rootCert, rootKey)
	leafCert, privKey, _ := test.GenerateLeafCert(subect, oidcIssuer, subCert, subKey)
	leafCertPEM, _ := cryptoutils.MarshalCertificateToPEM(leafCert)

	var pe models.ProposedEntry
	var err error
	b := []byte("test-artifact")
	h := sha256.Sum256(b)
	sig, _ := privKey.Sign(rand.Reader, h[:], nil)

	switch e := ei.(type) {
	case *alpine_v001.V001Entry:
		break
	case *cose_v001.V001Entry:
		break
	case *hashedrekord_v001.V001Entry:
		pe, err = e.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
			ArtifactHash:   hex.EncodeToString(h[:]),
			SignatureBytes: sig,
			PublicKeyBytes: [][]byte{leafCertPEM},
			PKIFormat:      "x509",
		})
	case *helm_v001.V001Entry:
		break
	case *intoto_v001.V001Entry:
		break
	case *intoto_v002.V002Entry:
		break
	case *jar_v001.V001Entry:
		break
	case *rekord_v001.V001Entry:
		pe, err = e.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
			ArtifactBytes:  b,
			SignatureBytes: sig,
			PublicKeyBytes: [][]byte{leafCertPEM},
			PKIFormat:      "x509",
		})
	case *rfc3161_v001.V001Entry:
		break
	case *rpm_v001.V001Entry:
		break
	case *tuf_v001.V001Entry:
		break
	default:
		t.Fatalf("unexpected type: %v", e)
	}
	if err != nil {
		t.Fatalf("error for type %v: %v", reflect.TypeOf(ei), err)
	}

	entry, err := types.UnmarshalEntry(pe)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := entry.Canonicalize(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	e := models.LogEntryAnon{Body: base64.StdEncoding.EncodeToString(leaf), LogIndex: swag.Int64(1)}
	return models.LogEntry{string(h[:]): e}
}
