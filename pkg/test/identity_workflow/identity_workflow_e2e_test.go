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

//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/rekor"
	"github.com/sigstore/rekor-monitor/pkg/test"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"sigs.k8s.io/release-utils/version"

	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
)

const (
	rekorURL       = "http://127.0.0.1:3000"
	subject        = "subject@example.com"
	issuer         = "oidc-issuer@domain.com"
	extValueString = "test cert value"
)

// Test IdentitySearch:
// Check that Rekor-monitor reusable identity search workflow successfully
// finds a monitored identity within the checkpoint indices and writes it to file.
func TestIdentitySearch(t *testing.T) {
	rekorClient, err := client.GetRekorClient(rekorURL, client.WithUserAgent(strings.TrimSpace(fmt.Sprintf("rekor-monitor/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH))))
	if err != nil {
		log.Fatalf("getting Rekor client: %v", err)
	}

	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}
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
		t.Fatalf("error creating hashed rekord entry: %v", err)
	}

	x509Cert, err := cryptoutils.UnmarshalCertificatesFromPEM(pemCert)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(x509Cert[0].Raw)
	certFingerprint := hex.EncodeToString(digest[:])

	params := entries.NewCreateLogEntryParams()
	params.SetProposedEntry(pe)
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if !resp.IsSuccess() || err != nil {
		t.Errorf("error creating log entry: %v", err)
	}

	logInfo, err := rekor.GetLogInfo(context.Background(), rekorClient)
	if err != nil {
		t.Errorf("error getting log info: %v", err)
	}
	checkpoint := &util.SignedCheckpoint{}
	if err := checkpoint.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
		t.Errorf("%v", err)
	}
	if checkpoint.Size != 1 {
		t.Errorf("expected checkpoint size of 1, received size %d", checkpoint.Size)
	}

	tempDir := t.TempDir()
	tempLogInfoFile, err := os.CreateTemp(tempDir, "")
	if err != nil {
		t.Errorf("failed to create temp log file: %v", err)
	}
	tempLogInfoFileName := tempLogInfoFile.Name()
	defer os.Remove(tempLogInfoFileName)

	tempOutputIdentitiesFile, err := os.CreateTemp(tempDir, "")
	if err != nil {
		t.Errorf("failed to create temp output identities file: %v", err)
	}
	tempOutputIdentitiesFileName := tempOutputIdentitiesFile.Name()
	defer os.Remove(tempOutputIdentitiesFileName)

	tempMetadataFile, err := os.CreateTemp(tempDir, "")
	if err != nil {
		t.Errorf("failed to create temp output identities file: %v", err)
	}
	tempMetadataFileName := tempMetadataFile.Name()
	defer os.Remove(tempMetadataFileName)

	monitoredVals := identity.MonitoredValues{
		Subjects: []string{subject},
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: ".*ubje.*",
				Issuers:     []string{".+@domain.com"},
			},
		},
		OIDMatchers: []extensions.OIDMatcher{
			{
				ObjectIdentifier: oid,
				ExtensionValues:  []string{extValueString},
			},
		},
		Fingerprints: []string{
			certFingerprint,
		},
	}

	payload = []byte{1, 2, 3, 4, 5, 6}
	sig, err = signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("error signing message: %v", err)
	}
	hashedrekord = &hashedrekord_v001.V001Entry{}
	hash = sha256.Sum256(payload)
	pe, err = hashedrekord.CreateFromArtifactProperties(context.Background(), types.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(hash[:]),
		SignatureBytes: sig,
		PublicKeyBytes: [][]byte{pemCert},
		PKIFormat:      "x509",
	})
	if err != nil {
		t.Fatalf("error creating hashed rekord log entry: %v", err)
	}
	params = entries.NewCreateLogEntryParams()
	params.SetProposedEntry(pe)
	resp, err = rekorClient.Entries.CreateLogEntry(params)
	if !resp.IsSuccess() || err != nil {
		t.Errorf("error creating log entry: %v", err)
	}

	logInfo, err = rekor.GetLogInfo(context.Background(), rekorClient)
	if err != nil {
		t.Errorf("error getting log info: %v", err)
	}
	checkpoint = &util.SignedCheckpoint{}
	if err := checkpoint.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
		t.Errorf("%v", err)
	}
	if checkpoint.Size != 2 {
		t.Errorf("expected checkpoint size of 2, received size %d", checkpoint.Size)
	}

	err = rekor.IdentitySearch(0, 1, rekorClient, monitoredVals, tempOutputIdentitiesFileName, nil)
	if err != nil {
		log.Fatal(err.Error())
	}

	tempOutputIdentities, err := os.ReadFile(tempOutputIdentitiesFileName)
	if err != nil {
		t.Errorf("error reading from output identities file: %v", err)
	}
	tempOutputIdentitiesString := string(tempOutputIdentities)
	if !strings.Contains(tempOutputIdentitiesString, subject) {
		t.Errorf("expected to find subject %s, did not", subject)
	}
	if !strings.Contains(tempOutputIdentitiesString, issuer) {
		t.Errorf("expected to find issuer %s, did not", issuer)
	}
	if !strings.Contains(tempOutputIdentitiesString, oid.String()) {
		t.Errorf("expected to find oid %s, did not", oid.String())
	}
	if !strings.Contains(tempOutputIdentitiesString, oid.String()) {
		t.Errorf("expected to find oid value %s, did not", extValueString)
	}
	if !strings.Contains(tempOutputIdentitiesString, certFingerprint) {
		t.Errorf("expected to find fingerprint %s, did not", certFingerprint)
	}

	tempMetadata, err := os.ReadFile(tempMetadataFileName)
	if err != nil {
		t.Errorf("error reading from output identities file: %v", err)
	}
	tempMetadataString := string(tempMetadata)
	if !strings.Contains(tempOutputIdentitiesString, "2") {
		t.Errorf("expected to find latest index 2 in %s, did not", tempMetadataString)
	}
}
