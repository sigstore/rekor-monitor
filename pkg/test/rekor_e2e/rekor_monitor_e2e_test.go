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
	"github.com/sigstore/rekor-monitor/pkg/notifications"
	rekor_v1 "github.com/sigstore/rekor-monitor/pkg/rekor/v1"
	"github.com/sigstore/rekor-monitor/pkg/test"
	monitor_util "github.com/sigstore/rekor-monitor/pkg/util"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/pubkey"
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

	p := pubkey.NewGetPublicKeyParamsWithContext(context.Background())
	keyResp, err := monitor_util.Retry(context.Background(), func() (any, error) {
		return rekorClient.Pubkey.GetPublicKey(p)
	})
	if err != nil {
		log.Fatalf("getting Rekor pub key: %v", err)
	}
	clientPemPubKey := []byte(keyResp.(*pubkey.GetPublicKeyOK).Payload)
	clientPubKey, err := cryptoutils.UnmarshalPEMToPublicKey(clientPemPubKey)
	if err != nil {
		log.Fatalf("error parsing client public key: %v", err)
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

	logInfo, err := rekor_v1.GetLogInfo(context.Background(), rekorClient)
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

	configMonitoredValues := notifications.ConfigMonitoredValues{
		Subjects: []string{subject},
		CertificateIdentities: []identity.CertificateIdentity{
			{
				CertSubject: ".*ubje.*",
				Issuers:     []string{".+@domain.com"},
			},
		},
		OIDMatchers: extensions.OIDMatchers{
			OIDExtensions: []extensions.OIDExtension{
				{
					ObjectIdentifier: oid,
					ExtensionValues:  []string{extValueString},
				},
			},
			FulcioExtensions: extensions.FulcioExtensions{},
			CustomExtensions: []extensions.CustomExtension{},
		},
		Fingerprints: []string{
			certFingerprint,
		},
	}

	verifier, err := signature.LoadVerifier(clientPubKey, crypto.SHA256)
	if err != nil {
		t.Errorf("error getting log verifier: %v", err)
	}

	prevCheckpoint, logInfo, err := rekor_v1.RunConsistencyCheck(rekorClient, verifier, tempLogInfoFileName)
	if err != nil {
		t.Errorf("first consistency check failed: %v", err)
	}
	if logInfo == nil {
		t.Errorf("first consistency check did not return log info")
	}
	if prevCheckpoint != nil {
		t.Errorf("first consistency check should not have returned checkpoint")
	}

	err = file.WriteCheckpointRekorV1(checkpoint, prevCheckpoint, tempLogInfoFileName, false)
	if err != nil {
		t.Errorf("error writing checkpoint: %v", err)
	}

	configRenderedOIDMatchers, err := configMonitoredValues.OIDMatchers.RenderOIDMatchers()
	if err != nil {
		t.Errorf("error rendering OID matchers: %v", err)
	}

	monitoredVals := identity.MonitoredValues{
		Subjects:              configMonitoredValues.Subjects,
		Fingerprints:          configMonitoredValues.Fingerprints,
		OIDMatchers:           configRenderedOIDMatchers,
		CertificateIdentities: configMonitoredValues.CertificateIdentities,
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

	prevCheckpoint, logInfo, err = rekor_v1.RunConsistencyCheck(rekorClient, verifier, tempLogInfoFileName)
	if err != nil {
		t.Errorf("second consistency check failed: %v", err)
	}
	if logInfo == nil {
		t.Errorf("second consistency check did not return log info")
	}
	if prevCheckpoint == nil {
		t.Errorf("second consistency check did not return previous checkpoint")
	}
	checkpoint = &util.SignedCheckpoint{}
	if err := checkpoint.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
		t.Errorf("%v", err)
	}
	if checkpoint.Size != 2 {
		t.Errorf("expected checkpoint size of 2, received size %d", checkpoint.Size)
	}
	if prevCheckpoint.Size != 1 {
		t.Errorf("expected previous checkpoint size of 1, received size %d", prevCheckpoint.Size)
	}

	_, _, err = rekor_v1.IdentitySearch(context.Background(), 0, 1, rekorClient, monitoredVals, tempOutputIdentitiesFileName, nil)
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

	err = file.WriteCheckpointRekorV1(checkpoint, prevCheckpoint, tempLogInfoFileName, false)
	if err != nil {
		t.Errorf("error writing checkpoint: %v", err)
	}

}
