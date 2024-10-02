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

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/rekor"
	"github.com/sigstore/rekor-monitor/pkg/test"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"sigs.k8s.io/release-utils/version"

	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
)

const (
	rekorURL = "http://127.0.0.1:3000"
)

// Test RunConsistencyCheck:
// Check that Rekor-monitor reusable monitoring workflow successfully verifies consistency of the log checkpoint
// and is able to find a monitored identity within the checkpoint indices and write it to file.
func TestRunConsistencyCheck(t *testing.T) {
	t.Skip("skipping test outside of being run from e2e_test.sh")
	rekorClient, err := client.GetRekorClient(rekorURL, client.WithUserAgent(strings.TrimSpace(fmt.Sprintf("rekor-monitor/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH))))
	if err != nil {
		log.Fatalf("getting Rekor client: %v", err)
	}

	verifier, err := rekor.GetLogVerifier(context.Background(), rekorClient)
	if err != nil {
		t.Errorf("error getting log verifier: %v", err)
	}

	subject := "subject@example.com"
	issuer := "oidc-issuer@domain.com"

	rootCert, rootKey, _ := test.GenerateRootCA()
	leafCert, leafKey, _ := test.GenerateLeafCert(subject, issuer, rootCert, rootKey)

	signer, err := signature.LoadECDSASignerVerifier(leafKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("error loading signer and verifier: %v", err)
	}
	pemCert, _ := cryptoutils.MarshalCertificateToPEM(leafCert)

	payload := []byte{1, 2, 3, 4}
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("error signing message: %v", err)
	}

	rekordEntry := rekord.V001Entry{
		RekordObj: models.RekordV001Schema{
			Data: &models.RekordV001SchemaData{
				Content: strfmt.Base64(payload),
			},
			Signature: &models.RekordV001SchemaSignature{
				Content: (*strfmt.Base64)(&sig),
				Format:  swag.String(models.RekordV001SchemaSignatureFormatX509),
				PublicKey: &models.RekordV001SchemaSignaturePublicKey{
					Content: (*strfmt.Base64)(&pemCert),
				},
			},
		},
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

	params := entries.NewCreateLogEntryParams()
	params.SetProposedEntry(pe)
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if !resp.IsSuccess() || err != nil {
		t.Errorf("error creating log entry: %v", err)
	}

	params = entries.NewCreateLogEntryParams()
	rekordModel := models.Rekord{
		APIVersion: swag.String(rekordEntry.APIVersion()),
		Spec:       rekordEntry.RekordObj,
	}
	params.SetProposedEntry(&rekordModel)
	resp, err = rekorClient.Entries.CreateLogEntry(params)
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
	iterator := 0
	for checkpoint.Size <= 0 {
		logInfo, err = rekor.GetLogInfo(context.Background(), rekorClient)
		if err != nil {
			t.Errorf("error getting log info: %v", err)
		}
		checkpoint := &util.SignedCheckpoint{}
		if err := checkpoint.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
			t.Errorf("error unmarshalling checkpoint: %v", err)
		}
		iterator++
		if iterator >= 5 {
			t.Errorf("log info checkpoint failed to update in time")
		}
		time.Sleep(2 * time.Second)
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

	interval := time.Minute
	monitoredVals := identity.MonitoredValues{
		Subjects: []string{subject},
	}
	once := true

	err = RunConsistencyCheck(&interval, rekorClient, verifier, &tempLogInfoFileName, monitoredVals, &tempOutputIdentitiesFileName, &once)
	if err != nil {
		t.Errorf("first consistency check failed: %v", err)
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
	err = RunConsistencyCheck(&interval, rekorClient, verifier, &tempLogInfoFileName, monitoredVals, &tempOutputIdentitiesFileName, &once)
	if err != nil {
		t.Errorf("second consistency check failed: %v", err)
	}

	tempOutputIdentities, err := os.ReadFile(tempOutputIdentitiesFileName)
	if err != nil {
		t.Errorf("error reading from output identities file: %v", err)
	}
	tempOutputIdentitiesString := string(tempOutputIdentities)
	if !strings.Contains(tempOutputIdentitiesString, subject) {
		t.Errorf("expected to find subject@example.com, did not")
	}
}
