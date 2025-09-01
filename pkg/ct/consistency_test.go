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

package ct

import (
	"encoding/base64"
	"net/http"
	"os"
	"testing"

	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/sigstore/rekor-monitor/pkg/util/file"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
)

// Test VerifyCertificateTransparencyConsistency
func TestVerifyCertificateTransparencyConsistency(t *testing.T) {
	// TODO: placeholder test, fill this out with mock CT Log client
	hs := serveRspAt(t, "/ct/v1/get-sth-consistency", GetSTHConsistencyEmptyResp)
	defer hs.Close()

	var rootHash ct.SHA256Hash
	err := rootHash.FromBase64String(ValidSTHResponseSHA256RootHash)
	if err != nil {
		t.Errorf("error parsing root hash from string: %v", err)
	}

	wantRawSignature, err := base64.StdEncoding.DecodeString(ValidSTHResponseTreeHeadSignature)
	if err != nil {
		t.Fatalf("Couldn't b64 decode 'correct' STH signature: %v", err)
	}
	var wantDS ct.DigitallySigned
	if _, err := tls.Unmarshal(wantRawSignature, &wantDS); err != nil {
		t.Fatalf("Couldn't unmarshal DigitallySigned: %v", err)
	}

	sth := &ct.SignedTreeHead{
		TreeSize:          ValidSTHResponseTreeSize,
		Timestamp:         ValidSTHResponseTimestamp,
		SHA256RootHash:    rootHash,
		TreeHeadSignature: wantDS,
	}

	tempDir := t.TempDir()
	tempLogInfoFile, err := os.CreateTemp(tempDir, "")
	if err != nil {
		t.Errorf("failed to create temp log file: %v", err)
	}
	tempLogInfoFileName := tempLogInfoFile.Name()
	defer os.Remove(tempLogInfoFileName)

	err = file.WriteCTSignedTreeHead(sth, nil, tempLogInfoFileName, false)
	if err != nil {
		t.Errorf("error writing sth to log info file: %v", err)
	}

	logClient, err := ctclient.New(hs.URL, http.DefaultClient, jsonclient.Options{})
	if err != nil {
		t.Errorf("error creating log client: %v", err)
	}

	prevSTH, err := verifyCertificateTransparencyConsistency(tempLogInfoFileName, logClient, sth)
	if err == nil {
		t.Errorf("expected error verifying ct consistency, received nil")
	}
	if prevSTH != nil {
		t.Errorf("expected nil, received %v", prevSTH)
	}
}
