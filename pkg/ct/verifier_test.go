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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/sigstore/rekor-monitor/pkg/util/file"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
)

const (
	ValidSTHResponseTreeSize                 = 3721782
	ValidSTHResponseTimestamp         uint64 = 1396609800587
	ValidSTHResponseSHA256RootHash           = "SxKOxksguvHPyUaKYKXoZHzXl91Q257+JQ0AUMlFfeo="
	ValidSTHResponseTreeHeadSignature        = "BAMARjBEAiBUYO2tODlUUw4oWGiVPUHqZadRRyXs9T2rSXchA79VsQIgLASkQv3cu4XdPFCZbgFkIUefniNPCpO3LzzHX53l+wg="
	GetSTHConsistencyEmptyResp               = `{ "consistency": [ ] }`
)

// serveHandlerAt returns a test HTTP server that only expects requests at the given path, and invokes
// the provided handler for that path.
func serveHandlerAt(t *testing.T, path string, handler func(http.ResponseWriter, *http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			handler(w, r)
		} else {
			t.Fatalf("Incorrect URL path: %s", r.URL.Path)
		}
	}))
}

// serveRspAt returns a test HTTP server that returns a canned response body rsp for a given path.
func serveRspAt(t *testing.T, path, rsp string) *httptest.Server {
	t.Helper()
	return serveHandlerAt(t, path, func(w http.ResponseWriter, _ *http.Request) {
		if _, err := fmt.Fprint(w, rsp); err != nil {
			t.Fatal(err)
		}
	})
}

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

	err = file.WriteCTSignedTreeHead(sth, tempLogInfoFileName)
	if err != nil {
		t.Errorf("error writing sth to log info file: %v", err)
	}

	logClient, err := ctclient.New(hs.URL, http.DefaultClient, jsonclient.Options{})
	if err != nil {
		t.Errorf("error creating log client: %v", err)
	}

	err = verifyCertificateTransparencyConsistency(tempLogInfoFileName, logClient, sth)
	if err == nil {
		t.Errorf("expected error verifying ct consistency, received nil")
	}
}
