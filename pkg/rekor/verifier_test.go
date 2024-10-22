// Copyright 2023 The Sigstore Authors.
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/sigstore/rekor-monitor/pkg/rekor/mock"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
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

func TestGetLogVerifier(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemKey, err := cryptoutils.MarshalPublicKeyToPEM(key.Public())
	if err != nil {
		t.Fatalf("unexpected error marshalling key: %v", err)
	}

	var mClient client.Rekor
	mClient.Pubkey = &mock.PubkeyClient{
		PEMPubKey: string(pemKey),
	}

	verifier, err := GetLogVerifier(context.Background(), &mClient)
	if err != nil {
		t.Fatalf("unexpected error getting log verifier: %v", err)
	}
	pubkey, _ := verifier.PublicKey()
	if err := cryptoutils.EqualKeys(key.Public(), pubkey); err != nil {
		t.Fatalf("expected equal keys: %v", err)
	}
}

func TestVerifyConsistencyCheckInputs(t *testing.T) {
	interval := 5 * time.Minute
	logInfoFile := "./test/example_log_info_file_path.txt"
	outputIdentitiesFile := "./test/example_output_identities_file.txt"
	once := true
	verifyConsistencyCheckInputTests := map[string]struct {
		interval             *time.Duration
		logInfoFile          *string
		outputIdentitiesFile *string
		once                 *bool
		expectedError        error
	}{
		"successful verification": {
			interval:             &interval,
			logInfoFile:          &logInfoFile,
			outputIdentitiesFile: &outputIdentitiesFile,
			once:                 &once,
			expectedError:        nil,
		},
		"fail --interval verification": {
			interval:             nil,
			logInfoFile:          &logInfoFile,
			outputIdentitiesFile: &outputIdentitiesFile,
			once:                 &once,
			expectedError:        errors.New("--interval flag equal to nil"),
		},
		"fail --file verification": {
			interval:             &interval,
			logInfoFile:          nil,
			outputIdentitiesFile: &outputIdentitiesFile,
			once:                 &once,
			expectedError:        errors.New("--file flag equal to nil"),
		},
		"fail --output-identities verification": {
			interval:             &interval,
			logInfoFile:          &logInfoFile,
			outputIdentitiesFile: nil,
			once:                 &once,
			expectedError:        errors.New("--output-identities flag equal to nil"),
		},
		"fail --once verification": {
			interval:             &interval,
			logInfoFile:          &logInfoFile,
			outputIdentitiesFile: &outputIdentitiesFile,
			once:                 nil,
			expectedError:        errors.New("--once flag equal to nil"),
		},
		"empty case": {
			interval:             nil,
			logInfoFile:          nil,
			outputIdentitiesFile: nil,
			once:                 nil,
			expectedError:        errors.New("--interval flag equal to nil"),
		},
	}

	for verifyConsistencyCheckInputTestCaseName, verifyConsistencyCheckInputTestCase := range verifyConsistencyCheckInputTests {
		interval := verifyConsistencyCheckInputTestCase.interval
		logInfoFile := verifyConsistencyCheckInputTestCase.logInfoFile
		outputIdentitiesFile := verifyConsistencyCheckInputTestCase.outputIdentitiesFile
		once := verifyConsistencyCheckInputTestCase.once
		expectedError := verifyConsistencyCheckInputTestCase.expectedError
		err := VerifyConsistencyCheckInputs(interval, logInfoFile, outputIdentitiesFile, once)
		if (err == nil && expectedError != nil) || (err != nil && expectedError != nil && err.Error() != expectedError.Error()) {
			t.Errorf("%s: expected error %v, received error %v", verifyConsistencyCheckInputTestCaseName, expectedError, err)
		}
	}
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
	if err != nil {
		t.Errorf("error verifying ct consistency: %v", err)
	}
}
