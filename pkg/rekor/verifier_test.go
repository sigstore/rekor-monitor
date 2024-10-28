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
	"errors"
	"testing"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/rekor/mock"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

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
