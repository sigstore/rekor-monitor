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
	"context"
	"fmt"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

const (
	ctfe2022PubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNK
AaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==
-----END PUBLIC KEY-----`
)

func verifyCertificateTransparencyConsistency(logInfoFile string, logClient *ctclient.LogClient, signedTreeHead *ct.SignedTreeHead) error {
	prevSTH, err := file.ReadLatestCTSignedTreeHead(logInfoFile)
	if err != nil {
		return fmt.Errorf("error reading checkpoint: %v", err)
	}

	if logClient.Verifier == nil {
		// TODO: this public key is currently hardcoded- should be fetched from TUF repository instead
		pubKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(ctfe2022PubKey))

		if err != nil {
			return fmt.Errorf("error loading public key: %v", err)
		}
		logClient.Verifier = &ct.SignatureVerifier{
			PubKey: pubKey,
		}
	}

	err = logClient.VerifySTHSignature(*prevSTH)
	if err != nil {
		return fmt.Errorf("error verifying previous STH signature: %v", err)
	}
	err = logClient.VerifySTHSignature(*signedTreeHead)
	if err != nil {
		return fmt.Errorf("error verifying current STH signature: %v", err)
	}

	first := prevSTH.TreeSize
	second := signedTreeHead.TreeSize
	pf, err := logClient.GetSTHConsistency(context.Background(), first, second)
	if err != nil {
		return fmt.Errorf("error getting consistency proof: %v", err)
	}

	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, first, second, pf, prevSTH.SHA256RootHash[:], signedTreeHead.SHA256RootHash[:]); err != nil {
		return fmt.Errorf("error verifying consistency: %v", err)
	}

	return nil
}
