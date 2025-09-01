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
	"os"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

const (
	ctfe2022KeyID = "dd3d306ac6c7113263191e1c99673702a24a5eb8de3cadff878a72802f29ee8e"
)

func getCTLogVerifier() (*ct.SignatureVerifier, error) {
	client, err := tuf.DefaultClient()
	if err != nil {
		return nil, err
	}

	trustedRoot, err := root.GetTrustedRoot(client)
	if err != nil {
		return nil, err
	}

	ctLogs := trustedRoot.CTLogs()

	if log, ok := ctLogs[ctfe2022KeyID]; ok {
		verifier, err := ct.NewSignatureVerifier(log.PublicKey)
		if err != nil {
			return nil, err
		}
		return verifier, nil
	}

	return nil, fmt.Errorf("could not find certificate transparency log in trusted root")
}

func verifyCertificateTransparencyConsistency(logInfoFile string, logClient *ctclient.LogClient, signedTreeHead *ct.SignedTreeHead) (*ct.SignedTreeHead, error) {
	prevSTH, err := file.ReadLatestCTSignedTreeHead(logInfoFile)
	if err != nil {
		return nil, fmt.Errorf("error reading checkpoint: %v", err)
	}

	if logClient.Verifier == nil {
		verifier, err := getCTLogVerifier()

		if err != nil {
			return nil, fmt.Errorf("error loading public key: %v", err)
		}
		logClient.Verifier = verifier
	}

	err = logClient.VerifySTHSignature(*prevSTH)
	if err != nil {
		return nil, fmt.Errorf("error verifying previous STH signature: %v", err)
	}
	err = logClient.VerifySTHSignature(*signedTreeHead)
	if err != nil {
		return nil, fmt.Errorf("error verifying current STH signature: %v", err)
	}

	first := prevSTH.TreeSize
	second := signedTreeHead.TreeSize
	pf, err := logClient.GetSTHConsistency(context.Background(), first, second)
	if err != nil {
		return nil, fmt.Errorf("error getting consistency proof: %v", err)
	}

	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, first, second, pf, prevSTH.SHA256RootHash[:], signedTreeHead.SHA256RootHash[:]); err != nil {
		return nil, fmt.Errorf("error verifying consistency: %v", err)
	}

	return prevSTH, nil
}

// RunConsistencyCheck periodically verifies the root hash consistency of a certificate transparency log.
func RunConsistencyCheck(logClient *ctclient.LogClient, logInfoFile string) (*ct.SignedTreeHead, *ct.SignedTreeHead, error) {
	currentSTH, err := logClient.GetSTH(context.Background())
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching latest STH: %v", err)
	}

	fi, err := os.Stat(logInfoFile)
	// File containing previous checkpoints exists
	var prevSTH *ct.SignedTreeHead
	if err == nil && fi.Size() != 0 {
		prevSTH, err = verifyCertificateTransparencyConsistency(logInfoFile, logClient, currentSTH)
		if err != nil {
			return nil, nil, fmt.Errorf("error verifying consistency between previous and current STHs: %v", err)
		}
	}

	return prevSTH, currentSTH, nil
}
