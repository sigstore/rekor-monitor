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
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// TrustRootConfig for trust roots (aka custom roots)
type TrustRootConfig struct {
	CustomRoots []*x509.Certificate
}

// GetLogVerifier creates a verifier from the log's public key
func GetLogVerifier(ctx context.Context, rekorClient *client.Rekor, trustRootConfig *TrustRootConfig) (signature.Verifier, error) {
	trustedRoots, err := fetchTrustedRoots(trustRootConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted roots: %v", err)
	}

	certChain, err := getCertificateChain(ctx, rekorClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate chain: %v", err)
	}

	if err := verifyCertificateChain(certChain, trustedRoots); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %v", err)
	}

	// Extract and create verifier
	pubKey := certChain[0].PublicKey
	verifier, err := signature.LoadVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to load verifier: %v", err)
	}

	return verifier, nil
}

func fetchTrustedRoots(config *TrustRootConfig) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()

	defaultRoots, err := root.FetchTrustedRoot()
	if err != nil {
		log.Printf("Warning: Failed to fetch trusted roots: %v", err)
	}

	fulcioCAs := defaultRoots.FulcioCertificateAuthorities()
	if len(fulcioCAs) == 0 {
		log.Println("Warning: No Fulcio CAs found in TUF metadata")
	}

	for _, ca := range fulcioCAs {
		if fulcioCa, ok := ca.(*root.FulcioCertificateAuthority); ok {
			if fulcioCa.Root != nil {
				certPool.AddCert(fulcioCa.Root)
			}
			for _, intermediateCert := range fulcioCa.Intermediates {
				certPool.AddCert(intermediateCert)
			}
		}
	}

	// for custom roots (if any)
	if len(config.CustomRoots) > 0 {
		for _, rootCert := range config.CustomRoots {
			certPool.AddCert(rootCert)
		}
	}

	return certPool, nil
}

func verifyCertificateChain(certChain []*x509.Certificate, trustedRoots *x509.CertPool) error {
	if len(certChain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certChain[1:] { //skipp the first cert as it is the leaf cert
		intermediates.AddCert(cert)
	}

	// using intermediate CAs to verify the chain of trust so that we can support intermediate CAs and it won't fail
	// should we? or should we just use the root CAs? let me know
	opts := x509.VerifyOptions{
		Roots:         trustedRoots,
		Intermediates: intermediates,
	}

	verifiedChains, err := certChain[0].Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %v", err)
	}

	for _, chain := range verifiedChains {
		rootCert := chain[len(chain)-1]
		if trustedRoots.Subjects() != nil {
			for _, subject := range trustedRoots.Subjects() {
				if bytes.Equal(rootCert.RawSubject, subject) {
					return nil
				}
			}
		}
	}

	return fmt.Errorf("certificate chain does not terminate at a trusted root")
}

func getCertificateChain(ctx context.Context, rekorClient *client.Rekor) ([]*x509.Certificate, error) {
	pemPubKey, err := GetPublicKey(ctx, rekorClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(pemPubKey)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("failed to parse certificates: %v", err)
	}

	return certs, nil
}

// ReadLatestCheckpoint fetches the latest checkpoint from log info fetched from Rekor.
// It returns the checkpoint if it successfully fetches one; otherwise, it returns an error.
func ReadLatestCheckpoint(logInfo *models.LogInfo) (*util.SignedCheckpoint, error) {
	checkpoint := &util.SignedCheckpoint{}
	if err := checkpoint.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
		return nil, fmt.Errorf("unmarshalling logInfo.SignedTreeHead to Checkpoint: %v", err)
	}
	return checkpoint, nil
}

// verifyLatestCheckpoint fetches and verifies the signature of the latest checkpoint from log info fetched from Rekor.
// If it successfully verifies the checkpoint's signature, it returns the checkpoint; otherwise, it returns an error.
func verifyLatestCheckpointSignature(logInfo *models.LogInfo, verifier signature.Verifier) (*util.SignedCheckpoint, error) {
	checkpoint, err := ReadLatestCheckpoint(logInfo)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling logInfo.SignedTreeHead to Checkpoint: %v", err)
	}
	if !checkpoint.Verify(verifier) {
		return nil, fmt.Errorf("verifying checkpoint (size %d, hash %s) failed", checkpoint.Size, hex.EncodeToString(checkpoint.Hash))
	}
	return checkpoint, nil
}

// verifyCheckpointConsistency reads and verifies the consistency of the previous latest checkpoint from a log info file against the current up-to-date checkpoint.
// If it successfully fetches and verifies the consistency between these two checkpoints, it returns the previous checkpoint; otherwise, it returns an error.
func verifyCheckpointConsistency(logInfoFile string, checkpoint *util.SignedCheckpoint, treeID string, rekorClient *client.Rekor, verifier signature.Verifier) (*util.SignedCheckpoint, error) {
	var prevCheckpoint *util.SignedCheckpoint
	prevCheckpoint, err := file.ReadLatestCheckpoint(logInfoFile)
	if err != nil {
		return nil, fmt.Errorf("reading checkpoint log: %v", err)
	}
	if !prevCheckpoint.Verify(verifier) {
		return nil, fmt.Errorf("verifying checkpoint (size %d, hash %s) failed", checkpoint.Size, hex.EncodeToString(checkpoint.Hash))
	}
	if err := verify.ProveConsistency(context.Background(), rekorClient, prevCheckpoint, checkpoint, treeID); err != nil {
		return nil, fmt.Errorf("failed to verify log consistency: %v", err)
	}
	fmt.Fprintf(os.Stderr, "Root hash consistency verified - Current Size: %d Root Hash: %s - Previous Size: %d Root Hash %s\n",
		checkpoint.Size, hex.EncodeToString(checkpoint.Hash), prevCheckpoint.Size, hex.EncodeToString(prevCheckpoint.Hash))
	return prevCheckpoint, nil
}

// RunConsistencyCheck periodically verifies the root hash consistency of a Rekor log.
func RunConsistencyCheck(rekorClient *client.Rekor, verifier signature.Verifier, logInfoFile string) (*util.SignedCheckpoint, *models.LogInfo, error) {
	logInfo, err := GetLogInfo(context.Background(), rekorClient)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get log info: %v", err)
	}
	checkpoint, err := verifyLatestCheckpointSignature(logInfo, verifier)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify signature of latest checkpoint: %v", err)
	}

	fi, err := os.Stat(logInfoFile)
	// File containing previous checkpoints exists
	var prevCheckpoint *util.SignedCheckpoint
	if err == nil && fi.Size() != 0 {
		prevCheckpoint, err = verifyCheckpointConsistency(logInfoFile, checkpoint, *logInfo.TreeID, rekorClient, verifier)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to verify previous checkpoint: %v", err)
		}

	}

	// Write if there was no stored checkpoint or the sizes differ
	if prevCheckpoint == nil || prevCheckpoint.Size != checkpoint.Size {
		if err := file.WriteCheckpoint(checkpoint, logInfoFile); err != nil {
			// TODO: Once the consistency check and identity search are split into separate tasks, this should hard fail.
			// Temporarily skipping this to allow this job to succeed, remediating the issue noted here: https://github.com/sigstore/rekor-monitor/issues/271
			fmt.Fprintf(os.Stderr, "failed to write checkpoint: %v", err)
		}
	}

	// TODO: Switch to writing checkpoints to GitHub so that the history is preserved. Then we only need
	// to persist the last checkpoint.
	// Delete old checkpoints to avoid the log growing indefinitely
	if err := file.DeleteOldCheckpoints(logInfoFile); err != nil {
		return nil, nil, fmt.Errorf("failed to delete old checkpoints: %v", err)
	}

	return prevCheckpoint, logInfo, nil
}
