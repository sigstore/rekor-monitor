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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// TrustRootConfig defines the set of trusted roots for certificate verification
type TrustRootConfig struct {
	CustomRoots   []*x509.Certificate
	UseTUFDefault bool
}

var certPoolMutex sync.Mutex

// GetTrustedRoots builds a CertPool from the configured trusted roots
func GetTrustedRoots(ctx context.Context, config *TrustRootConfig, rekorClient *client.Rekor) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()

	if config.UseTUFDefault {
		defaultRoots, err := root.FetchTrustedRoot()
		if err != nil {
			log.Printf("Critical: Failed to fetch TUF trusted roots: %v", err)
			return nil, fmt.Errorf("failed to fetch TUF trusted roots: %v", err)
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
	}

	if len(config.CustomRoots) > 0 {
		for _, rootCert := range config.CustomRoots {
			if !isValidRoot(rootCert) {
				log.Printf("Warning: Skipping invalid custom root: %v", rootCert.Subject.CommonName)
				continue
			}
			certPoolMutex.Lock()
			certPool.AddCert(rootCert)
			certPoolMutex.Unlock()
		}
	}

	if len(certPool.Subjects()) == 0 {
		return nil, fmt.Errorf("no valid trusted roots configured")
	}

	return certPool, nil
}

// GetLogVerifier creates a verifier from the log's public key, ensuring it chains to trusted roots
func GetLogVerifier(ctx context.Context, rekorClient *client.Rekor, trustedRoots *x509.CertPool) (signature.Verifier, error) {
	certChain, err := getCertificateChain(rekorClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate chain: %v", err)
	}

	if len(certChain) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}

	if err := verifyCertificateChain(certChain, trustedRoots); err != nil {
		return nil, fmt.Errorf("certificate chain does not chain to a trusted root: %v", err)
	}

	pubKey := certChain[0].PublicKey
	verifier, err := signature.LoadVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to load verifier: %v", err)
	}
	return verifier, nil
}

// VerifyLogEntryCertChain verifies that a log entry's certificate chain chains up to a trusted root
func VerifyLogEntryCertChain(entry models.LogEntryAnon, certPool *x509.CertPool) bool {
	certChain := extractCertChain(entry)
	if len(certChain) == 0 {
		logIndex := "<nil>"
		if entry.LogIndex != nil {
			logIndex = fmt.Sprintf("%d", *entry.LogIndex)
		}
		log.Printf("No certificate chain found in log entry: %s", logIndex)
		return false
	}

	cert, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		logIndex := "<nil>"
		if entry.LogIndex != nil {
			logIndex = fmt.Sprintf("%d", *entry.LogIndex)
		}
		log.Printf("Failed to parse end-entity certificate for entry %s: %v", logIndex, err)
		return false
	}

	intermediates := x509.NewCertPool()
	for _, der := range certChain[1:] {
		inter, err := x509.ParseCertificate(der)
		if err != nil {
			logIndex := "<nil>"
			if entry.LogIndex != nil {
				logIndex = fmt.Sprintf("%d", *entry.LogIndex)
			}
			log.Printf("Failed to parse intermediate certificate for entry %s: %v", logIndex, err)
			return false
		}
		intermediates.AddCert(inter)
	}

	opts := x509.VerifyOptions{
		Roots:         certPool,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	if _, err := cert.Verify(opts); err != nil {
		logIndex := "<nil>"
		if entry.LogIndex != nil {
			logIndex = fmt.Sprintf("%d", *entry.LogIndex)
		}
		log.Printf("Certificate chain verification failed for entry %s: %v", logIndex, err)
		return false
	}
	return true
}

func extractCertChain(entry models.LogEntryAnon) [][]byte {
	if entry.Body == nil {
		return [][]byte{}
	}

	bodyStr, ok := entry.Body.(string)
	if !ok {
		log.Printf("Failed to convert body to string")
		return [][]byte{}
	}

	decodedBody, err := base64.StdEncoding.DecodeString(bodyStr)
	if err != nil {
		log.Printf("Failed to decode base64 body: %v", err)
		return [][]byte{}
	}

	var rekord models.Rekord
	if err := json.Unmarshal(decodedBody, &rekord); err != nil {
		log.Printf("Failed to unmarshal rekord body: %v", err)
		return [][]byte{}
	}

	if rekord.APIVersion == nil || rekord.Spec == nil {
		return [][]byte{}
	}

	if *rekord.APIVersion != "0.0.1" {
		log.Printf("Unsupported rekord API version: %s", *rekord.APIVersion)
		return [][]byte{}
	}

	specBytes, err := json.Marshal(rekord.Spec)
	if err != nil {
		log.Printf("Failed to marshal spec: %v", err)
		return [][]byte{}
	}

	var rekordSpec models.RekordV001Schema
	if err := json.Unmarshal(specBytes, &rekordSpec); err != nil {
		log.Printf("Failed to unmarshal rekord spec: %v", err)
		return [][]byte{}
	}

	if rekordSpec.Signature != nil && rekordSpec.Signature.PublicKey != nil && rekordSpec.Signature.PublicKey.Content != nil {
		return [][]byte{*rekordSpec.Signature.PublicKey.Content}
	}

	return [][]byte{}
}

func ProcessLogEntries(ctx context.Context, config *TrustRootConfig, rekorClient *client.Rekor) error {
	certPool, err := GetTrustedRoots(ctx, config, rekorClient)
	if err != nil {
		return fmt.Errorf("failed to get trusted roots: %v", err)
	}

	logVerifier, err := GetLogVerifier(ctx, rekorClient, certPool)
	if err != nil {
		return fmt.Errorf("failed to get log verifier: %v", err)
	}

	logIndex := int64(0)
	batchSize := int64(100)

	for {
		params := &entries.GetLogEntryByIndexParams{
			Context:  ctx,
			LogIndex: logIndex,
		}
		entries, err := rekorClient.Entries.GetLogEntryByIndex(params)
		if err != nil {
			return fmt.Errorf("failed to fetch log entries at index %d: %v", logIndex, err)
		}

		if len(entries.Payload) == 0 {
			break
		}

		for _, entry := range entries.Payload {
			logIndexStr := "<nil>"
			if entry.LogIndex != nil {
				logIndexStr = fmt.Sprintf("%d", *entry.LogIndex)
			}

			if !VerifyLogEntryCertChain(entry, certPool) {
				return fmt.Errorf("skipping log entry %s due to invalid certificate chain", logIndexStr)

			}

			bodyStr, ok := entry.Body.(string)
			if !ok {
				return fmt.Errorf("failed to convert body to string for entry %s", logIndexStr)

			}

			decodedBody, err := base64.StdEncoding.DecodeString(bodyStr)
			if err != nil {
				return fmt.Errorf("failed to decode base64 body for entry %s: %v", logIndexStr, err)

			}

			var rekord models.Rekord
			if err := json.Unmarshal(decodedBody, &rekord); err != nil {
				return fmt.Errorf("failed to unmarshal rekord body for entry %s: %v", logIndexStr, err)

			}

			specBytes, err := json.Marshal(rekord.Spec)
			if err != nil {
				return fmt.Errorf("failed to marshal spec for entry %s: %v", logIndexStr, err)

			}

			var rekordSpec models.RekordV001Schema
			if err := json.Unmarshal(specBytes, &rekordSpec); err != nil {
				return fmt.Errorf("failed to unmarshal rekord spec for entry %s: %v", logIndexStr, err)

			}

			if rekordSpec.Signature == nil || rekordSpec.Signature.Content == nil || rekordSpec.Data == nil || rekordSpec.Data.Content == nil {
				return fmt.Errorf("missing signature or data in entry %s", logIndexStr)
			}

			signatureBytes := []byte(*rekordSpec.Signature.Content)
			signedData := []byte(rekordSpec.Data.Content)

			err = logVerifier.VerifySignature(bytes.NewReader(signatureBytes), bytes.NewReader(signedData))
			if err != nil {
				return err
			}
			log.Printf("Successfully verified signature for log entry %s", logIndexStr)
		}

		logIndex += batchSize
	}

	return nil
}

func isValidRoot(cert *x509.Certificate) bool {
	if !cert.IsCA || !cert.BasicConstraintsValid {
		log.Printf("Root certificate is not a valid CA: %v", cert.Subject.CommonName)
		return false
	}

	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		log.Printf("Root certificate expired or not yet valid: %v", cert.Subject.CommonName)
		return false
	}

	if !isSelfSigned(cert) {
		log.Printf("Root certificate is not self-signed: %v", cert.Subject.CommonName)
		return false
	}

	return true
}

func isSelfSigned(cert *x509.Certificate) bool {
	err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	return err == nil
}

func verifyCertificateChain(certChain []*x509.Certificate, trustedRoots *x509.CertPool) error {
	if len(certChain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	leafCert := certChain[0]
	intermediates := x509.NewCertPool()
	for _, cert := range certChain[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         trustedRoots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	_, err := leafCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %v", err)
	}
	return nil
}

func getCertificateChain(rekorClient *client.Rekor) ([]*x509.Certificate, error) {
	if rekorClient == nil || rekorClient.Pubkey == nil {
		return nil, fmt.Errorf("invalid rekor client or pubkey client")
	}

	resp, err := rekorClient.Pubkey.GetPublicKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(resp.Payload))
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
