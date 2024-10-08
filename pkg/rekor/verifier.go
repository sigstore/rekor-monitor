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
	"crypto"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// GetLogVerifier creates a verifier from the log's public key
// TODO: Fetch the public key from TUF
func GetLogVerifier(ctx context.Context, rekorClient *client.Rekor) (signature.Verifier, error) {
	pemPubKey, err := GetPublicKey(ctx, rekorClient)
	if err != nil {
		return nil, err
	}
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(pemPubKey)
	if err != nil {
		return nil, err
	}
	verifier, err := signature.LoadVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return verifier, nil
}

// verifyLatestCheckpoint fetches and verifies the signature of the latest checkpoint from log info fetched from Rekor.
// If it successfully verifies the checkpoint's signature, it returns the checkpoint; otherwise, it returns an error.
func verifyLatestCheckpointSignature(logInfo *models.LogInfo, verifier signature.Verifier) (*util.SignedCheckpoint, error) {
	checkpoint := &util.SignedCheckpoint{}
	if err := checkpoint.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
		return nil, fmt.Errorf("unmarshalling logInfo.SignedTreeHead to Checkpoint: %v", err)
	}
	if !checkpoint.Verify(verifier) {
		return nil, fmt.Errorf("verifying checkpoint (size %d, hash %s) failed", checkpoint.Size, hex.EncodeToString(checkpoint.Hash))
	}
	return checkpoint, nil
}

// verifyCheckpointConsistency reads and verifies the consistency of the previous latest checkpoint from a log info file against the current up-to-date checkpoint.
// If it successfully fetches and verifies the consistency between these two checkpoints, it returns the previous checkpoint; otherwise, it returns an error.
func verifyCheckpointConsistency(logInfoFile *string, checkpoint *util.SignedCheckpoint, treeID string, rekorClient *client.Rekor, verifier signature.Verifier) (*util.SignedCheckpoint, error) {
	var prevCheckpoint *util.SignedCheckpoint
	prevCheckpoint, err := file.ReadLatestCheckpoint(*logInfoFile)
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
func RunConsistencyCheck(interval *time.Duration, rekorClient *client.Rekor, verifier signature.Verifier, logInfoFile *string, mvs identity.MonitoredValues, outputIdentitiesFile *string, once *bool) error {
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	// Loop will:
	// 1. Fetch latest checkpoint and verify
	// 2. If old checkpoint is present, verify consistency proof
	// 3. Write latest checkpoint to file

	// To get an immediate first tick
	for ; ; <-ticker.C {
		logInfo, err := GetLogInfo(context.Background(), rekorClient)
		if err != nil {
			return fmt.Errorf("failed to get log info: %v", err)
		}
		checkpoint, err := verifyLatestCheckpointSignature(logInfo, verifier)
		if err != nil {
			return fmt.Errorf("failed to verify signature of latest checkpoint: %v", err)
		}
		fi, err := os.Stat(*logInfoFile)
		// File containing previous checkpoints exists
		var prevCheckpoint *util.SignedCheckpoint
		if err == nil && fi.Size() != 0 {
			prevCheckpoint, err = verifyCheckpointConsistency(logInfoFile, checkpoint, *logInfo.TreeID, rekorClient, verifier)
			if err != nil {
				return fmt.Errorf("failed to verify previous checkpoint: %v", err)
			}

		}

		// Write if there was no stored checkpoint or the sizes differ
		if prevCheckpoint == nil || prevCheckpoint.Size != checkpoint.Size {
			if err := file.WriteCheckpoint(checkpoint, *logInfoFile); err != nil {
				return fmt.Errorf("failed to write checkpoint: %v", err)
			}
		}

		if prevCheckpoint != nil && prevCheckpoint.Size != checkpoint.Size {
			// Get log size of inactive shards
			totalSize := 0
			for _, s := range logInfo.InactiveShards {
				totalSize += int(*s.TreeSize)
			}
			startIndex := int(prevCheckpoint.Size) + totalSize - 1 //nolint: gosec // G115, log will never be large enough to overflow
			endIndex := int(checkpoint.Size) + totalSize - 1       //nolint: gosec // G115

			// Search for identities in the log range
			if len(mvs.CertificateIdentities) > 0 || len(mvs.Fingerprints) > 0 || len(mvs.Subjects) > 0 {
				entries, err := GetEntriesByIndexRange(context.Background(), rekorClient, startIndex, endIndex)
				if err != nil {
					return fmt.Errorf("error getting entries by index range: %v", err)
				}
				idEntries, err := MatchedIndices(entries, mvs)
				if err != nil {
					return fmt.Errorf("error finding log indices: %v", err)
				}

				if len(idEntries) > 0 {
					for _, idEntry := range idEntries {
						fmt.Fprintf(os.Stderr, "Found %s\n", idEntry.String())

						if err := file.WriteIdentity(*outputIdentitiesFile, idEntry); err != nil {
							return fmt.Errorf("failed to write entry: %v", err)
						}
					}
				}
			}
		}

		// TODO: Switch to writing checkpoints to GitHub so that the history is preserved. Then we only need
		// to persist the last checkpoint.
		// Delete old checkpoints to avoid the log growing indefinitely
		if err := file.DeleteOldCheckpoints(*logInfoFile); err != nil {
			return fmt.Errorf("failed to delete old checkpoints: %v", err)
		}

		if *once {
			return nil
		}
	}
}
