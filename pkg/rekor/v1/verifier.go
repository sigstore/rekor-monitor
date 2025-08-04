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

package v1

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
)

// GetLogVerifier creates a verifier from the log's public key
func GetLogVerifier(ctx context.Context, rekorClient *client.Rekor, trustedRoot root.TrustedMaterial) (signature.Verifier, error) {
	logInfo, err := GetLogInfo(ctx, rekorClient)
	if err != nil {
		return nil, err
	}
	latestCheckpoint, err := ReadLatestCheckpoint(logInfo)
	if err != nil {
		return nil, err
	}
	signatures := latestCheckpoint.Signatures
	if len(signatures) == 0 {
		return nil, fmt.Errorf("couldn't get signatures from checkpoint %v", latestCheckpoint)
	}
	keyID := make([]byte, 4)
	binary.BigEndian.PutUint32(keyID, signatures[0].Hash)

	var matchingLogInstance *root.TransparencyLog
	rekorLogs := trustedRoot.RekorLogs()
	for k, v := range rekorLogs {
		logID, err := hex.DecodeString(k)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(logID[:4], keyID) {
			matchingLogInstance = v
		}
	}

	if matchingLogInstance == nil {
		return nil, fmt.Errorf("couldn't find matching log instance with keyID %v", keyID)
	}

	verifier, err := signature.LoadVerifier(matchingLogInstance.PublicKey, matchingLogInstance.HashFunc)
	if err != nil {
		return nil, err
	}
	return verifier, nil
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
	prevCheckpoint, err := file.ReadLatestCheckpointRekorV1(logInfoFile)
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
		if err := file.WriteCheckpointRekorV1(checkpoint, logInfoFile); err != nil {
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
