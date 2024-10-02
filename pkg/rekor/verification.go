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

	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor/pkg/generated/client"
	gclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

type LogConsistencyCheckConfiguration struct {
	LogInfoFile *string        `yaml:"logInfoFile"`
	URL         *string        `yaml:"url"`
	Interval    *time.Duration `yaml:"interval"`
	Once        *bool          `yaml:"once"`
	UserAgent   *string        `yaml:"userAgent"`
}

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

func LogConsistencyCheck(config LogConsistencyCheckConfiguration, rekorClient *gclient.Rekor, verifier signature.Verifier) error {
	ticker := time.NewTicker(*config.Interval)
	defer ticker.Stop()

	// To get an immediate first tick
	for ; ; <-ticker.C {
		logInfo, err := GetLogInfo(context.Background(), rekorClient)
		if err != nil {
			return fmt.Errorf("getting log info: %v", err)
		}
		checkpoint := &util.SignedCheckpoint{}
		if err := checkpoint.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
			return fmt.Errorf("unmarshalling logInfo.SignedTreeHead to Checkpoint: %v", err)
		}
		if !checkpoint.Verify(verifier) {
			return fmt.Errorf("verifying checkpoint (size %d, hash %s) failed", checkpoint.Size, hex.EncodeToString(checkpoint.Hash))
		}

		fi, err := os.Stat(*config.LogInfoFile)
		var prevCheckpoint *util.SignedCheckpoint
		if err == nil && fi.Size() != 0 {
			// File containing previous checkpoints exists
			prevCheckpoint, err = file.ReadLatestCheckpoint(*config.LogInfoFile)
			if err != nil {
				return fmt.Errorf("reading checkpoint log: %v", err)
			}
			if !prevCheckpoint.Verify(verifier) {
				return fmt.Errorf("verifying checkpoint (size %d, hash %s) failed", checkpoint.Size, hex.EncodeToString(checkpoint.Hash))
			}
		}
		if prevCheckpoint != nil {
			if err := verify.ProveConsistency(context.Background(), rekorClient, prevCheckpoint, checkpoint, *logInfo.TreeID); err != nil {
				return fmt.Errorf("failed to verify log consistency: %v", err)
			}
			fmt.Fprintf(os.Stderr, "Root hash consistency verified - Current Size: %d Root Hash: %s - Previous Size: %d Root Hash %s\n",
				checkpoint.Size, hex.EncodeToString(checkpoint.Hash), prevCheckpoint.Size, hex.EncodeToString(prevCheckpoint.Hash))
		}

		// Write if there was no stored checkpoint or the sizes differ
		if prevCheckpoint == nil || prevCheckpoint.Size != checkpoint.Size {
			if err := file.WriteCheckpoint(checkpoint, *config.LogInfoFile); err != nil {
				return fmt.Errorf("failed to write checkpoint: %v", err)
			}
		}

		// TODO: Switch to writing checkpoints to GitHub so that the history is preserved. Then we only need
		// to persist the last checkpoint.
		// Delete old checkpoints to avoid the log growing indefinitely
		if err := file.DeleteOldCheckpoints(*config.LogInfoFile); err != nil {
			return fmt.Errorf("failed to delete old checkpoints: %v", err)
		}

		if *config.Once {
			return nil
		}
	}
}
