// Copyright 2025 The Sigstore Authors.
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

package v2

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor-tiles/pkg/client"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	tclient "github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

// GetCheckpointKeyIDUnverified fetches the latest checkpoint from the server at baseURL
// and extracts the key ID from it.
//
// No verification of the checkpoint is performed, since this function is meant
// to be called before we have a public key to verify against.
func GetCheckpointKeyIDUnverified(ctx context.Context, baseURL *url.URL, userAgent string) ([]byte, error) {
	httpClient := &http.Client{
		Transport: client.CreateRoundTripper(http.DefaultTransport, userAgent),
	}
	tileClient, err := tclient.NewHTTPFetcher(baseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("creating tile client: %v", err)
	}
	cpRaw, err := tileClient.ReadCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("error fetching checkpoint: %v", err)
	}

	// The sumdb/note API requires verification to happen while
	// opening/parsing a note. Since we don't have a public key
	// at this point in time, we force the parsing by passing an
	// empty list of verifiers and extracting the (unverified)
	// parsed note from the returned error.
	var checkpointNote *note.Note
	var unverifiedErr *note.UnverifiedNoteError
	_, err = note.Open(cpRaw, note.VerifierList())
	if errors.As(err, &unverifiedErr) {
		checkpointNote = unverifiedErr.Note
	} else {
		return nil, fmt.Errorf("error parsing checkpoint: %v", err)
	}

	if len(checkpointNote.UnverifiedSigs) == 0 {
		return nil, fmt.Errorf("no signatures found in checkpoint: %v", checkpointNote)
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(checkpointNote.UnverifiedSigs[0].Base64)
	if err != nil {
		return nil, fmt.Errorf("error decoding checkpoint signature: %v", err)
	}
	if len(signatureBytes) < 4 {
		return nil, fmt.Errorf("signature too short, expected >=4 bytes: %v", signatureBytes)
	}
	return signatureBytes[:4], nil
}

func GetLogVerifier(ctx context.Context, baseURL *url.URL, trustedRoot root.TrustedMaterial, userAgent string) (signature.Verifier, error) {
	checkpointKeyID, err := GetCheckpointKeyIDUnverified(ctx, baseURL, userAgent)
	if err != nil {
		return nil, err
	}

	var matchingLogInstance *root.TransparencyLog
	rekorLogs := trustedRoot.RekorLogs()
	for k, v := range rekorLogs {
		logID, err := hex.DecodeString(k)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(logID[:4], checkpointKeyID) {
			matchingLogInstance = v
		}
	}

	if matchingLogInstance == nil {
		return nil, fmt.Errorf("couldn't find matching log instance with baseURL %v", baseURL)
	}

	verifier, err := signature.LoadVerifier(matchingLogInstance.PublicKey, matchingLogInstance.HashFunc)
	if err != nil {
		return nil, err
	}
	return verifier, nil
}

func RunConsistencyCheck(ctx context.Context, rekorShards map[string]ShardInfo, activeShardOrigin string, logInfoFile string) (*log.Checkpoint, error) {
	// First, we select the correct shard. Most of the time this will be
	// the latest active shard (with origin == activeShardOrigin), but
	// in situations where the previously stored checkpoint is from an older
	// shard, we have to:
	// - Verify the previous checkpoint against the last checkpoint of the older shard
	// - Store the last checkpoint of the *newest* shard as the last-seen checkpoint
	// in order to migrate from the old shald to the new one.

	// Fetch (and verify) the latest checkpoint of the latest active shard
	// This is the checkpoint that will be saved to `logInfoFile`.
	latestActiveCheckpoint, _, err := (*rekorShards[activeShardOrigin].client).ReadCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current checkpoint: %v", err)
	}

	var prevCheckpoint *log.Checkpoint
	fi, err := os.Stat(logInfoFile)
	if err == nil && fi.Size() != 0 {
		// Read the latest saved checkpoint from the log file
		prevCheckpoint, err = file.ReadLatestCheckpointRekorV2(logInfoFile)
		if err != nil {
			return nil, fmt.Errorf("reading checkpoint log: %v", err)
		}

		// The new checkpoint we fetch for the consistency check has to be from the same
		// shard as the previous checkpoint.
		rekorClient := *rekorShards[activeShardOrigin].client
		newCheckpoint := latestActiveCheckpoint
		if prevCheckpoint.Origin != activeShardOrigin {
			rekorClient = *rekorShards[prevCheckpoint.Origin].client
			newCheckpoint, _, err = rekorClient.ReadCheckpoint(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get current checkpoint: %v", err)
			}
		}

		// Build the consistency proof between the tree sizes of the previous (stored)
		// checkpoint and the newest fetched checkpoint
		pb, err := tclient.NewProofBuilder(ctx, newCheckpoint.Size, rekorClient.ReadTile)
		if err != nil {
			return nil, fmt.Errorf("failed to get proof builder: %v", err)
		}
		consistencyProof, err := pb.ConsistencyProof(ctx, prevCheckpoint.Size, newCheckpoint.Size)
		if err != nil {
			return nil, fmt.Errorf("failed to build consistency proof: %v", err)
		}

		err = proof.VerifyConsistency(rfc6962.DefaultHasher, prevCheckpoint.Size, newCheckpoint.Size, consistencyProof, prevCheckpoint.Hash, newCheckpoint.Hash)
		if err != nil {
			return nil, fmt.Errorf("consistency check failed: %v", err)
		}

		fmt.Fprintf(os.Stderr, "Root hash consistency verified - Current Size: %d Root Hash: %s - Previous Size: %d Root Hash %s\n",
			newCheckpoint.Size, hex.EncodeToString(newCheckpoint.Hash), prevCheckpoint.Size, hex.EncodeToString(prevCheckpoint.Hash))
	}

	// Write if there was no stored checkpoint or the origin/sizes differ
	if prevCheckpoint == nil || prevCheckpoint.Origin != latestActiveCheckpoint.Origin || prevCheckpoint.Size != latestActiveCheckpoint.Size {
		if err := file.WriteCheckpointRekorV2(latestActiveCheckpoint, logInfoFile); err != nil {
			// TODO: Once the consistency check and identity search are split into separate tasks, this should hard fail.
			// Temporarily skipping this to allow this job to succeed, remediating the issue noted here: https://github.com/sigstore/rekor-monitor/issues/271
			fmt.Fprintf(os.Stderr, "failed to write checkpoint: %v", err)
		}
	}

	return prevCheckpoint, nil
}
