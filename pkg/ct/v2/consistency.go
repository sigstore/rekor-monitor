// Copyright 2026 The Sigstore Authors.
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
	"context"
	"fmt"
	"os"

	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	tclient "github.com/transparency-dev/tessera/client"
)

// RunConsistencyCheck periodically verifies the root hash consistency of a certificate transparency log.
func RunConsistencyCheck(ctx context.Context, logClient *Client, logInfoFile string) (*log.Checkpoint, *log.Checkpoint, error) {
	// get current checkpoint
	currentCP, _, err := logClient.ReadCheckpoint(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("reading checkpoint: %w", err)
	}

	fi, err := os.Stat(logInfoFile)
	// File containing previous checkpoints exists
	if err != nil || fi.Size() == 0 {
		return nil, currentCP, nil
	}
	// verify consistency to current checkpoint and return previous checkpoint
	prevCP, err := file.ReadLatestCheckpointRekorV2(logInfoFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading checkpoint log: %w", err)
	}

	pb, err := tclient.NewProofBuilder(ctx, currentCP.Size, logClient.ReadTile)
	if err != nil {
		return nil, nil, fmt.Errorf("getting proof builder: %w", err)
	}
	consistencyProof, err := pb.ConsistencyProof(ctx, prevCP.Size, currentCP.Size)
	if err != nil {
		return nil, nil, fmt.Errorf("building consistency proof: %w", err)
	}
	err = proof.VerifyConsistency(rfc6962.DefaultHasher, prevCP.Size, currentCP.Size, consistencyProof, prevCP.Hash, currentCP.Hash)
	if err != nil {
		return nil, nil, fmt.Errorf("consistency check failed: %w", err)
	}

	return prevCP, currentCP, nil
}
