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
	"context"
	"fmt"
	"net/url"
	"time"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	tiles_client "github.com/sigstore/rekor-tiles/pkg/client"
	"github.com/sigstore/rekor-tiles/pkg/client/read"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
)

type ShardInfo struct {
	client   *read.Client
	verifier *signature.Verifier
}

func GetRekorShards(ctx context.Context, trustedRoot *root.TrustedRoot, rekorServices []root.Service, userAgent string) (map[string]ShardInfo, string, error) {
	rekorURLsV2, err := root.SelectServices(rekorServices, root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ALL}, []uint32{2}, time.Now())
	if err != nil {
		return nil, "", fmt.Errorf("error selecting rekor services: %v", err)
	}

	rekorShards := make(map[string]ShardInfo)
	activeShardOrigin := ""
	for _, rekorURL := range rekorURLsV2 {
		parsedURL, err := url.Parse(rekorURL)
		if err != nil {
			return nil, "", fmt.Errorf("error parsing Rekor url: %v", err)
		}
		origin := rekorURL[len(parsedURL.Scheme)+len("://"):]

		// The urls in rekorURLsV2 are ordered from newest to oldest,
		// so we store the origin of the first one as the origin
		// of the latest (active) shard
		if activeShardOrigin == "" {
			activeShardOrigin = origin
		}
		verifier, err := GetLogVerifier(ctx, parsedURL, trustedRoot, userAgent)
		if err != nil {
			return nil, "", err
		}

		rekorClient, err := read.NewReader(rekorURL, origin, verifier, tiles_client.WithUserAgent(userAgent))
		if err != nil {
			return nil, "", fmt.Errorf("getting Rekor client: %v", err)
		}

		// ReadCheckpoint fetches and verifies the current checkpoint
		// We verify the checkpoints of all active v2 shards
		checkpoint, _, err := rekorClient.ReadCheckpoint(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get current checkpoint for log '%v': %v", origin, err)
		}

		rekorShards[checkpoint.Origin] = ShardInfo{&rekorClient, &verifier}
	}
	return rekorShards, activeShardOrigin, nil
}
