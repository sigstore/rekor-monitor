//
// Copyright 2021 The Sigstore Authors.
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

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/sigstore/rekor-monitor/internal/cmd"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/notifications"
	rekor_v1 "github.com/sigstore/rekor-monitor/pkg/rekor/v1"
	rekor_v2 "github.com/sigstore/rekor-monitor/pkg/rekor/v2"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// Default values for monitoring job parameters
const (
	publicRekorServerURL     = "https://rekor.sigstore.dev"
	TUFRepository            = "default"
	outputIdentitiesFileName = "identities.txt"
	logInfoFileNamePrefix    = "logInfo"
)

// This main function performs a periodic identity search.
// Upon starting, any existing latest snapshot data is loaded and the function runs
// indefinitely to perform identity search for every time interval that was specified.
func main() {
	flags, config, err := cmd.ParseAndLoadConfig(publicRekorServerURL, TUFRepository, outputIdentitiesFileName, "rekor-monitor")
	if err != nil {
		log.Fatalf("error parsing flags and loading config: %v", err)
	}

	var tufClient *tuf.Client
	switch flags.TUFRepository {
	case "default":
		tufClient, err = tuf.DefaultClient()
	case "staging":
		options := tuf.DefaultOptions().WithRoot(tuf.StagingRoot()).WithRepositoryBaseURL(tuf.StagingMirror)
		tufClient, err = tuf.New(options)
	default:
		log.Fatalf("custom TUF repository not currently supported")
	}
	if err != nil {
		log.Fatal(err)
	}

	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		log.Fatal(err)
	}
	// TODO: Use root.GetSigningConfig once https://github.com/sigstore/sigstore-go/pull/506 is merged
	signingConfigBytes, err := tufClient.GetTarget("signing_config.v0.2.json")
	if err != nil {
		log.Fatal(err)
	}
	signingConfig, err := root.NewSigningConfigFromJSON(signingConfigBytes)
	if err != nil {
		log.Fatal(err)
	}

	allRekorServices := signingConfig.RekorLogURLs()
	rekorVersion := uint32(1)
	for _, service := range allRekorServices {
		if flags.ServerURL == service.URL {
			rekorVersion = service.MajorAPIVersion
		}
	}
	if flags.LogInfoFile == "" {
		logInfoFileName := fmt.Sprintf("%s.v%d.txt", logInfoFileNamePrefix, rekorVersion)
		flags.LogInfoFile = logInfoFileName
	}
	switch rekorVersion {
	case 1:
		mainLoopV1(flags, config, trustedRoot)
	case 2:
		fmt.Fprintf(os.Stderr, "Warning: the monitor currently only checks for the consistency of the log in Rekor v2 logs.\n")
		rekorShards, activeShardOrigin, err := rekor_v2.GetRekorShards(context.Background(), trustedRoot, allRekorServices, flags.UserAgent)
		if err != nil {
			log.Fatal(err)
		}
		mainLoopV2(flags, config, rekorShards, activeShardOrigin)
	default:
		log.Fatalf("Unsupported server version %v, only '1' and '2' are supported", rekorVersion)
	}
}

func mainLoopV1(flags *cmd.MonitorFlags, config *notifications.IdentityMonitorConfiguration, trustedRoot *root.TrustedRoot) {
	rekorClient, err := client.GetRekorClient(flags.ServerURL, client.WithUserAgent(flags.UserAgent))
	if err != nil {
		log.Fatalf("getting Rekor client: %v", err)
	}

	verifier, err := rekor_v1.GetLogVerifier(context.Background(), rekorClient, trustedRoot)
	if err != nil {
		log.Fatal(err)
	}

	allOIDMatchers, err := config.MonitoredValues.OIDMatchers.RenderOIDMatchers()
	if err != nil {
		fmt.Printf("error parsing OID matchers: %v", err)
	}

	monitoredValues := identity.MonitoredValues{
		CertificateIdentities: config.MonitoredValues.CertificateIdentities,
		Subjects:              config.MonitoredValues.Subjects,
		Fingerprints:          config.MonitoredValues.Fingerprints,
		OIDMatchers:           allOIDMatchers,
	}

	cmd.PrintMonitoredValues(monitoredValues)
	cmd.MonitorLoop(cmd.MonitorLoopParams{
		Interval:        flags.Interval,
		Config:          config,
		MonitoredValues: monitoredValues,
		Once:            flags.Once,
		RunConsistencyCheckFn: func(_ context.Context) (cmd.Checkpoint, cmd.LogInfo, error) {
			prev, cur, err := rekor_v1.RunConsistencyCheck(rekorClient, verifier, flags.LogInfoFile)
			if err != nil {
				return nil, nil, err
			}
			var prevCheckpoint cmd.Checkpoint
			if prev != nil {
				prevCheckpoint = prev
			}
			var curLogInfo cmd.LogInfo
			if cur != nil {
				curLogInfo = cur
			}
			return prevCheckpoint, curLogInfo, nil
		},
		GetStartIndexFn: func(prev cmd.Checkpoint, cur cmd.LogInfo) *int {
			checkpointStartIndex := rekor_v1.GetCheckpointIndex(cur.(*models.LogInfo), prev.(*util.SignedCheckpoint))
			return &checkpointStartIndex
		},
		GetEndIndexFn: func(_ cmd.Checkpoint, cur cmd.LogInfo) *int {
			checkpoint, err := rekor_v1.ReadLatestCheckpoint(cur.(*models.LogInfo))
			if err != nil {
				return nil
			}
			checkpointEndIndex := rekor_v1.GetCheckpointIndex(cur.(*models.LogInfo), checkpoint)
			return &checkpointEndIndex
		},
		IdentitySearchFn: func(ctx context.Context, config *notifications.IdentityMonitorConfiguration, monitoredValues identity.MonitoredValues) ([]identity.MonitoredIdentity, error) {
			return rekor_v1.IdentitySearch(ctx, *config.StartIndex, *config.EndIndex, rekorClient, monitoredValues, config.OutputIdentitiesFile, config.IdentityMetadataFile)
		},
	})
}

func mainLoopV2(flags *cmd.MonitorFlags, config *notifications.IdentityMonitorConfiguration, rekorShards map[string]rekor_v2.ShardInfo, activeShardOrigin string) {
	cmd.MonitorLoop(cmd.MonitorLoopParams{
		Interval:        flags.Interval,
		Config:          config,
		MonitoredValues: identity.MonitoredValues{},
		Once:            flags.Once,
		RunConsistencyCheckFn: func(_ context.Context) (cmd.Checkpoint, cmd.LogInfo, error) {
			// TODO: should return prev and cur
			cur, err := rekor_v2.RunConsistencyCheck(context.Background(), rekorShards, activeShardOrigin, flags.LogInfoFile)
			if err != nil {
				return nil, nil, err
			}
			var curLogInfo cmd.LogInfo
			if cur != nil {
				curLogInfo = cur
			}
			return nil, curLogInfo, nil
		},
		GetStartIndexFn: func(_ cmd.Checkpoint, _ cmd.LogInfo) *int {
			return nil
		},
		GetEndIndexFn: func(_ cmd.Checkpoint, _ cmd.LogInfo) *int {
			return nil
		},
		IdentitySearchFn: func(_ context.Context, _ *notifications.IdentityMonitorConfiguration, _ identity.MonitoredValues) ([]identity.MonitoredIdentity, error) {
			return nil, nil
		},
	})
}
