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
	"time"

	"github.com/sigstore/rekor-monitor/internal/cmd"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/notifications"
	rekor_v1 "github.com/sigstore/rekor-monitor/pkg/rekor/v1"
	rekor_v2 "github.com/sigstore/rekor-monitor/pkg/rekor/v2"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor/pkg/client"
	rekor_client "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore/pkg/signature"
	tlog "github.com/transparency-dev/formats/log"
)

// Default values for monitoring job parameters
const (
	publicRekorServerURL     = "https://rekor.sigstore.dev"
	TUFRepository            = "default"
	outputIdentitiesFileName = "identities.txt"
	logInfoFileNamePrefix    = "logInfo"
)

func getTUFClient(flags *cmd.MonitorFlags) (*tuf.Client, error) {
	switch flags.TUFRepository {
	case "default":
		if flags.TUFRootPath != "" {
			log.Fatal("tuf-root-path is not supported when using the default TUF repository")
		}
		return tuf.DefaultClient()
	case "staging":
		if flags.TUFRootPath != "" {
			log.Fatal("tuf-root-path is not supported when using the staging TUF repository")
		}
		options := tuf.DefaultOptions().WithRoot(tuf.StagingRoot()).WithRepositoryBaseURL(tuf.StagingMirror)
		return tuf.New(options)
	default:
		if flags.TUFRootPath == "" {
			log.Fatal("tuf-root-path is required when using a custom TUF repository")
		}
		rootBytes, err := os.ReadFile(flags.TUFRootPath)
		if err != nil {
			log.Fatal(err)
		}
		options := tuf.DefaultOptions().WithRoot(rootBytes).WithRepositoryBaseURL(flags.TUFRepository)
		return tuf.New(options)
	}
}

type RekorV1MonitorLogic struct {
	rekorClient     *rekor_client.Rekor
	verifier        signature.Verifier
	flags           *cmd.MonitorFlags
	config          *notifications.IdentityMonitorConfiguration
	monitoredValues identity.MonitoredValues
}

func (l RekorV1MonitorLogic) Interval() time.Duration {
	return l.flags.Interval
}

func (l RekorV1MonitorLogic) Config() *notifications.IdentityMonitorConfiguration {
	return l.config
}

func (l RekorV1MonitorLogic) MonitoredValues() identity.MonitoredValues {
	return l.monitoredValues
}

func (l RekorV1MonitorLogic) Once() bool {
	return l.flags.Once
}

func (l RekorV1MonitorLogic) NotificationContextNew() notifications.NotificationContext {
	return notifications.CreateNotificationContext(
		"rekor-monitor",
		fmt.Sprintf("rekor-monitor workflow results for %s", time.Now().Format(time.RFC822)),
	)
}

func (l RekorV1MonitorLogic) RunConsistencyCheck(_ context.Context) (cmd.Checkpoint, cmd.LogInfo, error) {
	prev, cur, err := rekor_v1.RunConsistencyCheck(l.rekorClient, l.verifier, l.flags.LogInfoFile)
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
}

func (l RekorV1MonitorLogic) WriteCheckpoint(prev cmd.Checkpoint, cur cmd.LogInfo) error {
	prevCheckpoint, ok := prev.(*util.SignedCheckpoint)
	if !ok && prev != nil {
		return fmt.Errorf("prev is not a SignedCheckpoint")
	}
	curCheckpoint, err := rekor_v1.ReadLatestCheckpoint(cur.(*models.LogInfo))
	if err != nil {
		return fmt.Errorf("failed to read latest checkpoint: %v", err)
	}

	// Skip writing if the current checkpoint size is 0
	if curCheckpoint.Size == 0 {
		fmt.Fprintf(os.Stderr, "skipping write of checkpoint: size is 0\n")
		return nil
	}

	// TODO: Switch to writing checkpoints to GitHub so that the history is preserved. Then we only need
	// to persist the last checkpoint.
	if err := file.WriteCheckpointRekorV1(curCheckpoint, prevCheckpoint, l.flags.LogInfoFile, false); err != nil {
		return fmt.Errorf("failed to write checkpoint: %v", err)
	}

	return nil
}

func (l RekorV1MonitorLogic) GetStartIndex(prev cmd.Checkpoint, cur cmd.LogInfo) *int64 {
	checkpointStartIndex := rekor_v1.GetCheckpointIndex(cur.(*models.LogInfo), prev.(*util.SignedCheckpoint))
	return &checkpointStartIndex
}

func (l RekorV1MonitorLogic) GetEndIndex(cur cmd.LogInfo) *int64 {
	checkpoint, err := rekor_v1.ReadLatestCheckpoint(cur.(*models.LogInfo))
	if err != nil {
		return nil
	}
	checkpointEndIndex := rekor_v1.GetCheckpointIndex(cur.(*models.LogInfo), checkpoint)
	return &checkpointEndIndex
}

func (l RekorV1MonitorLogic) IdentitySearch(ctx context.Context, config *notifications.IdentityMonitorConfiguration, monitoredValues identity.MonitoredValues) ([]identity.MonitoredIdentity, []identity.FailedLogEntry, error) {
	return rekor_v1.IdentitySearch(ctx, *config.StartIndex, *config.EndIndex, l.rekorClient, monitoredValues, config.OutputIdentitiesFile, config.IdentityMetadataFile)
}

type RekorV2MonitorLogic struct {
	tufClient         *tuf.Client
	flags             *cmd.MonitorFlags
	config            *notifications.IdentityMonitorConfiguration
	rekorShards       map[string]rekor_v2.ShardInfo
	latestShardOrigin string
	monitoredValues   identity.MonitoredValues
}

func (l RekorV2MonitorLogic) Interval() time.Duration {
	return l.flags.Interval
}

func (l RekorV2MonitorLogic) Config() *notifications.IdentityMonitorConfiguration {
	return l.config
}

func (l RekorV2MonitorLogic) MonitoredValues() identity.MonitoredValues {
	return l.monitoredValues
}

func (l RekorV2MonitorLogic) Once() bool {
	return l.flags.Once
}

func (l RekorV2MonitorLogic) NotificationContextNew() notifications.NotificationContext {
	return notifications.CreateNotificationContext(
		"rekor-monitor-v2",
		fmt.Sprintf("rekor-monitor v2 workflow results for %s", time.Now().Format(time.RFC822)),
	)
}

func (l RekorV2MonitorLogic) RunConsistencyCheck(_ context.Context) (cmd.Checkpoint, cmd.LogInfo, error) {
	// On each iteration, we refresh the SigningConfig metadata and
	// update the shards if we detect a change in the newest shard
	signingConfig, err := rekor_v2.RefreshSigningConfig(l.tufClient)
	if err != nil {
		return nil, nil, err
	}
	shouldUpdate, err := rekor_v2.ShardsNeedUpdating(l.rekorShards, signingConfig)
	if err != nil {
		return nil, nil, err
	}
	if shouldUpdate {
		trustedRoot, err := root.GetTrustedRoot(l.tufClient)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting trusted root: %v", err)
		}
		l.rekorShards, l.latestShardOrigin, err = rekor_v2.GetRekorShards(context.Background(), trustedRoot, signingConfig.RekorLogURLs(), l.flags.UserAgent)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting shards: %v", err)
		}
	}

	prev, cur, err := rekor_v2.RunConsistencyCheck(context.Background(), l.rekorShards, l.latestShardOrigin, l.flags.LogInfoFile)
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
}

func (l RekorV2MonitorLogic) WriteCheckpoint(prev cmd.Checkpoint, cur cmd.LogInfo) error {
	prevCheckpoint, ok := prev.(*tlog.Checkpoint)
	if !ok && prev != nil {
		return fmt.Errorf("prev is not a Checkpoint")
	}
	curCheckpoint, ok := cur.(*tlog.Checkpoint)
	if !ok {
		return fmt.Errorf("cur is not a Checkpoint")
	}

	// Skip writing if the current checkpoint size is 0
	if curCheckpoint.Size == 0 {
		fmt.Fprintf(os.Stderr, "skipping write of checkpoint: size is 0\n")
		return nil
	}

	if err := file.WriteCheckpointRekorV2(curCheckpoint, prevCheckpoint, l.flags.LogInfoFile, false); err != nil {
		return fmt.Errorf("failed to write checkpoint: %v", err)
	}
	return nil
}

func (l RekorV2MonitorLogic) GetStartIndex(_ cmd.Checkpoint, _ cmd.LogInfo) *int64 {
	return nil
}

func (l RekorV2MonitorLogic) GetEndIndex(_ cmd.LogInfo) *int64 {
	return nil
}

func (l RekorV2MonitorLogic) IdentitySearch(_ context.Context, _ *notifications.IdentityMonitorConfiguration, _ identity.MonitoredValues) ([]identity.MonitoredIdentity, []identity.FailedLogEntry, error) {
	return nil, nil, nil
}

func getRekorVersion(allRekorServices []root.Service, serverURL string) uint32 {
	rekorVersion := uint32(1)
	for _, service := range allRekorServices {
		if serverURL == service.URL {
			rekorVersion = service.MajorAPIVersion
		}
	}
	return rekorVersion
}

// This main function performs a periodic identity search.
// Upon starting, any existing latest snapshot data is loaded and the function runs
// indefinitely to perform identity search for every time interval that was specified.
func main() {
	flags, config, err := cmd.ParseAndLoadConfig(publicRekorServerURL, TUFRepository, outputIdentitiesFileName, "rekor-monitor")
	if err != nil {
		log.Fatalf("error parsing flags and loading config: %v", err)
	}

	if err != nil {
		log.Fatal(err)
	}

	tufClient, err := getTUFClient(flags)
	if err != nil {
		log.Fatal(err)
	}

	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		log.Fatal(err)
	}
	signingConfig, err := root.GetSigningConfig(tufClient)
	if err != nil {
		log.Fatal(err)
	}

	allRekorServices := signingConfig.RekorLogURLs()
	rekorVersion := getRekorVersion(allRekorServices, flags.ServerURL)
	if flags.LogInfoFile == "" {
		logInfoFileName := fmt.Sprintf("%s.v%d.txt", logInfoFileNamePrefix, rekorVersion)
		flags.LogInfoFile = logInfoFileName
	}
	switch rekorVersion {
	case 1:
		mainLoopV1(flags, config, trustedRoot)
	case 2:
		fmt.Fprintf(os.Stderr, "Warning: the monitor currently only checks for the consistency of the log in Rekor v2 logs.\n")
		rekorShards, latestShardOrigin, err := rekor_v2.GetRekorShards(context.Background(), trustedRoot, allRekorServices, flags.UserAgent)
		if err != nil {
			log.Fatal(err)
		}
		mainLoopV2(tufClient, flags, config, rekorShards, latestShardOrigin)
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
	rekorV1MonitorLogic := RekorV1MonitorLogic{
		rekorClient:     rekorClient,
		verifier:        verifier,
		flags:           flags,
		config:          config,
		monitoredValues: monitoredValues,
	}
	cmd.MonitorLoop(rekorV1MonitorLogic)
}

func mainLoopV2(tufClient *tuf.Client, flags *cmd.MonitorFlags, config *notifications.IdentityMonitorConfiguration, rekorShards map[string]rekor_v2.ShardInfo, latestShardOrigin string) {
	rekorV2MonitorLogic := RekorV2MonitorLogic{
		tufClient:         tufClient,
		flags:             flags,
		config:            config,
		rekorShards:       rekorShards,
		latestShardOrigin: latestShardOrigin,
		monitoredValues:   identity.MonitoredValues{},
	}
	cmd.MonitorLoop(rekorV2MonitorLogic)
}
