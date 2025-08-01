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
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/notifications"
	rekor_v1 "github.com/sigstore/rekor-monitor/pkg/rekor/v1"
	rekor_v2 "github.com/sigstore/rekor-monitor/pkg/rekor/v2"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"gopkg.in/yaml.v2"
	"sigs.k8s.io/release-utils/version"
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
	// Command-line flags that are parameters to the verifier job
	configFilePath := flag.String("config-file", "", "path to yaml configuration file containing identity monitor settings")
	configYamlInput := flag.String("config", "", "string with YAML configuration containing identity monitor settings")
	once := flag.Bool("once", true, "whether to run the monitor on a repeated interval or once")
	serverURL := flag.String("url", publicRekorServerURL, "URL to the rekor server that is to be monitored")
	logInfoFile := flag.String("file", "", "path to the initial log info checkpoint file to be read from")
	interval := flag.Duration("interval", 5*time.Minute, "Length of interval between each periodical consistency check")
	userAgentString := flag.String("user-agent", "", "details to include in the user agent string")
	tufRepository := flag.String("tuf-repository", TUFRepository, "TUF repository to use. Can be 'default' or 'staging'")
	flag.Parse()

	var config notifications.IdentityMonitorConfiguration

	if *configFilePath != "" && *configYamlInput != "" {
		log.Fatalf("error: only one of --config and --config-file should be specified")
	}

	if *configFilePath != "" {
		readConfig, err := os.ReadFile(*configFilePath)
		if err != nil {
			log.Fatalf("error reading from identity monitor configuration file: %v", err)
		}

		configString := string(readConfig)
		if err := yaml.Unmarshal([]byte(configString), &config); err != nil {
			log.Fatalf("error parsing identities: %v", err)
		}
	}

	if *configYamlInput != "" {
		if err := yaml.Unmarshal([]byte(*configYamlInput), &config); err != nil {
			log.Fatalf("error parsing identities: %v", err)
		}
	}

	if config.OutputIdentitiesFile == "" {
		config.OutputIdentitiesFile = outputIdentitiesFileName
	}

	var tufClient *tuf.Client
	var err error
	switch *tufRepository {
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
		if *serverURL == service.URL {
			rekorVersion = service.MajorAPIVersion
		}
	}
	if *logInfoFile == "" {
		logInfoFileName := fmt.Sprintf("%s.v%d.txt", logInfoFileNamePrefix, rekorVersion)
		logInfoFile = &logInfoFileName
	}
	switch rekorVersion {
	case 1:
		mainLoopV1(*serverURL, *once, *logInfoFile, *interval, *userAgentString, config, trustedRoot)
		return
	case 2:
		fmt.Fprintf(os.Stderr, "Warning: the monitor currently only checks for the consistency of the log in Rekor v2 logs.\n")
		userAgent := strings.TrimSpace(fmt.Sprintf("rekor-monitor/%s (%s; %s) %s", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH, *userAgentString))
		rekorShards, activeShardOrigin, err := rekor_v2.GetRekorShards(context.Background(), trustedRoot, allRekorServices, userAgent)
		if err != nil {
			log.Fatal(err)
		}
		mainLoopV2(*once, *logInfoFile, *interval, rekorShards, activeShardOrigin)
		return
	default:
		log.Fatalf("Unsupported server version %v, only '1' and '2' are supported", rekorVersion)
	}
}

func mainLoopV1(serverURL string, once bool, logInfoFile string, interval time.Duration, userAgentString string, config notifications.IdentityMonitorConfiguration, trustedRoot *root.TrustedRoot) {
	rekorClient, err := client.GetRekorClient(serverURL, client.WithUserAgent(strings.TrimSpace(fmt.Sprintf("rekor-monitor/%s (%s; %s) %s", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH, userAgentString))))
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

	for _, certID := range monitoredValues.CertificateIdentities {
		if len(certID.Issuers) == 0 {
			fmt.Printf("Monitoring certificate subject %s\n", certID.CertSubject)
		} else {
			fmt.Printf("Monitoring certificate subject %s for issuer(s) %s\n", certID.CertSubject, strings.Join(certID.Issuers, ","))
		}
	}
	for _, fp := range monitoredValues.Fingerprints {
		fmt.Printf("Monitoring fingerprint %s\n", fp)
	}
	for _, sub := range monitoredValues.Subjects {
		fmt.Printf("Monitoring subject %s\n", sub)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// To get an immediate first tick, for-select is at the end of the loop
	for {
		inputEndIndex := config.EndIndex

		// TODO: Handle Rekor sharding
		// https://github.com/sigstore/rekor-monitor/issues/57
		var logInfo *models.LogInfo
		var prevCheckpoint *util.SignedCheckpoint
		prevCheckpoint, logInfo, err = rekor_v1.RunConsistencyCheck(rekorClient, verifier, logInfoFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error running consistency check: %v", err)
			return
		}

		if config.StartIndex == nil {
			if prevCheckpoint != nil {
				checkpointStartIndex := rekor_v1.GetCheckpointIndex(logInfo, prevCheckpoint)
				config.StartIndex = &checkpointStartIndex
			} else {
				fmt.Fprintf(os.Stderr, "no start index set and no log checkpoint")
				return
			}
		}

		if config.EndIndex == nil {
			checkpoint, err := rekor_v1.ReadLatestCheckpoint(logInfo)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading checkpoint: %v", err)
				return
			}

			checkpointEndIndex := rekor_v1.GetCheckpointIndex(logInfo, checkpoint)
			config.EndIndex = &checkpointEndIndex
		}

		if *config.StartIndex >= *config.EndIndex {
			fmt.Fprintf(os.Stderr, "start index %d must be strictly less than end index %d", *config.StartIndex, *config.EndIndex)
			return
		}

		if identity.MonitoredValuesExist(monitoredValues) {
			_, err = rekor_v1.IdentitySearch(*config.StartIndex, *config.EndIndex, rekorClient, monitoredValues, config.OutputIdentitiesFile, config.IdentityMetadataFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to successfully complete identity search: %v", err)
				return
			}
		}

		if once || inputEndIndex != nil {
			return
		}

		config.StartIndex = config.EndIndex
		config.EndIndex = nil

		select {
		case <-ticker.C:
			continue
		case <-signalChan:
			fmt.Fprintf(os.Stderr, "received signal, exiting")
			return
		}
	}
}

func mainLoopV2(once bool, logInfoFile string, interval time.Duration, rekorShards map[string]rekor_v2.ShardInfo, activeShardOrigin string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// To get an immediate first tick, for-select is at the end of the loop
	for {
		_, err := rekor_v2.RunConsistencyCheck(context.Background(), rekorShards, activeShardOrigin, logInfoFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error running consistency check: %v", err)
			return
		}

		if once {
			return
		}

		select {
		case <-ticker.C:
			continue
		case <-signalChan:
			fmt.Fprintf(os.Stderr, "received signal, exiting")
			return
		}
	}
}
