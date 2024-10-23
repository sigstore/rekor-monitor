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
	"runtime"
	"strings"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/rekor"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/util"
	"gopkg.in/yaml.v2"
	"sigs.k8s.io/release-utils/version"
)

// Default values for monitoring job parameters
const (
	publicRekorServerURL     = "https://rekor.sigstore.dev"
	logInfoFileName          = "logInfo.txt"
	outputIdentitiesFileName = "identities.txt"
)

// This main function performs a periodic identity search.
// Upon starting, any existing latest snapshot data is loaded and the function runs
// indefinitely to perform identity search for every time interval that was specified.
func main() {
	// Command-line flags that are parameters to the verifier job
	configFilePath := flag.String("config-file", "", "path to yaml configuration file containing identity monitor settings")
	once := flag.Bool("once", true, "whether to run the monitor on a repeated interval or once")
	flag.Parse()

	if configFilePath == nil {
		log.Fatalf("empty configuration file path")
	}

	readConfig, err := os.ReadFile(*configFilePath)
	if err != nil {
		log.Fatalf("error reading from identity monitor configuration file: %v", err)
	}

	configString := string(readConfig)
	var config IdentityMonitorConfiguration
	if err := yaml.Unmarshal([]byte(configString), &config); err != nil {
		log.Fatalf("error parsing identities: %v", err)
	}

	rekorClient, err := client.GetRekorClient(config.ServerURL, client.WithUserAgent(strings.TrimSpace(fmt.Sprintf("rekor-monitor/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH))))
	if err != nil {
		log.Fatalf("getting Rekor client: %v", err)
	}

	if config.ServerURL == "" {
		config.ServerURL = publicRekorServerURL
	}
	if config.LogInfoFile == "" {
		config.LogInfoFile = logInfoFileName
	}
	if config.OutputIdentitiesFile == "" {
		config.OutputIdentitiesFile = outputIdentitiesFileName
	}
	if config.Interval == nil {
		defaultInterval := time.Hour
		config.Interval = &defaultInterval
	}

	ticker := time.NewTicker(*config.Interval)
	defer ticker.Stop()

	// To get an immediate first tick
	for ; ; <-ticker.C {
		inputEndIndex := config.EndIndex
		if config.StartIndex == nil || config.EndIndex == nil {
			logInfo, err := rekor.GetLogInfo(context.Background(), rekorClient)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error getting log info: %v", err)
				return
			}

			checkpoint, err := rekor.ReadLatestCheckpoint(logInfo)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading checkpoint: %v", err)
				return
			}

			var prevCheckpoint *util.SignedCheckpoint
			prevCheckpoint, err = file.ReadLatestCheckpoint(config.LogInfoFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "reading checkpoint log: %v", err)
				return
			}

			checkpointStartIndex, checkpointEndIndex := rekor.GetCheckpointIndices(logInfo, prevCheckpoint, checkpoint)
			if config.StartIndex == nil {
				config.StartIndex = &checkpointStartIndex
			}
			if config.EndIndex == nil {
				config.EndIndex = &checkpointEndIndex
			}
		}

		if *config.StartIndex >= *config.EndIndex {
			fmt.Fprintf(os.Stderr, "start index %d must be strictly less than end index %d", *config.StartIndex, *config.EndIndex)
		}

		// TODO: This should subsequently read from the identity metadata file to fetch the latest index.
		err := rekor.IdentitySearch(*config.StartIndex, *config.EndIndex, rekorClient, config.MonitoredValues, config.OutputIdentitiesFile, config.IdentityMetadataFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to successfully complete identity search: %v", err)
			return
		}

		if *once || inputEndIndex != nil {
			return
		}

		config.StartIndex = config.EndIndex
		config.EndIndex = nil
	}
}
