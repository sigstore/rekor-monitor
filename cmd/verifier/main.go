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
	"github.com/sigstore/rekor/pkg/client"
	"gopkg.in/yaml.v2"

	"sigs.k8s.io/release-utils/version"
)

// Default values for monitoring job parameters
const (
	publicRekorServerURL     = "https://rekor.sigstore.dev"
	logInfoFileName          = "logInfo.txt"
	outputIdentitiesFileName = "identities.txt"
)

// This main function performs a periodic root hash consistency check.
// Upon starting, any existing latest snapshot data is loaded and the function runs
// indefinitely to perform consistency check for every time interval that was specified.
func main() {
	// Command-line flags that are parameters to the verifier job
	configFilePath := flag.String("config-file", "", "Name of the file containing the consistency check workflow configuration settings")
	configString := flag.String("config-string", "", "Consistency check workflow configuration settings input as a string")
	once := flag.Bool("once", false, "Perform consistency check once and exit")
	flag.Parse()

	if configFilePath == nil && configString == nil {
		log.Fatalf("empty configuration input")
	}

	if configFilePath != nil && configString != nil {
		log.Fatalf("only input one of --config-file or --config-string")
	}

	var config ConsistencyCheckConfiguration
	if configString != nil {
		if err := yaml.Unmarshal([]byte(*configString), &config); err != nil {
			log.Fatalf("error parsing identities: %v", err)
		}
	}

	if configFilePath != nil {
		readConfig, err := os.ReadFile(*configFilePath)
		if err != nil {
			log.Fatalf("error reading from identity monitor configuration file: %v", err)
		}
		if err := yaml.Unmarshal([]byte(readConfig), &config); err != nil {
			log.Fatalf("error parsing identities: %v", err)
		}
	}

	if config.ServerURL == "" {
		config.ServerURL = publicRekorServerURL
	}
	if config.Interval == nil {
		defaultInterval := time.Hour
		config.Interval = &defaultInterval
	}
	if config.LogInfoFile == "" {
		config.LogInfoFile = logInfoFileName
	}

	rekorClient, err := client.GetRekorClient(config.ServerURL, client.WithUserAgent(strings.TrimSpace(fmt.Sprintf("rekor-monitor/%s (%s; %s) %s", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH, config.UserAgentString))))
	if err != nil {
		log.Fatalf("getting Rekor client: %v", err)
	}

	verifier, err := rekor.GetLogVerifier(context.Background(), rekorClient)
	if err != nil {
		log.Fatal(err)
	}

	err = rekor.VerifyConsistencyCheckInputs(config.Interval, &config.LogInfoFile, once)
	if err != nil {
		log.Fatal(err)
	}

	ticker := time.NewTicker(*config.Interval)
	defer ticker.Stop()

	// Loop will:
	// 1. Fetch latest checkpoint and verify
	// 2. If old checkpoint is present, verify consistency proof
	// 3. Write latest checkpoint to file

	// To get an immediate first tick
	for ; ; <-ticker.C {
		err = rekor.RunConsistencyCheck(rekorClient, verifier, config.LogInfoFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error running consistency check: %v", err)
			return
		}

		if *once {
			return
		}
	}
}
