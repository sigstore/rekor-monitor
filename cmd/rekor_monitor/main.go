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

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/notifications"
	"github.com/sigstore/rekor-monitor/pkg/rekor"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/util"
	"gopkg.in/yaml.v2"
	"sigs.k8s.io/release-utils/version"
)

// Default values for monitoring job parameters
const (
	publicRekorServerURL     = "https://rekor.sigstore.dev"
	outputIdentitiesFileName = "identities.txt"
	logInfoFileName          = "logInfo.txt"
)

// This main function performs a periodic identity search.
// Upon starting, any existing latest snapshot data is loaded and the function runs
// indefinitely to perform identity search for every time interval that was specified.
func main() {
	// Command-line flags that are parameters to the verifier job
	configFilePath := flag.String("config-file", "", "path to yaml configuration file containing identity monitor settings")
	configYamlInput := flag.String("config", "", "path to yaml configuration file containing identity monitor settings")
	once := flag.Bool("once", true, "whether to run the monitor on a repeated interval or once")
	serverURL := flag.String("url", publicRekorServerURL, "URL to the rekor server that is to be monitored")
	interval := flag.Duration("interval", 5*time.Minute, "Length of interval between each periodical consistency check")
	userAgentString := flag.String("user-agent", "", "details to include in the user agent string")
	flag.Parse()

	if *configFilePath == "" && *configYamlInput == "" {
		log.Fatalf("empty configuration input")
	}

	if *configFilePath != "" && *configYamlInput != "" {
		log.Fatalf("only input one of configuration file path or yaml input")
	}

	var config notifications.IdentityMonitorConfiguration

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

	err := rekor.VerifyConsistencyCheckInputs(interval, &config.LogInfoFile, once)
	if err != nil {
		log.Fatal(err)
	}

	rekorClient, err := client.GetRekorClient(*serverURL, client.WithUserAgent(strings.TrimSpace(fmt.Sprintf("rekor-monitor/%s (%s; %s) %s", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH, *userAgentString))))
	if err != nil {
		log.Fatalf("getting Rekor client: %v", err)
	}

	verifier, err := rekor.GetLogVerifier(context.Background(), rekorClient)
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

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	// To get an immediate first tick
	for ; ; <-ticker.C {
		inputEndIndex := config.EndIndex

		var logInfo *models.LogInfo
		if config.StartIndex == nil || config.EndIndex == nil {
			logInfo, err = rekor.GetLogInfo(context.Background(), rekorClient)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error getting log info: %v", err)
				return
			}
		}

		if config.StartIndex == nil {
			if config.LogInfoFile != "" {
				var prevCheckpoint *util.SignedCheckpoint
				prevCheckpoint, err = file.ReadLatestCheckpoint(config.LogInfoFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "reading checkpoint log: %v", err)
					return
				}

				checkpointStartIndex := rekor.GetCheckpointIndex(logInfo, prevCheckpoint)
				config.StartIndex = &checkpointStartIndex
			} else {
				defaultStartIndex := 0
				config.StartIndex = &defaultStartIndex
			}
		}

		if config.EndIndex == nil {

			checkpoint, err := rekor.ReadLatestCheckpoint(logInfo)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading checkpoint: %v", err)
				return
			}

			checkpointEndIndex := rekor.GetCheckpointIndex(logInfo, checkpoint)
			config.EndIndex = &checkpointEndIndex
		}

		if *config.StartIndex >= *config.EndIndex {
			fmt.Fprintf(os.Stderr, "start index %d must be strictly less than end index %d", *config.StartIndex, *config.EndIndex)
		}

		err = rekor.RunConsistencyCheck(rekorClient, verifier, config.LogInfoFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error running consistency check: %v", err)
			return
		}

		// TODO: This should subsequently read from the identity metadata file to fetch the latest index.
		_, err = rekor.IdentitySearch(*config.StartIndex, *config.EndIndex, rekorClient, monitoredValues, config.OutputIdentitiesFile, config.IdentityMetadataFile)
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
