//
// Copyright 2024 The Sigstore Authors.
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
	"net/http"
	"os"
	"strings"
	"time"

	ctgo "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/sigstore/rekor-monitor/pkg/ct"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/notifications"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"gopkg.in/yaml.v2"
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
	configFilePath := flag.String("config-file", "", "path to yaml configuration file containing identity monitor settings")
	configYamlInput := flag.String("config", "", "path to yaml configuration file containing identity monitor settings")
	once := flag.Bool("once", true, "whether to run the monitor on a repeated interval or once")
	serverURL := flag.String("url", publicRekorServerURL, "URL to the rekor server that is to be monitored")
	interval := flag.Duration("interval", 5*time.Minute, "Length of interval between each periodical consistency check")
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

	var fulcioClient *ctclient.LogClient
	fulcioClient, err := ctclient.New(*serverURL, http.DefaultClient, jsonclient.Options{})
	if err != nil {
		log.Fatalf("getting Fulcio client: %v", err)
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

		var currentSTH *ctgo.SignedTreeHead
		if config.StartIndex == nil || config.EndIndex == nil {
			currentSTH, err = fulcioClient.GetSTH(context.Background())
			if err != nil {
				fmt.Fprintf(os.Stderr, "error getting signed tree head: %v", err)
				return
			}
		}

		if config.StartIndex == nil {
			if config.LogInfoFile != "" {
				var prevSTH *ctgo.SignedTreeHead
				prevSTH, err = file.ReadLatestCTSignedTreeHead(config.LogInfoFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "reading checkpoint log: %v", err)
					return
				}

				checkpointStartIndex := int(prevSTH.TreeSize) //nolint: gosec // G115, log will never be large enough to overflow
				config.StartIndex = &checkpointStartIndex
			} else {
				defaultStartIndex := 0
				config.StartIndex = &defaultStartIndex
			}
		}

		if config.EndIndex == nil {
			checkpointEndIndex := int(currentSTH.TreeSize) //nolint: gosec // G115
			config.EndIndex = &checkpointEndIndex
		}

		if *config.StartIndex >= *config.EndIndex {
			fmt.Fprintf(os.Stderr, "start index %d must be strictly less than end index %d", *config.StartIndex, *config.EndIndex)
		}

		_, err = ct.IdentitySearch(fulcioClient, *config.StartIndex, *config.EndIndex, monitoredValues)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to successfully complete identity search: %v", err)
			return
		}

		err = ct.RunConsistencyCheck(fulcioClient, config.LogInfoFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to successfully complete consistency check: %v", err)
			return
		}

		if *once || inputEndIndex != nil {
			return
		}

		config.StartIndex = config.EndIndex
		config.EndIndex = nil
	}

}
