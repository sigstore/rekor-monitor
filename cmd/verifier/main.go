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
	"runtime"
	"strings"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/rekor"
	"github.com/sigstore/rekor/pkg/client"
	"gopkg.in/yaml.v3"

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
	serverURL := flag.String("url", publicRekorServerURL, "URL to the rekor server that is to be monitored")
	interval := flag.Duration("interval", 5*time.Minute, "Length of interval between each periodical consistency check")
	logInfoFile := flag.String("file", logInfoFileName, "Name of the file containing initial merkle tree information")
	once := flag.Bool("once", false, "Perform consistency check once and exit")
	monitoredValsInput := flag.String("monitored-values", "", "yaml of certificate subjects and issuers, key subjects, "+
		"and fingerprints. For certificates, if no issuers are specified, match any OIDC provider.")
	outputIdentitiesFile := flag.String("output-identities", outputIdentitiesFileName,
		"Name of the file containing indices and identities found in the log. Format is \"subject issuer index uuid\"")
	userAgentString := flag.String("user-agent", "", "details to include in the user agent string")
	flag.Parse()

	var monitoredVals identity.MonitoredValues
	if err := yaml.Unmarshal([]byte(*monitoredValsInput), &monitoredVals); err != nil {
		log.Fatalf("error parsing identities: %v", err)
	}
	for _, certID := range monitoredVals.CertificateIdentities {
		if len(certID.Issuers) == 0 {
			fmt.Printf("Monitoring certificate subject %s\n", certID.CertSubject)
		} else {
			fmt.Printf("Monitoring certificate subject %s for issuer(s) %s\n", certID.CertSubject, strings.Join(certID.Issuers, ","))
		}
	}
	for _, fp := range monitoredVals.Fingerprints {
		fmt.Printf("Monitoring fingerprint %s\n", fp)
	}
	for _, sub := range monitoredVals.Subjects {
		fmt.Printf("Monitoring subject %s\n", sub)
	}

	rekorClient, err := client.GetRekorClient(*serverURL, client.WithUserAgent(strings.TrimSpace(fmt.Sprintf("rekor-monitor/%s (%s; %s) %s", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH, *userAgentString))))
	if err != nil {
		log.Fatalf("getting Rekor client: %v", err)
	}

	verifier, err := rekor.GetLogVerifier(context.Background(), rekorClient)
	if err != nil {
		log.Fatal(err)
	}

	err = rekor.RunConsistencyCheck(interval, rekorClient, verifier, logInfoFile, monitoredVals, outputIdentitiesFile, once)
	if err != nil {
		log.Fatalf("%v", err)
	}
}
