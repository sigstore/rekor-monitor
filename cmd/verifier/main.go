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
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/rekor"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/rekor/pkg/client"
	gclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"gopkg.in/yaml.v3"

	"sigs.k8s.io/release-utils/version"
)

// Default values for monitoring job parameters
const (
	publicRekorServerURL     = "https://rekor.sigstore.dev"
	logInfoFileName          = "logInfo.txt"
	outputIdentitiesFileName = "identities.txt"
)

// runConsistencyCheck periodically verifies the root hash consistency of a Rekor log.
func RunConsistencyCheck(interval *time.Duration, rekorClient *gclient.Rekor, verifier signature.Verifier, logInfoFile *string, mvs identity.MonitoredValues, outputIdentitiesFile *string, once *bool) error {
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	// Loop will:
	// 1. Fetch latest checkpoint and verify
	// 2. If old checkpoint is present, verify consistency proof
	// 3. Write latest checkpoint to file

	// To get an immediate first tick
	for ; ; <-ticker.C {
		logInfo, err := rekor.GetLogInfo(context.Background(), rekorClient)
		if err != nil {
			return fmt.Errorf("getting log info: %v", err)
		}
		checkpoint := &util.SignedCheckpoint{}
		if err := checkpoint.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
			return fmt.Errorf("unmarshalling logInfo.SignedTreeHead to Checkpoint: %v", err)
		}
		if !checkpoint.Verify(verifier) {
			return fmt.Errorf("verifying checkpoint (size %d, hash %s) failed", checkpoint.Size, hex.EncodeToString(checkpoint.Hash))
		}

		fi, err := os.Stat(*logInfoFile)
		var prevCheckpoint *util.SignedCheckpoint
		if err == nil && fi.Size() != 0 {
			// File containing previous checkpoints exists
			prevCheckpoint, err = file.ReadLatestCheckpoint(*logInfoFile)
			if err != nil {
				return fmt.Errorf("reading checkpoint log: %v", err)
			}
			if !prevCheckpoint.Verify(verifier) {
				return fmt.Errorf("verifying checkpoint (size %d, hash %s) failed", checkpoint.Size, hex.EncodeToString(checkpoint.Hash))
			}
		}
		if prevCheckpoint != nil {
			if err := verify.ProveConsistency(context.Background(), rekorClient, prevCheckpoint, checkpoint, *logInfo.TreeID); err != nil {
				return fmt.Errorf("failed to verify log consistency: %v", err)
			}
			fmt.Fprintf(os.Stderr, "Root hash consistency verified - Current Size: %d Root Hash: %s - Previous Size: %d Root Hash %s\n",
				checkpoint.Size, hex.EncodeToString(checkpoint.Hash), prevCheckpoint.Size, hex.EncodeToString(prevCheckpoint.Hash))
		}

		// Write if there was no stored checkpoint or the sizes differ
		if prevCheckpoint == nil || prevCheckpoint.Size != checkpoint.Size {
			if err := file.WriteCheckpoint(checkpoint, *logInfoFile); err != nil {
				return fmt.Errorf("failed to write checkpoint: %v", err)
			}
		}

		// TODO: Switch to writing checkpoints to GitHub so that the history is preserved. Then we only need
		// to persist the last checkpoint.
		// Delete old checkpoints to avoid the log growing indefinitely
		if err := file.DeleteOldCheckpoints(*logInfoFile); err != nil {
			return fmt.Errorf("failed to delete old checkpoints: %v", err)
		}

		// Look for identities if there was a previous, different checkpoint
		if prevCheckpoint != nil && prevCheckpoint.Size != checkpoint.Size {
			// Get log size of inactive shards
			totalSize := 0
			for _, s := range logInfo.InactiveShards {
				totalSize += int(*s.TreeSize)
			}
			startIndex := int(prevCheckpoint.Size) + totalSize - 1 //nolint: gosec // G115, log will never be large enough to overflow
			endIndex := int(checkpoint.Size) + totalSize - 1       //nolint: gosec // G115

			// Search for identities in the log range
			if len(mvs.CertificateIdentities) > 0 || len(mvs.Fingerprints) > 0 || len(mvs.Subjects) > 0 {
				entries, err := rekor.GetEntriesByIndexRange(context.Background(), rekorClient, startIndex, endIndex)
				if err != nil {
					return fmt.Errorf("error getting entries by index range: %v", err)
				}
				idEntries, err := rekor.MatchedIndices(entries, mvs)
				if err != nil {
					return fmt.Errorf("error finding log indices: %v", err)
				}

				if len(idEntries) > 0 {
					for _, idEntry := range idEntries {
						fmt.Fprintf(os.Stderr, "Found %s\n", idEntry.String())

						if err := file.WriteIdentity(*outputIdentitiesFile, idEntry); err != nil {
							return fmt.Errorf("failed to write entry: %v", err)
						}
					}
				}
			}
		}

		if *once {
			return nil
		}
	}
}

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

	err = RunConsistencyCheck(interval, rekorClient, verifier, logInfoFile, monitoredVals, outputIdentitiesFile, once)
	if err != nil {
		log.Fatalf("%v", err)
	}
}
