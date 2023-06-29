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
	"bufio"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/rekor"
	file "github.com/sigstore/rekor-monitor/pkg/util"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/rekor/pkg/verify"
)

// Default values for monitoring job parameters
const (
	publicRekorServerURL     = "https://rekor.sigstore.dev"
	logInfoFileName          = "logInfo.txt"
	outputIdentitiesFileName = "identities.txt"
)

func parseIdentities(identitiesInput string) (rekor.Identities, error) {
	ids := rekor.Identities{}
	scanner := bufio.NewScanner(strings.NewReader(identitiesInput))
	for scanner.Scan() {
		l := strings.Fields(scanner.Text())
		switch len(l) {
		case 0:
			continue
		case 1:
			ids.Identities = append(ids.Identities, rekor.Identity{Subject: l[0]})
		default:
			ids.Identities = append(ids.Identities, rekor.Identity{Subject: l[0], Issuers: l[1:]})
		}
	}
	if err := scanner.Err(); err != nil {
		return ids, err
	}
	return ids, nil
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
	identitiesInput := flag.String("identities", "", "newline-separated list of identities and issuers in the format "+
		"subject [issuer...]. If no issuers are specified, match any OIDC providers.")
	outputIdentitiesFile := flag.String("output-identities", outputIdentitiesFileName,
		"Name of the file containing indices and identities found in the log. Format is \"subject issuer index uuid\"")
	flag.Parse()

	ids, err := parseIdentities(*identitiesInput)
	if err != nil {
		log.Fatalf("error parsing identities: %v", err)
	}
	for _, id := range ids.Identities {
		if len(id.Issuers) == 0 {
			fmt.Printf("Monitoring subject %s\n", id.Subject)
		} else {
			fmt.Printf("Monitoring subject %s for issuer(s) %s\n", id.Subject, strings.Join(id.Issuers, ","))
		}
	}

	rekorClient, err := client.GetRekorClient(*serverURL)
	if err != nil {
		log.Fatalf("getting Rekor client: %v", err)
	}

	verifier, err := rekor.GetLogVerifier(context.Background(), rekorClient)
	if err != nil {
		log.Fatal(err)
	}

	// Loop will:
	// 1. Fetch latest checkpoint and verify
	// 2. If old checkpoint is present, verify consistency proof
	// 3. Write latest checkpoint to file
	for {
		logInfo, err := rekor.GetLogInfo(context.Background(), rekorClient)
		if err != nil {
			log.Fatalf("Getting log info: %v", err)
		}
		checkpoint := &util.SignedCheckpoint{}
		if err := checkpoint.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
			log.Fatalf("unmarshalling logInfo.SignedTreeHead to Checkpoint: %v", err)
		}
		if !checkpoint.Verify(verifier) {
			log.Fatalf("verifying checkpoint (size %d, hash %s) failed", checkpoint.Size, hex.EncodeToString(checkpoint.Hash))
		}

		fi, err := os.Stat(*logInfoFile)
		var prevCheckpoint *util.SignedCheckpoint
		if err == nil && fi.Size() != 0 {
			// File containing previous checkpoints exists
			prevCheckpoint, err = file.ReadLatestCheckpoint(*logInfoFile)
			if err != nil {
				log.Fatalf("reading checkpoint log: %v", err)
			}
			if !prevCheckpoint.Verify(verifier) {
				log.Fatalf("verifying checkpoint (size %d, hash %s) failed", checkpoint.Size, hex.EncodeToString(checkpoint.Hash))
			}
		}
		if prevCheckpoint != nil {
			if err := verify.ProveConsistency(context.Background(), rekorClient, prevCheckpoint, checkpoint, *logInfo.TreeID); err != nil {
				log.Fatalf("failed to verify log consistency: %v", err)
			}
			fmt.Fprintf(os.Stderr, "Root hash consistency verified - Current Size: %d Root Hash: %s - Previous Size: %d Root Hash %s\n",
				checkpoint.Size, hex.EncodeToString(checkpoint.Hash), prevCheckpoint.Size, hex.EncodeToString(prevCheckpoint.Hash))
		}

		// Write if there was no stored checkpoint or the sizes differ
		if prevCheckpoint == nil || prevCheckpoint.Size != checkpoint.Size {
			if err := file.WriteCheckpoint(checkpoint, *logInfoFile); err != nil {
				log.Fatalf("failed to write checkpoint: %v", err)
			}
		}

		// TODO: Switch to writing checkpoints to GitHub so that the history is preserved. Then we only need
		// to persist the last checkpoint.
		// Delete old checkpoints to avoid the log growing indefinitely
		if err := file.DeleteOldCheckpoints(*logInfoFile); err != nil {
			log.Fatalf("failed to delete old checkpoints: %v", err)
		}

		// Look for identities if there was a previous, different checkpoint
		if prevCheckpoint != nil && prevCheckpoint.Size != checkpoint.Size {
			// Get log size of inactive shards
			totalSize := 0
			for _, s := range logInfo.InactiveShards {
				totalSize += int(*s.TreeSize)
			}
			startIndex := int(prevCheckpoint.Size) + totalSize - 1
			endIndex := int(checkpoint.Size) + totalSize - 1

			// Search for identities in the log range
			if len(ids.Identities) > 0 {
				entries, err := rekor.GetEntriesByIndexRange(context.Background(), rekorClient, startIndex, endIndex)
				if err != nil {
					log.Fatalf("error getting entries by index range: %v", err)
				}
				idEntries, err := rekor.MatchedIndices(entries, ids)
				if err != nil {
					log.Fatalf("error finding log indices: %v", err)
				}

				if len(idEntries) > 0 {
					for _, idEntry := range idEntries {
						fmt.Fprintf(os.Stderr, "Found subject %s, issuer %s at log index %d, uuid %s\n",
							idEntry.Subject, idEntry.Issuer, idEntry.Index, idEntry.UUID)

						if err := file.WriteIdentity(*outputIdentitiesFile, idEntry); err != nil {
							log.Fatalf("failed to write identity: %v", err)
						}
					}
				}
			}
		}

		if *once {
			return
		}
		time.Sleep(*interval)
	}
}
