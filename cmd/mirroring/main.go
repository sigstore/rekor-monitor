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
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/mirroring"
	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/rekor/pkg/verify"
)

// Default values for mirroring job parameters
const (
	publicRekorServerURL = "https://rekor.sigstore.dev"
	logInfoFileName      = "logInfo.txt"
)

// readLatestCheckpoint reads the most recent signed checkpoint
// from the log file.
func readLatestCheckpoint(logInfoFile string) (*util.SignedCheckpoint, error) {
	// Each line in the file is one signed checkpoint
	file, err := os.Open(logInfoFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read line by line and get the last line
	scanner := bufio.NewScanner(file)
	line := ""
	for scanner.Scan() {
		line = scanner.Text()
	}

	sth := util.SignedCheckpoint{}
	if err := sth.UnmarshalText([]byte(strings.ReplaceAll(line, "\\n", "\n"))); err != nil {
		return nil, err
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &sth, nil
}

// deleteOldCheckpoints persists the latest 100 checkpoints. This expects that the log file
// is not being concurrently written to.
func deleteOldCheckpoints(logInfoFile string) error {
	// read all lines from file
	file, err := os.Open(logInfoFile)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	// exit early if there aren't checkpoints to truncate
	if len(lines) <= 100 {
		return nil
	}

	// open file again to overwrite
	file, err = os.OpenFile(logInfoFile, os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	for i := len(lines) - 100; i < len(lines); i++ {
		if _, err := file.WriteString(fmt.Sprintf("%s\n", lines[i])); err != nil {
			return err
		}
	}

	return nil
}

// This main function performs a periodic root hash consistency check.
// Upon starting, any existing latest snapshot data is loaded and the function runs
// indefinitely to perform consistency check for every time interval that was specified.
func main() {
	// Command-line flags that are parameters to the mirroring job
	serverURL := flag.String("url", publicRekorServerURL, "URL to the rekor server that is to be monitored")
	interval := flag.Duration("interval", 5*time.Minute, "Length of interval between each periodical consistency check")
	logInfoFile := flag.String("file", logInfoFileName, "Name of the file containing initial merkle tree information")
	once := flag.Bool("once", false, "Perform consistency check once and exit")
	flag.Parse()

	rekorClient, err := client.GetRekorClient(*serverURL)
	if err != nil {
		log.Fatalf("Getting Rekor client: %v", err)
	}

	var sth *util.SignedCheckpoint
	var first bool

	// TODO: Change order of operations:
	// * Fetch latest STH and verify
	// * If old STH is present, very consistency proof
	// * Write new STH to log

	_, err = os.Stat(*logInfoFile)
	switch {
	case err == nil:
		// File containing previous checkpoints exists
		sth, err = readLatestCheckpoint(*logInfoFile)
		if err != nil {
			log.Fatalf("Reading log info: %v", err)
		}
	case errors.Is(err, fs.ErrNotExist):
		// No old snapshot data available, get latest checkpoint
		logInfo, err := mirroring.GetLogInfo(rekorClient)
		if err != nil {
			log.Fatalf("Getting log info: %v", err)
		}
		sth = &util.SignedCheckpoint{}
		if err := sth.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
			log.Fatalf("unmarshalling logInfo.SignedTreeHead to Checkpoint: %v", err)
		}
		first = true
	default:
		// Any other errors reading the file
		log.Fatalf("reading %q: %v", *logInfoFile, err)
	}

	// TODO: Verify using public key from TUF
	pemPubKey, err := mirroring.GetPublicKey(rekorClient)
	if err != nil {
		log.Fatalf("getting public key: %v", err)
	}
	verifier, err := mirroring.LoadVerifier(pemPubKey)
	if err != nil {
		log.Fatal(err)
	}

	// Verify the checkpoint with the server's public key
	if !sth.Verify(verifier) {
		log.Fatalf("verifying checkpoint (size %d, hash %s) failed", sth.Size, hex.EncodeToString(sth.Hash))
	}
	log.Printf("Current checkpoint verified - Tree Size: %d Root Hash: %s\n", sth.Size, hex.EncodeToString(sth.Hash))

	// If this is the very first snapshot within the monitor, save the snapshot
	if first {
		s, err := sth.SignedNote.MarshalText()
		if err != nil {
			log.Fatalf("failed to marshal checkpoint: %v", err)
		}

		// Open file to create new snapshot
		file, err := os.OpenFile(*logInfoFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			file.Close()
			log.Fatalf("failed to open log file: %v", err)
		}

		// Replace newlines to flatten checkpoint to single line
		if _, err := file.WriteString(fmt.Sprintf("%s\n", strings.ReplaceAll(string(s), "\n", "\\n"))); err != nil {
			file.Close()
			log.Fatalf("failed to write to file: %v", err)
		}
		file.Close()
	}

	for {
		// Check for root hash consistency
		newSTH, err := verify.VerifyCurrentCheckpoint(context.Background(), rekorClient, verifier, sth)
		if err != nil {
			log.Fatalf("failed to verify log consistency: %v", err)
		} else {
			log.Printf("Root hash consistency verified - Tree Size: %d Root Hash: %s\n", newSTH.Size, hex.EncodeToString(newSTH.Hash))
		}

		// Append new, consistency-checked snapshot
		if newSTH.Size != sth.Size {
			s, err := newSTH.SignedNote.MarshalText()
			if err != nil {
				log.Fatalf("failed to marshal STH: %v", err)
			}

			// Open file to append new snapshot
			file, err := os.OpenFile(*logInfoFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				file.Close()
				log.Fatalf("failed to open log file: %v", err)
			}

			// Replace newlines to flatten checkpoint to single line
			if _, err := file.WriteString(fmt.Sprintf("%s\n", strings.ReplaceAll(string(s), "\n", "\\n"))); err != nil {
				file.Close()
				log.Fatalf("failed to write to file: %v", err)
			}
			file.Close()

			sth = newSTH
		}

		// TODO: Switch to writing checkpoints to GitHub so that the history is preserved. Then we only need
		// to persist the last checkpoint.
		// Delete old checkpoints to avoid the log growing indefinitely
		if err := deleteOldCheckpoints(*logInfoFile); err != nil {
			log.Fatalf("failed to delete old checkpoints: %v", err)
		}

		if *once {
			return
		}
		time.Sleep(*interval)
	}
}
