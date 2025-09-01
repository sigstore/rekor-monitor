// Copyright 2023 The Sigstore Authors.
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

package file

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	ct "github.com/google/certificate-transparency-go"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/transparency-dev/formats/log"
)

type IdentityMetadata struct {
	LatestIndex int `json:"latestIndex"`
}

func (idMetadata IdentityMetadata) String() string {
	return fmt.Sprint(idMetadata.LatestIndex)
}

func readLastCheckpoint(logInfoFile string) (string, error) {
	// Each line in the file is one signed checkpoint
	file, err := os.Open(logInfoFile)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Read line by line and get the last line
	scanner := bufio.NewScanner(file)
	line := ""
	for scanner.Scan() {
		line = scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}
	return strings.ReplaceAll(line, "\\n", "\n"), nil
}

// ReadLatestCheckpoint reads the most recent signed checkpoint from the log file
func ReadLatestCheckpointRekorV1(logInfoFile string) (*util.SignedCheckpoint, error) {
	lastCheckpointString, err := readLastCheckpoint(logInfoFile)
	if err != nil {
		return nil, err
	}

	checkpoint := util.SignedCheckpoint{}
	if err := checkpoint.UnmarshalText([]byte(lastCheckpointString)); err != nil {
		return nil, err
	}

	return &checkpoint, nil
}

// ReadLatestCheckpoint reads the most recent checkpoint from the log file
func ReadLatestCheckpointRekorV2(logInfoFile string) (*log.Checkpoint, error) {
	lastCheckpointString, err := readLastCheckpoint(logInfoFile)
	if err != nil {
		return nil, err
	}

	checkpoint := log.Checkpoint{}
	_, err = checkpoint.Unmarshal([]byte(lastCheckpointString))
	if err != nil {
		return nil, err
	}

	return &checkpoint, nil
}

// ReadLatestCTSignedTreeHead reads the most recent signed tree head from the log file
func ReadLatestCTSignedTreeHead(logInfoFile string) (*ct.SignedTreeHead, error) {
	// Each line in the file is one signed tree head
	signedTreeHead, err := os.ReadFile(logInfoFile)
	if err != nil {
		return nil, err
	}

	var checkpoint ct.SignedTreeHead
	err = json.Unmarshal([]byte(strings.ReplaceAll(string(signedTreeHead), "\\n", "\n")), &checkpoint)
	if err != nil {
		return nil, err
	}

	return &checkpoint, nil
}

// WriteCTSignedTreeHead writes a signed tree head to a given log file
func WriteCTSignedTreeHead(sth *ct.SignedTreeHead, prev *ct.SignedTreeHead, logInfoFile string, force bool) error {
	if force || prev == nil || prev.TreeSize != sth.TreeSize {
		marshalledSTH, err := json.Marshal(sth)
		if err != nil {
			return err
		}

		if err := os.WriteFile(logInfoFile, []byte(fmt.Sprintf("%s\n", strings.ReplaceAll(string(marshalledSTH), "\n", "\\n"))), 0600); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}
	return nil
}

func writeCheckpointBytes(checkpoint []byte, logInfoFile string) error {
	// Open file to append new snapshot
	file, err := os.OpenFile(logInfoFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()
	// Replace newlines to flatten checkpoint to single line
	if _, err := fmt.Fprintf(file, "%s\n", strings.ReplaceAll(string(checkpoint), "\n", "\\n")); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	return nil
}

// WriteCheckpointRekorV1 writes a signed checkpoint to the log file
func WriteCheckpointRekorV1(checkpoint *util.SignedCheckpoint, prev *util.SignedCheckpoint, logInfoFile string, force bool) error {
	// Delete old checkpoints to avoid the log growing indefinitely
	if _, err := os.Stat(logInfoFile); err == nil {
		if err := DeleteOldCheckpoints(logInfoFile); err != nil {
			return fmt.Errorf("failed to delete old checkpoints: %v", err)
		}
	}

	// Write if there was no stored checkpoint or the sizes differ
	if force || prev == nil || prev.Size != checkpoint.Size {
		// Write latest checkpoint to file
		s, err := checkpoint.MarshalText()
		if err != nil {
			return fmt.Errorf("failed to marshal checkpoint: %w", err)
		}
		return writeCheckpointBytes(s, logInfoFile)
	}

	return nil
}

// WriteCheckpointRekorV2 writes a checkpoint to the log file
func WriteCheckpointRekorV2(checkpoint *log.Checkpoint, prev *log.Checkpoint, logInfoFile string, force bool) error {
	if force || prev == nil || prev.Origin != checkpoint.Origin || prev.Size != checkpoint.Size {
		// Write latest checkpoint to file
		s := checkpoint.Marshal()
		return writeCheckpointBytes(s, logInfoFile)
	}
	return nil
}

// DeleteOldCheckpoints persists the latest 100 checkpoints. This expects that the log file
// is not being concurrently written to
func DeleteOldCheckpoints(logInfoFile string) error {
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
		if _, err := fmt.Fprintf(file, "%s\n", lines[i]); err != nil {
			return err
		}
	}

	return nil
}

// WriteIdentity writes an identity found in the log to a file
func WriteIdentity(idFile string, idEntry identity.LogEntry) error {
	file, err := os.OpenFile(idFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open identities file: %w", err)
	}
	defer file.Close()

	if _, err := fmt.Fprintf(file, "%s\n", idEntry.String()); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}

// WriteIdentityMetadata writes information about what log indices have been scanned to a file
func WriteIdentityMetadata(metadataFile string, idMetadata IdentityMetadata) error {
	marshalled, err := json.Marshal(idMetadata)
	if err != nil {
		return fmt.Errorf("failed to marshal identity metadata: %v", err)
	}
	if err := os.WriteFile(metadataFile, marshalled, 0600); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	return nil
}

// ReadIdentityMetadata reads the latest information about what log indices have been scanned to a file
func ReadIdentityMetadata(metadataFile string) (*IdentityMetadata, error) {
	// Each line represents a piece of identity metadata
	idMetadataBytes, err := os.ReadFile(metadataFile)
	if err != nil {
		return nil, err
	}

	idMetadata := &IdentityMetadata{}
	err = json.Unmarshal(idMetadataBytes, idMetadata)
	if err != nil {
		return nil, err
	}

	return idMetadata, nil
}

// WriteMatchedIdentityEntries writes a list of matched identities to a file
func WriteMatchedIdentityEntries(identitiesFile string, matchedEntries []identity.LogEntry, idMetadataFile *string, endIndex int) error {
	if len(matchedEntries) > 0 {
		for _, idEntry := range matchedEntries {
			fmt.Fprintf(os.Stderr, "Found %s\n", idEntry.String())

			if err := WriteIdentity(identitiesFile, idEntry); err != nil {
				return fmt.Errorf("failed to write entry: %v", err)
			}
		}
	}

	if idMetadataFile != nil {
		idMetadata := IdentityMetadata{
			LatestIndex: endIndex,
		}
		if err := WriteIdentityMetadata(*idMetadataFile, idMetadata); err != nil {
			return fmt.Errorf("failed to write identity metadata: %v", err)
		}
	}

	return nil
}
