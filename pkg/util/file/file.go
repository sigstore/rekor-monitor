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

// ReadLatestCheckpoint reads the most recent signed checkpoint from the log file
func ReadLatestCheckpointRekorV1(logInfoFile string) (*util.SignedCheckpoint, error) {
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

	checkpoint := util.SignedCheckpoint{}
	if err := checkpoint.UnmarshalText([]byte(strings.ReplaceAll(line, "\\n", "\n"))); err != nil {
		return nil, err
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &checkpoint, nil
}

// ReadLatestCheckpoint reads the most recent checkpoint from the log file
func ReadLatestCheckpointRekorV2(logInfoFile string) (*log.Checkpoint, error) {
	// Each line in the file is one checkpoint
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

	checkpoint := log.Checkpoint{}
	_, err = checkpoint.Unmarshal([]byte(strings.ReplaceAll(line, "\\n", "\n")))
	if err != nil {
		return nil, err
	}

	if err := scanner.Err(); err != nil {
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
func WriteCTSignedTreeHead(sth *ct.SignedTreeHead, logInfoFile string) error {
	marshalledSTH, err := json.Marshal(sth)
	if err != nil {
		return err
	}

	if err := os.WriteFile(logInfoFile, []byte(fmt.Sprintf("%s\n", strings.ReplaceAll(string(marshalledSTH), "\n", "\\n"))), 0600); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	return nil
}

// WriteCheckpointRekorV1 writes a signed checkpoint to the log file
func WriteCheckpointRekorV1(checkpoint *util.SignedCheckpoint, logInfoFile string) error {
	// Write latest checkpoint to file
	s, err := checkpoint.MarshalText()
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}
	// Open file to append new snapshot
	file, err := os.OpenFile(logInfoFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()
	// Replace newlines to flatten checkpoint to single line
	if _, err := fmt.Fprintf(file, "%s\n", strings.ReplaceAll(string(s), "\n", "\\n")); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	return nil
}

// WriteCheckpointRekorV2 writes a checkpoint to the log file
func WriteCheckpointRekorV2(checkpoint *log.Checkpoint, logInfoFile string) error {
	// Write latest checkpoint to file
	s := checkpoint.Marshal()
	// Open file to append new snapshot
	file, err := os.OpenFile(logInfoFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()
	// Replace newlines to flatten checkpoint to single line
	if _, err := fmt.Fprintf(file, "%s\n", strings.ReplaceAll(string(s), "\n", "\\n")); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
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
