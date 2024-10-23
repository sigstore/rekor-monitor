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
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/rekor/pkg/util"
	"golang.org/x/mod/sumdb/note"
)

func TestReadLatestCheckpoint(t *testing.T) {
	f := filepath.Join(t.TempDir(), "logfile")
	root, _ := hex.DecodeString("1a341bc342ff4e567387de9789ab14000b147124317841489172419874198147")

	// success: read checkpoint
	// generate fake checkpoint
	sc, err := util.CreateSignedCheckpoint(util.Checkpoint{
		Origin: "origin",
		Size:   uint64(123),
		Hash:   root,
	})
	sc.Signatures = []note.Signature{{Name: "name", Hash: 1, Base64: "adbadbadb"}}
	if err != nil {
		t.Fatal(err)
	}
	text, err := sc.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	data := fmt.Sprintf("%s\n", strings.ReplaceAll(string(text), "\n", "\\n"))
	err = os.WriteFile(f, []byte(data), 0644)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ReadLatestCheckpoint(f)
	if err != nil {
		t.Fatalf("error reading checkpoint: %v", err)
	}
	result, _ := c.MarshalText()
	if !bytes.Equal(text, result) {
		log.Fatalf("checkpoints are not equal")
	}

	// failure: no log file
	_, err = ReadLatestCheckpoint("empty")
	if err == nil || !strings.Contains(err.Error(), "no such file or directory") {
		t.Fatalf("expected no error, got: %v", err)
	}

	// failure: malformed note
	os.WriteFile(f, []byte{1}, 0644)
	_, err = ReadLatestCheckpoint(f)
	if err == nil || !strings.Contains(err.Error(), "malformed note") {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestWriteAndRead(t *testing.T) {
	f := filepath.Join(t.TempDir(), "logfile")
	root, _ := hex.DecodeString("1a341bc342ff4e567387de9789ab14000b147124317841489172419874198147")

	// success: read and write checkpoint
	// generate fake checkpoint
	sc, err := util.CreateSignedCheckpoint(util.Checkpoint{
		Origin: "origin",
		Size:   uint64(123),
		Hash:   root,
	})
	sc.Signatures = []note.Signature{{Name: "name", Hash: 1, Base64: "adbadbadb"}}
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteCheckpoint(sc, f); err != nil {
		t.Fatalf("error writing checkpoint: %v", err)
	}
	c, err := ReadLatestCheckpoint(f)
	if err != nil {
		t.Fatalf("error reading checkpoint: %v", err)
	}
	input, _ := sc.MarshalText()
	result, _ := c.MarshalText()
	if !bytes.Equal(input, result) {
		log.Fatalf("checkpoints are not equal")
	}
}

func TestDeleteOldCheckpoints(t *testing.T) {
	f := filepath.Join(t.TempDir(), "logfile")
	file, _ := os.OpenFile(f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	// log size will be 200 by end of loop
	for i := 0; i < 200; i++ {
		file.WriteString("\n")
	}
	fi, _ := os.Stat(f)
	if fi.Size() != 200 {
		t.Fatalf("log size should be 200, got %d", fi.Size())
	}

	if err := DeleteOldCheckpoints(f); err != nil {
		t.Fatalf("error deleting: %v", err)
	}

	fi, _ = os.Stat(f)
	if fi.Size() != 100 {
		t.Fatalf("log size should be 100, got %d", fi.Size())
	}
}

func TestWriteIdentityMetadata(t *testing.T) {
	tempDir := t.TempDir()
	tempMetadataFile, err := os.CreateTemp(tempDir, "")
	if err != nil {
		t.Errorf("failed to create temp log file: %v", err)
	}
	tempMetadataFileName := tempMetadataFile.Name()
	defer os.Remove(tempMetadataFileName)

	WriteIdentityMetadata(tempMetadataFileName, IdentityMetadata{
		LatestIndex: 1,
	})

	tempMetadata, err := os.ReadFile(tempMetadataFileName)
	if err != nil {
		t.Errorf("error reading from output identities file: %v", err)
	}
	tempMetadataString := string(tempMetadata)
	if !strings.Contains(tempMetadataString, "1") {
		t.Errorf("expected to find index 1, did not in %s", tempMetadataString)
	}
}
