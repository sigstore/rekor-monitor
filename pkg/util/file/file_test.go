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

	ct "github.com/google/certificate-transparency-go"
	"github.com/sigstore/rekor/pkg/util"
	"golang.org/x/mod/sumdb/note"
)

func TestReadLatestCheckpointRekorV1(t *testing.T) {
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
	c, err := ReadLatestCheckpointRekorV1(f)
	if err != nil {
		t.Fatalf("error reading checkpoint: %v", err)
	}
	result, _ := c.MarshalText()
	if !bytes.Equal(text, result) {
		log.Fatalf("checkpoints are not equal")
	}

	// failure: no log file
	_, err = ReadLatestCheckpointRekorV1("empty")
	if err == nil || !strings.Contains(err.Error(), "no such file or directory") {
		t.Fatalf("expected no error, got: %v", err)
	}

	// failure: malformed note
	os.WriteFile(f, []byte{1}, 0644)
	_, err = ReadLatestCheckpointRekorV1(f)
	if err == nil || !strings.Contains(err.Error(), "malformed note") {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestWriteAndReadRekorV1(t *testing.T) {
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
	if err := WriteCheckpointRekorV1(sc, f); err != nil {
		t.Fatalf("error writing checkpoint: %v", err)
	}
	c, err := ReadLatestCheckpointRekorV1(f)
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

func TestReadWriteCTSignedTreeHead(t *testing.T) {
	sth := &ct.SignedTreeHead{
		TreeSize: 1,
	}

	tempDir := t.TempDir()
	tempSTHFile, err := os.CreateTemp(tempDir, "")
	if err != nil {
		t.Errorf("failed to create temp STH file: %v", err)
	}
	tempSTHFileName := tempSTHFile.Name()
	defer os.Remove(tempSTHFileName)

	err = WriteCTSignedTreeHead(sth, tempSTHFileName)
	if err != nil {
		t.Errorf("failed to write STH: %v", err)
	}

	readSTH, err := ReadLatestCTSignedTreeHead(tempSTHFileName)
	if err != nil {
		t.Errorf("failed to read STH: %v", err)
	}

	if readSTH.String() != sth.String() {
		t.Errorf("expected STH: %s, received STH: %s", sth, readSTH)
	}
}

func TestReadWriteIdentityMetadata(t *testing.T) {
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

	idMetadata, err := ReadIdentityMetadata(tempMetadataFileName)
	if err != nil {
		t.Errorf("failed to read identity metadata: %v", err)
	}
	if idMetadata == nil || idMetadata.LatestIndex != 1 {
		t.Errorf("expected latest index of 1, received incorrect or nil")
	}
}
