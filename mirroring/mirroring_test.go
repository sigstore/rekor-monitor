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

package mirroring

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"testing"

	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/spf13/viper"
)

func TestVerifySignedTreeHead(t *testing.T) {
	viper.Set("rekorServerURL", "https://rekor.sigstore.dev")
	rekorClient, err := client.GetRekorClient(viper.GetString("rekorServerURL"))
	if err != nil {
		t.Errorf("%s\n", err)
	}

	logInfo, err := GetLogInfo(rekorClient)
	if err != nil {
		t.Errorf("%s\n", err)
	}

	pubkey, err := GetPublicKey(rekorClient)
	if err != nil {
		t.Errorf("%s\n", err)
	}

	sth := &util.SignedCheckpoint{}
	if err := sth.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
		log.Fatalf("Unmarshalling logInfo.SignedTreeHead to Checkpoint: %v", err)
	}

	if err := VerifySignedTreeHead(sth, pubkey); err != nil {
		t.Errorf("%s\n", err)
	}
}

func TestVerifyLogConsistency(t *testing.T) {
	viper.Set("rekorServerURL", "https://rekor.sigstore.dev")
	rekorClient, err := client.GetRekorClient(viper.GetString("rekorServerURL"))
	if err != nil {
		t.Errorf("%s\n", err)
	}

	entry, err := GetLogEntryData(0, rekorClient)
	if err != nil {
		t.Errorf("%s\n", err)
	}

	hash, err := hex.DecodeString(entry.MerkleTreeHash)
	if err != nil {
		t.Errorf("%s\n", err)
	}

	_, err = VerifyLogConsistency(rekorClient, 1, hash)
	if err != nil {
		t.Errorf("%s\n", err)
	}
}

func TestVerifyLogInclusion(t *testing.T) {
	viper.Set("rekorServerURL", "https://rekor.sigstore.dev")
	rekorClient, err := client.GetRekorClient(viper.GetString("rekorServerURL"))
	if err != nil {
		t.Errorf("%s\n", err)
	}

	entry, err := GetLogEntryData(47906, rekorClient)
	if err != nil {
		panic(err)
	}

	err = VerifyLogInclusion(rekorClient, entry.MerkleTreeHash)
	if err != nil {
		t.Errorf("%s\n", err)
	}
}

func TestFetchLeavesByRange(t *testing.T) {
	viper.Set("rekorServerURL", "https://rekor.sigstore.dev")
	viper.Set("tree_file_dir", ".tree")
	viper.Set("metadata_file_dir", ".metadata")
	err := FetchLeavesByRange(0, 10)
	if err != nil {
		t.Errorf("%s\n", err)
	}
}

func TestComputeRoot(t *testing.T) {
	viper.Set("rekorServerURL", "https://rekor.sigstore.dev")
	viper.Set("tree_file_dir", ".tree")
	viper.Set("metadata_file_dir", ".metadata")

	// the .tree file is not an json array instead it have one json per line
	f, err := os.Open(".tree")
	if err != nil {
		t.Errorf("%s\n", err)
		return
	}
	defer f.Close()

	var leaves []Artifact
	r := bufio.NewReader(f)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		var leaf Artifact
		err = json.Unmarshal([]byte(line), &leaf)
		if err != nil {
			t.Errorf("%s\n", err)
			return
		}

		leaves = append(leaves, leaf)
	}

	STH, err := ComputeRootFromMemory(leaves)
	if err != nil {
		t.Errorf("%s\n", err)
		t.Log(STH)
		return
	}
}
