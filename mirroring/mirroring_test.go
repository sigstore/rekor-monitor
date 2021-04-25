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
	"encoding/json"
	"os"
	"testing"

	"github.com/spf13/viper"
)

// TestVerifySignature tests normal operation of the verifySignature function.
func TestVerifySignature(t *testing.T) {
	viper.Set("rekorServerURL", "http://0.0.0.0:3000")
	viper.Set("tree_file_dir", ".tree")
	viper.Set("metadata_file_dir", ".metadata")
	pub, err := GetPublicKey()
	if err != nil {
		t.Errorf("%s\n", err)
	}

	err = VerifySignature(pub)
	if err != nil {
		t.Errorf("%s\n", err)
	}
}

func TestFetchLeavesByRange(t *testing.T) {
	viper.Set("rekorServerURL", "https://api.sigstore.dev")
	viper.Set("tree_file_dir", ".tree")
	viper.Set("metadata_file_dir", ".metadata")
	err := FetchLeavesByRange(0, 10)
	if err != nil {
		t.Errorf("%s\n", err)
	}
}

func TestComputeRoot(t *testing.T) {
	viper.Set("rekorServerURL", "https://api.sigstore.dev")
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
	/*
		// 4th hash in inclusion proof of entry at log index 8
		h := "441828658e8d21c60ba3923da71cdac07f8e4c621ce611c94499ce9c185a5dcb"
		if hex.EncodeToString(STH) != h {
			t.Errorf("Computed STH is incorrect.")
		}
		leaves, err = rekorclient.FetchLeavesByRange(0, 32)
		if err != nil {
			t.Errorf("%s\n", err)
			return
		}
		STH, err = rekorclient.ComputeRoot(leaves)
		if err != nil {
			t.Errorf("%s\n", err)
			return
		}
		// 6th hash in inclusion proof of entry at log index 33
		h = "3c2e1362343083e685240da2c9bfbbe2d61a4ca3768b6b4c8ddeb0f1c5d6a034"
		if hex.EncodeToString(STH) != h {
			t.Errorf("Computed STH is incorrect.")
		}*/
}

// TODO: commented out missing FullAudit func
// func TestFullAudit(t *testing.T) {
// 	viper.Set("rekorServerURL", "https://api.sigstore.dev")
// 	viper.Set("tree_file_dir", ".tree")
// 	viper.Set("metadata_file_dir", ".metadata")
// 	err := FullAudit()
// 	if err != nil {
// 		t.Errorf("%s\n", err)
// 	}
// }

/*func TestGetLogEntryByIndex(t *testing.T) {
	viper.Set("rekorServerURL", "https://api.sigstore.dev")
	ix, entry, err := rekorclient.GetLogEntryByIndex(10)
	if err != nil {
		t.Errorf("%s\n", err)
	} else {
		a, err := rekorclient.ParseEntry(ix, entry)
		t.Errorf("%+v\n", a)
		t.Errorf("%+v\n", entry)
		t.Errorf("%s\n", err)
		var pk string
		var hash string
		var sig string
		switch v := a.Body.(type) {
		case *rekord_v001.V001Entry:
			pk = string([]byte(v.RekordObj.Signature.PublicKey.Content))
			sig = base64.StdEncoding.EncodeToString([]byte(v.RekordObj.Signature.Content))
			hash = *v.RekordObj.Data.Hash.Value
			t.Errorf("+ Found Rekord:")
		case *rpm_v001.V001Entry:
			pk = string([]byte(v.RPMModel.PublicKey.Content))
			t.Errorf("+ Found RPM ")
		default:
			fmt.Println("no type found")
			t.Errorf("no type found %+v", v)
		}
		t.Errorf("+%v ", pk)
		t.Errorf("+%v ", sig)
		t.Errorf("+%v ", hash)
		// d := entry.Body.(string)
		// t.Errorf(d)
		// decoded, err := base64.StdEncoding.DecodeString(d)
		// var obj types.EntryImpl
		// err = obj.Unmarshal(d)
		// if err != nil {
		// 	t.Errorf("%s\n", err)
		// }
		// t.Errorf("%s\n", decoded)
	}
}*/

/*func TestBuildTree(t *testing.T) {
	viper.Set("rekorServerURL", "https://api.sigstore.dev")
	err := rekorclient.BuildTree()
	if err != nil {
		t.Errorf("%s\n", err)
	}
}*/
