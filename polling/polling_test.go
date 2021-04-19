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

package polling

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/spf13/viper"
)

// TODO: fixme! :)
// func TestPolling(t *testing.T) {
// 	viper.Set("tree_file_dir", "./tree.test")
// 	viper.Set("metadata_file_dir", "./metadata.test")
// 	viper.Set("rekorServerURL", "https://api.sigstore.dev")

// 	err := PollSTH()
// 	if err != nil {
// 		t.Error(err)
// 	}
// }

func TestPollPublicKey(t *testing.T) {
	viper.Set("poll_config_file_dir", "./pollConfig.test")
	viper.Set("metadata_file_dir", "./metadata.test")
	viper.Set("tree_file_dir", "./tree.test")
	err := makePollCfg()
	if err != nil {
		t.Error(err)
	}
	err = PollPublicKey()
	if err == nil {
		t.Errorf("'Malicious' entry was not detected.")
	}
	if _, ok := err.(*MaliciousArtifactFound); !ok {
		t.Errorf("Unexpected error.")
	}
}

func makePollCfg() error {
	str := viper.GetString("poll_config_file_dir")
	// assumes that if file cannot be removed, it does not exist
	os.Remove(str)
	f, err := os.OpenFile(str, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	cfg := pollCfg{PublicKey: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n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\nWR6Fv7ySHTl7cQ13jGmSR1N8hg==\n=07ir\n-----END PGP PUBLIC KEY BLOCK-----",
		Hashes: []string{"381bb7ccbf82b380828fd6733a494d4a26facd76c76733f33c5a9efafde8e90a", "aee807548a1d75ba9857eae6a18f674a09820193f55e8c8fa5ebe610d007d44c", "60c9473a9785b2d25a8526bc093bc886d5084951d59d7930114bfa8a7233fca9"}}

	serial, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = f.Write(serial)
	if err != nil {
		return err
	}

	return nil
}
