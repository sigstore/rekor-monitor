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
	"io/ioutil"

	"github.com/spf13/viper"
)

type PollCfg struct {
	Hashes    map[string]bool `json:"hashes,omitempty"`
	PublicKey string          `json:"public_key,omitempty"`
}

type pollCfg struct {
	Hashes    []string `json:"hashes,omitempty"`
	PublicKey string   `json:"public_key,omitempty"`
}

func ReadCfg() (PollCfg, error) {
	cfgFileDir := viper.GetString("poll_config_file_dir")

	bytes, err := ioutil.ReadFile(cfgFileDir)
	if err != nil {
		return PollCfg{}, err
	}

	cfg := pollCfg{}

	err = json.Unmarshal(bytes, &cfg)
	if err != nil {
		return PollCfg{}, err
	}

	Cfg := PollCfg{Hashes: make(map[string]bool)}

	for _, hash := range cfg.Hashes {
		Cfg.Hashes[hash] = true
	}
	Cfg.PublicKey = cfg.PublicKey

	return Cfg, nil
}
