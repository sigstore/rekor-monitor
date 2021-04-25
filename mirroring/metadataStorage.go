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
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/spf13/viper"

	"github.com/sigstore/rekor/pkg/generated/models"
)

type TreeMetadata struct {
	PublicKey     string          `json:"public_key,omitempty"`
	LogInfo       *models.LogInfo `json:"log_info,omitempty"`
	SavedMaxIndex int64           `json:"saved_max_index,omitempty"`
}

func LoadTreeMetadata() (TreeMetadata, error) {
	str := viper.GetString("metadata_file_dir")
	bytes, err := ioutil.ReadFile(str)
	if err != nil {
		return TreeMetadata{}, err
	}

	metadata := TreeMetadata{}

	err = json.Unmarshal(bytes, &metadata)
	if err != nil {
		return TreeMetadata{}, err
	}

	return metadata, nil
}

func SaveTreeMetadata() error {
	str := viper.GetString("metadata_file_dir")
	// assumes that if file cannot be removed, it does not exist
	os.Remove(str)
	f, err := os.OpenFile(str, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	pub, err := GetPublicKey()
	if err != nil {
		return err
	}

	logInfo, err := GetLogInfo()
	if err != nil {
		return err
	}

	metadata := TreeMetadata{PublicKey: pub, LogInfo: logInfo, SavedMaxIndex: -1}

	serialMetadata, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = f.Write(serialMetadata)
	if err != nil {
		return err
	}

	return nil
}

func UpdateMetadataByIndex(i int64) error {
	str := viper.GetString("metadata_file_dir")
	bytes, err := ioutil.ReadFile(str)
	if err != nil {
		return err
	}

	metadata := TreeMetadata{}

	err = json.Unmarshal(bytes, &metadata)
	if err != nil {
		return err
	}

	metadata.SavedMaxIndex = i

	serialMetadata, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	// assumes that if file cannot be removed, it does not exist
	os.Remove(str)

	f, err := os.OpenFile(str, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	_, err = f.Write(serialMetadata)
	if err != nil {
		return err
	}

	return nil
}

func UpdateMetadataBySTH() error {
	str := viper.GetString("metadata_file_dir")
	bytes, err := ioutil.ReadFile(str)
	if err != nil {
		return err
	}

	metadata := TreeMetadata{}

	err = json.Unmarshal(bytes, &metadata)
	if err != nil {
		return err
	}

	logInfo, err := GetLogInfo()
	if err != nil {
		return err
	}

	metadata.LogInfo = logInfo

	serialMetadata, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	// assumes that if file cannot be removed, it does not exist
	os.Remove(str)

	f, err := os.OpenFile(str, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	_, err = f.Write(serialMetadata)
	if err != nil {
		return err
	}

	return nil
}
