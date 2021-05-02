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

	"github.com/spf13/viper"
)

//consider loading filenames/paths from viper registry
func AppendArtifactsToFile(artifacts []Artifact) error {
	str := viper.GetString("tree_file_dir")
	f, err := os.OpenFile(str, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	for _, leave := range artifacts {
		serialLeave, err := json.Marshal(leave)
		if err != nil {
			return err
		}
		serialLeave = append(serialLeave, '\n')
		_, err = f.Write(serialLeave)
		if err != nil {
			return err
		}
	}

	return nil
}

func ReadLeaveFromFile(idx int64) (Artifact, error) {
	str := viper.GetString("tree_file_dir")
	file, err := os.Open(str)
	if err != nil {
		return Artifact{}, err
	}
	defer file.Close()
	leave := Artifact{}

	reader := bufio.NewReader(file)
	var line string
	for i := int64(0); i <= idx; i++ {
		line, err = reader.ReadString('\n')
		if err != nil {
			return Artifact{}, err
		}

	}
	err = json.Unmarshal([]byte(line), &leave)
	if err != nil {
		return Artifact{}, err
	}

	return leave, nil
}
