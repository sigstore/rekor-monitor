//
// Copyright 2026 The Sigstore Authors.
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

package monitorconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFileShippedConfigs(t *testing.T) {
	for _, environment := range []string{"prod", "staging"} {
		t.Run(environment, func(t *testing.T) {
			path := filepath.Join("..", "..", "targets", environment, "monitor_config.json")
			config, err := LoadFromFile(path)
			if err != nil {
				t.Fatalf("LoadFromFile(%s) returned error: %v", path, err)
			}
			if len(config.GetRekorLogs()) == 0 {
				t.Fatalf("%s lists no Rekor logs", path)
			}
			for _, logConfig := range config.GetRekorLogs() {
				if logConfig.GetReadUrl() == "" || logConfig.GetLogOrigin() == "" || logConfig.GetMajorApiVersion() == 0 {
					t.Errorf("%s has an incomplete log entry: %+v", path, logConfig)
				}
			}
		})
	}
}

func TestLoadFromFileRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "monitor_config.json")
	contents := `{"rekorLogs": [{"readUrl": "https://rekor.example.dev", "logOrigin": "rekor.example.dev", "majorApiVersion": 2, "typo": true}]}`
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadFromFile(path); err == nil {
		t.Fatal("expected an error for an unknown field, got nil")
	}
}
