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

// Package monitorconfig loads the monitor configuration that lists the
// transparency logs to monitor. The sigstore TUF repositories do not publish
// this target, so it is read from a local file.
package monitorconfig

import (
	"fmt"
	"os"

	monitor_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/monitor/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// LoadFromFile reads a protojson-encoded MonitorConfig from path.
func LoadFromFile(path string) (*monitor_v1.MonitorConfig, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading monitor config: %w", err)
	}

	config := &monitor_v1.MonitorConfig{}
	if err := protojson.Unmarshal(contents, config); err != nil {
		return nil, fmt.Errorf("parsing monitor config %s: %w", path, err)
	}
	return config, nil
}
