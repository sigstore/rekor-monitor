//
// Copyright 2024 The Sigstore Authors.
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

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	ctgo "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/sigstore/rekor-monitor/internal/cmd"
	"github.com/sigstore/rekor-monitor/pkg/ct"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/notifications"
)

// Default values for monitoring job parameters
const (
	publicCTServerURL        = "https://ctfe.sigstore.dev/2022"
	logInfoFileName          = "ctLogInfo"
	outputIdentitiesFileName = "ctIdentities.txt"
)

// This main function performs a periodic identity search.
// Upon starting, any existing latest snapshot data is loaded and the function runs
// indefinitely to perform identity search for every time interval that was specified.
func main() {
	flags, config, err := cmd.ParseAndLoadConfig(publicCTServerURL, logInfoFileName, outputIdentitiesFileName, "ct-monitor")
	if err != nil {
		log.Fatalf("error parsing flags and loading config: %v", err)
	}
	if flags.LogInfoFile == "" {
		logInfoFileName := fmt.Sprintf("%s.txt", logInfoFileName)
		flags.LogInfoFile = logInfoFileName
	}

	fulcioClient, err := ctclient.New(flags.ServerURL, http.DefaultClient, jsonclient.Options{
		UserAgent: flags.UserAgent,
	})
	if err != nil {
		log.Fatalf("getting Fulcio client: %v", err)
	}

	allOIDMatchers, err := config.MonitoredValues.OIDMatchers.RenderOIDMatchers()
	if err != nil {
		fmt.Printf("error parsing OID matchers: %v", err)
	}

	monitoredValues := identity.MonitoredValues{
		CertificateIdentities: config.MonitoredValues.CertificateIdentities,
		OIDMatchers:           allOIDMatchers,
	}

	cmd.PrintMonitoredValues(monitoredValues)
	cmd.MonitorLoop(cmd.MonitorLoopParams{
		Interval:                 flags.Interval,
		Config:                   config,
		MonitoredValues:          monitoredValues,
		Once:                     flags.Once,
		NotificationContextNewFn: notifications.CreateCTMonitorNotificationContext,
		RunConsistencyCheckFn: func(_ context.Context) (cmd.Checkpoint, cmd.LogInfo, error) {
			prev, cur, err := ct.RunConsistencyCheck(fulcioClient, flags.LogInfoFile)
			if err != nil {
				return nil, nil, err
			}
			var prevCheckpoint cmd.Checkpoint
			if prev != nil {
				prevCheckpoint = prev
			}
			var curLogInfo cmd.LogInfo
			if cur != nil {
				curLogInfo = cur
			}
			return prevCheckpoint, curLogInfo, nil
		},
		GetStartIndexFn: func(prev cmd.Checkpoint, _ cmd.LogInfo) *int {
			prevSTH := prev.(*ctgo.SignedTreeHead)
			checkpointStartIndex := int(prevSTH.TreeSize) //nolint: gosec // G115, log will never be large enough to overflow
			return &checkpointStartIndex
		},
		GetEndIndexFn: func(cur cmd.LogInfo) *int {
			currentSTH := cur.(*ctgo.SignedTreeHead)
			checkpointEndIndex := int(currentSTH.TreeSize) //nolint: gosec // G115
			return &checkpointEndIndex
		},
		IdentitySearchFn: func(ctx context.Context, config *notifications.IdentityMonitorConfiguration, monitoredValues identity.MonitoredValues) ([]identity.MonitoredIdentity, error) {
			return ct.IdentitySearch(ctx, fulcioClient, *config.StartIndex, *config.EndIndex, monitoredValues, config.OutputIdentitiesFile, config.IdentityMetadataFile)
		},
	})
}
