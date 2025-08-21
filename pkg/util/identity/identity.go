// Copyright 2025 The Sigstore Authors.
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

package identity

import (
	"fmt"
	"os"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
)

func ProcessMatchedEntries(matchedEntries []identity.LogEntry, monitoredValues identity.MonitoredValues, outputIdentitiesFile string, idMetadataFile *string) ([]identity.MonitoredIdentity, error) {
	if len(matchedEntries) > 0 {
		for _, idEntry := range matchedEntries {
			fmt.Fprintf(os.Stderr, "Found %s\n", idEntry.String())

			if err := file.WriteIdentity(outputIdentitiesFile, idEntry); err != nil {
				return nil, fmt.Errorf("failed to write entry: %v", err)
			}
		}
	}

	identities := identity.CreateIdentitiesList(monitoredValues)
	monitoredIdentities := identity.CreateMonitoredIdentities(matchedEntries, identities)
	return monitoredIdentities, nil
}

func WriteIdentityMetadataFile(idMetadataFile *string, latestIndex int) error {
	if idMetadataFile == nil {
		return nil
	}

	idMetadata := file.IdentityMetadata{
		LatestIndex: latestIndex,
	}
	return file.WriteIdentityMetadata(*idMetadataFile, idMetadata)
}
