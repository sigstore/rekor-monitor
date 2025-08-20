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
	"context"
	"fmt"
	"os"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
)

type GetMatchedEntriesFunc func(ctx context.Context, startIndex, endIndex int) ([]identity.LogEntry, error)

func Search(ctx context.Context, getMatchedEntries GetMatchedEntriesFunc, startIndex int, endIndex int, monitoredValues identity.MonitoredValues, outputIdentitiesFile string, idMetadataFile *string) ([]identity.MonitoredIdentity, error) {
	idEntries, err := getMatchedEntries(ctx, startIndex, endIndex)
	if err != nil {
		return nil, err
	}

	if len(idEntries) > 0 {
		for _, idEntry := range idEntries {
			fmt.Fprintf(os.Stderr, "Found %s\n", idEntry.String())

			if err := file.WriteIdentity(outputIdentitiesFile, idEntry); err != nil {
				return nil, fmt.Errorf("failed to write entry: %v", err)
			}
		}
	}

	// TODO: idMetadataFile currently takes in a string pointer to not cause a regression in the current reusable monitoring workflow.
	// Once the reusable monitoring workflow is split into a consistency check and identity search, idMetadataFile should always take in a string value.
	if idMetadataFile != nil {
		idMetadata := file.IdentityMetadata{
			LatestIndex: endIndex,
		}
		err = file.WriteIdentityMetadata(*idMetadataFile, idMetadata)
		if err != nil {
			return nil, fmt.Errorf("failed to write id metadata: %v", err)
		}
	}

	identities := identity.CreateIdentitiesList(monitoredValues)
	monitoredIdentities := identity.CreateMonitoredIdentities(idEntries, identities)
	return monitoredIdentities, nil
}
