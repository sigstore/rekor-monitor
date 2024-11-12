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

package ct

import (
	"context"
	"fmt"
	"regexp"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
)

func GetCTLogEntries(logClient *ctclient.LogClient, startIndex int, endIndex int) ([]ct.LogEntry, error) {
	entries, err := logClient.GetEntries(context.Background(), int64(startIndex), int64(endIndex))
	if err != nil {
		return nil, fmt.Errorf("error retrieving certificate transparency log entries: %v", err)
	}
	return entries, nil
}

func ScanEntrySubject(logEntry ct.LogEntry, monitoredSubjects []string) ([]*identity.LogEntry, error) {
	subject := logEntry.X509Cert.Subject.String()
	matchedEntries := []*identity.LogEntry{}
	for _, monitoredSub := range monitoredSubjects {
		regex, err := regexp.Compile(monitoredSub)
		if err != nil {
			return nil, fmt.Errorf("error compiling regex: %v", err)
		}
		matches := regex.FindAllString(subject, -1)
		for _, match := range matches {
			matchedEntries = append(matchedEntries, &identity.LogEntry{
				Index:       logEntry.Index,
				CertSubject: match,
			})
		}
	}

	return matchedEntries, nil
}

func ScanEntryOIDExtensions(logEntry ct.LogEntry, monitoredOIDMatchers []extensions.OIDExtension) ([]*identity.LogEntry, error) {
	matchedEntries := []*identity.LogEntry{}
	cert := logEntry.X509Cert
	for _, monitoredOID := range monitoredOIDMatchers {
		match, _, extValue, err := identity.OIDMatchesPolicy(cert, monitoredOID.ObjectIdentifier, monitoredOID.ExtensionValues)
		if err != nil {
			return nil, fmt.Errorf("error with policy matching at index %d: %w", logEntry.Index, err)
		}
		if match {
			matchedEntries = append(matchedEntries, &identity.LogEntry{
				Index:          logEntry.Index,
				OIDExtension:   monitoredOID.ObjectIdentifier,
				ExtensionValue: extValue,
			})
		}
	}
	return matchedEntries, nil
}
