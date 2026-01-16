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

package common

import (
	"crypto/x509"
	"fmt"

	google_x509 "github.com/google/certificate-transparency-go/x509"
	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
)

func ScanEntryCertSubject[Certificate *x509.Certificate | *google_x509.Certificate](cert Certificate, index int64, monitoredCertIDs []identity.CertificateIdentity) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	for _, monitoredCertID := range monitoredCertIDs {
		match, sub, iss, err := identity.CertMatchesPolicy(cert, monitoredCertID.CertSubject, monitoredCertID.Issuers)
		if err != nil {
			return nil, fmt.Errorf("error with policy matching  at index %d: %w", index, err)
		} else if match {
			matchedEntries = append(matchedEntries, identity.LogEntry{
				MatchedIdentity:     monitoredCertID.CertSubject,
				MatchedIdentityType: identity.MatchedIdentityTypeCertSubject,
				CertSubject:         sub,
				Issuer:              iss,
				Index:               index,
			})
		}
	}
	return matchedEntries, nil
}

func ScanEntryOIDExtensions[Certificate *x509.Certificate | *google_x509.Certificate](cert Certificate, index int64, monitoredOIDMatchers []extensions.OIDExtension) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	for _, monitoredOID := range monitoredOIDMatchers {
		match, _, extValue, err := identity.OIDMatchesPolicy(cert, monitoredOID.ObjectIdentifier, monitoredOID.ExtensionValues)
		if err != nil {
			return nil, fmt.Errorf("error with policy matching at index %d: %w", index, err)
		}
		if match {
			matchedEntries = append(matchedEntries, identity.LogEntry{
				MatchedIdentity:     extValue,
				MatchedIdentityType: identity.MatchedIdentityTypeExtensionValue,
				Index:               index,
				OIDExtension:        monitoredOID.ObjectIdentifier,
				ExtensionValue:      extValue,
			})
		}
	}
	return matchedEntries, nil
}
