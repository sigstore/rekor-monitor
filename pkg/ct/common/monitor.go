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
	"github.com/sigstore/rekor-monitor/pkg/identity"
)

func ScanEntryCertSubject[Certificate *x509.Certificate | *google_x509.Certificate](cert Certificate, index int64, monitoredCertID identity.CertIdentityValue) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	match, sub, iss, err := identity.CertMatchesPolicy(cert, monitoredCertID.CertSubject, monitoredCertID.Issuers)
	if err != nil {
		return nil, fmt.Errorf("error with policy matching at index %d: %w", index, err)
	} else if match {
		matchedEntries = append(matchedEntries, identity.LogEntry{
			MatchedIdentity: monitoredCertID,
			CertSubject:     sub,
			Issuer:          iss,
			Index:           index,
		})
	}
	return matchedEntries, nil
}

func ScanEntryOIDExtension[Certificate *x509.Certificate | *google_x509.Certificate](cert Certificate, index int64, monitoredOID identity.OIDMatcherValue) ([]identity.LogEntry, error) {
	matchedEntries := []identity.LogEntry{}
	match, _, extValue, err := identity.OIDMatchesPolicy(cert, monitoredOID.OID, monitoredOID.ExtensionValues)
	if err != nil {
		return nil, fmt.Errorf("error with policy matching at index %d: %w", index, err)
	}
	if match {
		matchedEntries = append(matchedEntries, identity.LogEntry{
			MatchedIdentity: monitoredOID,
			Index:           index,
			OIDExtension:    monitoredOID.OID,
			ExtensionValue:  extValue,
		})
	}
	return matchedEntries, nil
}

func ValidateCertificateChain(cert, preCert []byte, caRoots, caIntermediates string) error {
	if cert != nil {
		parsedCert, err := x509.ParseCertificate(cert)
		if err == nil {
			if err = identity.ValidateCertificateChain([]*x509.Certificate{parsedCert}, caRoots, caIntermediates); err != nil {
				return fmt.Errorf("validating certificate chain: %w", err)
			}
		}
	} else if preCert != nil {
		parsedCert, err := google_x509.ParseCertificate(preCert)
		if err == nil {
			if err = identity.ValidatePreCertificateChain([]*google_x509.Certificate{parsedCert}, caRoots, caIntermediates); err != nil {
				return fmt.Errorf("validating pre-certificate chain: %w", err)
			}
		}
	}
	return nil
}
