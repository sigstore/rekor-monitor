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
	"encoding/asn1"
	"testing"

	google_asn1 "github.com/google/certificate-transparency-go/asn1"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
)

const (
	subjectName      = "test-subject"
	organizationName = "test-org"
)

func TestScanEntryCertSubject(t *testing.T) {
	testCases := map[string]struct {
		inputEntry    ct.LogEntry
		inputSubjects []string
		expected      []*identity.LogEntry
	}{
		"no matching subject": {
			inputEntry: ct.LogEntry{
				Index: 1,
				X509Cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: subjectName,
					},
				},
			},
			inputSubjects: []string{},
			expected:      []*identity.LogEntry{},
		},
		"matching subject": {
			inputEntry: ct.LogEntry{
				Index: 1,
				X509Cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName:   subjectName,
						Organization: []string{organizationName},
					},
				},
			},
			inputSubjects: []string{subjectName, organizationName},
			expected: []*identity.LogEntry{
				{Index: 1,
					CertSubject: subjectName},
				{Index: 1,
					CertSubject: organizationName},
			},
		},
	}

	for _, tc := range testCases {
		logEntries, err := ScanEntryCertSubject(tc.inputEntry, tc.inputSubjects)
		if err != nil {
			t.Errorf("received error scanning entry for subjects: %v", err)
		}
		expected := tc.expected
		if logEntries == nil {
			if expected != nil {
				t.Errorf("received nil, expected log entry")
			}
		} else {
			for i, resultEntry := range logEntries {
				expectedEntry := tc.expected[i]
				resultIndex := resultEntry.Index
				expectedIndex := expectedEntry.Index
				if resultIndex != expectedIndex {
					t.Errorf("expected index %d, received index %d", expectedIndex, resultIndex)
				}

				resultCertSubject := resultEntry.CertSubject
				expectedCertSubject := expectedEntry.CertSubject
				if resultCertSubject != expectedCertSubject {
					t.Errorf("expected cert subject %s, received cert subject %s", expectedCertSubject, resultCertSubject)
				}
			}
		}
	}
}

func TestScanEntryOIDExtensions(t *testing.T) {
	cert, err := mockCertificateWithExtension(google_asn1.ObjectIdentifier{2, 5, 29, 17}, "test cert value")
	if err != nil {
		t.Errorf("Expected nil got %v", err)
	}
	unmatchedAsn1OID := asn1.ObjectIdentifier{2}
	matchedAsn1OID := asn1.ObjectIdentifier{2, 5, 29, 17}
	extValueString := "test cert value"
	testCases := map[string]struct {
		inputEntry         ct.LogEntry
		inputOIDExtensions []extensions.OIDExtension
		expected           []*identity.LogEntry
	}{
		"no matching subject": {
			inputEntry: ct.LogEntry{
				Index:    1,
				X509Cert: cert,
			},
			inputOIDExtensions: []extensions.OIDExtension{
				{
					ObjectIdentifier: unmatchedAsn1OID,
					ExtensionValues:  []string{extValueString},
				},
			},
			expected: []*identity.LogEntry{},
		},
		"matching subject": {
			inputEntry: ct.LogEntry{
				Index:    1,
				X509Cert: cert,
			},
			inputOIDExtensions: []extensions.OIDExtension{
				{
					ObjectIdentifier: matchedAsn1OID,
					ExtensionValues:  []string{extValueString},
				},
			},
			expected: []*identity.LogEntry{
				{
					Index:          1,
					OIDExtension:   matchedAsn1OID,
					ExtensionValue: extValueString,
				},
			},
		},
	}

	for _, tc := range testCases {
		logEntries, err := ScanEntryOIDExtensions(tc.inputEntry, tc.inputOIDExtensions)
		if err != nil {
			t.Errorf("received error scanning entry for oid extensions: %v", err)
		}
		expected := tc.expected
		if logEntries == nil {
			if expected != nil {
				t.Errorf("received nil, expected log entry")
			}
		} else {
			for i, resultEntry := range logEntries {
				expectedEntry := tc.expected[i]
				resultIndex := resultEntry.Index
				expectedIndex := expectedEntry.Index
				if resultIndex != expectedIndex {
					t.Errorf("expected index %d, received index %d", expectedIndex, resultIndex)
				}

				resultOID := resultEntry.OIDExtension.String()
				expectedOID := expectedEntry.OIDExtension.String()
				if resultOID != expectedOID {
					t.Errorf("expected oid %s, received oid %s", expectedOID, resultOID)
				}

				resultExtValue := resultEntry.ExtensionValue
				expectedExtValue := expectedEntry.ExtensionValue
				if resultExtValue != expectedExtValue {
					t.Errorf("expected extension value %s, received extension value %s", expectedExtValue, resultExtValue)
				}
			}
		}
	}
}
