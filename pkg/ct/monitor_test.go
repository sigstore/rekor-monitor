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
	"reflect"
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
	issuerName       = "test-issuer"
	organizationName = "test-org"
)

func TestScanEntrySubject(t *testing.T) {
	testCases := map[string]struct {
		inputEntry    ct.LogEntry
		inputSubjects []identity.CertificateIdentity
		expected      []identity.LogEntry
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
			inputSubjects: []identity.CertificateIdentity{},
			expected:      []identity.LogEntry{},
		},
		"matching subject": {
			inputEntry: ct.LogEntry{
				Index: 1,
				X509Cert: &x509.Certificate{
					DNSNames:       []string{subjectName},
					EmailAddresses: []string{organizationName},
					Extensions: []pkix.Extension{
						{
							Id:    google_asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
							Value: []byte(issuerName),
						},
					},
					Issuer: pkix.Name{
						CommonName: issuerName,
					},
				},
			},
			inputSubjects: []identity.CertificateIdentity{
				{
					CertSubject: subjectName,
					Issuers:     []string{issuerName},
				},
				{
					CertSubject: organizationName,
					Issuers:     []string{},
				},
			},
			expected: []identity.LogEntry{
				{Index: 1,
					CertSubject: subjectName,
					Issuer:      issuerName},
				{Index: 1,
					CertSubject: organizationName,
					Issuer:      issuerName},
			},
		},
	}

	for _, tc := range testCases {
		logEntries, err := ScanEntrySubject(tc.inputEntry, tc.inputSubjects)
		if err != nil {
			t.Errorf("received error scanning entry for subjects: %v", err)
		}
		expected := tc.expected
		if logEntries == nil {
			if expected != nil {
				t.Errorf("received nil, expected log entry")
			}
		} else {
			if !reflect.DeepEqual(logEntries, expected) {
				t.Errorf("expected %v, received %v", expected, logEntries)
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
		expected           []identity.LogEntry
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
			expected: []identity.LogEntry{},
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
			expected: []identity.LogEntry{
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
			if !reflect.DeepEqual(logEntries, expected) {
				t.Errorf("expected %v, received %v", expected, logEntries)
			}
		}
	}
}

func TestMatchedIndices(t *testing.T) {
	extCert, err := mockCertificateWithExtension(google_asn1.ObjectIdentifier{2, 5, 29, 17}, "test cert value")
	if err != nil {
		t.Errorf("Expected nil got %v", err)
	}
	unmatchedAsn1OID := asn1.ObjectIdentifier{2}
	matchedAsn1OID := asn1.ObjectIdentifier{2, 5, 29, 17}
	extValueString := "test cert value"
	extCert.Extensions = append(extCert.Extensions, pkix.Extension{
		Id:    google_asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
		Value: []byte(issuerName),
	})
	inputEntries := []ct.LogEntry{
		{Index: 1,
			X509Cert: &x509.Certificate{
				DNSNames:       []string{subjectName},
				EmailAddresses: []string{organizationName},
				Extensions:     extCert.Extensions,
				Issuer: pkix.Name{
					CommonName: issuerName,
				},
			},
		},
	}
	testCases := map[string]struct {
		inputEntries         []ct.LogEntry
		inputMonitoredValues identity.MonitoredValues
		expected             []identity.LogEntry
	}{
		"empty case": {
			inputEntries:         []ct.LogEntry{},
			inputMonitoredValues: identity.MonitoredValues{},
			expected:             []identity.LogEntry{},
		},
		"no matching entries": {
			inputEntries: inputEntries,
			inputMonitoredValues: identity.MonitoredValues{
				CertificateIdentities: []identity.CertificateIdentity{
					{
						CertSubject: "non-matched-subject",
					},
				},
				OIDMatchers: []extensions.OIDExtension{
					{
						ObjectIdentifier: unmatchedAsn1OID,
						ExtensionValues:  []string{"unmatched extension value"},
					},
				},
			},
			expected: []identity.LogEntry{},
		},
		"matching certificate identity and issuer": {
			inputEntries: inputEntries,
			inputMonitoredValues: identity.MonitoredValues{
				CertificateIdentities: []identity.CertificateIdentity{
					{
						CertSubject: subjectName,
						Issuers:     []string{issuerName},
					},
				},
			},
			expected: []identity.LogEntry{
				{
					Index:       1,
					CertSubject: subjectName,
					Issuer:      issuerName,
				},
			},
		},
		"matching OID extension": {
			inputEntries: inputEntries,
			inputMonitoredValues: identity.MonitoredValues{
				OIDMatchers: []extensions.OIDExtension{
					{
						ObjectIdentifier: matchedAsn1OID,
						ExtensionValues:  []string{extValueString},
					},
				},
			},
			expected: []identity.LogEntry{
				{
					Index:          1,
					OIDExtension:   matchedAsn1OID,
					ExtensionValue: extValueString,
				},
			},
		},
		"matching certificate subject and issuer and OID extension": {
			inputEntries: inputEntries,
			inputMonitoredValues: identity.MonitoredValues{
				CertificateIdentities: []identity.CertificateIdentity{
					{
						CertSubject: subjectName,
						Issuers:     []string{issuerName},
					},
				},
				OIDMatchers: []extensions.OIDExtension{
					{
						ObjectIdentifier: matchedAsn1OID,
						ExtensionValues:  []string{extValueString},
					},
				},
			},
			expected: []identity.LogEntry{
				{
					Index:       1,
					CertSubject: subjectName,
					Issuer:      issuerName,
				},
				{
					Index:          1,
					OIDExtension:   matchedAsn1OID,
					ExtensionValue: extValueString,
				},
			},
		},
	}

	for _, tc := range testCases {
		matchedEntries, err := MatchedIndices(tc.inputEntries, tc.inputMonitoredValues)
		if err != nil {
			t.Errorf("error matching indices: %v", err)
		}
		expected := tc.expected
		if !reflect.DeepEqual(matchedEntries, expected) {
			t.Errorf("received %v, expected %v", matchedEntries, expected)
		}
	}
}
