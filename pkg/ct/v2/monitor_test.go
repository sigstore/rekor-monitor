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

package v2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"go.step.sm/crypto/x509util"
)

const (
	subjectName      = "test-subject"
	issuerName       = "test-issuer"
	organizationName = "test-org"
)

func TestMatchedIndices(t *testing.T) {
	value, err := asn1.Marshal("test cert value")
	if err != nil {
		t.Fatalf("marshalling extension value: %v", err)
	}
	extensions := []pkix.Extension{
		{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 99999},
			Value: value,
		},
	}
	unmatchedAsn1OID := asn1.ObjectIdentifier{2}
	matchedAsn1OID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 99999}
	extValueString := "test cert value"
	extensions = append(extensions, pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
		Value: []byte(issuerName),
	})
	parent := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   issuerName,
			Organization: []string{organizationName},
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now().Add(-5 * time.Hour),
		NotAfter:              time.Now().Add(5 * time.Hour),
	}
	certTemplate := x509.Certificate{
		SerialNumber:    big.NewInt(2),
		DNSNames:        []string{subjectName},
		EmailAddresses:  []string{organizationName},
		ExtraExtensions: extensions,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("error generating key: %v", err)
	}
	cert, err := x509util.CreateCertificate(&certTemplate, &parent, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("error generating certificate: %v", err)
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	pem.Encode(os.Stdout, block)
	inputEntries := []Entry{
		{
			Entry: &staticCTEntry{
				LeafIndex:   1,
				Certificate: cert.Raw,
			},
			Index: 1,
		},
	}
	subjectCertID := identity.CertIdentityValue{CertSubject: subjectName, Issuers: []string{issuerName}}
	matchedOIDMatcher := identity.OIDMatcherValue{OID: matchedAsn1OID, ExtensionValues: []string{extValueString}}

	testCases := []struct {
		name                 string
		inputEntries         []Entry
		inputMonitoredValues identity.MonitoredValues
		expected             []identity.LogEntry
		expectErr            bool
	}{
		{
			name:                 "empty case",
			inputEntries:         []Entry{},
			inputMonitoredValues: identity.MonitoredValues{},
			expectErr:            true,
		},
		{
			name:         "no matching entries",
			inputEntries: inputEntries,
			inputMonitoredValues: identity.MonitoredValues{
				identity.CertIdentityValue{
					CertSubject: "non-matched-subject",
				},
				identity.OIDMatcherValue{
					OID:             unmatchedAsn1OID,
					ExtensionValues: []string{"unmatched extension value"},
				},
			},
			expected: []identity.LogEntry{},
		},
		{
			name:         "matching certificate identity and issuer",
			inputEntries: inputEntries,
			inputMonitoredValues: identity.MonitoredValues{
				subjectCertID,
			},
			expected: []identity.LogEntry{
				{
					MatchedIdentity: subjectCertID,
					Index:           1,
					CertSubject:     subjectName,
					Issuer:          issuerName,
				},
			},
		},
		{
			name:         "matching OID extension",
			inputEntries: inputEntries,
			inputMonitoredValues: identity.MonitoredValues{
				matchedOIDMatcher,
			},
			expected: []identity.LogEntry{
				{
					MatchedIdentity: matchedOIDMatcher,
					Index:           1,
					OIDExtension:    matchedAsn1OID,
					ExtensionValue:  extValueString,
				},
			},
		},
		{
			name:         "matching certificate subject and issuer and OID extension",
			inputEntries: inputEntries,
			inputMonitoredValues: identity.MonitoredValues{
				subjectCertID,
				matchedOIDMatcher,
			},
			expected: []identity.LogEntry{
				{
					MatchedIdentity: subjectCertID,
					Index:           1,
					CertSubject:     subjectName,
					Issuer:          issuerName,
				},
				{
					MatchedIdentity: matchedOIDMatcher,
					Index:           1,
					OIDExtension:    matchedAsn1OID,
					ExtensionValue:  extValueString,
				},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			matchedEntries, failedEntries, err := MatchedIndices(tc.inputEntries, tc.inputMonitoredValues, "", "")
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("error matching indices: %v", err)
				}
			}
			expected := tc.expected
			if !reflect.DeepEqual(matchedEntries, expected) {
				t.Errorf("received %v, expected %v", matchedEntries, expected)
			}
			if len(failedEntries) > 0 {
				t.Errorf("received failed entries: %v", failedEntries)
			}
		})
	}
}
