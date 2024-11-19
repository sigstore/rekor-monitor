// Copyright 2022 The Sigstore Authors.
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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"reflect"
	"sort"
	"strings"
	"testing"

	google_asn1 "github.com/google/certificate-transparency-go/asn1"
	google_x509 "github.com/google/certificate-transparency-go/x509"
	google_pkix "github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
)

// Test LogEntry.String()
func TestIdentityEntryString(t *testing.T) {
	identityEntry := LogEntry{
		CertSubject: "test-cert-subject",
		UUID:        "test-uuid",
		Index:       1,
	}
	identityEntryString := identityEntry.String()
	expectedIdentityEntryString := "test-cert-subject 1 test-uuid"
	if identityEntryString != expectedIdentityEntryString {
		t.Errorf("expected %s, received %s", expectedIdentityEntryString, identityEntryString)
	}
}

// Test CreateMonitoredIdentities
func TestCreateMonitoredIdentities(t *testing.T) {
	type test struct {
		inputEntries    []LogEntry
		inputIdentities []string
		output          []MonitoredIdentity
	}

	testIdentities := map[string]string{
		"testCertSubject":    "test-cert-subject",
		"testFingerprint":    "test-fingerprint",
		"testExtensionValue": "test-extension-value",
		"testSubject":        "test-subject",
	}

	testUUIDs := map[string]string{
		"testUUID":  "test-uuid",
		"testUUID2": "test-uuid-2",
	}

	testIndexes := map[string]int64{
		"1": int64(1),
		"2": int64(2),
	}

	testIdentityEntries := map[string]LogEntry{
		"testCertSubject1": {
			CertSubject: testIdentities["testCertSubject"],
			UUID:        testUUIDs["testUUID"],
			Index:       testIndexes["1"],
		},
		"testCertSubject2": {
			CertSubject: testIdentities["testCertSubject"],
			UUID:        testUUIDs["testUUID2"],
			Index:       testIndexes["2"],
		},
		"testFingerprint1": {
			Fingerprint: testIdentities["testFingerprint"],
			UUID:        testUUIDs["testUUID"],
			Index:       testIndexes["1"],
		},
		"testFingerprint2": {
			Fingerprint: testIdentities["testFingerprint"],
			UUID:        testUUIDs["testUUID"],
			Index:       testIndexes["2"],
		},
		"testExtensionValue1": {
			ExtensionValue: testIdentities["testExtensionValue"],
			UUID:           testUUIDs["testUUID"],
			Index:          testIndexes["1"],
		},
		"testExtensionValue2": {
			ExtensionValue: testIdentities["testExtensionValue"],
			UUID:           testUUIDs["testUUID"],
			Index:          testIndexes["2"],
		},
		"testSubject1": {
			Subject: testIdentities["testSubject"],
			UUID:    testUUIDs["testUUID"],
			Index:   testIndexes["1"],
		},
		"testSubject2": {
			Subject: testIdentities["testSubject"],
			UUID:    testUUIDs["testUUID"],
			Index:   testIndexes["2"],
		},
	}

	testMonitoredIdentities := map[string]MonitoredIdentity{
		"testMonitoredIdCertSubject1": {
			Identity:             testIdentities["testCertSubject"],
			FoundIdentityEntries: []LogEntry{testIdentityEntries["testCertSubject1"]},
		},
		"testMonitoredIdCertSubject2": {
			Identity:             testIdentities["testCertSubject"],
			FoundIdentityEntries: []LogEntry{testIdentityEntries["testCertSubject1"], testIdentityEntries["testCertSubject2"]},
		},
		"testMonitoredIdFingerprint1": {
			Identity:             testIdentities["testFingerprint"],
			FoundIdentityEntries: []LogEntry{testIdentityEntries["testFingerprint1"]},
		},
		"testMonitoredIdFingerprint2": {
			Identity:             testIdentities["testFingerprint"],
			FoundIdentityEntries: []LogEntry{testIdentityEntries["testFingerprint1"], testIdentityEntries["testFingerprint2"]},
		},
		"testMonitoredIdExtensionValue1": {
			Identity:             testIdentities["testExtensionValue"],
			FoundIdentityEntries: []LogEntry{testIdentityEntries["testExtensionValue1"]},
		},
		"testMonitoredIdExtensionValue2": {
			Identity:             testIdentities["testExtensionValue"],
			FoundIdentityEntries: []LogEntry{testIdentityEntries["testExtensionValue1"], testIdentityEntries["testExtensionValue2"]},
		},
		"testMonitoredIdSubject1": {
			Identity:             testIdentities["testSubject"],
			FoundIdentityEntries: []LogEntry{testIdentityEntries["testSubject1"]},
		},
		"testMonitoredIdSubject2": {
			Identity:             testIdentities["testSubject"],
			FoundIdentityEntries: []LogEntry{testIdentityEntries["testSubject1"], testIdentityEntries["testSubject2"]},
		},
	}

	tests := map[string]test{
		"empty case": {
			inputEntries:    []LogEntry{},
			inputIdentities: []string{},
			output:          []MonitoredIdentity{},
		},
		"one entry for given identity": {
			inputEntries:    []LogEntry{testIdentityEntries["testCertSubject1"]},
			inputIdentities: []string{testIdentities["testCertSubject"]},
			output:          []MonitoredIdentity{testMonitoredIdentities["testMonitoredIdCertSubject1"]},
		},
		"multiple log entries under same identity": {
			inputEntries:    []LogEntry{testIdentityEntries["testCertSubject1"], testIdentityEntries["testCertSubject2"]},
			inputIdentities: []string{testIdentities["testCertSubject"]},
			output:          []MonitoredIdentity{testMonitoredIdentities["testMonitoredIdCertSubject2"]},
		},
		"no log entries matching given identity": {
			inputEntries:    []LogEntry{testIdentityEntries["testCertSubject1"], testIdentityEntries["testCertSubject2"]},
			inputIdentities: []string{testIdentities["testFingerprint"]},
			output:          []MonitoredIdentity{},
		},
		"test all identities": {
			inputEntries:    []LogEntry{testIdentityEntries["testCertSubject1"], testIdentityEntries["testFingerprint1"], testIdentityEntries["testExtensionValue1"], testIdentityEntries["testSubject1"], testIdentityEntries["testCertSubject2"], testIdentityEntries["testFingerprint2"], testIdentityEntries["testExtensionValue2"], testIdentityEntries["testSubject2"]},
			inputIdentities: []string{testIdentities["testCertSubject"], testIdentities["testFingerprint"], testIdentities["testExtensionValue"], testIdentities["testSubject"]},
			output:          []MonitoredIdentity{testMonitoredIdentities["testMonitoredIdCertSubject2"], testMonitoredIdentities["testMonitoredIdExtensionValue2"], testMonitoredIdentities["testMonitoredIdFingerprint2"], testMonitoredIdentities["testMonitoredIdSubject2"]},
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			createMonitoredIdentitiesOutput := CreateMonitoredIdentities(testCase.inputEntries, testCase.inputIdentities)
			sort.Slice(createMonitoredIdentitiesOutput, func(i, j int) bool {
				return createMonitoredIdentitiesOutput[i].Identity < createMonitoredIdentitiesOutput[j].Identity
			})
			if !reflect.DeepEqual(createMonitoredIdentitiesOutput, testCase.output) {
				t.Errorf("expected %v, got %v", testCase.output, createMonitoredIdentitiesOutput)
			}
		})
	}
}

// Test PrintMonitoredIdentities
func TestPrintMonitoredIdentities(t *testing.T) {
	monitoredIdentity := MonitoredIdentity{
		Identity: "test-identity",
		FoundIdentityEntries: []LogEntry{
			{
				CertSubject: "test-cert-subject",
				UUID:        "test-uuid",
				Index:       0,
			},
		},
	}
	parsedMonitoredIdentity, err := PrintMonitoredIdentities([]MonitoredIdentity{monitoredIdentity})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	expectedParsedMonitoredIdentityOutput := strings.Fields(`[
        	{
        		"identity": "test-identity",
        		"foundIdentityEntries": [
        			{
        				"CertSubject": "test-cert-subject",
        				"Issuer": "",
        				"Fingerprint": "",
        				"Subject": "",
        				"Index": 0,
        				"UUID": "test-uuid",
        				"OIDExtension": null,
        				"ExtensionValue": ""
        			}
        		]
        	}
        ]`)
	parsedMonitoredIdentityFields := strings.Fields(string(parsedMonitoredIdentity))
	if !reflect.DeepEqual(parsedMonitoredIdentityFields, expectedParsedMonitoredIdentityOutput) {
		t.Errorf("expected parsed monitored identity to equal %s, got %s", expectedParsedMonitoredIdentityOutput, parsedMonitoredIdentityFields)
	}
}

func TestMonitoredValuesExist(t *testing.T) {
	testCases := map[string]struct {
		mvs      MonitoredValues
		expected bool
	}{
		"empty case": {
			mvs:      MonitoredValues{},
			expected: false,
		},
		"fingerprints": {
			mvs: MonitoredValues{
				Fingerprints: []string{"test fingerprint"},
			},
			expected: true,
		},
		"subjects": {
			mvs: MonitoredValues{
				Subjects: []string{"test subject"},
			},
			expected: true,
		},
		"certificate identities": {
			mvs: MonitoredValues{
				CertificateIdentities: []CertificateIdentity{
					{
						CertSubject: "test cert subject",
						Issuers:     []string{"test issuer"},
					},
				},
			},
			expected: true,
		},
		"oid matchers": {
			mvs: MonitoredValues{
				OIDMatchers: []extensions.OIDExtension{
					{
						ObjectIdentifier: asn1.ObjectIdentifier{1},
						ExtensionValues:  []string{"test extension value"},
					},
				},
			},
			expected: true,
		},
	}
	for testCaseName, testCase := range testCases {
		result := MonitoredValuesExist(testCase.mvs)
		expected := testCase.expected
		if result != expected {
			t.Errorf("%s failed: expected %t, received %t", testCaseName, result, expected)
		}
	}
}

func TestCreateIdentitiesList(t *testing.T) {
	testCases := map[string]struct {
		input    MonitoredValues
		expected []string
	}{
		"empty input": {
			input:    MonitoredValues{},
			expected: []string{},
		},
		"multiple identities": {
			input: MonitoredValues{
				CertificateIdentities: []CertificateIdentity{
					{
						CertSubject: "example-cert-subject",
						Issuers:     []string{},
					},
				},
				Fingerprints: []string{"example-fingerprint"},
				Subjects:     []string{"example-subject"},
				OIDMatchers: []extensions.OIDExtension{
					{
						ObjectIdentifier: asn1.ObjectIdentifier{1, 4, 1, 9},
						ExtensionValues:  []string{"example-oid-matcher"},
					},
				},
			},
			expected: []string{
				"example-cert-subject", "example-fingerprint", "example-subject", "example-oid-matcher",
			},
		},
	}
	for _, tc := range testCases {
		result := CreateIdentitiesList(tc.input)
		expected := tc.expected
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("expected %v, received %v", expected, result)
		}
	}
}

func mockCertificateWithExtension(oid asn1.ObjectIdentifier, value string) (*x509.Certificate, error) {
	extValue, err := asn1.Marshal(value)
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{
		Extensions: []pkix.Extension{
			{
				Id:       oid,
				Critical: false,
				Value:    extValue,
			},
		},
	}
	return cert, nil
}

// Test when OID is present but the value does not match
func TestOIDDoesNotMatch(t *testing.T) {
	cert, err := mockCertificateWithExtension(asn1.ObjectIdentifier{2, 5, 29, 17}, "test cert value")
	if err != nil {
		t.Errorf("Expected nil got %v", err)
	}
	oid := asn1.ObjectIdentifier{2, 5, 29, 17}
	extensionValues := []string{"wrong value"}

	matches, _, _, err := OIDMatchesPolicy(cert, oid, extensionValues)
	if matches || err != nil {
		t.Errorf("Expected false without error, got %v, error %v", matches, err)
	}
}

// Test when OID is not present in the certificate
func TestOIDNotPresent(t *testing.T) {
	cert := &x509.Certificate{} // No extensions
	oid := asn1.ObjectIdentifier{2, 5, 29, 17}
	extensionValues := []string{"wrong value"}

	matches, _, _, err := OIDMatchesPolicy(cert, oid, extensionValues)
	if matches || err != nil {
		t.Errorf("Expected false with nil, got %v, error %v", matches, err)
	}
}

// Test when OID is present and matches value
func TestOIDMatchesValue(t *testing.T) {
	cert, err := mockCertificateWithExtension(asn1.ObjectIdentifier{2, 5, 29, 17}, "test cert value")
	if err != nil {
		t.Errorf("Expected nil got %v", err)
	}
	oid := asn1.ObjectIdentifier{2, 5, 29, 17}
	extValueString := "test cert value"
	extensionValues := []string{extValueString}

	matches, matchedOID, extValue, err := OIDMatchesPolicy(cert, oid, extensionValues)
	if !matches || err != nil {
		t.Errorf("Expected true, got %v, error %v", matches, err)
	}
	if matchedOID.String() != oid.String() {
		t.Errorf("Expected oid to equal 2.5.29.17, got %s", matchedOID.String())
	}
	if extValue != extValueString {
		t.Errorf("Expected string to equal 'test cert value', got %s", extValue)
	}
}

// Test when OID is present and matches value
func TestGoogleOIDMatchesValue(t *testing.T) {
	oid := asn1.ObjectIdentifier{2, 5, 29, 17}
	extValueString := "test cert value"
	extensionValues := []string{extValueString}
	marshalledExtValue, err := google_asn1.Marshal(extValueString)
	if err != nil {
		t.Errorf("error marshalling extension value: %v", err)
	}
	cert := &google_x509.Certificate{
		Extensions: []google_pkix.Extension{
			{
				Id:    google_asn1.ObjectIdentifier{2, 5, 29, 17},
				Value: marshalledExtValue,
			},
		},
	}
	matches, matchedOID, extValue, err := OIDMatchesPolicy(cert, oid, extensionValues)
	if !matches || err != nil {
		t.Errorf("Expected true, got %v, error %v", matches, err)
	}
	if matchedOID.String() != oid.String() {
		t.Errorf("Expected oid to equal 2.5.29.17, got %s", matchedOID.String())
	}
	if extValue != extValueString {
		t.Errorf("Expected string to equal 'test cert value', got %s", extValue)
	}
}

// Test when cert is present but the value does not match
func TestCertDoesNotMatch(t *testing.T) {
	emailAddr := "test@address.com"
	cert := &x509.Certificate{
		EmailAddresses: []string{emailAddr},
	}
	matches, _, _, err := CertMatchesPolicy(cert, "", []string{})
	if matches || err != nil {
		t.Errorf("Expected false without error, got %v, error %v", matches, err)
	}
}

// Test when cert is present but the value does not match
func TestCertMatches(t *testing.T) {
	emailAddr := "test@address.com"
	issuer := "test-issuer"
	cert := &x509.Certificate{
		EmailAddresses: []string{emailAddr},
		Extensions: []pkix.Extension{
			{
				Id:    certExtensionOIDCIssuer,
				Value: []byte(issuer),
			},
		},
	}
	matches, receivedSub, receivedIssuer, err := CertMatchesPolicy(cert, emailAddr, []string{issuer})
	if !matches || err != nil {
		t.Errorf("Expected true without error, got %v, error %v", matches, err)
	}
	if receivedSub != emailAddr || receivedIssuer != issuer {
		t.Errorf("expected subject %s and issuer %s, received subject %s and issuer %s", emailAddr, issuer, receivedSub, receivedIssuer)
	}
}

func TestGoogleCertMatches(t *testing.T) {
	emailAddr := "test@address.com"
	issuer := "test-issuer"
	cert := &google_x509.Certificate{
		EmailAddresses: []string{emailAddr},
		Extensions: []google_pkix.Extension{
			{
				Id:    (google_asn1.ObjectIdentifier)(certExtensionOIDCIssuer),
				Value: []byte(issuer),
			},
		},
	}
	matches, receivedSub, receivedIssuer, err := CertMatchesPolicy(cert, emailAddr, []string{issuer})
	if !matches || err != nil {
		t.Errorf("Expected true without error, got %v, error %v", matches, err)
	}
	if receivedSub != emailAddr || receivedIssuer != issuer {
		t.Errorf("expected subject %s and issuer %s, received subject %s and issuer %s", emailAddr, issuer, receivedSub, receivedIssuer)
	}
}
