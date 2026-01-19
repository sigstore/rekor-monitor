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
		inputEntries []LogEntry
		output       []MonitoredIdentity
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

	// MonitoredValue instances
	testMVCertSubject := CertIdentityValue{CertSubject: testIdentities["testCertSubject"]}
	testMVFingerprint := FingerprintValue{Fingerprint: testIdentities["testFingerprint"]}
	testMVExtensionValue := OIDMatcherValue{OID: asn1.ObjectIdentifier{1}, ExtensionValues: []string{testIdentities["testExtensionValue"]}}
	testMVSubject := SubjectValue{Subject: testIdentities["testSubject"]}

	testIdentityEntries := map[string]LogEntry{
		"testCertSubject1": {
			MatchedIdentity: testMVCertSubject,
			CertSubject:     testIdentities["testCertSubject"],
			UUID:            testUUIDs["testUUID"],
			Index:           testIndexes["1"],
		},
		"testCertSubject2": {
			MatchedIdentity: testMVCertSubject,
			CertSubject:     testIdentities["testCertSubject"],
			UUID:            testUUIDs["testUUID2"],
			Index:           testIndexes["2"],
		},
		"testFingerprint1": {
			MatchedIdentity: testMVFingerprint,
			Fingerprint:     testIdentities["testFingerprint"],
			UUID:            testUUIDs["testUUID"],
			Index:           testIndexes["1"],
		},
		"testFingerprint2": {
			MatchedIdentity: testMVFingerprint,
			Fingerprint:     testIdentities["testFingerprint"],
			UUID:            testUUIDs["testUUID"],
			Index:           testIndexes["2"],
		},
		"testExtensionValue1": {
			MatchedIdentity: testMVExtensionValue,
			ExtensionValue:  testIdentities["testExtensionValue"],
			UUID:            testUUIDs["testUUID"],
			Index:           testIndexes["1"],
		},
		"testExtensionValue2": {
			MatchedIdentity: testMVExtensionValue,
			ExtensionValue:  testIdentities["testExtensionValue"],
			UUID:            testUUIDs["testUUID"],
			Index:           testIndexes["2"],
		},
		"testSubject1": {
			MatchedIdentity: testMVSubject,
			Subject:         testIdentities["testSubject"],
			UUID:            testUUIDs["testUUID"],
			Index:           testIndexes["1"],
		},
		"testSubject2": {
			MatchedIdentity: testMVSubject,
			Subject:         testIdentities["testSubject"],
			UUID:            testUUIDs["testUUID"],
			Index:           testIndexes["2"],
		},
	}

	tests := map[string]test{
		"empty case": {
			inputEntries: []LogEntry{},
			output:       []MonitoredIdentity{},
		},
		"one entry for given identity": {
			inputEntries: []LogEntry{testIdentityEntries["testCertSubject1"]},
			output: []MonitoredIdentity{
				{
					Identity:             testMVCertSubject,
					FoundIdentityEntries: []LogEntry{testIdentityEntries["testCertSubject1"]},
				},
			},
		},
		"multiple log entries under same identity": {
			inputEntries: []LogEntry{testIdentityEntries["testCertSubject1"], testIdentityEntries["testCertSubject2"]},
			output: []MonitoredIdentity{
				{
					Identity:             testMVCertSubject,
					FoundIdentityEntries: []LogEntry{testIdentityEntries["testCertSubject1"], testIdentityEntries["testCertSubject2"]},
				},
			},
		},
		"test all identities": {
			inputEntries: []LogEntry{testIdentityEntries["testCertSubject1"], testIdentityEntries["testFingerprint1"], testIdentityEntries["testExtensionValue1"], testIdentityEntries["testSubject1"], testIdentityEntries["testCertSubject2"], testIdentityEntries["testFingerprint2"], testIdentityEntries["testExtensionValue2"], testIdentityEntries["testSubject2"]},
			output: []MonitoredIdentity{
				{
					Identity:             testMVCertSubject,
					FoundIdentityEntries: []LogEntry{testIdentityEntries["testCertSubject1"], testIdentityEntries["testCertSubject2"]},
				},
				{
					Identity:             testMVExtensionValue,
					FoundIdentityEntries: []LogEntry{testIdentityEntries["testExtensionValue1"], testIdentityEntries["testExtensionValue2"]},
				},
				{
					Identity:             testMVFingerprint,
					FoundIdentityEntries: []LogEntry{testIdentityEntries["testFingerprint1"], testIdentityEntries["testFingerprint2"]},
				},
				{
					Identity:             testMVSubject,
					FoundIdentityEntries: []LogEntry{testIdentityEntries["testSubject1"], testIdentityEntries["testSubject2"]},
				},
			},
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			createMonitoredIdentitiesOutput := CreateMonitoredIdentities(testCase.inputEntries)
			sort.Slice(createMonitoredIdentitiesOutput, func(i, j int) bool {
				return createMonitoredIdentitiesOutput[i].Identity.String() < createMonitoredIdentitiesOutput[j].Identity.String()
			})
			sort.Slice(testCase.output, func(i, j int) bool {
				return testCase.output[i].Identity.String() < testCase.output[j].Identity.String()
			})
			if !reflect.DeepEqual(createMonitoredIdentitiesOutput, testCase.output) {
				t.Errorf("expected %v, got %v", testCase.output, createMonitoredIdentitiesOutput)
			}
		})
	}
}

// Test PrintMonitoredIdentities
func TestPrintMonitoredIdentities(t *testing.T) {
	testCertIdentity := CertIdentityValue{CertSubject: "test-identity"}
	monitoredIdentity := MonitoredIdentity{
		Identity: testCertIdentity,
		FoundIdentityEntries: []LogEntry{
			{
				MatchedIdentity: testCertIdentity,
				CertSubject:     "test-cert-subject",
				UUID:            "test-uuid",
				Index:           0,
			},
		},
	}
	parsedMonitoredIdentity, err := PrintMonitoredIdentities([]MonitoredIdentity{monitoredIdentity})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	// Just check that it doesn't error and contains key elements
	parsedStr := string(parsedMonitoredIdentity)
	if !strings.Contains(parsedStr, "test-identity") {
		t.Errorf("expected output to contain 'test-identity', got %s", parsedStr)
	}
	if !strings.Contains(parsedStr, "test-cert-subject") {
		t.Errorf("expected output to contain 'test-cert-subject', got %s", parsedStr)
	}
	if !strings.Contains(parsedStr, "certIdentity") {
		t.Errorf("expected output to contain 'certIdentity' type, got %s", parsedStr)
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

// mockCertificateWithRawExtension creates a certificate with a raw string extension
// (not ASN.1 encoded), simulating the deprecated Fulcio extension format
func mockCertificateWithRawExtension(oid asn1.ObjectIdentifier, value string) *x509.Certificate {
	return &x509.Certificate{
		Extensions: []pkix.Extension{
			{
				Id:       oid,
				Critical: false,
				Value:    []byte(value), // Raw bytes, not ASN.1 encoded
			},
		},
	}
}

// mockGoogleCertificateWithRawExtension creates a google_x509 certificate with a raw string extension
func mockGoogleCertificateWithRawExtension(oid asn1.ObjectIdentifier, value string) *google_x509.Certificate {
	return &google_x509.Certificate{
		Extensions: []google_pkix.Extension{
			{
				Id:       (google_asn1.ObjectIdentifier)(oid),
				Critical: false,
				Value:    []byte(value), // Raw bytes, not ASN.1 encoded
			},
		},
	}
}

// Test OIDMatchesPolicy falls back to raw string when ASN.1 unmarshalling fails
func TestOIDMatchesRawStringFallback(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1} // Fulcio deprecated issuer OID
	extValueString := "https://github.com/login/oauth"

	// Create certificate with raw string extension (not ASN.1 encoded)
	cert := mockCertificateWithRawExtension(oid, extValueString)

	matches, matchedOID, extValue, err := OIDMatchesPolicy(cert, oid, []string{extValueString})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !matches {
		t.Errorf("Expected match to be true, got false")
	}
	if matchedOID.String() != oid.String() {
		t.Errorf("Expected OID %s, got %s", oid.String(), matchedOID.String())
	}
	if extValue != extValueString {
		t.Errorf("Expected extension value '%s', got '%s'", extValueString, extValue)
	}
}

// Test OIDMatchesPolicy with raw string extension that doesn't match value
func TestOIDRawStringNoMatch(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	certValue := "https://github.com/login/oauth"
	wrongValue := "https://accounts.google.com"

	cert := mockCertificateWithRawExtension(oid, certValue)

	matches, _, _, err := OIDMatchesPolicy(cert, oid, []string{wrongValue})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if matches {
		t.Errorf("Expected match to be false, got true")
	}
}

// Test OIDMatchesPolicy falls back to raw string for google_x509 certificate
func TestGoogleOIDMatchesRawStringFallback(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	extValueString := "https://github.com/login/oauth"

	cert := mockGoogleCertificateWithRawExtension(oid, extValueString)

	matches, matchedOID, extValue, err := OIDMatchesPolicy(cert, oid, []string{extValueString})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !matches {
		t.Errorf("Expected match to be true, got false")
	}
	if matchedOID.String() != oid.String() {
		t.Errorf("Expected OID %s, got %s", oid.String(), matchedOID.String())
	}
	if extValue != extValueString {
		t.Errorf("Expected extension value '%s', got '%s'", extValueString, extValue)
	}
}

// Test OIDMatchesPolicy with multiple extension values where one matches (raw string)
func TestOIDRawStringMultipleValuesOneMatch(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	certValue := "https://github.com/login/oauth"

	cert := mockCertificateWithRawExtension(oid, certValue)

	extensionValues := []string{
		"https://accounts.google.com",
		"https://github.com/login/oauth",
		"https://token.actions.githubusercontent.com",
	}

	matches, matchedOID, extValue, err := OIDMatchesPolicy(cert, oid, extensionValues)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !matches {
		t.Errorf("Expected match to be true, got false")
	}
	if matchedOID.String() != oid.String() {
		t.Errorf("Expected OID %s, got %s", oid.String(), matchedOID.String())
	}
	if extValue != certValue {
		t.Errorf("Expected extension value '%s', got '%s'", certValue, extValue)
	}
}

// Test OIDMatchesPolicy prefers ASN.1 encoding over raw string when valid
func TestOIDPrefersASN1OverRawString(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8} // Fulcio v2 issuer OID
	extValueString := "https://accounts.google.com"

	// Create certificate with properly ASN.1 encoded extension
	cert, err := mockCertificateWithExtension(oid, extValueString)
	if err != nil {
		t.Fatalf("Failed to create mock certificate: %v", err)
	}

	matches, matchedOID, extValue, err := OIDMatchesPolicy(cert, oid, []string{extValueString})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !matches {
		t.Errorf("Expected match to be true, got false")
	}
	if matchedOID.String() != oid.String() {
		t.Errorf("Expected OID %s, got %s", oid.String(), matchedOID.String())
	}
	if extValue != extValueString {
		t.Errorf("Expected extension value '%s', got '%s'", extValueString, extValue)
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
