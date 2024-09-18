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
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Test RekorLogEntry.String()
func TestIdentityEntryString(t *testing.T) {
	identityEntry := RekorLogEntry{
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
		inputEntries    []RekorLogEntry
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

	testIdentityEntries := map[string]RekorLogEntry{
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
			CertSubject: testIdentities["testFingerprint"],
			UUID:        testUUIDs["testUUID"],
			Index:       testIndexes["1"],
		},
		"testExtensionValue1": {
			ExtensionValue: testIdentities["testExtensionValue"],
			UUID:           testUUIDs["testUUID"],
			Index:          testIndexes["1"],
		},
		"testSubject1": {
			ExtensionValue: testIdentities["testSubject"],
			UUID:           testUUIDs["testUUID"],
			Index:          testIndexes["1"],
		},
	}

	testMonitoredIdentities := map[string]MonitoredIdentity{
		"testMonitoredIdCertSubject1": {
			Identity:             testIdentities["testCertSubject"],
			FoundIdentityEntries: []RekorLogEntry{testIdentityEntries["testCertSubject1"]},
		},
		"testMonitoredIdCertSubject2": {
			Identity:             testIdentities["testCertSubject"],
			FoundIdentityEntries: []RekorLogEntry{testIdentityEntries["testCertSubject1"], testIdentityEntries["testCertSubject2"]},
		},
		"testMonitoredIdFingerprint1": {
			Identity:             testIdentities["testFingerprint"],
			FoundIdentityEntries: []RekorLogEntry{testIdentityEntries["testFingerprint1"]},
		},
		"testMonitoredIdExtensionValue1": {
			Identity:             testIdentities["testExtensionValue"],
			FoundIdentityEntries: []RekorLogEntry{testIdentityEntries["testExtensionValue1"]},
		},
		"testMonitoredIdSubject1": {
			Identity:             testIdentities["testSubject"],
			FoundIdentityEntries: []RekorLogEntry{testIdentityEntries["testSubject1"]},
		},
	}

	tests := map[string]test{
		"empty case": {
			inputEntries:    []RekorLogEntry{},
			inputIdentities: []string{},
			output:          []MonitoredIdentity{},
		},
		"one entry for given identity": {
			inputEntries:    []RekorLogEntry{testIdentityEntries["testCertSubject1"]},
			inputIdentities: []string{testIdentities["testCertSubject"]},
			output:          []MonitoredIdentity{testMonitoredIdentities["testMonitoredIdCertSubject1"]},
		},
		"multiple log entries under same identity": {
			inputEntries:    []RekorLogEntry{testIdentityEntries["testCertSubject1"], testIdentityEntries["testCertSubject2"]},
			inputIdentities: []string{testIdentities["testCertSubject"]},
			output:          []MonitoredIdentity{testMonitoredIdentities["testMonitoredIdCertSubject2"]},
		},
		"no log entries matching given identity": {
			inputEntries:    []RekorLogEntry{testIdentityEntries["testCertSubject1"], testIdentityEntries["testCertSubject2"]},
			inputIdentities: []string{testIdentities["testFingerprint"]},
			output:          []MonitoredIdentity{},
		},
		"test all identities": {
			inputEntries:    []RekorLogEntry{testIdentityEntries["testCertSubject1"], testIdentityEntries["testFingerprint1"], testIdentityEntries["testExtensionValue1"], testIdentityEntries["testSubject1"]},
			inputIdentities: []string{testIdentities["testCertSubject"], testIdentities["testFingerprint"], testIdentities["testExtensionValue"], testIdentities["testSubject"]},
			output:          []MonitoredIdentity{testMonitoredIdentities["testMonitoredIdCertSubject1"], testMonitoredIdentities["testMonitoredIdExtensionValue1"], testMonitoredIdentities["testMonitoredIdFingerprint1"], testMonitoredIdentities["testMonitoredIdSubject1"]},
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

// Test ParseMonitoredIdentitiesAsJSON
func TestParseMonitoredIdentitiesAsJSON(t *testing.T) {
	monitoredIdentity := MonitoredIdentity{
		Identity: "test-identity",
		FoundIdentityEntries: []RekorLogEntry{
			{
				CertSubject: "test-cert-subject",
				UUID:        "test-uuid",
				Index:       0,
			},
		},
	}
	parsedMonitoredIdentity, err := ParseMonitoredIdentitiesAsJSON([]MonitoredIdentity{monitoredIdentity})
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
