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
	"reflect"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/sigstore/rekor-monitor/pkg/identity"
)

const (
	subjectName      = "test-subject"
	organizationName = "test-org"
)

func TestScanEntrySubject(t *testing.T) {
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
