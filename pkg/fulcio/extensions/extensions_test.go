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

package extensions

import (
	"encoding/asn1"
	"errors"
	"testing"
)

// Test mergeOIDMatchers
func TestMergeOIDMatchers(t *testing.T) {
	oidMatchers, err := MergeOIDMatchers([]OIDMatcher{{
		ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
		ExtensionValues:  []string{},
	}}, FulcioExtensions{}, []CustomExtension{})
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
	if len(oidMatchers) != 1 {
		t.Errorf("Expected 1 OIDMatcher, got %d", len(oidMatchers))
	}

	oidMatchers, err = MergeOIDMatchers([]OIDMatcher{{
		ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
		ExtensionValues:  []string{""},
	}}, FulcioExtensions{}, []CustomExtension{})
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
	if len(oidMatchers) != 1 {
		t.Errorf("Expected 1 OIDMatcher, got %d", len(oidMatchers))
	}

	oidMatchers, err = MergeOIDMatchers([]OIDMatcher{{
		ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
		ExtensionValues:  []string{"test", "test2"},
	}}, FulcioExtensions{}, []CustomExtension{})
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
	if len(oidMatchers) != 1 {
		t.Errorf("Expected 1 OIDMatcher, got %d", len(oidMatchers))
	}

	oidMatchers, err = MergeOIDMatchers([]OIDMatcher{{
		ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
		ExtensionValues:  []string{"test1"},
	}, {
		ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
		ExtensionValues:  []string{"test"},
	}}, FulcioExtensions{}, []CustomExtension{})
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
	if len(oidMatchers) != 1 {
		t.Errorf("Expected 1 OIDMatcher, got %d", len(oidMatchers))
	}

	oidMatchers, err = MergeOIDMatchers([]OIDMatcher{{
		ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 17},
		ExtensionValues:  []string{"test1"},
	}, {
		ObjectIdentifier: asn1.ObjectIdentifier{2, 5, 29, 18},
		ExtensionValues:  []string{"test"},
	}}, FulcioExtensions{
		BuildConfigDigest: []string{"test"},
	}, []CustomExtension{{
		ObjectIdentifier: "2.5.29.16",
		ExtensionValues:  []string{"test"},
	}})
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
	if len(oidMatchers) != 4 {
		t.Errorf("Expected 4 OIDMatchers, got %d", len(oidMatchers))
	}
}

// test ParseObjectIdentifier
func TestParseObjectIdentifier(t *testing.T) {
	// success cases
	objectIdentifierTests := map[string]struct {
		oid         string
		expectedErr error
	}{
		"empty string": {
			oid:         "",
			expectedErr: errors.New("could not parse object identifier: empty input"),
		},
		"one dot": {
			oid:         ".",
			expectedErr: errors.New("could not parse object identifier: no characters between two dots"),
		},
		"four dots": {
			oid:         "....",
			expectedErr: errors.New("could not parse object identifier: no characters between two dots"),
		},
		"letters": {
			oid:         "a.a",
			expectedErr: errors.New("strconv.Atoi: parsing \"a\": invalid syntax"),
		},
		"ending dot": {
			oid:         "1.",
			expectedErr: errors.New("could not parse object identifier: no characters between two dots"),
		},
		"ending dots": {
			oid:         "1.1.5.6.7.8..",
			expectedErr: errors.New("could not parse object identifier: no characters between two dots"),
		},
		"leading dot": {
			oid:         ".1.1.5.67.8",
			expectedErr: errors.New("could not parse object identifier: no characters between two dots"),
		},
		"one number": {
			oid:         "1",
			expectedErr: nil,
		},
		"4 numbers, correctly spaced": {
			oid:         "1.4.1.5",
			expectedErr: nil,
		},
		"long numbers": {
			oid:         "11254215212.4.123.54.1.622",
			expectedErr: nil,
		},
	}
	for name, testCase := range objectIdentifierTests {
		t.Run(name, func(t *testing.T) {
			oid, err := ParseObjectIdentifier(testCase.oid)
			if err != nil && (testCase.expectedErr == nil || err.Error() != testCase.expectedErr.Error()) {
				t.Errorf("for oid %s, expected error %v, received %v", oid, testCase.expectedErr, err)
			}
		})
	}
}

// test renderFulcioOIDMatchers
func TestRenderFulcioOIDMatchers(t *testing.T) {
	extValueString := "test cert value"
	fulcioExtensions := FulcioExtensions{
		BuildSignerURI: []string{extValueString},
		BuildConfigURI: []string{"1", "2", "3", "4", "5", "6"},
	}

	renderedFulcioOIDMatchers, err := fulcioExtensions.RenderFulcioOIDMatchers()
	if err != nil {
		t.Errorf("expected nil, received error %v", err)
	}

	if len(renderedFulcioOIDMatchers) != 2 {
		t.Errorf("expected OIDMatchers to have length 2, received length %d", len(renderedFulcioOIDMatchers))
	}

	buildSignerURIMatcher := renderedFulcioOIDMatchers[0]
	buildSignerURIMatcherOID := buildSignerURIMatcher.ObjectIdentifier
	buildSignerURIMatcherExtValues := buildSignerURIMatcher.ExtensionValues
	if !buildSignerURIMatcherOID.Equal(OIDBuildSignerURI) {
		t.Errorf("expected OIDMatcher to be BuildSignerURI 1.3.6.1.4.1.57264.1.9, received %s", buildSignerURIMatcherOID)
	}
	if len(buildSignerURIMatcherExtValues) != 1 {
		t.Errorf("expected BuildSignerURI extension values to have length 1, received %d", len(buildSignerURIMatcherExtValues))
	}
	buildSignerURIMatcherExtValue := buildSignerURIMatcherExtValues[0]
	if buildSignerURIMatcherExtValue != extValueString {
		t.Errorf("expected BuildSignerURI extension value to be 'test cert value', received %s", buildSignerURIMatcherExtValue)
	}

	buildConfigURIMatcher := renderedFulcioOIDMatchers[1]
	buildConfigURIMatcherOID := buildConfigURIMatcher.ObjectIdentifier
	buildConfigURIMatcherExtValues := buildConfigURIMatcher.ExtensionValues
	if !buildConfigURIMatcherOID.Equal(OIDBuildConfigURI) {
		t.Errorf("expected OIDMatcher to be BuildConfigURI 1.3.6.1.4.1.57264.1.18, received %s", buildConfigURIMatcherOID)
	}

	if len(buildConfigURIMatcherExtValues) != 6 {
		t.Errorf("expected BuildConfigURI extension values to have length 6, received %d", len(buildConfigURIMatcherExtValues))
	}
}

func TestRenderFulcioOIDMatchersAllFields(t *testing.T) {
	testValueString := "test"
	fulcioExtensions := FulcioExtensions{
		Issuer:                              []string{testValueString},
		GithubWorkflowTrigger:               []string{testValueString},
		GithubWorkflowSHA:                   []string{testValueString},
		GithubWorkflowName:                  []string{testValueString},
		GithubWorkflowRepository:            []string{testValueString},
		GithubWorkflowRef:                   []string{testValueString},
		BuildSignerURI:                      []string{testValueString},
		BuildConfigURI:                      []string{testValueString},
		BuildSignerDigest:                   []string{testValueString},
		RunnerEnvironment:                   []string{testValueString},
		SourceRepositoryURI:                 []string{testValueString},
		SourceRepositoryDigest:              []string{testValueString},
		SourceRepositoryIdentifier:          []string{testValueString},
		SourceRepositoryRef:                 []string{testValueString},
		SourceRepositoryOwnerURI:            []string{testValueString},
		SourceRepositoryOwnerIdentifier:     []string{testValueString},
		SourceRepositoryVisibilityAtSigning: []string{testValueString},
		BuildConfigDigest:                   []string{testValueString},
		BuildTrigger:                        []string{testValueString},
		RunInvocationURI:                    []string{testValueString},
	}

	renderedFulcioOIDMatchers, err := fulcioExtensions.RenderFulcioOIDMatchers()
	if err != nil {
		t.Errorf("expected nil, received error %v", err)
	}

	if len(renderedFulcioOIDMatchers) != 21 {
		t.Errorf("expected OIDMatchers to have length 21, received length %d", len(renderedFulcioOIDMatchers))
	}
}
