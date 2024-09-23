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
	}}, FulcioExtensions{}, []CustomExtension{})
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
	if len(oidMatchers) != 2 {
		t.Errorf("Expected 1 OIDMatcher, got %d", len(oidMatchers))
	}
}

// test ParseObjectIdentifier
func TestParseObjectIdentifier(t *testing.T) {
	oid, err := ParseObjectIdentifier("")
	if err == nil {
		t.Errorf("Expected error, got nil and oid %s", oid)
	}

	oid, err = ParseObjectIdentifier(".")
	if err == nil {
		t.Errorf("Expected error, got nil and oid %s", oid)
	}

	oid, err = ParseObjectIdentifier("....")
	if err == nil {
		t.Errorf("Expected error, got nil and oid %s", oid)
	}

	oid, err = ParseObjectIdentifier("a.a")
	if err == nil {
		t.Errorf("Expected error, got nil and oid %s", oid)
	}

	oid, err = ParseObjectIdentifier("1.")
	if err == nil {
		t.Errorf("Expected error, got nil and oid %s", oid)
	}

	oid, err = ParseObjectIdentifier("1.1.5.6.7.8..")
	if err == nil {
		t.Errorf("Expected error, got nil and oid %s", oid)
	}

	oid, err = ParseObjectIdentifier(".1.1.5.67.8")
	if err == nil {
		t.Errorf("Expected error, got nil and oid %s", oid)
	}

	_, err = ParseObjectIdentifier("1")
	if err != nil {
		t.Errorf("Expected nil, got error %v", err)
	}

	_, err = ParseObjectIdentifier("1.4.1.5")
	if err != nil {
		t.Errorf("Expected nil, got error %v", err)
	}

	_, err = ParseObjectIdentifier("11254215212.4.123.54.1.622")
	if err != nil {
		t.Errorf("Expected nil, got error %v", err)
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
