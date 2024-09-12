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
	"testing"
)

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
