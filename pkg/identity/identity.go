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

package identity

import (
	"encoding/asn1"
	"errors"
	"strconv"
	"strings"
)

// OIDMatcher holds an OID field and a list of values to match on
type OIDMatcher struct {
	ObjectIdentifier asn1.ObjectIdentifier `yaml:"objectIdentifier"`
	ExtensionValues  []string              `yaml:"extensionValues"`
}

// CustomOID holds an OID field represented in dot notation and a list of values to match on
type CustomExtension struct {
	ObjectIdentifier string   `yaml:"objectIdentifier"`
	ExtensionValues  []string `yaml:"extensionValues"`
}

// ParseObjectIdentifier parses a string representing an ObjectIdentifier in dot notation
// and converts it into an asn1.ObjectIdentiifer.
func ParseObjectIdentifier(oid string) (asn1.ObjectIdentifier, error) {
	if len(oid) == 0 {
		return nil, errors.New("could not parse object identifier: empty input")
	}
	nodes := strings.Split(oid, ".")
	objectIdentifier := make([]int, len(nodes))
	for i, node := range nodes {
		if strings.TrimSpace(node) == "" {
			return nil, errors.New("could not parse object identifier: no characters between two dots")
		}
		intNode, err := strconv.Atoi(node)
		if err != nil {
			return nil, err
		}
		objectIdentifier[i] = intNode
	}
	return asn1.ObjectIdentifier(objectIdentifier), nil
}
