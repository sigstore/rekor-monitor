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
	"strconv"
	"strings"

	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
)

// CertificateIdentity holds a certificate subject and an optional list of identity issuers
type CertificateIdentity struct {
	CertSubject string   `yaml:"certSubject"`
	Issuers     []string `yaml:"issuers"`
}

// MonitoredValues holds a set of values to compare against a given entry
type MonitoredValues struct {
	// CertificateIdentities contains a list of subjects and issuers
	CertificateIdentities []CertificateIdentity `yaml:"certIdentities"`
	// Fingerprints contains a list of key fingerprints. Values are as follows:
	// For keys, certificates, and minisign, hex-encoded SHA-256 digest
	// of the DER-encoded PKIX public key or certificate
	// For SSH and PGP, the standard for each ecosystem:
	// For SSH, unpadded base-64 encoded SHA-256 digest of the key
	// For PGP, hex-encoded SHA-1 digest of a key, which can be either
	// a primary key or subkey
	Fingerprints []string `yaml:"fingerprints"`
	// Subjects contains a list of subjects that are not specified in a
	// certificate, such as a SSH key or PGP key email address
	Subjects []string `yaml:"subjects"`
	// OIDMatchers contains a list of OID extension fields and associated values
	// ex. Build Signer URI, associated with specific workflow URIs
	OIDMatchers []extensions.OIDMatcher `yaml:"oidMatchers"`
	// FulcioExtensions contains all extensions currently supported by Fulcio
	// each extension has a list of values to match on, ex. `build-signer-uri`
	FulcioExtensions extensions.FulcioExtensions `yaml:"fulcioExtensions"`
	// CustomExtensions contains a list of custom extension fields, represented in dot notation
	// and associated values to match on.
	CustomExtensions []extensions.CustomExtension `yaml:"customExtensions"`
}

// RekorLogEntry holds a certificate subject, issuer, OID extension and associated value, and log entry metadata
// nolint:all
type RekorLogEntry struct {
	CertSubject    string
	Issuer         string
	Fingerprint    string
	Subject        string
	Index          int64
	UUID           string
	OIDExtension   asn1.ObjectIdentifier
	ExtensionValue string
}

func (e *RekorLogEntry) String() string {
	var parts []string
	for _, s := range []string{e.CertSubject, e.Issuer, e.Fingerprint, e.Subject, strconv.Itoa(int(e.Index)), e.UUID, e.OIDExtension.String(), e.ExtensionValue} {
		if strings.TrimSpace(s) != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}
