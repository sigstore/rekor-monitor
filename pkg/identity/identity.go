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
	"encoding/json"
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

// MonitoredIdentity holds an identity and associated log entries matching the identity being monitored.
type MonitoredIdentity struct {
	Identity             string          `json:"identity"`
	FoundIdentityEntries []RekorLogEntry `json:"foundIdentityEntries"`
}

// ParseMonitoredIdentitiesAsJSON formats a list of monitored identities and corresponding log entries
// using JSON tagging into JSON formatting.
func ParseMonitoredIdentitiesAsJSON(monitoredIdentities []MonitoredIdentity) ([]byte, error) {
	jsonBody, err := json.MarshalIndent(monitoredIdentities, "", "\t")
	if err != nil {
		return nil, err
	}
	return jsonBody, nil
}

// CreateMonitoredIdentities takes in a list of IdentityEntries and groups them by
// associated identity based on an input list of identities to monitor.
// It returns a list of MonitoredIdentities.
func CreateMonitoredIdentities(inputIdentityEntries []RekorLogEntry, monitoredIdentities []string) []MonitoredIdentity {
	identityMap := make(map[string]bool)
	for _, id := range monitoredIdentities {
		identityMap[id] = true
	}

	monitoredIdentityMap := make(map[string][]RekorLogEntry)
	for _, idEntry := range inputIdentityEntries {
		switch {
		case identityMap[idEntry.CertSubject]:
			idCertSubject := idEntry.CertSubject
			_, ok := monitoredIdentityMap[idCertSubject]
			if ok {
				monitoredIdentityMap[idCertSubject] = append(monitoredIdentityMap[idCertSubject], idEntry)
			} else {
				monitoredIdentityMap[idCertSubject] = []RekorLogEntry{idEntry}
			}
		case identityMap[idEntry.ExtensionValue]:
			idExtValue := idEntry.ExtensionValue
			_, ok := monitoredIdentityMap[idExtValue]
			if ok {
				monitoredIdentityMap[idExtValue] = append(monitoredIdentityMap[idExtValue], idEntry)
			} else {
				monitoredIdentityMap[idExtValue] = []RekorLogEntry{idEntry}
			}
		case identityMap[idEntry.Fingerprint]:
			idFingerprint := idEntry.Fingerprint
			_, ok := monitoredIdentityMap[idFingerprint]
			if ok {
				monitoredIdentityMap[idFingerprint] = append(monitoredIdentityMap[idFingerprint], idEntry)
			} else {
				monitoredIdentityMap[idFingerprint] = []RekorLogEntry{idEntry}
			}
		case identityMap[idEntry.Subject]:
			idSubject := idEntry.Subject
			_, ok := monitoredIdentityMap[idSubject]
			if ok {
				monitoredIdentityMap[idSubject] = append(monitoredIdentityMap[idSubject], idEntry)
			} else {
				monitoredIdentityMap[idSubject] = []RekorLogEntry{idEntry}
			}
		}
	}

	parsedMonitoredIdentities := []MonitoredIdentity{}
	for id, idEntries := range monitoredIdentityMap {
		parsedMonitoredIdentities = append(parsedMonitoredIdentities, MonitoredIdentity{
			Identity:             id,
			FoundIdentityEntries: idEntries,
		})
	}

	return parsedMonitoredIdentities
}
