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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	google_asn1 "github.com/google/certificate-transparency-go/asn1"
	google_x509 "github.com/google/certificate-transparency-go/x509"
)

var (
	certExtensionOIDCIssuer   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	certExtensionOIDCIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
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
	// OIDMatchers represents a list of OID extension fields and associated values,
	// which includes those constructed directly, those supported by Fulcio, and any constructed via dot notation.
	OIDMatchers []extensions.OIDExtension `yaml:"oidMatchers"`
}

// LogEntry holds a certificate subject, issuer, OID extension and associated value, and log entry metadata
type LogEntry struct {
	CertSubject    string
	Issuer         string
	Fingerprint    string
	Subject        string
	Index          int64
	UUID           string
	OIDExtension   asn1.ObjectIdentifier
	ExtensionValue string
}

func (e *LogEntry) String() string {
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
	Identity             string     `json:"identity"`
	FoundIdentityEntries []LogEntry `json:"foundIdentityEntries"`
}

// PrintMonitoredIdentities formats a list of monitored identities and corresponding log entries
// using JSON tagging into JSON formatting.
func PrintMonitoredIdentities(monitoredIdentities []MonitoredIdentity) ([]byte, error) {
	jsonBody, err := json.MarshalIndent(monitoredIdentities, "", "\t")
	if err != nil {
		return nil, err
	}
	return jsonBody, nil
}

// MonitoredIdentityList wraps []MonitoredIdentity to implement NotificationBodyConverter
type MonitoredIdentityList []MonitoredIdentity

// ToNotificationBody implements the NotificationBodyConverter interface for MonitoredIdentityList
func (identities MonitoredIdentityList) ToNotificationBody() (string, error) {
	jsonBody, err := json.MarshalIndent(identities, "", "\t")
	if err != nil {
		return "", err
	}
	return string(jsonBody), nil
}

// CreateIdentitiesList takes in a MonitoredValues input and returns a list of all currently monitored identities.
// It returns a list of strings.
func CreateIdentitiesList(mvs MonitoredValues) []string {
	identities := []string{}

	for _, certID := range mvs.CertificateIdentities {
		identities = append(identities, certID.CertSubject)
		identities = append(identities, certID.Issuers...)
	}

	identities = append(identities, mvs.Fingerprints...)
	identities = append(identities, mvs.Subjects...)

	for _, oidMatcher := range mvs.OIDMatchers {
		identities = append(identities, oidMatcher.ExtensionValues...)
	}

	return identities
}

// CreateMonitoredIdentities takes in a list of IdentityEntries and groups them by
// associated identity based on an input list of identities to monitor.
// It returns a list of MonitoredIdentities.
func CreateMonitoredIdentities(inputIdentityEntries []LogEntry, monitoredIdentities []string) []MonitoredIdentity {
	identityMap := make(map[string]bool)
	for _, id := range monitoredIdentities {
		identityMap[id] = true
	}

	monitoredIdentityMap := make(map[string][]LogEntry)
	for _, idEntry := range inputIdentityEntries {
		switch {
		case identityMap[idEntry.CertSubject]:
			idCertSubject := idEntry.CertSubject
			_, ok := monitoredIdentityMap[idCertSubject]
			if ok {
				monitoredIdentityMap[idCertSubject] = append(monitoredIdentityMap[idCertSubject], idEntry)
			} else {
				monitoredIdentityMap[idCertSubject] = []LogEntry{idEntry}
			}
		case identityMap[idEntry.ExtensionValue]:
			idExtValue := idEntry.ExtensionValue
			_, ok := monitoredIdentityMap[idExtValue]
			if ok {
				monitoredIdentityMap[idExtValue] = append(monitoredIdentityMap[idExtValue], idEntry)
			} else {
				monitoredIdentityMap[idExtValue] = []LogEntry{idEntry}
			}
		case identityMap[idEntry.Fingerprint]:
			idFingerprint := idEntry.Fingerprint
			_, ok := monitoredIdentityMap[idFingerprint]
			if ok {
				monitoredIdentityMap[idFingerprint] = append(monitoredIdentityMap[idFingerprint], idEntry)
			} else {
				monitoredIdentityMap[idFingerprint] = []LogEntry{idEntry}
			}
		case identityMap[idEntry.Subject]:
			idSubject := idEntry.Subject
			_, ok := monitoredIdentityMap[idSubject]
			if ok {
				monitoredIdentityMap[idSubject] = append(monitoredIdentityMap[idSubject], idEntry)
			} else {
				monitoredIdentityMap[idSubject] = []LogEntry{idEntry}
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

// MonitoredValuesExist checks if there are monitored values in an input and returns accordingly.
func MonitoredValuesExist(mvs MonitoredValues) bool {
	if len(mvs.CertificateIdentities) > 0 {
		return true
	}
	if len(mvs.Fingerprints) > 0 {
		return true
	}
	if len(mvs.OIDMatchers) > 0 {
		return true
	}
	if len(mvs.Subjects) > 0 {
		return true
	}
	return false
}

// getExtension gets a certificate extension by OID where the extension value is an
// ASN.1-encoded string
func getExtension[Certificate *x509.Certificate | *google_x509.Certificate](certificate Certificate, oid asn1.ObjectIdentifier) (string, error) {
	switch cert := any(certificate).(type) {
	case *x509.Certificate:
		for _, ext := range cert.Extensions {
			if !ext.Id.Equal(oid) {
				continue
			}
			var extValue string
			rest, err := asn1.Unmarshal(ext.Value, &extValue)
			if err != nil {
				return "", fmt.Errorf("%w", err)
			}
			if len(rest) != 0 {
				return "", fmt.Errorf("unmarshalling extension had rest for oid %v", oid)
			}
			return extValue, nil
		}
		return "", nil
	case *google_x509.Certificate:
		for _, ext := range cert.Extensions {
			if !ext.Id.Equal((google_asn1.ObjectIdentifier)(oid)) {
				continue
			}
			var extValue string
			rest, err := asn1.Unmarshal(ext.Value, &extValue)
			if err != nil {
				return "", fmt.Errorf("%w", err)
			}
			if len(rest) != 0 {
				return "", fmt.Errorf("unmarshalling extension had rest for oid %v", oid)
			}
			return extValue, nil
		}
		return "", nil
	}
	return "", errors.New("certificate was neither x509 nor google_x509")
}

// getDeprecatedExtension gets a certificate extension by OID where the extension value is a raw string
func getDeprecatedExtension[Certificate *x509.Certificate | *google_x509.Certificate](certificate Certificate, oid asn1.ObjectIdentifier) (string, error) {
	switch cert := any(certificate).(type) {
	case *x509.Certificate:
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oid) {
				return string(ext.Value), nil
			}
		}
		return "", nil
	case *google_x509.Certificate:
		for _, ext := range cert.Extensions {
			if ext.Id.Equal((google_asn1.ObjectIdentifier)(oid)) {
				return string(ext.Value), nil
			}
		}
		return "", nil
	}
	return "", errors.New("certificate was neither x509 nor google_x509")
}

// OIDMatchesPolicy returns if a certificate contains both a given OID field and a matching value associated with that field
// if true, it returns the OID extension and extension value that were matched on
func OIDMatchesPolicy[Certificate *x509.Certificate | *google_x509.Certificate](cert Certificate, oid asn1.ObjectIdentifier, extensionValues []string) (bool, asn1.ObjectIdentifier, string, error) {
	extValue, err := getExtension(cert, oid)
	if err != nil {
		return false, nil, "", fmt.Errorf("error getting extension value: %w", err)
	}
	if extValue == "" {
		return false, nil, "", nil
	}
	for _, extensionValue := range extensionValues {
		if extValue == extensionValue {
			return true, oid, extValue, nil
		}
	}
	return false, nil, "", nil
}

// getSubjectAlternateNames extracts all subject alternative names from
// the certificate, including email addresses, DNS, IP addresses, URIs, and OtherName SANs
// duplicate of cryptoutils function GetSubjectAlternateNames to match in case of google_x509 fork certificate
func getSubjectAlternateNames[Certificate *x509.Certificate | *google_x509.Certificate](certificate Certificate) []string {
	sans := []string{}
	switch cert := any(certificate).(type) {
	case *x509.Certificate:
		sans = append(sans, cert.DNSNames...)
		sans = append(sans, cert.EmailAddresses...)
		for _, ip := range cert.IPAddresses {
			sans = append(sans, ip.String())
		}
		for _, uri := range cert.URIs {
			sans = append(sans, uri.String())
		}
		// ignore error if there's no OtherName SAN
		otherName, _ := cryptoutils.UnmarshalOtherNameSAN(cert.Extensions)
		if len(otherName) > 0 {
			sans = append(sans, otherName)
		}
		return sans
	case *google_x509.Certificate:
		sans = append(sans, cert.DNSNames...)
		sans = append(sans, cert.EmailAddresses...)
		for _, ip := range cert.IPAddresses {
			sans = append(sans, ip.String())
		}
		for _, uri := range cert.URIs {
			sans = append(sans, uri.String())
		}
		// ignore error if there's no OtherName SAN
		pkixExts := []pkix.Extension{}
		for _, googleExt := range cert.Extensions {
			pkixExt := pkix.Extension{
				Id:       (asn1.ObjectIdentifier)(googleExt.Id),
				Critical: googleExt.Critical,
				Value:    googleExt.Value,
			}
			pkixExts = append(pkixExts, pkixExt)
		}
		otherName, _ := cryptoutils.UnmarshalOtherNameSAN(pkixExts)
		if len(otherName) > 0 {
			sans = append(sans, otherName)
		}
		return sans
	}
	return sans
}

// CertMatchesPolicy returns true if a certificate contains a given subject and optionally a given issuer
// expectedSub and expectedIssuers can be regular expressions
// CertMatchesPolicy also returns the matched subject and issuer on success
func CertMatchesPolicy[Certificate *x509.Certificate | *google_x509.Certificate](cert Certificate, expectedSub string, expectedIssuers []string) (bool, string, string, error) {
	sans := getSubjectAlternateNames(cert)
	var issuer string
	var err error
	issuer, err = getExtension(cert, certExtensionOIDCIssuerV2)
	if err != nil || issuer == "" {
		// fallback to deprecated issuer extension
		issuer, err = getDeprecatedExtension(cert, certExtensionOIDCIssuer)
		if err != nil || issuer == "" {
			return false, "", "", err
		}
	}
	subjectMatches := false
	regex, err := regexp.Compile(expectedSub)
	if err != nil {
		return false, "", "", fmt.Errorf("malformed subject regex: %w", err)
	}
	matchedSub := ""
	for _, sub := range sans {
		if regex.MatchString(sub) {
			subjectMatches = true
			matchedSub = sub
		}
	}
	// allow any issuer
	if len(expectedIssuers) == 0 {
		return subjectMatches, matchedSub, issuer, nil
	}

	issuerMatches := false
	for _, expectedIss := range expectedIssuers {
		regex, err := regexp.Compile(expectedIss)
		if err != nil {
			return false, "", "", fmt.Errorf("malformed issuer regex: %w", err)
		}
		if regex.MatchString(issuer) {
			issuerMatches = true
		}
	}
	return subjectMatches && issuerMatches, matchedSub, issuer, nil
}
