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
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

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

type MatchedIdentityType string

const (
	MatchedIdentityTypeCertSubject    MatchedIdentityType = "certSubject"
	MatchedIdentityTypeExtensionValue MatchedIdentityType = "extensionValue"
	MatchedIdentityTypeFingerprint    MatchedIdentityType = "fingerprint"
	MatchedIdentityTypeSubject        MatchedIdentityType = "subject"
)

// LogEntry holds a certificate subject, issuer, OID extension and associated value, and log entry metadata
type LogEntry struct {
	MatchedIdentity     string
	MatchedIdentityType MatchedIdentityType
	CertSubject         string
	Issuer              string
	Fingerprint         string
	Subject             string
	Index               int64
	UUID                string
	OIDExtension        asn1.ObjectIdentifier
	ExtensionValue      string
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

// FailedLogEntry holds a log entry that failed to be parsed/extracted
type FailedLogEntry struct {
	Index int64  `json:"index"`
	UUID  string `json:"uuid"`
	Error string `json:"error"`
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
func (identities MonitoredIdentityList) ToNotificationBody() ([]byte, error) {
	return PrintMonitoredIdentities(identities)
}

// ToNotificationHeader implements the NotificationBodyConverter interface for MonitoredIdentityList
func (identities MonitoredIdentityList) ToNotificationHeader() string {
	return "Found the following pairs of monitored identities and matching log entries: "
}

// FailedLogEntryList wraps []FailedLogEntry to implement NotificationBodyConverter
type FailedLogEntryList []FailedLogEntry

// ToNotificationBody implements the NotificationBodyConverter interface for FailedLogEntryList
func (failedEntries FailedLogEntryList) ToNotificationBody() ([]byte, error) {
	jsonBody, err := json.MarshalIndent(failedEntries, "", "\t")
	if err != nil {
		return nil, err
	}
	return jsonBody, nil
}

// ToNotificationHeader implements the NotificationBodyConverter interface for FailedLogEntryList
func (failedEntries FailedLogEntryList) ToNotificationHeader() string {
	return "Failed to parse the following log entries: "
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
		if _, ok := identityMap[idEntry.MatchedIdentity]; !ok {
			fmt.Fprintf(os.Stderr, "Matched identity %s not found in identity map\n", idEntry.MatchedIdentity)
			continue
		}

		identityValue := ""
		switch idEntry.MatchedIdentityType {
		case MatchedIdentityTypeCertSubject:
			identityValue = idEntry.CertSubject
		case MatchedIdentityTypeExtensionValue:
			identityValue = idEntry.ExtensionValue
		case MatchedIdentityTypeFingerprint:
			identityValue = idEntry.Fingerprint
		case MatchedIdentityTypeSubject:
			identityValue = idEntry.Subject
		}

		_, ok := monitoredIdentityMap[identityValue]
		if ok {
			monitoredIdentityMap[identityValue] = append(monitoredIdentityMap[identityValue], idEntry)
		} else {
			monitoredIdentityMap[identityValue] = []LogEntry{idEntry}
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

// verifyMonitoredOIDs checks that monitored OID extensions and matching values are valid
func verifyMonitoredOIDs(mvs MonitoredValues) error {
	for _, oidMatcher := range mvs.OIDMatchers {
		if len(oidMatcher.ObjectIdentifier) == 0 {
			return errors.New("oid extension empty")
		}
		if len(oidMatcher.ExtensionValues) == 0 {
			return errors.New("oid matched values empty")
		}
		for _, extensionValue := range oidMatcher.ExtensionValues {
			if len(extensionValue) == 0 {
				return errors.New("oid matched value empty")
			}
		}
	}
	return nil
}

// VerifyMonitoredValues checks that monitored values are valid
func VerifyMonitoredValues(mvs MonitoredValues) error {
	if !MonitoredValuesExist(mvs) {
		return errors.New("no identities provided to monitor")
	}
	for _, certID := range mvs.CertificateIdentities {
		if len(certID.CertSubject) == 0 {
			return errors.New("certificate subject empty")
		}
		// issuers can be empty
		for _, iss := range certID.Issuers {
			if len(iss) == 0 {
				return errors.New("issuer empty")
			}
		}
	}
	for _, fp := range mvs.Fingerprints {
		if len(fp) == 0 {
			return errors.New("fingerprint empty")
		}
	}
	for _, sub := range mvs.Subjects {
		if len(sub) == 0 {
			return errors.New("subject empty")
		}
	}
	err := verifyMonitoredOIDs(mvs)
	if err != nil {
		return err
	}
	return nil
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

func getCertPool[T *x509.CertPool | *google_x509.CertPool](pemFile string) (T, error) {
	caBytes, err := os.ReadFile(pemFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read trusted CA file %q: %w", pemFile, err)
	}

	var genericRoots T
	switch any(genericRoots).(type) {
	case *x509.CertPool:
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to append trusted CA certificate in %q", pemFile)
		}
		genericRoots = any(roots).(T)
	case *google_x509.CertPool:
		roots := google_x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to append trusted CA certificate in %q", pemFile)
		}
		genericRoots = any(roots).(T)
	default:
		return nil, fmt.Errorf("unsupported CertPool type")
	}

	return genericRoots, nil
}

// ValidateCertificateChain checks that at least one certificate in the chain is signed by a trusted CA.
func ValidateCertificateChain(certs []*x509.Certificate, caRoots string, caIntermediates string) error {
	if (caRoots == "" && caIntermediates == "") || len(certs) == 0 {
		return nil // No trusted CAs or no certs, skip validation
	}

	var roots *x509.CertPool
	var err error
	if caRoots != "" {
		roots, err = getCertPool[*x509.CertPool](caRoots)
		if err != nil {
			return err
		}
	}

	var intermediates *x509.CertPool
	if caIntermediates != "" {
		intermediates, err = getCertPool[*x509.CertPool](caIntermediates)
		if err != nil {
			return err
		}
	}

	for _, cert := range certs {
		opts := x509.VerifyOptions{
			CurrentTime:   cert.NotBefore,
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		}
		if _, err := cert.Verify(opts); err == nil {
			return nil
		}
	}

	return errors.New("no certificate in the chain is signed by a trusted CA")
}

func ValidatePreCertificateChain(certs []*google_x509.Certificate, caRoots string, caIntermediates string) error {
	if (caRoots == "" && caIntermediates == "") || len(certs) == 0 {
		return nil // No trusted CAs or no certs, skip validation
	}

	var roots *google_x509.CertPool
	var err error
	if caRoots != "" {
		roots, err = getCertPool[*google_x509.CertPool](caRoots)
		if err != nil {
			return err
		}
	}

	var intermediates *google_x509.CertPool
	if caIntermediates != "" {
		intermediates, err = getCertPool[*google_x509.CertPool](caIntermediates)
		if err != nil {
			return err
		}
	}

	for _, cert := range certs {
		// These are the same verification options as in the Go library code for CT
		// https://github.com/google/certificate-transparency-go/blob/856995301233fa52f69e283f5c3cdbef1bebca21/trillian/ctfe/cert_checker.go#L143-L146
		opts := google_x509.VerifyOptions{
			DisableTimeChecks: true,
			// Precertificates have the poison extension; also the Go library code does not
			// support the standard PolicyConstraints extension (which is required to be marked
			// critical, RFC 5280 s4.2.1.11), so never check unhandled critical extensions.
			DisableCriticalExtensionChecks: true,
			// Pre-issued precertificates have the Certificate Transparency EKU; also some
			// leaves have unknown EKUs that should not be bounced just because the intermediate
			// does not also have them (cf. https://github.com/golang/go/issues/24590)
			DisableEKUChecks: true,
			// Path length checks get confused by the presence of an additional
			// pre-issuer intermediate, so disable them.
			DisablePathLenChecks:        true,
			DisableNameConstraintChecks: true,
			DisableNameChecks:           false,
			CurrentTime:                 time.Now(),
			Roots:                       roots,
			Intermediates:               intermediates,
			KeyUsages:                   []google_x509.ExtKeyUsage{google_x509.ExtKeyUsageCodeSigning},
		}
		if _, err := cert.Verify(opts); err == nil {
			return nil
		}
	}

	return errors.New("no certificate in the chain is signed by a trusted CA")
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
