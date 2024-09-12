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

package rekor

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	// required imports to call init methods
	_ "github.com/sigstore/rekor/pkg/types/alpine/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/cose/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/helm/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	_ "github.com/sigstore/rekor/pkg/types/jar/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rfc3161/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/tuf/v0.0.1"
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
	// OIDMatchers contains a list of OID extension fields and associated values
	// ex. Build Signer URI, associated with specific workflow URIs
	OIDMatchers []identity.OIDMatcher `yaml:"oidMatchers"`
	// FulcioExtensions contains all extensions currently supported by Fulcio
	// each extension has a list of values to match on, ex. `build-signer-uri`
	FulcioExtensions extensions.FulcioExtensions `yaml:"fulcioExtensions"`
}

// IdentityEntry holds a certificate subject, issuer, OID extension and associated value, and log entry metadata
type IdentityEntry struct {
	CertSubject    string
	Issuer         string
	Fingerprint    string
	Subject        string
	Index          int64
	UUID           string
	OIDExtension   asn1.ObjectIdentifier
	ExtensionValue string
}

func (e *IdentityEntry) String() string {
	var parts []string
	for _, s := range []string{e.CertSubject, e.Issuer, e.Fingerprint, e.Subject, strconv.Itoa(int(e.Index)), e.UUID, e.OIDExtension.String(), e.ExtensionValue} {
		if strings.TrimSpace(s) != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// parseObjectIdentifier parses a string representing an ObjectIdentifier in dot notation
// and converts it into an asn1.ObjectIdentiifer.
func parseObjectIdentifier(oid string) (asn1.ObjectIdentifier, error) {
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

// mergeOIDMatchers groups all OID matchers from OIDMatchers, FulcioExtensions, and CustomOIDs into one slice of OIDMatchers
func mergeOIDMatchers(mvs MonitoredValues) ([]identity.OIDMatcher, error) {
	fulcioOIDMatchers, err := mvs.FulcioExtensions.RenderFulcioOIDMatchers()
	if err != nil {
		return nil, fmt.Errorf("error rendering OID Matchers from Fulcio OID extensions: %w", err)
	}
	// map of all OID extensions to all associated matching extension values
	oidMap := make(map[string]map[string]bool)
	// dedup OID extensions and associated values through one mapping
	for _, oidMatcher := range mvs.OIDMatchers {
		oidMatcherString := oidMatcher.ObjectIdentifier.String()
		oidMap[oidMatcherString] = make(map[string]bool)
		for _, extValue := range oidMatcher.ExtensionValues {
			oidMap[oidMatcherString][extValue] = true
		}
	}
	for _, oidMatcher := range fulcioOIDMatchers {
		oidMatcherString := oidMatcher.ObjectIdentifier.String()
		oidMap[oidMatcherString] = make(map[string]bool)
		for _, extValue := range oidMatcher.ExtensionValues {
			oidMap[oidMatcherString][extValue] = true
		}
	}
	// convert map into list of OIDMatchers
	var allMatchers []identity.OIDMatcher
	for oidExtension, extValueMap := range oidMap {
		parsedOID, err := parseObjectIdentifier(oidExtension)
		if err != nil {
			return nil, fmt.Errorf("error parsing OID from extension: %w", err)
		}
		var extValues []string
		for extValue := range extValueMap {
			extValues = append(extValues, extValue)
		}
		allMatchers = append(allMatchers, identity.OIDMatcher{
			ObjectIdentifier: parsedOID,
			ExtensionValues:  extValues,
		})
	}

	return allMatchers, nil
}

// MatchedIndices returns a list of log indices that contain the requested identities.
func MatchedIndices(logEntries []models.LogEntry, mvs MonitoredValues) ([]IdentityEntry, error) {
	allOIDMatchers, err := mergeOIDMatchers(mvs)
	if err != nil {
		return nil, err
	}
	// TODO: preprocess OIDMatchers before being passed into MatchedIndices
	mvs.OIDMatchers = allOIDMatchers
	if err := verifyMonitoredValues(mvs); err != nil {
		return nil, err
	}

	var matchedEntries []IdentityEntry

	for _, entries := range logEntries {
		for uuid, entry := range entries {
			entry := entry

			verifiers, err := extractVerifiers(&entry)
			if err != nil {
				return nil, fmt.Errorf("error extracting verifiers for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
			}
			subjects, certs, fps, err := extractAllIdentities(verifiers)
			if err != nil {
				return nil, fmt.Errorf("error extracting identities for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
			}

			for _, monitoredFp := range mvs.Fingerprints {
				for _, fp := range fps {
					if fp == monitoredFp {
						matchedEntries = append(matchedEntries, IdentityEntry{
							Fingerprint: fp,
							Index:       *entry.LogIndex,
							UUID:        uuid,
						})
					}
				}
			}

			for _, monitoredCertID := range mvs.CertificateIdentities {
				for _, cert := range certs {
					match, sub, iss, err := certMatchesPolicy(cert, monitoredCertID.CertSubject, monitoredCertID.Issuers)
					if err != nil {
						return nil, fmt.Errorf("error with policy matching for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
					} else if match {
						matchedEntries = append(matchedEntries, IdentityEntry{
							CertSubject: sub,
							Issuer:      iss,
							Index:       *entry.LogIndex,
							UUID:        uuid,
						})
					}
				}
			}

			for _, monitoredSub := range mvs.Subjects {
				regex, err := regexp.Compile(monitoredSub)
				if err != nil {
					return nil, fmt.Errorf("error compiling regex for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
				}
				for _, sub := range subjects {
					if regex.MatchString(sub) {
						matchedEntries = append(matchedEntries, IdentityEntry{
							Subject: sub,
							Index:   *entry.LogIndex,
							UUID:    uuid,
						})
					}
				}
			}

			for _, monitoredOID := range mvs.OIDMatchers {
				for _, cert := range certs {
					match, oid, extValue, err := oidMatchesPolicy(cert, monitoredOID.ObjectIdentifier, monitoredOID.ExtensionValues)
					if err != nil {
						return nil, fmt.Errorf("error with policy matching for UUID %s at index %d: %w", uuid, *entry.LogIndex, err)
					}
					if match {
						matchedEntries = append(matchedEntries, IdentityEntry{
							Index:          *entry.LogIndex,
							UUID:           uuid,
							OIDExtension:   oid,
							ExtensionValue: extValue,
						})
					}
				}
			}
		}
	}

	return matchedEntries, nil
}

// verifyMonitoredValues checks that monitored values are valid
func verifyMonitoredValues(mvs MonitoredValues) error {
	if len(mvs.CertificateIdentities) == 0 && len(mvs.Fingerprints) == 0 && len(mvs.Subjects) == 0 && len(mvs.OIDMatchers) == 0 {
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

// extractVerifiers extracts a set of keys or certificates that can verify an
// artifact signature from a Rekor entry
func extractVerifiers(e *models.LogEntryAnon) ([]pki.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}

	return eimpl.Verifiers()
}

// extractAllIdentities gets all certificates, email addresses, and key fingerprints
// from a list of verifiers
func extractAllIdentities(verifiers []pki.PublicKey) ([]string, []*x509.Certificate, []string, error) {
	var subjects []string
	var certificates []*x509.Certificate
	var fps []string

	for _, v := range verifiers {
		// append all verifier subjects (email or SAN)
		subjects = append(subjects, v.Subjects()...)
		ids, err := v.Identities()
		if err != nil {
			return nil, nil, nil, err
		}
		// append all certificate and key fingerprints
		for _, i := range ids {
			fps = append(fps, i.Fingerprint)
			if cert, ok := i.Crypto.(*x509.Certificate); ok {
				certificates = append(certificates, cert)
			}
		}
	}
	return subjects, certificates, fps, nil
}

// getExtension gets a certificate extension by OID where the extension value is an
// ASN.1-encoded string
func getExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (string, error) {
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
}

// getDeprecatedExtension gets a certificate extension by OID where the extension value is a raw string
func getDeprecatedExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (string, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return string(ext.Value), nil
		}
	}
	return "", nil
}

// certMatchesPolicy returns true if a certificate contains a given subject and optionally a given issuer
// expectedSub and expectedIssuers can be regular expressions
// certMatchesPolicy also returns the matched subject and issuer on success
func certMatchesPolicy(cert *x509.Certificate, expectedSub string, expectedIssuers []string) (bool, string, string, error) {
	sans := cryptoutils.GetSubjectAlternateNames(cert)
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

// oidMatchesPolicy returns if a certificate contains both a given OID field and a matching value associated with that field
// if true, it returns the OID extension and extension value that were matched on
func oidMatchesPolicy(cert *x509.Certificate, oid asn1.ObjectIdentifier, extensionValues []string) (bool, asn1.ObjectIdentifier, string, error) {
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
