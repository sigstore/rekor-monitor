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
	"encoding/base64"
	"errors"

	"github.com/go-openapi/runtime"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"

	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// IdentityEntry holds a certificate subject, issuer, and log entry metadata
type IdentityEntry struct {
	Subject string
	Issuer  string
	Index   int64
	UUID    string
}

// Identities are the subjects/issuers to search
type Identities struct {
	Identities []Identity `json:"identities,omitempty"`
}

type Identity struct {
	Subject string   `json:"subject"`
	Issuers []string `json:"issuers,omitempty"`
}

// MatchedIndices returns a list of log indices that contain the requested identities.
func MatchedIndices(logEntries []models.LogEntry, identities Identities) ([]IdentityEntry, error) {
	if err := verifyIdentities(identities); err != nil {
		return nil, err
	}

	var matchedIndices []IdentityEntry

	for _, entries := range logEntries {
		for uuid, entry := range entries {
			entry := entry

			certs, err := extractCertificates(&entry)
			if err != nil {
				// TODO: Add support for handling public keys in x509 struct
				// TODO: Add support for minisign
				// TODO: Add support for SSH
				// TODO: Add support for PKCS7
				// TODO: Add support for PGP
				// TODO: Add support for TUF
				continue
			}

			// TODO: Support regular expressions using co.Identities
			// TODO: Support GitHub CI claims

			var checks []*cosign.CheckOpts
			for _, ids := range identities.Identities {
				// match any issuer with no issuers specified
				if len(ids.Issuers) == 0 {
					checks = append(checks, &cosign.CheckOpts{Identities: []cosign.Identity{{Subject: ids.Subject}}})
				} else {
					for _, iss := range ids.Issuers {
						checks = append(checks, &cosign.CheckOpts{Identities: []cosign.Identity{{Subject: ids.Subject, Issuer: iss}}})
					}
				}
			}

			for _, co := range checks {
				if err := cosign.CheckCertificatePolicy(certs[0], co); err == nil {
					// certificate matched policy
					exts := cosign.CertExtensions{Cert: certs[0]}
					matchedIndices = append(matchedIndices,
						IdentityEntry{
							Subject: co.Identities[0].Subject,
							Issuer:  exts.GetIssuer(),
							Index:   *entry.LogIndex,
							UUID:    uuid,
						})
				}
			}
		}
	}

	return matchedIndices, nil
}

// TODO: Change once https://github.com/sigstore/rekor/pull/1210 is merged
func extractCertificates(e *models.LogEntryAnon) ([]*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.CreateVersionedEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *hashedrekord_v001.V001Entry:
		publicKeyB64, err = e.HashedRekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("tlog entry type not supported")
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		// This returns an error if the publicKey field does not contain certificates.
		// This is expected for this case.
		return nil, err
	}

	if len(certs) == 0 {
		return nil, errors.New("no certficates found in entry")
	}

	return certs, err
}

func verifyIdentities(ids Identities) error {
	if len(ids.Identities) == 0 {
		return errors.New("no identities provided")
	}
	for _, id := range ids.Identities {
		if len(id.Subject) == 0 {
			return errors.New("subject empty")
		}
	}
	return nil
}
