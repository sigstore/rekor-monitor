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
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"

	// alpine_v001 "github.com/sigstore/rekor/pkg/types/alpine/v0.0.1"
	// cose_v001 "github.com/sigstore/rekor/pkg/types/cose/v0.0.1"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	// helm_v001 "github.com/sigstore/rekor/pkg/types/helm/v0.0.1"
	// intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	// intoto_v002 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	// jar_v001 "github.com/sigstore/rekor/pkg/types/jar/v0.0.1"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	// rfc3161_v001 "github.com/sigstore/rekor/pkg/types/rfc3161/v0.0.1"
	// rpm_v001 "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	// tuf_v001 "github.com/sigstore/rekor/pkg/types/tuf/v0.0.1"
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
				// TODO: Add support for TUF?
				continue
			}

			// TODO: Support regular expressions using co.Identities
			// TODO: Support GitHub CI claims

			var checks []*cosign.CheckOpts
			for _, ids := range identities.Identities {
				// skip empty subjects
				if len(ids.Subject) == 0 {
					continue
				}

				// match any issuer with no issuers specified
				if len(ids.Issuers) == 0 {
					checks = append(checks, &cosign.CheckOpts{CertIdentity: ids.Subject})
				} else {
					for _, iss := range ids.Issuers {
						checks = append(checks, &cosign.CheckOpts{CertIdentity: ids.Subject, CertOidcIssuer: iss})
					}
				}
			}

			for _, co := range checks {
				err = cosign.CheckCertificatePolicy(certs[0], co)
				// certificate matched policy
				if err == nil {
					exts := cosign.CertExtensions{Cert: certs[0]}
					matchedIndices = append(matchedIndices,
						IdentityEntry{
							Subject: co.CertIdentity,
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

	// TODO: Implement support for other entry types
	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	// case *alpine_v001.V001Entry:
	// 	publicKeyB64, err = e.AlpineModel.PublicKey.Content.MarshalText()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// case *cose_v001.V001Entry:
	// 	publicKeyB64, err = e.CoseObj.PublicKey.MarshalText()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	case *hashedrekord_v001.V001Entry:
		publicKeyB64, err = e.HashedRekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	// case *helm_v001.V001Entry:
	// 	publicKeyB64, err = e.HelmObj.PublicKey.Content.MarshalText()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// case *intoto_v001.V001Entry:
	// 	publicKeyB64, err = e.IntotoObj.PublicKey.MarshalText()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// case *intoto_v002.V002Entry:
	// 	// TODO: Handle multiple certificates
	// 	sigs := e.IntotoObj.Content.Envelope.Signatures
	// 	if len(sigs) > 0 {
	// 		publicKeyB64 = sigs[0].PublicKey
	// 	}
	// case *jar_v001.V001Entry:
	// 	publicKeyB64, err = e.JARModel.Signature.PublicKey.Content.MarshalText()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	case *rekord_v001.V001Entry:
		publicKeyB64, err = e.RekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	// case *rfc3161_v001.V001Entry:
	// 	// There is no way to know the structure of the timestamp message.
	// 	return nil, errors.New("unsupported type: rfc3161_v001.V001Entry")
	// case *rpm_v001.V001Entry:
	// 	publicKeyB64, err = e.RPMModel.PublicKey.Content.MarshalText()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// case *tuf_v001.V001Entry:
	// 	// This uses public keys and not certificates.
	// 	return nil, errors.New("unsupported type: tuf_v001.V001Entry")
	default:
		return nil, errors.New("unexpected tlog entry type")
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
