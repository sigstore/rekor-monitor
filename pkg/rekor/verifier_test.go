// Copyright 2023 The Sigstore Authors.
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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor-monitor/pkg/rekor/mock"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func generateCert(template, parent *x509.Certificate, pubKey interface{}, privKey interface{}) ([]byte, error) {
	if _, ok := privKey.(*ecdsa.PrivateKey); ok {
		template.SignatureAlgorithm = x509.ECDSAWithSHA256
	}
	return x509.CreateCertificate(rand.Reader, template, parent, pubKey, privKey)
}

func TestGetLogVerifierWithRootVerification(t *testing.T) {
	trustedRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate trusted root key: %v", err)
	}
	trustedRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Trusted Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	trustedRootCertBytes, err := generateCert(trustedRootTemplate, trustedRootTemplate, &trustedRootKey.PublicKey, trustedRootKey)
	if err != nil {
		t.Fatalf("failed to create trusted root certificate: %v", err)
	}
	trustedRootCert, err := x509.ParseCertificate(trustedRootCertBytes)
	if err != nil {
		t.Fatalf("failed to parse trusted root certificate: %v", err)
	}

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate key: %v", err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	intermediateCertBytes, err := generateCert(intermediateTemplate, trustedRootTemplate, &intermediateKey.PublicKey, trustedRootKey)
	if err != nil {
		t.Fatalf("failed to create intermediate certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "rekor.sigstore.dev"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafCertBytes, err := generateCert(leafTemplate, intermediateTemplate, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}

	directLeafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate direct leaf key: %v", err)
	}
	directLeafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(6),
		Subject:      pkix.Name{CommonName: "direct-rekor.sigstore.dev"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	directLeafCertBytes, err := generateCert(directLeafTemplate, trustedRootTemplate, &directLeafKey.PublicKey, trustedRootKey)
	if err != nil {
		t.Fatalf("failed to create direct leaf certificate: %v", err)
	}

	untrustedRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate untrusted root key: %v", err)
	}
	untrustedRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               pkix.Name{CommonName: "Untrusted Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	untrustedRootCertBytes, err := generateCert(untrustedRootTemplate, untrustedRootTemplate, &untrustedRootKey.PublicKey, untrustedRootKey)
	if err != nil {
		t.Fatalf("failed to create untrusted root certificate: %v", err)
	}

	untrustedLeafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate untrusted leaf key: %v", err)
	}
	untrustedLeafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(5),
		Subject:      pkix.Name{CommonName: "untrusted-rekor.sigstore.dev"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	untrustedLeafCertBytes, err := generateCert(untrustedLeafTemplate, untrustedRootTemplate, &untrustedLeafKey.PublicKey, untrustedRootKey)
	if err != nil {
		t.Fatalf("failed to create untrusted leaf certificate: %v", err)
	}

	tests := []struct {
		name          string
		config        *TrustRootConfig
		setupClient   func() *client.Rekor
		expectSuccess bool
	}{
		{
			name: "Valid chain with custom root",
			config: &TrustRootConfig{
				CustomRoots:   []*x509.Certificate{trustedRootCert},
				UseTUFDefault: false,
			},
			setupClient: func() *client.Rekor {
				chainPEM := append(
					pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertBytes}),
					pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateCertBytes})...,
				)
				chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trustedRootCertBytes})...)
				return &client.Rekor{
					Pubkey: &mock.PubkeyClient{
						PEMPubKey: string(chainPEM),
					},
				}
			},
			expectSuccess: true,
		},
		{
			name: "Valid chain with direct root",
			config: &TrustRootConfig{
				CustomRoots:   []*x509.Certificate{trustedRootCert},
				UseTUFDefault: false,
			},
			setupClient: func() *client.Rekor {
				chainPEM := append(
					pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: directLeafCertBytes}),
					pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trustedRootCertBytes})...,
				)
				return &client.Rekor{
					Pubkey: &mock.PubkeyClient{
						PEMPubKey: string(chainPEM),
					},
				}
			},
			expectSuccess: true,
		},
		{
			name: "Untrusted root",
			config: &TrustRootConfig{
				CustomRoots:   []*x509.Certificate{trustedRootCert},
				UseTUFDefault: false,
			},
			setupClient: func() *client.Rekor {
				chainPEM := append(
					pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: untrustedLeafCertBytes}),
					pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: untrustedRootCertBytes})...,
				)
				return &client.Rekor{
					Pubkey: &mock.PubkeyClient{
						PEMPubKey: string(chainPEM),
					},
				}
			},
			expectSuccess: false,
		},
		{
			name: "Missing intermediate cert",
			config: &TrustRootConfig{
				CustomRoots:   []*x509.Certificate{trustedRootCert},
				UseTUFDefault: false,
			},
			setupClient: func() *client.Rekor {
				chainPEM := append(
					pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertBytes}),
					pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trustedRootCertBytes})...,
				)
				return &client.Rekor{
					Pubkey: &mock.PubkeyClient{
						PEMPubKey: string(chainPEM),
					},
				}
			},
			expectSuccess: false,
		},
		{
			name: "Empty chain",
			config: &TrustRootConfig{
				CustomRoots:   []*x509.Certificate{trustedRootCert},
				UseTUFDefault: false,
			},
			setupClient: func() *client.Rekor {
				return &client.Rekor{
					Pubkey: &mock.PubkeyClient{
						PEMPubKey: "",
					},
				}
			},
			expectSuccess: false,
		},
		{
			name: "Only leaf certificate",
			config: &TrustRootConfig{
				CustomRoots:   []*x509.Certificate{trustedRootCert},
				UseTUFDefault: false,
			},
			setupClient: func() *client.Rekor {
				chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertBytes})
				return &client.Rekor{
					Pubkey: &mock.PubkeyClient{
						PEMPubKey: string(chainPEM),
					},
				}
			},
			expectSuccess: false,
		},
		{
			name: "Malformed PEM data",
			config: &TrustRootConfig{
				CustomRoots:   []*x509.Certificate{trustedRootCert},
				UseTUFDefault: false,
			},
			setupClient: func() *client.Rekor {
				return &client.Rekor{
					Pubkey: &mock.PubkeyClient{
						PEMPubKey: "invalid-pem-data",
					},
				}
			},
			expectSuccess: false,
		},
		{
			name: "No custom roots and TUF disabled",
			config: &TrustRootConfig{
				CustomRoots:   nil,
				UseTUFDefault: false,
			},
			setupClient: func() *client.Rekor {
				chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertBytes})
				return &client.Rekor{
					Pubkey: &mock.PubkeyClient{
						PEMPubKey: string(chainPEM),
					},
				}
			},
			expectSuccess: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mClient := tc.setupClient()
			trustedRoots, err := GetTrustedRoots(context.Background(), tc.config, mClient)
			if err != nil && tc.expectSuccess {
				t.Fatalf("failed to get trusted roots: %v", err)
			}
			if !tc.expectSuccess && tc.name == "No custom roots and TUF disabled" {
				if err == nil {
					t.Errorf("expected error for no trusted roots but got none")
				}
				return
			}
			if trustedRoots == nil && tc.expectSuccess {
				t.Fatalf("trusted roots should not be nil")
			}

			verifier, err := GetLogVerifier(context.Background(), mClient, trustedRoots)
			if tc.expectSuccess {
				if err != nil {
					t.Errorf("expected success but got error: %v", err)
				}
				if verifier == nil {
					t.Error("expected verifier but got nil")
				} else {
					pubKey, err := verifier.PublicKey()
					if err != nil {
						t.Errorf("failed to get public key from verifier: %v", err)
					}
					if tc.name == "Valid chain with direct root" {
						if err := cryptoutils.EqualKeys(directLeafKey.Public(), pubKey); err != nil {
							t.Errorf("public keys don't match: %v", err)
						}
					}
				}
			} else {
				if err == nil {
					t.Errorf("expected error but got success")
				}
			}
		})
	}
}

func TestVerifyLogEntryCertChain(t *testing.T) {
	trustedRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate trusted root key: %v", err)
	}
	trustedRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Trusted Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	trustedRootCertBytes, err := generateCert(trustedRootTemplate, trustedRootTemplate, &trustedRootKey.PublicKey, trustedRootKey)
	if err != nil {
		t.Fatalf("failed to create trusted root certificate: %v", err)
	}
	trustedRootCert, err := x509.ParseCertificate(trustedRootCertBytes)
	if err != nil {
		t.Fatalf("failed to parse trusted root certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "rekor.sigstore.dev"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafCertBytes, err := generateCert(leafTemplate, trustedRootTemplate, &leafKey.PublicKey, trustedRootKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}

	untrustedRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate untrusted root key: %v", err)
	}
	untrustedRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               pkix.Name{CommonName: "Untrusted Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	untrustedRootCertBytes, err := generateCert(untrustedRootTemplate, untrustedRootTemplate, &untrustedRootKey.PublicKey, untrustedRootKey)
	if err != nil {
		t.Fatalf("failed to create untrusted root certificate: %v", err)
	}
	untrustedRootCert, err := x509.ParseCertificate(untrustedRootCertBytes)
	if err != nil {
		t.Fatalf("failed to parse untrusted root certificate: %v", err)
	}

	untrustedLeafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate untrusted leaf key: %v", err)
	}
	untrustedLeafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(5),
		Subject:      pkix.Name{CommonName: "untrusted-rekor.sigstore.dev"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	untrustedLeafCertBytes, err := generateCert(untrustedLeafTemplate, untrustedRootTemplate, &untrustedLeafKey.PublicKey, untrustedRootKey)
	if err != nil {
		t.Fatalf("failed to create untrusted leaf certificate: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(trustedRootCert)

	untrustedCertPool := x509.NewCertPool()
	untrustedCertPool.AddCert(untrustedRootCert)

	tests := []struct {
		name          string
		entry         models.LogEntryAnon
		certPool      *x509.CertPool
		expectSuccess bool
	}{
		{
			name: "Valid certificate chain",
			entry: func() models.LogEntryAnon {
				apiVersion := "0.0.1"
				content := leafCertBytes
				dataContent := []byte("test data")
				signer, err := signature.LoadECDSASignerVerifier(leafKey, crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to create signer: %v", err)
				}
				sig, err := signer.SignMessage(bytes.NewReader(dataContent))
				if err != nil {
					t.Fatalf("failed to sign data: %v", err)
				}
				contentBase64 := strfmt.Base64(content)
				sigBase64 := strfmt.Base64(sig)
				dataContentBase64 := strfmt.Base64(dataContent)

				spec := models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Content: &sigBase64,
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: &contentBase64,
						},
					},
					Data: &models.RekordV001SchemaData{
						Content: dataContentBase64,
					},
				}
				rekord := models.Rekord{
					APIVersion: &apiVersion,
					Spec:       spec,
				}
				bodyBytes, err := json.Marshal(rekord)
				if err != nil {
					t.Fatalf("failed to marshal rekord: %v", err)
				}
				body := base64.StdEncoding.EncodeToString(bodyBytes)
				logIndex := int64(1)
				return models.LogEntryAnon{
					Body:     body,
					LogIndex: &logIndex,
				}
			}(),
			certPool:      certPool,
			expectSuccess: true,
		},
		{
			name: "Untrusted certificate chain",
			entry: func() models.LogEntryAnon {
				apiVersion := "0.0.1"
				content := untrustedLeafCertBytes
				dataContent := []byte("test data")
				signer, err := signature.LoadECDSASignerVerifier(untrustedLeafKey, crypto.SHA256)
				if err != nil {
					t.Fatalf("failed to create signer: %v", err)
				}
				sig, err := signer.SignMessage(bytes.NewReader(dataContent))
				if err != nil {
					t.Fatalf("failed to sign data: %v", err)
				}
				contentBase64 := strfmt.Base64(content)
				sigBase64 := strfmt.Base64(sig)
				dataContentBase64 := strfmt.Base64(dataContent)

				spec := models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Content: &sigBase64,
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: &contentBase64,
						},
					},
					Data: &models.RekordV001SchemaData{
						Content: dataContentBase64,
					},
				}
				specBytes, err := json.Marshal(spec)
				if err != nil {
					t.Fatalf("failed to marshal spec: %v", err)
				}
				rekord := models.Rekord{
					APIVersion: &apiVersion,
					Spec:       specBytes,
				}
				bodyBytes, err := json.Marshal(rekord)
				if err != nil {
					t.Fatalf("failed to marshal rekord: %v", err)
				}
				body := base64.StdEncoding.EncodeToString(bodyBytes)
				logIndex := int64(2)
				return models.LogEntryAnon{
					Body:     body,
					LogIndex: &logIndex,
				}
			}(),
			certPool:      certPool,
			expectSuccess: false,
		},
		{
			name: "Empty certificate chain",
			entry: func() models.LogEntryAnon {
				apiVersion := "0.0.1"
				rekord := models.Rekord{
					APIVersion: &apiVersion,
					Spec:       []byte(`{}`),
				}
				bodyBytes, err := json.Marshal(rekord)
				if err != nil {
					t.Fatalf("failed to marshal rekord: %v", err)
				}
				body := base64.StdEncoding.EncodeToString(bodyBytes)
				logIndex := int64(0)
				return models.LogEntryAnon{
					Body:     body,
					LogIndex: &logIndex,
				}
			}(),
			certPool:      certPool,
			expectSuccess: false,
		},
		{
			name: "Invalid certificate data",
			entry: func() models.LogEntryAnon {
				apiVersion := "0.0.1"
				invalidCert := strfmt.Base64([]byte("invalid-cert-data"))
				sig := strfmt.Base64([]byte("dummy-signature"))
				data := strfmt.Base64([]byte("dummy-data"))
				spec := models.RekordV001Schema{
					Signature: &models.RekordV001SchemaSignature{
						Content: &sig,
						PublicKey: &models.RekordV001SchemaSignaturePublicKey{
							Content: &invalidCert,
						},
					},
					Data: &models.RekordV001SchemaData{
						Content: data,
					},
				}
				specBytes, err := json.Marshal(spec)
				if err != nil {
					t.Fatalf("failed to marshal spec: %v", err)
				}
				rekord := models.Rekord{
					APIVersion: &apiVersion,
					Spec:       specBytes,
				}
				bodyBytes, err := json.Marshal(rekord)
				if err != nil {
					t.Fatalf("failed to marshal rekord: %v", err)
				}
				body := base64.StdEncoding.EncodeToString(bodyBytes)
				logIndex := int64(0)
				return models.LogEntryAnon{
					Body:     body,
					LogIndex: &logIndex,
				}
			}(),
			certPool:      certPool,
			expectSuccess: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := VerifyLogEntryCertChain(tc.entry, tc.certPool)
			if result != tc.expectSuccess {
				t.Errorf("expected %v but got %v", tc.expectSuccess, result)
			}
		})
	}
}

func generateLeafCert(t *testing.T, rootKey *ecdsa.PrivateKey, rootCert *x509.Certificate) (*ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "valid.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certBytes, err := generateCert(template, rootCert, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	return key, certBytes
}

func createTestRekord(t *testing.T, certBytes []byte, signature []byte, data []byte) string {
	spec := models.RekordV001Schema{
		Signature: &models.RekordV001SchemaSignature{
			Content: (*strfmt.Base64)(&signature),
			PublicKey: &models.RekordV001SchemaSignaturePublicKey{
				Content: (*strfmt.Base64)(&certBytes),
			},
		},
		Data: &models.RekordV001SchemaData{
			Content: strfmt.Base64(data),
		},
	}

	rekord := models.Rekord{
		APIVersion: strPtr("0.0.1"),
		Spec:       spec,
	}

	bodyBytes, err := json.Marshal(rekord)
	if err != nil {
		t.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(bodyBytes)
}

type mockEntriesClient struct {
	entries.ClientService
	getLogEntryByIndexFunc func(params *entries.GetLogEntryByIndexParams) (*entries.GetLogEntryByIndexOK, error)
}

func (m *mockEntriesClient) GetLogEntryByIndex(params *entries.GetLogEntryByIndexParams, _ ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	return m.getLogEntryByIndexFunc(params)
}

func TestProcessLogEntries(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Trusted Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootCertBytes, err := generateCert(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootCertBytes)
	if err != nil {
		t.Fatalf("Failed to parse root certificate: %v", err)
	}

	leafKey, leafCertBytes := generateLeafCert(t, rootKey, rootCert)

	data := []byte("test payload for verification")

	h := crypto.SHA256.New()
	h.Write(data)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, leafKey, digest)
	if err != nil {
		t.Fatalf("Failed to sign digest: %v", err)
	}
	sig := append(r.Bytes(), s.Bytes()...)

	t.Logf("Signature length: %d bytes", len(sig))
	if len(sig) == 0 || len(sig) > 132 || len(sig)%2 != 0 {
		t.Fatalf("Generated signature does not meet IEEE P1363 requirements: length=%d", len(sig))
	}

	chainPEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertBytes})...,
	)

	config := &TrustRootConfig{
		CustomRoots:   []*x509.Certificate{rootCert},
		UseTUFDefault: false,
	}

	tests := []struct {
		name          string
		setupClient   func() *client.Rekor
		expectSuccess bool
	}{
		{
			name: "valid certificate chain",
			setupClient: func() *client.Rekor {
				validBody := createTestRekord(t, leafCertBytes, sig, data)
				return &client.Rekor{
					Entries: &mockEntriesClient{
						getLogEntryByIndexFunc: func(params *entries.GetLogEntryByIndexParams) (*entries.GetLogEntryByIndexOK, error) {
							if params.LogIndex == 0 {
								return &entries.GetLogEntryByIndexOK{
									Payload: map[string]models.LogEntryAnon{
										"1": {
											Body:           validBody,
											LogIndex:       ptrInt64(1),
											IntegratedTime: ptrInt64(time.Now().Unix()),
											Verification: &models.LogEntryAnonVerification{
												InclusionProof: &models.InclusionProof{
													LogIndex: ptrInt64(1),
													RootHash: strPtr("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
													TreeSize: ptrInt64(2),
													Hashes:   []string{"sha256:a1b2c3d4e5f6"},
												},
											},
										},
									},
								}, nil
							}
							return &entries.GetLogEntryByIndexOK{Payload: map[string]models.LogEntryAnon{}}, nil
						},
					},
					Pubkey: &mock.PubkeyClient{PEMPubKey: string(chainPEM)},
				}
			},
			expectSuccess: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rekorClient := tc.setupClient()
			err := ProcessLogEntries(context.Background(), config, rekorClient)

			if tc.expectSuccess && err != nil {
				t.Fatalf("Expected success but got error: %v", err)
			}
			if !tc.expectSuccess && err == nil {
				t.Fatalf("Expected error but got success")
			}
		})
	}
}

func ptrInt64(i int64) *int64 {
	return &i
}

func strPtr(s string) *string {
	return &s
}
