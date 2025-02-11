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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/rekor/mock"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func fetchRealCertChain() ([]*x509.Certificate, error) {
	resp, err := http.Get("https://rekor.sigstore.dev/api/v1/log/publicKey")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(bodyBytes)
	if err == nil && len(certs) > 0 {
		return certs, nil
	}

	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	dummyCert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "Rekor Public Key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		PublicKey:    pubKey,
	}

	return []*x509.Certificate{dummyCert}, nil
}

func TestGetLogVerifierWithRealAndMockData(t *testing.T) {
	realCertChain, err := fetchRealCertChain()
	if err != nil {
		t.Fatalf("failed to fetch certificate chain: %v", err)
	}
	if len(realCertChain) == 0 {
		t.Fatalf("certificate chain is empty")
	}

	realPubKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(realCertChain[0].PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal real public key to PEM: %v", err)
	}

	var mClient client.Rekor
	mClient.Pubkey = &mock.PubkeyClient{
		PEMPubKey: string(realPubKeyPEM),
	}

	realTrustRootConfig := &TrustRootConfig{}

	_, err = GetLogVerifier(context.Background(), &mClient, realTrustRootConfig)
	if err == nil {
		t.Fatalf("expected error due to unknown authority, but got a verifier")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unexpected error generating key: %v", err)
	}

	mockTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	mockCertBytes, err := x509.CreateCertificate(rand.Reader, mockTemplate, mockTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("unexpected error creating certificate: %v", err)
	}

	mockCert, err := x509.ParseCertificate(mockCertBytes)
	if err != nil {
		t.Fatalf("failed to parse created certificate: %v", err)
	}

	mockCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mockCertBytes})

	mockTrustRootConfig := &TrustRootConfig{
		CustomRoots: []*x509.Certificate{mockCert},
	}

	mClient.Pubkey = &mock.PubkeyClient{
		PEMPubKey: string(mockCertPEM),
	}

	_, err = GetLogVerifier(context.Background(), &mClient, &TrustRootConfig{})
	if err == nil {
		t.Fatalf("expected error due to unknown authority, but got a verifier")
	}

	verifier, err := GetLogVerifier(context.Background(), &mClient, mockTrustRootConfig)
	if err != nil {
		t.Fatalf("unexpected error getting log verifier with mock certificate: %v", err)
	}

	verifierPubKey, _ := verifier.PublicKey()
	if err := cryptoutils.EqualKeys(key.Public(), verifierPubKey); err != nil {
		t.Fatalf("expected equal keys: %v", err)
	}

}
