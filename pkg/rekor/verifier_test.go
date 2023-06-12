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
	"testing"

	"github.com/sigstore/rekor-monitor/pkg/rekor/mock"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestGetLogVerifier(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemKey, err := cryptoutils.MarshalPublicKeyToPEM(key.Public())
	if err != nil {
		t.Fatalf("unexpected error marshalling key: %v", err)
	}

	var mClient client.Rekor
	mClient.Pubkey = &mock.PubkeyClient{
		PEMPubKey: string(pemKey),
	}

	verifier, err := GetLogVerifier(context.Background(), &mClient)
	if err != nil {
		t.Fatalf("unexpected error getting log verifier: %v", err)
	}
	pubkey, _ := verifier.PublicKey()
	if err := cryptoutils.EqualKeys(key.Public(), pubkey); err != nil {
		t.Fatalf("expected equal keys: %v", err)
	}
}
