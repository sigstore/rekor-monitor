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

package v1

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/sigstore/rekor-monitor/pkg/rekor/mock"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/root"
	"golang.org/x/mod/sumdb/note"
)

func TestGetLogVerifier(t *testing.T) {
	rootHash, _ := hex.DecodeString("1a341bc342ff4e567387de9789ab14000b147124317841489172419874198147")
	sc, err := util.CreateSignedCheckpoint(util.Checkpoint{
		Origin: "origin",
		Size:   uint64(123),
		Hash:   rootHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	sc.Signatures = []note.Signature{{Name: "name", Hash: 1, Base64: "adbadbadb"}}

	logInfo := &models.LogInfo{}
	signedNoteString := sc.SignedNote.String()
	logInfo.SignedTreeHead = &signedNoteString
	treeSize := int64(1234)
	logInfo.TreeSize = &treeSize

	var mClient client.Rekor
	mClient.Tlog = &mock.TlogClient{
		LogInfo: logInfo,
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rekorLogs := make(map[string]*root.TransparencyLog)
	rekorLogs["00000001"] = &root.TransparencyLog{HashFunc: crypto.SHA256, PublicKey: &key.PublicKey}
	trustedRoot := mock.NewTrustedRoot(nil, rekorLogs)

	verifier, err := GetLogVerifier(context.Background(), &mClient, trustedRoot)
	if err != nil {
		t.Fatalf("unexpected error getting log verifier: %v", err)
	}

	verifierPubKey, err := verifier.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error getting public key from verifier: %v", err)
	}

	if !key.PublicKey.Equal(verifierPubKey) {
		t.Fatalf("public keys were not equal")
	}
}
