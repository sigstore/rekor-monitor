//
// Copyright 2021 The Sigstore Authors.
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

package mirroring

import (
	"bytes"
	"container/list"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/google/trillian/merkle/logverifier"
	rfc6962 "github.com/google/trillian/merkle/rfc6962/hasher"
	"github.com/sigstore/rekor/pkg/client"
	gclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	rpm_v001 "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
)

type getCmdOutput struct {
	Body           types.EntryImpl
	LogIndex       int
	IntegratedTime int64
	UUID           string
}

type Artifact struct {
	Pk             string `json:"pk,omitempty"`
	DataHash       string `json:"data_hash,omitempty"`
	Sig            string `json:"sig,omitempty"`
	MerkleTreeHash string `json:"merkle_tree_hash,omitempty"`
}

type queueElement struct {
	hash  []byte
	depth int64
}

type LogInconsistencyError struct {
	Err error
}

func (e *LogInconsistencyError) Error() string {
	return fmt.Sprintf("Log consistency check failed: %v", e.Err)
}

func GetPublicKey(rekorClient *gclient.Rekor) (string, error) {
	pubkeyResp, err := rekorClient.Pubkey.GetPublicKey(nil)
	if err != nil {
		return "", err
	}
	return pubkeyResp.Payload, nil
}

func GetLogInfo(rekorClient *gclient.Rekor) (*models.LogInfo, error) {
	logInfoResp, err := rekorClient.Tlog.GetLogInfo(nil)
	if err != nil {
		return nil, err
	}
	return logInfoResp.GetPayload(), nil
}

func GetLogProof(rekorClient *gclient.Rekor, firstSize, lastSize *int64) (*models.ConsistencyProof, error) {
	params := tlog.NewGetLogProofParams()
	if *firstSize > 1 {
		params.FirstSize = firstSize
	}
	params.LastSize = *lastSize

	logProofResp, err := rekorClient.Tlog.GetLogProof(params)
	if err != nil {
		return nil, err
	}
	return logProofResp.GetPayload(), nil
}

func VerifySignedTreeHead(logInfo *models.LogInfo, pubkey string) error {
	sth := util.SignedCheckpoint{}
	if err := sth.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(pubkey))
	if block == nil {
		return errors.New("failed to decode public key of server")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	// Initialize verfier and verify
	verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return err
	}

	if !sth.Verify(verifier) {
		return errors.New("signature on tree head did not verify")
	}

	return nil
}

func VerifyLogConsistency(rekorClient *gclient.Rekor, oldSize int64, oldRootHash string) (int64, string, error) {
	logInfo, err := GetLogInfo(rekorClient)
	if err != nil {
		return 0, "", err
	}

	logProof, err := GetLogProof(rekorClient, &oldSize, logInfo.TreeSize)
	if err != nil {
		return 0, "", err
	}

	oldRoot, err := hex.DecodeString(oldRootHash)
	if err != nil {
		return 0, "", err
	}

	newRoot, err := hex.DecodeString(*logInfo.RootHash)
	if err != nil {
		return 0, "", err
	}

	proofs := make([][]byte, len(logProof.Hashes))
	for i, h := range logProof.Hashes {
		hash, err := hex.DecodeString(h)
		if err != nil {
			return 0, "", err
		}
		proofs[i] = hash
	}

	verifier := logverifier.New(rfc6962.DefaultHasher)
	err = verifier.VerifyConsistencyProof(oldSize, *logInfo.TreeSize, oldRoot, newRoot, proofs)
	if err != nil {
		return 0, "", &LogInconsistencyError{err}
	}
	return *logInfo.TreeSize, hex.EncodeToString(newRoot), nil
}

func VerifyLogInclusion(rekorClient *gclient.Rekor, entryUUID string) error {
	params := entries.NewGetLogEntryByUUIDParams()
	params.EntryUUID = entryUUID
	resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return err
	}
	entry := resp.GetPayload()[entryUUID]

	treeSize := entry.Verification.InclusionProof.TreeSize

	proof := make([][]byte, len(entry.Verification.InclusionProof.Hashes))
	for i, hash := range entry.Verification.InclusionProof.Hashes {
		h, err := hex.DecodeString(hash)
		if err != nil {
			return err
		}
		proof[i] = h
	}

	root, err := hex.DecodeString(*entry.Verification.InclusionProof.RootHash)
	if err != nil {
		return err
	}

	leafHash, err := hex.DecodeString(entryUUID)
	if err != nil {
		return err
	}

	verifier := logverifier.New(rfc6962.DefaultHasher)
	err = verifier.VerifyInclusionProof(*entry.LogIndex, *treeSize, proof, root, leafHash)
	if err != nil {
		return err
	}
	return nil
}

func GetLogEntryByIndex(logIndex int64, rekorClient *gclient.Rekor) (string, models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByIndexParams()
	params.LogIndex = logIndex

	resp, err := rekorClient.Entries.GetLogEntryByIndex(params)
	if err != nil {
		return "", models.LogEntryAnon{}, err
	}
	for ix, entry := range resp.Payload {
		return ix, entry, nil
	}

	return "", models.LogEntryAnon{}, errors.New("response returned no entries. Please check logIndex.")
}

func GetLogEntryData(logIndex int64, rekorClient *gclient.Rekor) (Artifact, error) {
	ix, entry, err := GetLogEntryByIndex(logIndex, rekorClient)
	if err != nil {
		return Artifact{}, err
	}

	a, err := ParseEntry(ix, entry)
	b := Artifact{}
	b.MerkleTreeHash = a.UUID

	switch v := a.Body.(type) {
	case *rekord_v001.V001Entry:
		b.Pk = string([]byte(v.RekordObj.Signature.PublicKey.Content))
		b.Sig = base64.StdEncoding.EncodeToString([]byte(v.RekordObj.Signature.Content))
		b.DataHash = *v.RekordObj.Data.Hash.Value
	case *rpm_v001.V001Entry:
		b.Pk = string([]byte(v.RPMModel.PublicKey.Content))
	default:
		return b, errors.New("The type of this log entry is not supported.")
	}

	return b, nil
}

// this function also verifies the integrity of an entry.
func ParseEntry(uuid string, e models.LogEntryAnon) (getCmdOutput, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return getCmdOutput{}, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return getCmdOutput{}, err
	}
	eimpl, err := types.NewEntry(pe)
	if err != nil {
		return getCmdOutput{}, err
	}

	/*
		// verify if signature matches the given public key + hash

		// verify if merkle tree hash is computed correctly
		marshalledEntry, err := eimpl.Canonicalize(context.TODO()) ////////////
		if err != nil {
			return getCmdOutput{}, err
		}

		mth := rfc6962.DefaultHasher.HashLeaf(marshalledEntry)

		if a, _ := hex.DecodeString(uuid); !bytes.Equal(a, mth) {
			return getCmdOutput{}, errors.New("MALICIOUS LOG: Computed hash does not match log entry hash.")
		}
	*/

	obj := getCmdOutput{
		Body:           eimpl,
		UUID:           uuid,
		IntegratedTime: *e.IntegratedTime,
		LogIndex:       int(*e.LogIndex),
	}

	return obj, nil
}

// FetchLeavesByRange fetches leaves by range and saves them into a file.
func FetchLeavesByRange(initSize, finalSize int64) error {
	rekorServerURL := viper.GetString("rekorServerURL")
	rekorClient, err := client.GetRekorClient(rekorServerURL)
	if err != nil {
		return err
	}

	leaves := make([]Artifact, 1)
	var i int64
	// use retrieve post request instead, retrieve multiple entries at once
	for i = initSize; i < finalSize; i++ {
		artifact, err := GetLogEntryData(i, rekorClient)
		if err != nil {
			return err
		}
		leaves[0] = artifact
		err = AppendArtifactsToFile(leaves)
		if err != nil {
			return err
		}
	}

	return nil
}

func ComputeRootFromMemory(artifacts []Artifact) ([]byte, error) {
	queue := list.New()
	el := queueElement{}

	// hash leaves here and fill queue with []byte representations of hashes
	for _, artifact := range artifacts {

		str := artifact.MerkleTreeHash

		hash, err := hex.DecodeString(str)
		if err != nil {
			return nil, err
		}
		el.hash = hash
		el.depth = 0
		queue.PushBack(el)
	}

	for queue.Len() >= 2 {
		a := queue.Front()
		aVal := queue.Remove(a).(queueElement)

		b := queue.Front()

		var leftHash, rightHash []byte
		if b.Value.(queueElement).depth > aVal.depth { // wrap around case
			el.depth = aVal.depth + 1
			el.hash = aVal.hash
		} else {
			bVal := queue.Remove(b).(queueElement)
			rightHash = bVal.hash
			leftHash = aVal.hash

			hash := rfc6962.DefaultHasher.HashChildren(leftHash, rightHash)
			el.depth = bVal.depth + 1
			el.hash = hash
		}

		queue.PushBack(el)
	}
	if queue.Front() == nil {
		return nil, errors.New("Something went wrong.")
	}

	return queue.Front().Value.(queueElement).hash, nil
}
