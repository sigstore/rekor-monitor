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

// TODO: Move rekor client functions to rekor/client.go
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

	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor/pkg/client"
	gclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	rpm_v001 "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"github.com/transparency-dev/merkle/rfc6962"
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

func LoadVerifier(pemPubKey string) (signature.Verifier, error) {
	block, _ := pem.Decode([]byte(pemPubKey))
	if block == nil {
		return nil, errors.New("failed to decode public key of server")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return signature.LoadVerifier(pub, crypto.SHA256)
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

	return "", models.LogEntryAnon{}, errors.New("response returned no entries, check log index")
}

func GetLogEntryData(logIndex int64, rekorClient *gclient.Rekor) (Artifact, error) {
	ix, entry, err := GetLogEntryByIndex(logIndex, rekorClient)
	if err != nil {
		return Artifact{}, err
	}

	a, err := parseEntry(ix, entry)
	if err != nil {
		return Artifact{}, err
	}
	b := Artifact{}
	b.MerkleTreeHash = a.UUID

	switch v := a.Body.(type) {
	case *rekord_v001.V001Entry:
		b.Pk = string([]byte(*v.RekordObj.Signature.PublicKey.Content))
		b.Sig = base64.StdEncoding.EncodeToString([]byte(*v.RekordObj.Signature.Content))
		b.DataHash = *v.RekordObj.Data.Hash.Value
	case *rpm_v001.V001Entry:
		b.Pk = string([]byte(*v.RPMModel.PublicKey.Content))
	default:
		return b, errors.New("the type of this log entry is not supported")
	}

	return b, nil
}

// this function also verifies the integrity of an entry.
func parseEntry(uuid string, e models.LogEntryAnon) (getCmdOutput, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return getCmdOutput{}, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return getCmdOutput{}, err
	}
	eimpl, err := types.UnmarshalEntry(pe)
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
		return nil, errors.New("something went wrong")
	}

	return queue.Front().Value.(queueElement).hash, nil
}
