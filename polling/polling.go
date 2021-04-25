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

package polling

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	tclient "github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	rfc6962 "github.com/google/trillian/merkle/rfc6962/hasher"
	trilliantypes "github.com/google/trillian/types"

	mirroring "github.com/sigstore/rekor-monitor/mirroring"
)

type MaliciousArtifactFound struct {
	maliciousHash string
	publicKey     string
}

func (e *MaliciousArtifactFound) Error() string {
	return e.maliciousHash + " signed with public key: " + e.publicKey + " not found in provided hash list."
}

// PollPublicKey looks for unauthorized entries published with the public key of the monitor client.
func PollPublicKey() error {
	cfg, err := ReadCfg()
	if err != nil {
		return err
	}

	err = pollPublicKey(cfg.Hashes, cfg.PublicKey)
	if err != nil {
		return err
	}

	return nil
}

func pollPublicKey(hashes map[string]bool, publicKey string) error {
	metadata, err := mirroring.LoadTreeMetadata()
	if err != nil {
		return err
	}

	treeSize := *metadata.LogInfo.TreeSize
	for idx := int64(0); idx < treeSize; idx++ {
		artifact, err := mirroring.ReadLeaveFromFile(idx)
		if err != nil {
			return err
		}

		hash := artifact.DataHash
		if artifact.Pk == publicKey {
			if _, ok := hashes[hash]; !ok {
				return &MaliciousArtifactFound{maliciousHash: hash, publicKey: artifact.Pk}
			}
		}
	}

	return nil
}

func PollSTH() error {
	metadata, err := mirroring.LoadTreeMetadata()
	if err != nil { // if metadata isn't saved properly (or at all)
		// fetch all leaves
		err1 := mirroring.SaveTreeMetadata()
		if err1 != nil {
			return err1
		}
	}

	metadata, err = mirroring.LoadTreeMetadata()
	if err != nil {
		return err
	}
	sth := metadata.LogInfo.SignedTreeHead.Signature

	fetchedLogInfo, err := mirroring.GetLogInfo()
	if err != nil {
		return err
	}

	if sth != fetchedLogInfo.SignedTreeHead.Signature { // new leaves must have been appended, or it's a malicious log
		pub := metadata.PublicKey

		block, _ := pem.Decode([]byte(pub))
		if block == nil {
			return errors.New("failed to decode public key of server")
		}

		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}

		err = mirroring.FetchLeavesByRange(metadata.SavedMaxIndex+1, *fetchedLogInfo.TreeSize)
		if err != nil {
			return err
		}

		computedSTH, err := mirroring.ComputeRoot(*fetchedLogInfo.TreeSize)
		if err != nil {
			return err
		}
		logRootBytes, err := base64.StdEncoding.DecodeString(fetchedLogInfo.SignedTreeHead.LogRoot.String())
		if err != nil {
			return err
		}

		logRoot := trilliantypes.LogRootV1{}
		err = logRoot.UnmarshalBinary(logRootBytes)
		if err != nil {
			return err
		}
		logRoot.RootHash = computedSTH

		verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, publicKey, crypto.SHA256)

		fetchedSTH := fetchedLogInfo.SignedTreeHead
		sig, err := base64.StdEncoding.DecodeString(fetchedSTH.Signature.String())
		if err != nil {
			return err
		}

		logRootBytes, err = logRoot.MarshalBinary()
		if err != nil {
			return err
		}

		err = tcrypto.Verify(verifier.PubKey, verifier.SigHash, logRootBytes, sig)
		if err != nil {
			return err
		}

		// sth verified
		err = mirroring.UpdateMetadataBySTH()
		if err != nil {
			return err
		}

		err = mirroring.UpdateMetadataByIndex(*fetchedLogInfo.TreeSize - 1)
		if err != nil {
			return err
		}
	}

	return nil
}
