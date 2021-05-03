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
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/go-openapi/strfmt"
	trilliantypes "github.com/google/trillian/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/spf13/viper"
)

type LogHandler struct {
	metadata        TreeMetadata
	client          *client.Rekor
	newLeavesBuffer []Artifact
	logRoot         *trilliantypes.LogRootV1
}

func LoadFromRemote(serverURL string) (h LogHandler, err error) {
	viper.Set("rekorServerURL", serverURL)
	viper.SetDefault("metadata_file_directory", "./.newmetadata")
	viper.SetDefault("tree_file_directory", "./.newtree")
	pub, err := GetPublicKey()
	if err != nil {
		return
	}

	logInfo, err := GetLogInfo()
	if err != nil {
		return
	}

	metadata := TreeMetadata{PublicKey: pub, LogInfo: logInfo, SavedMaxIndex: -1}
	h.metadata = metadata
	err = h.verifyLogRoot(h.metadata.LogInfo.SignedTreeHead.LogRoot)
	if err != nil {
		return
	}
	h.client, err = NewClient()
	if err != nil {
		return h, err
	}
	return
}

// LoadFromLocal parses a JSON file to create a log handler that can be used
// to fetch and verify properties about the log.
func LoadFromLocal(fileName string) (LogHandler, error) {
	viper.SetConfigFile(fileName)
	viper.AddConfigPath(".")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {
		panic(fmt.Errorf("configuration file could not be found.\n%s", err))
	}

	handler := LogHandler{}
	metadata, err := LoadTreeMetadata()
	if err != nil {
		return handler, err
	}
	handler.client, err = NewClient()
	if err != nil {
		return handler, err
	}

	handler.metadata = metadata
	err = handler.verifyLogRoot(handler.metadata.LogInfo.SignedTreeHead.LogRoot)
	if err != nil {
		return handler, err
	}

	handler.newLeavesBuffer = make([]Artifact, 0)
	return handler, nil
}

func (h *LogHandler) verifyLogRoot(logRootBase64 *strfmt.Base64) error {
	// stored information will contain duplicates. the following code checks if these duplicates match.
	// if they don't, the log-handler fails to instantiate.
	logRoot := trilliantypes.LogRootV1{}

	err := logRoot.UnmarshalBinary(*logRootBase64)
	if err != nil {
		return err
	}

	if logRoot.TreeSize != uint64(*h.metadata.LogInfo.TreeSize) {
		return errors.New("the log provided may not be trusted, as the duplicates of the tree size field do not match")
	}

	if hex.EncodeToString(logRoot.RootHash) != *h.metadata.LogInfo.RootHash {
		return errors.New("the log provided may not be trusted, as the duplicates of the root hash field do not match")
	}

	err = h.verifyLogRootSignature(true, logRoot)
	if err != nil {
		return err
	}
	return nil
}

// This function is copied from https://github.com/sigstore/rekor/blob/main/pkg/verify/log_root.go
// as it isn't in a major  release yet.

// SignedLogRoot verifies the signed log root and returns its contents
func SignedLogRoot(pub crypto.PublicKey, logRoot, logRootSignature []byte) (*trilliantypes.LogRootV1, error) {
	hash := crypto.SHA256
	if err := verify(pub, hash, logRoot, logRootSignature); err != nil {
		return nil, err
	}

	var lr trilliantypes.LogRootV1
	if err := lr.UnmarshalBinary(logRoot); err != nil {
		return nil, err
	}
	return &lr, nil
}

// This function is copied from https://github.com/sigstore/rekor/blob/main/pkg/verify/log_root.go
// as it isn't in a major release yet.

// verify cryptographically verifies the output of Signer.
func verify(pub crypto.PublicKey, hasher crypto.Hash, data, sig []byte) error {
	if sig == nil {
		return errors.New("signature is nil")
	}

	h := hasher.New()
	if _, err := h.Write(data); err != nil {
		return err
	}
	digest := h.Sum(nil)

	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return errors.New("verification failed")
		}
	default:
		return fmt.Errorf("unknown public key type: %T", pub)
	}
	return nil
}
func (h *LogHandler) verifyLogRootSignature(addLogRoot bool, logRoot trilliantypes.LogRootV1) error {
	signature, err := base64.StdEncoding.DecodeString(h.metadata.LogInfo.SignedTreeHead.Signature.String())
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(h.metadata.PublicKey))
	if block == nil {
		return errors.New("failed to decode public key of server")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	logRootBytes, err := logRoot.MarshalBinary()
	if err != nil {
		return err
	}

	_, err = SignedLogRoot(publicKey, logRootBytes, signature)
	if err != nil {
		return err
	}

	if addLogRoot {
		h.logRoot = &logRoot
	}
	return nil
}

func (h *LogHandler) GetLeafBuffer() []Artifact {
	return h.newLeavesBuffer
}

func (h *LogHandler) SetLeafBuffer(b []Artifact) {
	h.newLeavesBuffer = b
}

func (h *LogHandler) GetLocalPublicKey() string {
	return h.metadata.PublicKey
}

func (h *LogHandler) GetLocalTreeSize() int64 {
	return h.metadata.SavedMaxIndex + 1
}

func (h *LogHandler) GetRemoteTreeSize() (int64, error) {
	a, err := GetLogInfo()
	if err != nil {
		return 0, err
	}
	return *a.TreeSize, nil
}

func (h *LogHandler) GetRemoteRootSignature() (strfmt.Base64, error) {
	a, err := GetLogInfo()
	if err != nil {
		return nil, err
	}
	return *a.SignedTreeHead.Signature, nil
}

func (h *LogHandler) GetRemoteRootPublicKey() (string, error) {
	keyResp, err := h.client.Tlog.GetPublicKey(nil)
	if err != nil {
		return "", err
	}
	publicKey := keyResp.Payload

	return publicKey, nil
}

func (h *LogHandler) GetRootSignature() ([]byte, error) {
	s, err := base64.StdEncoding.DecodeString(h.metadata.LogInfo.SignedTreeHead.Signature.String())
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (h *LogHandler) GetLocalRootHash() string {
	return *h.metadata.LogInfo.RootHash
}

func (h *LogHandler) GetRemoteRootHash() ([]byte, error) {
	info, err := GetLogInfo()
	if err != nil {
		return nil, err
	}
	logRootBytes, err := base64.StdEncoding.DecodeString(info.SignedTreeHead.LogRoot.String())
	if err != nil {
		return nil, err
	}
	logRoot := trilliantypes.LogRootV1{}
	err = logRoot.UnmarshalBinary(logRootBytes)
	if err != nil {
		return nil, err
	}
	return logRoot.RootHash, nil
}

func (h *LogHandler) SetRootHash(rootHash string) {
	*h.metadata.LogInfo.RootHash = rootHash
}

func (h *LogHandler) SetPublicKey(publicKey string) {
	h.metadata.PublicKey = publicKey
}

func (h *LogHandler) SetRootSignature(sig strfmt.Base64) {
	*h.metadata.LogInfo.SignedTreeHead.Signature = sig
}

func (h *LogHandler) SetLocalTreeSize(treeSize int64) {
	h.metadata.SavedMaxIndex = treeSize - 1
}

// if kind=="", get all kinds of leaves
func (h *LogHandler) GetAllLeavesForKind(kind string) error {
	str := viper.GetString("tree_file_directory")
	if h.newLeavesBuffer != nil && len(h.newLeavesBuffer) != 0 {
		return errors.New("leaf buffer is not empty, please sync by saving")
	}
	file, err := os.Open(str)
	artifacts := make([]Artifact, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	leaf := Artifact{}
	reader := bufio.NewReader(file)
	var line string
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}

		err = json.Unmarshal([]byte(line), &leaf)
		if err != nil {
			return err
		}
		if kind == "" || leaf.Kind == kind {
			artifacts = append(artifacts, leaf)
		}
	}
	h.newLeavesBuffer = artifacts
	return nil
}

func (h *LogHandler) SetLogRoot(a *models.LogInfoSignedTreeHead) {
	h.metadata.LogInfo.SignedTreeHead = a
}
