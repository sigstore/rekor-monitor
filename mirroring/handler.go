package mirroring

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
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

// consider adding a rekorClient field so that the same client struct is used for all operations, potentially saving some time
type LogHandler struct {
	metadata        TreeMetadata
	client          *client.Rekor
	newLeavesBuffer []Artifact
}

func LoadFromRemote(serverURL string) (h LogHandler, err error) {
	viper.Set("rekorServerURL", serverURL)
	viper.SetDefault("metadata_file_dir", "./.newmetadata")
	viper.SetDefault("tree_file_dir", "./.newtree")
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
	// stored information will contain duplicates. should these duplicates be checked?
	/*
			logRoot := trilliantypes.LogRootV1{}
			logRootBytes, err := base64.StdEncoding.DecodeString(metadata.LogInfo.SignedTreeHead.LogRoot.String())
			if err != nil {
				return handler, err
			}
			err = logRoot.UnmarshalBinary(logRootBytes)
			if err != nil {
				return handler, err
			}
		logRoot.
			if logRoot.RootHash != []byte(*metadata.LogInfo.RootHash)
	*/
	handler.newLeavesBuffer = make([]Artifact, 0)
	return handler, nil
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
	str := viper.GetString("tree_file_dir")
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
	for kind != "" {
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
		if leaf.Kind == kind {
			artifacts = append(artifacts, leaf)
		}
	}
	for kind == "" {
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
		artifacts = append(artifacts, leaf)
	}
	h.newLeavesBuffer = artifacts
	return nil
}

func (h *LogHandler) SetLogRoot(a *models.LogInfoSignedTreeHead) {
	h.metadata.LogInfo.SignedTreeHead = a
}
