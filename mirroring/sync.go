package mirroring

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/spf13/viper"
)

func (h *LogHandler) IsSTHUpdated() (bool, error) {
	sth := h.metadata.LogInfo.SignedTreeHead.Signature

	remoteSig, err := h.GetRemoteRootSignature()
	if err != nil {
		return false, err
	}

	if sth.String() != remoteSig.String() {
		return true, nil
	} else {
		return false, nil
	}

}

func (h *LogHandler) Save() error {
	err := h.FetchLogRoot()
	if err != nil {
		return err
	}
	metadata := h.metadata

	serialMetadata, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	str := viper.GetString("metadata_file_directory")
	// assumes that if file cannot be removed, it does not exist
	os.Remove(str)
	f, err := os.OpenFile(str, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	_, err = f.Write(serialMetadata)
	if err != nil {
		return err
	}

	err = AppendArtifactsToFile(h.GetLeafBuffer())
	if err != nil {
		return err
	}

	h.newLeavesBuffer = make([]Artifact, 0)
	return nil
}

func (h *LogHandler) FetchAllLeavesForKind(kind string) error {
	leaves := make([]Artifact, 0)

	size, err := h.GetRemoteTreeSize()
	if err != nil {
		return err
	}

	var i int64
	// use retrieve post request instead, retrieve multiple entries at once
	for i = 0; i < size; i++ {
		artifact, err := GetLogEntryData(i, h.client)
		if err != nil {
			return err
		}
		if kind == "" || artifact.Kind == kind {
			leaves = append(leaves, artifact)
		}
	}
	h.SetLeafBuffer(leaves)
	h.SetLocalTreeSize(int64(len(leaves)))
	return nil
}

func (h *LogHandler) FetchByRange(initSize, finalSize int64) error {
	leaves := make([]Artifact, 0)
	var i int64
	var err error
	if h.newLeavesBuffer != nil && len(h.newLeavesBuffer) != 0 {
		return errors.New("leaf buffer is not empty, please sync by saving")
	}
	// use retrieve post request instead, retrieve multiple entries at once
	for i = initSize; i < finalSize; i++ {
		artifact, err := GetLogEntryData(i, h.client)
		if err != nil {
			return err
		}

		leaves = append(leaves, artifact)
		if err != nil {
			return err
		}
	}
	h.SetLeafBuffer(leaves)
	h.SetLocalTreeSize(finalSize)
	return err
}

func (h *LogHandler) FetchLogRoot() error {
	logInfo, err := GetLogInfo()
	if err != nil {
		return err
	}
	h.metadata.LogInfo.SignedTreeHead = logInfo.SignedTreeHead
	h.metadata.LogInfo.RootHash = logInfo.RootHash
	h.metadata.LogInfo.TreeSize = logInfo.TreeSize
	return nil
}
