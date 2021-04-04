package mirroring

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/spf13/viper"
)

type TreeMetadata struct {
	PublicKey     string          `json:"public_key,omitempty"`
	LogInfo       *models.LogInfo `json:"log_info,omitempty"`
	SavedMaxIndex int64           `json:"saved_max_index,omitempty"`
}

// consider loading filenames/paths from viper registry
func LoadTreeMetadata() (TreeMetadata, error) {
	str := viper.GetString("metadata_file_dir")
	bytes, err := ioutil.ReadFile(str)
	if err != nil {
		return TreeMetadata{}, err
	}

	metadata := TreeMetadata{}

	err = json.Unmarshal(bytes, &metadata)
	if err != nil {
		return TreeMetadata{}, err
	}

	return metadata, nil
}

func SaveTreeMetadata() error {
	f, err := os.OpenFile(".metadata", os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	pub, err := GetPublicKey()
	if err != nil {
		return err
	}

	logInfo, err := GetLogInfo()
	if err != nil {
		return err
	}

	metadata := TreeMetadata{PublicKey: pub, LogInfo: logInfo, SavedMaxIndex: -1}

	serialMetadata, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = f.Write(serialMetadata)
	if err != nil {
		return err
	}

	return nil
}

func UpdateMetadataByIndex(i int64) error {
	bytes, err := ioutil.ReadFile(".metadata")
	if err != nil {
		return err
	}

	metadata := TreeMetadata{}

	err = json.Unmarshal(bytes, &metadata)
	if err != nil {
		return err
	}

	metadata.SavedMaxIndex = i

	serialMetadata, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	err = os.Remove(".metadata")
	if err != nil {
		return err
	}

	f, err := os.OpenFile(".metadata", os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	_, err = f.Write(serialMetadata)
	if err != nil {
		return err
	}
	return nil
}
