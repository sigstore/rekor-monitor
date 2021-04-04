package mirroring

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/spf13/viper"
)

//consider loading filenames/paths from viper registry
func AppendArtifactsToFile(artifacts []Artifact) error {
	str := viper.GetString("tree_file_dir")
	f, err := os.OpenFile(str, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	for _, leave := range artifacts {
		serialLeave, err := json.Marshal(leave)
		if err != nil {
			return err
		}
		serialLeave = append(serialLeave, '\n')
		_, err = f.Write(serialLeave)
		if err != nil {
			return err
		}
	}

	return nil
}

func ReadLeaveFromFile(idx int64) (Artifact, error) {
	str := viper.GetString("tree_file_dir")
	file, err := os.Open(str)
	if err != nil {
		return Artifact{}, err
	}
	defer file.Close()
	leave := Artifact{}

	reader := bufio.NewReader(file)
	var line string
	for i := int64(0); i <= idx; i++ {
		line, err = reader.ReadString('\n')
		if err != nil {
			return Artifact{}, err
		}

	}
	err = json.Unmarshal([]byte(line), &leave)
	if err != nil {
		return Artifact{}, err
	}
	return leave, nil
}
