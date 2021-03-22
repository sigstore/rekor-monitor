package rekorclient

import (
	"encoding/json"
	"os"
)

//consider loading filenames/paths from viper registry
func AppendArtifactsToFile(artifacts []Artifact) error {
	f, err := os.OpenFile(".tree", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	/*for _, leave := range artifacts {
		serialLeave, err := json.Marshal(leave)
		if err != nil {
			return err
		}

		_, err = f.Write(serialLeave)
		if err != nil {
			return err
		}
	}*/

	serialArtifacts, err := json.Marshal(artifacts)
	if err != nil {
		return err
	}

	_, err = f.Write(serialArtifacts)
	if err != nil {
		return err
	}
	return nil
}
