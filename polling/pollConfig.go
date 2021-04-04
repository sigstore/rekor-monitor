package polling

import (
	"encoding/json"
	"io/ioutil"

	"github.com/spf13/viper"
)

type PollCfg struct {
	Hashes    map[string]bool `json:"hashes,omitempty"`
	PublicKey string          `json:"public_key,omitempty"`
}

type pollCfg struct {
	Hashes    []string `json:"hashes,omitempty"`
	PublicKey string   `json:"public_key,omitempty"`
}

func ReadCfg() (PollCfg, error) {
	cfgFileDir := viper.GetString("poll_config_file_dir")

	bytes, err := ioutil.ReadFile(cfgFileDir)
	if err != nil {
		return PollCfg{}, err
	}

	cfg := pollCfg{}

	err = json.Unmarshal(bytes, &cfg)
	if err != nil {
		return PollCfg{}, err
	}

	Cfg := PollCfg{Hashes: make(map[string]bool)}

	for _, hash := range cfg.Hashes {
		Cfg.Hashes[hash] = true
	}
	Cfg.PublicKey = cfg.PublicKey

	return Cfg, nil
}
