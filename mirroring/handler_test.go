package mirroring

import (
	"testing"

	"github.com/spf13/viper"
)

func TestLoadFromLocal(t *testing.T) {
	h, err := LoadFromLocal("./.config.json")
	if err != nil {
		t.Errorf("error in loadfromlocal %s", err)
	}
	c := TreeMetadata{}
	if h.metadata == c { // deep comparison with empty struct
		t.Errorf("handler not filled in")
	}
}

func TestGetAllLeavesForKind(t *testing.T) {
	h, err := LoadFromLocal("./.config.json")
	if err != nil {
		t.Errorf("%s", err)
	}
	a, err := h.GetAllLeavesForKind("rekord")
	if err != nil {
		t.Errorf("%s", err)
	}
	t.Log(a)
}

func TestFetchAllLeavesForKind(t *testing.T) {
	h, err := LoadFromLocal("./.config.json")
	if err != nil {
		t.Errorf("%s", err)
	}
	a, err := h.FetchAllLeavesForKind("rekord")
	if err != nil {
		t.Errorf("%s", err)
	}
	t.Log(a)
}

func TestSaveTree(t *testing.T) {
	h, err := LoadFromRemote("https://api.sigstore.dev")
	if err != nil {
		t.Errorf("%s", err)
	}
	a, err := h.FetchAllLeavesForKind("")
	if err != nil {
		t.Errorf("%s", err)
	}
	h.SetLeafBuffer(a)
	viper.Set("metadata_file_dir", "./.newmetadata")
	viper.Set("tree_file_dir", "./.newtree")
	h.Save()

	t.Log(a)
}
