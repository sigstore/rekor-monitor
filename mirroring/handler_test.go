package mirroring

import (
	"testing"
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
	err = h.GetAllLeavesForKind("rekord")
	if err != nil {
		t.Errorf("%s", err)
	}
}

func TestFetchAllLeavesForKind(t *testing.T) {
	h, err := LoadFromLocal("./.config.json")
	if err != nil {
		t.Errorf("%s", err)
	}
	err = h.FetchAllLeavesForKind("rekord")
	if err != nil {
		t.Errorf("%s", err)
	}

}

func TestSaveTree(t *testing.T) {
	h, err := LoadFromRemote("https://api.sigstore.dev")
	if err != nil {
		t.Errorf("%s", err)
	}
	err = h.FetchAllLeavesForKind("")
	if err != nil {
		t.Errorf("%s", err)
	}

	h.Save()

}

func TestFetchByRange(t *testing.T) {
	h, err := LoadFromLocal("./.config.json")
	if err != nil {
		t.Errorf("%s", err)
	}
	finalSize, err := h.GetRemoteTreeSize()
	if err != nil {
		t.Errorf("%s", err)
	}
	err = h.FetchByRange(h.GetLocalTreeSize(), finalSize)
	if err != nil {
		t.Errorf("%s", err)
	}

	h.Save()

}
