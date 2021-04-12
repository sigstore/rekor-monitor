package mirroring

import (
	"testing"
)

func TestLoadFromLocal(t *testing.T) {
	h, err := LoadFromLocal("./.config.json")
	if err != nil {
		t.Errorf("error in loadfromlocal")
	}
	c := TreeMetadata{}
	if h.metadata == c { // deep comparison with empty struct
		t.Errorf("handler not filled in")
	}
}
