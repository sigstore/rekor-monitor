package main

import (
	"encoding/hex"
	"testing"

	rekorclient "github.com/sigstore/rekor-monitor/pkg"
	"github.com/spf13/viper"
)

// TestVerifySignature tests normal operation of the verifySignature function.
func TestVerifySignature(t *testing.T) {
	viper.Set("rekorServerURL", "http://0.0.0.0:3000")
	err := rekorclient.VerifySignature()
	if err != nil {
		t.Errorf("%s\n", err)
	}
}

func TestFetchLeavesByRange(t *testing.T) {
	viper.Set("rekorServerURL", "https://api.sigstore.dev")
	leaves, err := rekorclient.FetchLeavesByRange(0, 10)
	if err != nil {
		t.Errorf("%s\n", err)
	} else {
		t.Logf("%s\n", leaves)
	}
}

func TestBuildTree(t *testing.T) {
	viper.Set("rekorServerURL", "https://api.sigstore.dev")
	leaves, err := rekorclient.FetchLeavesByRange(0, 8)
	if err != nil {
		t.Errorf("%s\n", err)
		return
	}
	STH, err := rekorclient.ComputeSTH(leaves)
	if err != nil {
		t.Errorf("%s\n", err)
		return
	}
	// 4th hash in inclusion proof of entry at log index 8
	h := "441828658e8d21c60ba3923da71cdac07f8e4c621ce611c94499ce9c185a5dcb"
	if hex.EncodeToString(STH) != h {
		t.Errorf("Computed STH is incorrect.")
	}
}

/*func TestGetLogEntryByIndex(t *testing.T) {
	viper.Set("rekorServerURL", "https://api.sigstore.dev")
	ix, entry, err := rekorclient.GetLogEntryByIndex(10)
	if err != nil {
		t.Errorf("%s\n", err)
	} else {
		a, err := rekorclient.ParseEntry(ix, entry)
		t.Errorf("%+v\n", a)
		t.Errorf("%+v\n", entry)
		t.Errorf("%s\n", err)

		var pk string
		var hash string
		var sig string
		switch v := a.Body.(type) {
		case *rekord_v001.V001Entry:
			pk = string([]byte(v.RekordObj.Signature.PublicKey.Content))
			sig = base64.StdEncoding.EncodeToString([]byte(v.RekordObj.Signature.Content))
			hash = *v.RekordObj.Data.Hash.Value
			t.Errorf("+ Found Rekord:")
		case *rpm_v001.V001Entry:
			pk = string([]byte(v.RPMModel.PublicKey.Content))
			t.Errorf("+ Found RPM ")
		default:
			fmt.Println("no type found")
			t.Errorf("no type found %+v", v)
		}
		t.Errorf("+%v ", pk)
		t.Errorf("+%v ", sig)
		t.Errorf("+%v ", hash)

		// d := entry.Body.(string)
		// t.Errorf(d)
		// decoded, err := base64.StdEncoding.DecodeString(d)
		// var obj types.EntryImpl
		// err = obj.Unmarshal(d)
		// if err != nil {
		// 	t.Errorf("%s\n", err)
		// }
		// t.Errorf("%s\n", decoded)
	}
}*/

/*func TestBuildTree(t *testing.T) {
	viper.Set("rekorServerURL", "https://api.sigstore.dev")
	err := rekorclient.BuildTree()
	if err != nil {
		t.Errorf("%s\n", err)
	}
}*/
