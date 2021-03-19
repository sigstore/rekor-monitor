package main

import (
	"testing"

	"encoding/base64"
	"fmt"
	rekorclient "github.com/sigstore/rekor-monitor/pkg"
	"github.com/spf13/viper"
	rpm_v001 "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
)

// TestVerifySignature tests normal operation of the verifySignature function.
func TestVerifySignature(t *testing.T) {
	viper.Set("rekorServerURL", "http://0.0.0.0:3000")
	err := rekorclient.VerifySignature()
	if err != nil {
		t.Errorf("%s\n", err)
	}
}

func TestGetLogEntryByIndex(t *testing.T) {
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
}
