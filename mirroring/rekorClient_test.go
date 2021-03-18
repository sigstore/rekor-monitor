package main

import (
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
