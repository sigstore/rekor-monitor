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
