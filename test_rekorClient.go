package main

import (
	"fmt"

	rekorclient "github.com/sigstore/rekor-monitor/pkg"
	"github.com/spf13/viper"
)

func main() {
	viper.Set("rekorServerURL", "http://0.0.0.0:3000")
	err := rekorclient.VerifySignature()
	if err != nil {
		fmt.Println(err)

	}

}
