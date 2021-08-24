//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mirroring

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
)

func GetPublicKey() (string, error) {
	// Initialize Rekor client
	rekorServerURL := viper.GetString("rekorServerURL")
	rekorClient, err := client.GetRekorClient(rekorServerURL)
	if err != nil {
		return "", err
	}

	// Get Rekor public key
	pubkeyResp, err := rekorClient.Pubkey.GetPublicKey(nil)
	if err != nil {
		return "", err
	}
	return pubkeyResp.Payload, nil
}

func GetLogInfo() (*models.LogInfo, error) {
	// Initialize Rekor client
	rekorServerURL := viper.GetString("rekorServerURL")
	rekorClient, err := client.GetRekorClient(rekorServerURL)
	if err != nil {
		return nil, err
	}

	// Get log info
	logInfoResp, err := rekorClient.Tlog.GetLogInfo(nil)
	if err != nil {
		return nil, err
	}
	return logInfoResp.GetPayload(), nil
}

func VerifySignedTreeHead() error {
	logInfo, err := GetLogInfo()
	if err != nil {
		return err
	}

	sth := util.SignedCheckpoint{}
	if err := sth.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
		return err
	}

	// Get Rekor public key
	pubkey, err := GetPublicKey()
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(pubkey))
	if block == nil {
		return errors.New("failed to decode public key of server")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	// Initialize verfier and verify
	verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return err
	}

	if !sth.Verify(verifier) {
		return errors.New("signature on tree head did not verify")
	}

	return nil
}
