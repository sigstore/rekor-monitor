package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sigstore/rekor/cmd/cli/app"
	"github.com/sigstore/rekor/cmd/cli/app/state"
	"github.com/spf13/viper"

	"github.com/google/trillian"
	tclient "github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/merkle/logverifier"
	rfc6962 "github.com/google/trillian/merkle/rfc6962/hasher"

	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/log"
)

type logInfoCmdOutput struct {
	TreeSize       int64
	RootHash       string
	TimestampNanos uint64
}

func (l *logInfoCmdOutput) String() string {
	// Verification is always successful if we return an object.
	ts := time.Unix(0, int64(l.TimestampNanos)).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`Verification Successful!
Tree Size: %v
Root Hash: %s
Timestamp: %s
`, l.TreeSize, l.RootHash, ts)
}

func mirror_log() (*logInfoCmdOutput, error) {
	serverURL := viper.GetString("rekor_server")
	rekorClient, err := app.GetRekorClient(serverURL)
	if err != nil {
		return nil, err
	}

	result, err := rekorClient.Tlog.GetLogInfo(nil)
	if err != nil {
		return nil, err
	}

	logInfo := result.GetPayload()

	keyHint, err := base64.StdEncoding.DecodeString(logInfo.SignedTreeHead.KeyHint.String())
	if err != nil {
		return nil, err
	}
	logRoot, err := base64.StdEncoding.DecodeString(logInfo.SignedTreeHead.LogRoot.String())
	if err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(logInfo.SignedTreeHead.Signature.String())
	if err != nil {
		return nil, err
	}
	sth := trillian.SignedLogRoot{
		KeyHint:          keyHint,
		LogRoot:          logRoot,
		LogRootSignature: signature,
	}

	publicKey := viper.GetString("rekor_server_public_key")
	if publicKey == "" {
		// fetch key from server
		keyResp, err := rekorClient.Tlog.GetPublicKey(nil)
		if err != nil {
			return nil, err
		}
		publicKey = keyResp.Payload
	}

	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("failed to decode public key of server")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, pub, crypto.SHA256)
	lr, err := tcrypto.VerifySignedLogRoot(verifier.PubKey, verifier.SigHash, &sth)
	if err != nil {
		return nil, err
	}

	cmdOutput := &logInfoCmdOutput{
		TreeSize:       *logInfo.TreeSize,
		RootHash:       *logInfo.RootHash,
		TimestampNanos: lr.TimestampNanos,
	}

	if lr.TreeSize != uint64(*logInfo.TreeSize) {
		return nil, errors.New("tree size in signed tree head does not match value returned in API call")
	}

	if !strings.EqualFold(hex.EncodeToString(lr.RootHash), *logInfo.RootHash) {
		return nil, errors.New("root hash in signed tree head does not match value returned in API call")
	}

	oldState := state.Load(serverURL)
	if oldState != nil {
		persistedSize := oldState.TreeSize
		if persistedSize < lr.TreeSize {
			log.CliLogger.Infof("Found previous log state, proving consistency between %d and %d", oldState.TreeSize, lr.TreeSize)
			params := tlog.NewGetLogProofParams()
			firstSize := int64(persistedSize)
			params.FirstSize = &firstSize
			params.LastSize = int64(lr.TreeSize)
			proof, err := rekorClient.Tlog.GetLogProof(params)
			if err != nil {
				return nil, err
			}
			hashes := [][]byte{}
			for _, h := range proof.Payload.Hashes {
				b, _ := hex.DecodeString(h)
				hashes = append(hashes, b)
			}
			v := logverifier.New(rfc6962.DefaultHasher)
			if err := v.VerifyConsistencyProof(firstSize, int64(lr.TreeSize), oldState.RootHash,
				lr.RootHash, hashes); err != nil {
				return nil, err
			}
			log.CliLogger.Infof("Consistency proof valid!")
		} else if persistedSize == lr.TreeSize {
			if !bytes.Equal(oldState.RootHash, lr.RootHash) {
				return nil, errors.New("root hash returned from server does not match previously persisted state")
			}
			log.CliLogger.Infof("Persisted log state matches the current state of the log")
		} else if persistedSize > lr.TreeSize {
			return nil, fmt.Errorf("current size of tree reported from server %d is less than previously persisted state %d", lr.TreeSize, persistedSize)
		}
	} else {
		log.CliLogger.Infof("No previous log state stored, unable to prove consistency")
	}

	if err := state.Dump(serverURL, lr); err != nil {
		log.CliLogger.Infof("Unable to store previous state: %v", err)
	}
	return cmdOutput, nil
}

func main() {
	if cmdOutput, err := mirror_log(); err != nil {
		fmt.Print(cmdOutput)
	}
}
