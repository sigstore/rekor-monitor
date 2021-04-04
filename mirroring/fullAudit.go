package mirroring

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	tclient "github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	rfc6962 "github.com/google/trillian/merkle/rfc6962/hasher"
	trilliantypes "github.com/google/trillian/types"
)

func FullAudit() error {

	metadata, err := LoadTreeMetadata()
	if err != nil { // if metadata isn't saved properly (or at all)
		// fetch all leaves
		err1 := SaveTreeMetadata()
		if err1 != nil {
			return err1
		}
	}

	metadata, err = LoadTreeMetadata()
	if err != nil {
		return err
	}

	logInfo, err := GetLogInfo()
	if err != nil {
		return err
	}
	logRootBytes, err := base64.StdEncoding.DecodeString(logInfo.SignedTreeHead.LogRoot.String())
	if err != nil {
		return err
	}

	logRoot := trilliantypes.LogRootV1{}
	err = logRoot.UnmarshalBinary(logRootBytes)
	if err != nil {
		return err
	}

	pub := metadata.PublicKey

	block, _ := pem.Decode([]byte(pub))
	if block == nil {
		return errors.New("failed to decode public key of server")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	sth := logInfo.SignedTreeHead

	err = VerifySignature(pub)
	if err != nil {
		return err
	}

	err = FetchLeavesByRange(metadata.SavedMaxIndex+1, *logInfo.TreeSize)
	if err != nil {
		return err
	}

	computedSTH, err := ComputeRoot(*logInfo.TreeSize)
	if err != nil {
		return err
	}

	logRoot.RootHash = computedSTH

	verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, publicKey, crypto.SHA256)

	sig, err := base64.StdEncoding.DecodeString(sth.Signature.String())
	if err != nil {
		return err
	}

	logRootBytes, err = logRoot.MarshalBinary()
	if err != nil {
		return err
	}

	err = tcrypto.Verify(verifier.PubKey, verifier.SigHash, logRootBytes, sig)
	if err != nil {
		return err
	}
	// sth verified
	err = UpdateMetadataBySTH()
	if err != nil {
		return err
	}

	err = UpdateMetadataByIndex(*logInfo.TreeSize - 1)
	if err != nil {
		return err
	}

	return nil
}
