package rekorclient

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/google/trillian"
	tclient "github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	rfc6962 "github.com/google/trillian/merkle/rfc6962/hasher"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/rekord"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/rpm"
	rpm_v001 "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/spf13/viper"
)

// START OF CODE FROM SIGSTORE/REKOR

// NewClient creates a Rekor Client for log queries.
func NewClient() (*client.Rekor, error) {
	//rekorAPI.ConfigureAPI() // enable_retrieve_api? possible performance improvement
	//context := context.TODO()
	//trillianClient := rekorAPI.NewTrillianClient(context)
	// sigstore/rekor/cmd/cli/app/root.go:117
	rekorServerURL := viper.GetString("rekorServerURL")
	url, err := url.Parse(rekorServerURL)
	if err != nil {
		return nil, err
	}
	rt := httptransport.New(url.Host, client.DefaultBasePath, []string{url.Scheme})
	rt.Consumers["application/yaml"] = util.YamlConsumer()
	rt.Consumers["application/x-pem-file"] = runtime.TextConsumer()
	rt.Producers["application/yaml"] = util.YamlProducer()

	if viper.GetString("api-key") != "" {
		rt.DefaultAuthentication = httptransport.APIKeyAuth("apiKey", "query", viper.GetString("api-key"))
	}
	rekorClient := client.New(rt, strfmt.Default)
	return rekorClient, nil
}

// GetLogInfo retrieves the root hash, the tree size,
// the key hint, log root, and signature of the log
// through the Rekor API.
func GetLogInfo() (*models.LogInfo, error) {
	rekorClient, err := NewClient()
	if err != nil {
		return nil, err
	}

	result, err := rekorClient.Tlog.GetLogInfo(nil)

	if err != nil {
		return nil, err
	}

	logInfo := result.GetPayload()
	return logInfo, nil
}

// VerifySignature a
func VerifySignature() error {
	logInfo, err := GetLogInfo()
	if err != nil {
		return err
	}

	rekorClient, err := NewClient()
	if err != nil {
		return err
	}

	keyHint, err := base64.StdEncoding.DecodeString(logInfo.SignedTreeHead.KeyHint.String())
	if err != nil {
		return err
	}

	logRoot, err := base64.StdEncoding.DecodeString(logInfo.SignedTreeHead.LogRoot.String())
	if err != nil {
		return err
	}

	signature, err := base64.StdEncoding.DecodeString(logInfo.SignedTreeHead.Signature.String())
	if err != nil {
		return err
	}

	sth := trillian.SignedLogRoot{
		KeyHint:          keyHint,
		LogRoot:          logRoot,
		LogRootSignature: signature,
	}

	publicKey := viper.GetString("rekor_server_public_key")
	if publicKey == "" {
		keyResp, err := rekorClient.Tlog.GetPublicKey(nil)
		if err != nil {
			return err
		}
		publicKey = keyResp.Payload
	}

	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return errors.New("failed to decode public key of server")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, pub, crypto.SHA256)
	lr, err := tcrypto.VerifySignedLogRoot(verifier.PubKey, verifier.SigHash, &sth)

	if err != nil {
		return err
	}
	fmt.Printf("%+v", lr)
	return nil
}

// GetLogEntryByIndex returns an object with the log index,
// integratedTime, UUID, and body
// logEntry := models.LogEntry{
// 	hex.EncodeToString(leaf.MerkleLeafHash): models.LogEntryAnon{
// 		LogIndex:       &leaf.LeafIndex,
// 		Body:           leaf.LeafValue,
// 		IntegratedTime: leaf.IntegrateTimestamp.AsTime().Unix(),
// 	},
// }
func GetLogEntryByIndex(logIndex int64) (string, models.LogEntryAnon, error) {
	rekorClient, err := NewClient()
	if err != nil {
		return "", models.LogEntryAnon{}, err
	}

	params := entries.NewGetLogEntryByIndexParams()
	params.LogIndex = logIndex

	resp, err := rekorClient.Entries.GetLogEntryByIndex(params)
	if err != nil {
		return "", models.LogEntryAnon{}, err
	}
	for ix, entry := range resp.Payload {
		return ix, entry, nil
	}

	return "", models.LogEntryAnon{}, errors.New("Response returned no entries. Please check logIndex.")
}

type getCmdOutput struct {
	Body           types.EntryImpl
	LogIndex       int
	IntegratedTime int64
	UUID           string
}

func ParseEntry(uuid string, e models.LogEntryAnon) (getCmdOutput, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return getCmdOutput{}, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return getCmdOutput{}, err
	}
	eimpl, err := types.NewEntry(pe)
	if err != nil {
		return getCmdOutput{}, err
	}

	obj := getCmdOutput{
		Body:           eimpl,
		UUID:           uuid,
		IntegratedTime: e.IntegratedTime,
		LogIndex:       int(*e.LogIndex),
	}

	return obj, nil
}

func BuildTree() {
	//verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, pub, crypto.SHA256)
	//v := logverifier.New(rfc6962.DefaultHasher)
}

// END OF CODE FROM SIGSTORE/REKOR

/*
func fetchAll() {
	// gRPCRequest
}

func fetchFromRange(startIndex int) {
	// gRPCRequest
}
*/
