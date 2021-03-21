package rekorclient

import (
	"bytes"
	"container/list"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"os"

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
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
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
	_, err = tcrypto.VerifySignedLogRoot(verifier.PubKey, verifier.SigHash, &sth)

	if err != nil {
		return err
	}
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
func GetLogEntryByIndex(logIndex int64, rekorClient *client.Rekor) (string, models.LogEntryAnon, error) {
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

type artifact struct {
	pk             string
	dataHash       string
	sig            string
	merkleTreeHash string
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

func GetLogEntryData(logIndex int64, rekorClient *client.Rekor) (artifact, error) {
	ix, entry, err := GetLogEntryByIndex(logIndex, rekorClient)
	if err != nil {
		return artifact{}, err
	}

	a, err := ParseEntry(ix, entry)
	b := artifact{}
	b.merkleTreeHash = a.UUID

	switch v := a.Body.(type) {
	case *rekord_v001.V001Entry:
		b.pk = string([]byte(v.RekordObj.Signature.PublicKey.Content))
		b.sig = base64.StdEncoding.EncodeToString([]byte(v.RekordObj.Signature.Content))
		b.dataHash = *v.RekordObj.Data.Hash.Value
	case *rpm_v001.V001Entry:
		b.pk = string([]byte(v.RPMModel.PublicKey.Content))
	default:
		return b, errors.New("The type of this log entry is not supported.")
	}
	return b, nil
}

/*func powerOfTwo(n int64) int64 {
	var res int64
	res = 0
	for i := n; i >= 1; i-- {
		if i&(i-1) == 0 {
			res = i
			break
		}
	}
	return res
}*/

/*
// rekor code, slightly modified
func CanonicalizeArtifact(entry artifact) ([]byte, error) {
	if entry.sig == "" {
		return nil, errors.New("signature not initialized before canonicalization")
	}
	if entry.pk == "" {
		return nil, errors.New("key not initialized before canonicalization")
	}



}
// end of rekor code
*/

func ComputeSTH(artifacts []artifact) ([]byte, error) {
	//verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, pub, crypto.SHA256)
	//v := logverifier.New(rfc6962.DefaultHasher)

	queue := list.New()

	// hash leaves here and fill queue with []byte representations of hashes
	for _, artifact := range artifacts {
		str := artifact.merkleTreeHash

		hash, err := hex.DecodeString(str)
		if err != nil {
			return nil, err
		}

		queue.PushBack(hash)
	}

	for queue.Len() >= 2 {
		a := queue.Front()
		hash0 := queue.Remove(a).([]byte)

		b := queue.Front()
		hash1 := queue.Remove(b).([]byte)

		hash := rfc6962.DefaultHasher.HashChildren(hash0, hash1)
		e := hex.EncodeToString(hash)
		if e == "" {
			return nil, nil
		}
		f := string(hash)
		if f == "" {
			return nil, nil
		}
		queue.PushBack(hash)
	}
	return queue.Front().Value.([]byte), nil
}

func FetchLeavesByRange(initSize, finalSize int64) ([]artifact, error) {
	rekorClient, err := NewClient()
	if err != nil {
		return nil, err
	}

	var leaves []artifact
	var i int64
	// use retrieve post request instead, retrieve multiple entries at once
	for i = initSize; i < finalSize; i++ {
		artifact, err := GetLogEntryData(i, rekorClient)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, artifact)
	}
	// TODO: verify integrity of leaves by canonicalizing and hashing leaves.
	// then strcmp those with the fetched leaf hashes
	return leaves, nil
}

func fullAudit() error {
	logInfo, err := GetLogInfo()
	if err != nil {
		return err
	}
	sth := logInfo.SignedTreeHead

	err = VerifySignature()
	if err != nil {
		return err
	}

	leaves, err := FetchLeavesByRange(0, *logInfo.TreeSize)
	if err != nil {
		return err
	}

	err = appendArtifactsToFile(leaves)
	if err != nil {
		return err
	}
	if sth == nil {
		return err
	}
	return nil
}

func appendArtifactsToFile(artifacts []artifact) error {
	f, err := os.OpenFile(".tree", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	for _, leave := range artifacts {
		serialLeave, err := json.Marshal(leave)
		if err != nil {
			return err
		}

		_, err = f.Write(serialLeave)
		if err != nil {
			return err
		}
	}

	return nil
}
