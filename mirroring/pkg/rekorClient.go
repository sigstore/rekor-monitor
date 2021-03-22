package rekorclient

import (
	"bytes"
	"container/list"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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
	trilliantypes "github.com/google/trillian/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	rpm_v001 "github.com/sigstore/rekor/pkg/types/rpm/v0.0.1"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/spf13/viper"
)

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

// GetPublicKey returns public key of entity that signed STH in string type.
func GetPublicKey() (string, error) {
	rekorClient, err := NewClient()
	if err != nil {
		return "", err
	}

	publicKey := viper.GetString("rekor_server_public_key")
	if publicKey == "" {
		keyResp, err := rekorClient.Tlog.GetPublicKey(nil)
		if err != nil {
			return "", err
		}
		publicKey = keyResp.Payload
	}
	return publicKey, nil
}

// VerifySignature verifies the integrity of the signed tree hash.
func VerifySignature(pub string) error {
	logInfo, err := GetLogInfo()
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

	block, _ := pem.Decode([]byte(pub))
	if block == nil {
		return errors.New("failed to decode public key of server")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	verifier := tclient.NewLogVerifier(rfc6962.DefaultHasher, publicKey, crypto.SHA256)
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

type Artifact struct {
	Pk             string `json:"pk,omitempty"`
	DataHash       string `json:"data_hash,omitempty"`
	Sig            string `json:"sig,omitempty"`
	MerkleTreeHash string `json:"merkle_tree_hash,omitempty"`
}

// this function also verifies the integrity of an entry.
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

	/*
			// verify if signature matches the given public key + hash

			// verify if merkle tree hash is computed correctly
			marshalledEntry, err := eimpl.Canonicalize(context.TODO()) ////////////
			if err != nil {
				return getCmdOutput{}, err
			}

		mth := rfc6962.DefaultHasher.HashLeaf(marshalledEntry)

		if a, _ := hex.DecodeString(uuid); !bytes.Equal(a, mth) {
			return getCmdOutput{}, errors.New("MALICIOUS LOG: Computed hash does not match log entry hash.")
		}
	*/

	obj := getCmdOutput{
		Body:           eimpl,
		UUID:           uuid,
		IntegratedTime: e.IntegratedTime,
		LogIndex:       int(*e.LogIndex),
	}

	return obj, nil
}

func GetLogEntryData(logIndex int64, rekorClient *client.Rekor) (Artifact, error) {
	ix, entry, err := GetLogEntryByIndex(logIndex, rekorClient)
	if err != nil {
		return Artifact{}, err
	}

	a, err := ParseEntry(ix, entry)
	b := Artifact{}
	b.MerkleTreeHash = a.UUID

	switch v := a.Body.(type) {
	case *rekord_v001.V001Entry:
		b.Pk = string([]byte(v.RekordObj.Signature.PublicKey.Content))
		b.Sig = base64.StdEncoding.EncodeToString([]byte(v.RekordObj.Signature.Content))
		b.DataHash = *v.RekordObj.Data.Hash.Value
	case *rpm_v001.V001Entry:
		b.Pk = string([]byte(v.RPMModel.PublicKey.Content))
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

type queueElement struct {
	hash  []byte
	depth int64
}

func ComputeRoot(artifacts []Artifact) ([]byte, error) {

	queue := list.New()
	el := queueElement{}

	// hash leaves here and fill queue with []byte representations of hashes
	for _, artifact := range artifacts {
		str := artifact.MerkleTreeHash

		hash, err := hex.DecodeString(str)
		if err != nil {
			return nil, err
		}
		el.hash = hash
		el.depth = 0
		queue.PushBack(el)
	}

	for queue.Len() >= 2 {
		a := queue.Front()
		aVal := queue.Remove(a).(queueElement)

		b := queue.Front()

		var leftHash, rightHash []byte
		if b.Value.(queueElement).depth > aVal.depth { // wrap around case
			el.depth = aVal.depth + 1
			el.hash = aVal.hash
		} else {
			bVal := queue.Remove(b).(queueElement)
			rightHash = bVal.hash
			leftHash = aVal.hash

			hash := rfc6962.DefaultHasher.HashChildren(leftHash, rightHash)
			el.depth = bVal.depth + 1
			el.hash = hash
		}
		de := hex.EncodeToString(el.hash)
		if de == "0d0f2102d842d56843727e1848872655501af276613f8d04b6ccad806a334d57" {
			fmt.Printf("asdf")
		}
		queue.PushBack(el)
	}
	if queue.Front() == nil {
		return nil, errors.New("Something went wrong.")
	}
	return queue.Front().Value.(queueElement).hash, nil
}

func FetchLeavesByRange(initSize, finalSize int64) ([]Artifact, error) {
	rekorClient, err := NewClient()
	if err != nil {
		return nil, err
	}

	var leaves []Artifact
	var i int64
	// use retrieve post request instead, retrieve multiple entries at once
	for i = initSize; i < finalSize; i++ {
		artifact, err := GetLogEntryData(i, rekorClient)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, artifact)
	}

	return leaves, nil
}

func FullAudit() error {

	metadata, err := LoadTreeMetadata()
	if err != nil { // if metadata isn't saved properly (or at all)
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

	leaves, err := FetchLeavesByRange(metadata.SavedMaxIndex+1, *logInfo.TreeSize)
	if err != nil {
		return err
	}

	err = AppendArtifactsToFile(leaves)
	if err != nil {
		return err
	}

	err = UpdateMetadataByIndex(*logInfo.TreeSize)

	computedSTH, err := ComputeRoot(leaves)
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
	return nil
}

type TreeMetadata struct {
	PublicKey     string          `json:"public_key,omitempty"`
	LogInfo       *models.LogInfo `json:"log_info,omitempty"`
	SavedMaxIndex int64           `json:"saved_max_index,omitempty"`
}
