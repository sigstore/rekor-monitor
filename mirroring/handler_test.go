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
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/golang/mock/gomock"
	mock_entries "github.com/sigstore/rekor-monitor/mirroring/mocks/entries"
	mock_index "github.com/sigstore/rekor-monitor/mirroring/mocks/index"
	mock_tlog "github.com/sigstore/rekor-monitor/mirroring/mocks/tlog"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/spf13/viper"
)

func TestLoadFromLocalValid(t *testing.T) {
	expectedPublicKey := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\nkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n-----END PUBLIC KEY-----\n"

	h, err := LoadFromLocal("./.config.json")
	if err != nil {
		t.Errorf("error in loadfromlocal %s", err)
	}
	c := TreeMetadata{}
	if h.metadata == c { // deep comparison with empty struct
		t.Errorf("handler not filled in")
	}

	if h.metadata.PublicKey != expectedPublicKey ||
		h.metadata.SavedMaxIndex != 3249 ||
		*h.metadata.LogInfo.TreeSize != 3250 {
		t.Errorf("handler is incorrect")
	}
}

// TODO: TestLoadFromLocalInvalid
// TODO: TestLoadFromLocalWithErrors
func TestLoadFromRemoteValid(t *testing.T) {
	viper.Set("testing", true)

	rh := "2407d22c273f3b4b6f280891bc6b709f716d576c1a586076a34d1f3a91e42d77"

	lr := new(strfmt.Base64)
	lr.Scan("AAEAAAAAAAANpiAkB9IsJz87S28oCJG8a3CfcW1XbBpYYHajTR86keQtdxZ7e+Pt31JTAAAAAAAAE2cAAA==")

	sig := new(strfmt.Base64)
	sig.Scan("MEYCIQDdckCoXYNg3/dNQFTCnOk0iQP1MNZfFSkRCkd4fYdYMQIhAIjGEDpjYoZcIE01P5vgR5mnzxmBbPQgRZkFhI/zz4IJ")

	sth := models.LogInfoSignedTreeHead{
		KeyHint:   nil,
		LogRoot:   lr,
		Signature: sig,
	}
	logInfo := new(models.LogInfo)
	logInfo.RootHash = &rh
	logInfo.SignedTreeHead = &sth

	logInfo.TreeSize = new(int64)
	*logInfo.TreeSize = 3494

	expectedPublicKey := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\nkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n-----END PUBLIC KEY-----"

	mockCtrl := gomock.NewController(t)

	expectedReturnPk := new(tlog.GetPublicKeyOK)
	expectedReturnPk.Payload = expectedPublicKey

	expectedLogInfo := new(tlog.GetLogInfoOK)
	expectedLogInfo.Payload = logInfo

	mockTlog := mock_tlog.NewMockClientService(mockCtrl)

	mockEntries := mock_entries.NewMockClientService(mockCtrl)
	mockEntries.EXPECT()
	mockIndex := mock_index.NewMockClientService(mockCtrl)
	mockIndex.EXPECT()

	mockTlog.EXPECT().GetPublicKey(nil).Return(expectedReturnPk, nil)

	mockTlog.EXPECT().GetLogInfo(nil).Return(expectedLogInfo, nil)

	viper.Set("metadata_file_directory", "./.test_metadata")
	viper.Set("tree_file_directory", "./.test_tree")
	viper.Set("mockTlog", mockTlog)
	viper.Set("mockIndex", mockIndex)
	viper.Set("mockEntries", mockEntries)
	h, err := LoadFromRemote("MOCK")

	if err != nil {
		t.Errorf(err.Error())
	}

	if h.metadata.PublicKey != expectedPublicKey {
		t.Errorf("handler is incorrect")
	}
}

// TODO: TestLoadFromRemoteInvalid
// TODO: TestLoadFromRemoteWithErrors
func TestGetAllLeavesForKind(t *testing.T) {
	mockCtrl := gomock.NewController(t)

	mockEntries := mock_entries.NewMockClientService(mockCtrl)
	mockEntries.EXPECT()
	mockIndex := mock_index.NewMockClientService(mockCtrl)
	mockIndex.EXPECT()
	mockTlog := mock_tlog.NewMockClientService(mockCtrl)
	mockTlog.EXPECT()

	h, err := LoadFromLocal("./.config.json")
	if err != nil {
		t.Errorf("%s", err)
	}
	err = h.GetAllLeavesForKind("rekord")
	if err != nil {
		t.Errorf("%s", err)
	}
}

func TestFetchAllLeavesForKind(t *testing.T) {
	h, err := LoadFromLocal("./.config.json")
	if err != nil {
		t.Errorf("%s", err)
	}
	err = h.FetchAllLeavesForKind("rekord")
	if err != nil {
		t.Errorf("%s", err)
	}

}

func TestSaveTree(t *testing.T) {
	h, err := LoadFromRemote("https://api.sigstore.dev")
	if err != nil {
		t.Errorf("%s", err)
	}
	err = h.FetchAllLeavesForKind("")
	if err != nil {
		t.Errorf("%s", err)
	}

	h.Save()

}

func TestFetchByRange(t *testing.T) {
	h, err := LoadFromLocal("./.config.json")
	if err != nil {
		t.Errorf("%s", err)
	}
	finalSize, err := h.GetRemoteTreeSize()
	if err != nil {
		t.Errorf("%s", err)
	}
	err = h.FetchByRange(h.GetLocalTreeSize(), finalSize)
	if err != nil {
		t.Errorf("%s", err)
	}

	h.Save()

}
