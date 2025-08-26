// Copyright 2024 The Sigstore Authors.
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

package notifications

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sigstore/rekor-monitor/pkg/identity"
)

type MockNotificationPlatform struct {
}

func (mockNotificationPlatform MockNotificationPlatform) Send(_ context.Context, _ NotificationData) error {
	return errors.New("successfully sent from mock notification platform")
}

func TestCreateAndSendNotifications(t *testing.T) {
	config := IdentityMonitorConfiguration{
		GitHubIssue: &GitHubIssueInput{
			AssigneeUsername:    "test-user",
			RepositoryOwner:     "test-repo-owner",
			RepositoryName:      "test-repo",
			AuthenticationToken: "test-auth-token",
		},
		EmailNotificationSMTP: &EmailNotificationInput{
			RecipientEmailAddress: "test-receiver-email-address",
			SenderEmailAddress:    "test-sender-email-address",
		},
	}

	mockNotificationPlatform := MockNotificationPlatform{}

	notificationPool := CreateNotificationPool(config)
	notificationPoolLength := len(notificationPool)
	if notificationPoolLength != 2 {
		t.Errorf("expected 2 notification platforms to be created, received %d", notificationPoolLength)
	}

	notificationData := NotificationData{
		Context: CreateNotificationContext("test-monitor", "test-subject"),
		Payload: identity.MonitoredIdentityList{},
	}

	err := TriggerNotifications([]NotificationPlatform{mockNotificationPlatform}, notificationData)
	if !strings.Contains(err.Error(), "successfully sent from mock notification platform") {
		t.Errorf("did not trigger notification from mock notification platform")
	}
}
