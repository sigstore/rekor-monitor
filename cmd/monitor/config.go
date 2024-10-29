//
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

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/notifications"
)

type IdentityMonitorConfiguration struct {
	StartIndex                *int                                     `yaml:"startIndex"`
	EndIndex                  *int                                     `yaml:"endIndex"`
	MonitoredValues           identity.MonitoredValues                 `yaml:"monitoredValues"`
	ServerURL                 string                                   `yaml:"serverURL"`
	OutputIdentitiesFile      string                                   `yaml:"outputIdentities"`
	LogInfoFile               string                                   `yaml:"logInfoFile"`
	IdentityMetadataFile      *string                                  `yaml:"identityMetadataFile"`
	GitHubIssue               *notifications.GitHubIssueInput          `yaml:"githubIssue"`
	EmailNotificationSMTP     *notifications.EmailNotificationInput    `yaml:"emailNotificationSMTP"`
	EmailNotificationMailgun  *notifications.MailgunNotificationInput  `yaml:"emailNotificationMailgun"`
	EmailNotificationSendGrid *notifications.SendGridNotificationInput `yaml:"emailNotificationSendGrid"`
	Interval                  *time.Duration                           `yaml:"interval"`
}

func CreateNotificationPool(config IdentityMonitorConfiguration) []notifications.NotificationPlatform {
	// update this as new notification platforms are implemented within rekor-monitor
	notificationPlatforms := []notifications.NotificationPlatform{}
	if config.GitHubIssue != nil {
		notificationPlatforms = append(notificationPlatforms, config.GitHubIssue)
	}

	if config.EmailNotificationSMTP != nil {
		notificationPlatforms = append(notificationPlatforms, config.EmailNotificationSMTP)
	}

	if config.EmailNotificationSendGrid != nil {
		notificationPlatforms = append(notificationPlatforms, config.EmailNotificationSendGrid)
	}

	if config.EmailNotificationMailgun != nil {
		notificationPlatforms = append(notificationPlatforms, config.EmailNotificationMailgun)
	}

	return notificationPlatforms
}

func TriggerNotifications(notificationPlatforms []notifications.NotificationPlatform, identities []identity.MonitoredIdentity) error {
	// update this as new notification platforms are implemented within rekor-monitor
	for _, notificationPlatform := range notificationPlatforms {
		if err := notificationPlatform.Send(context.Background(), identities); err != nil {
			return fmt.Errorf("error sending notification from platform: %v", err)
		}
	}

	return nil
}
