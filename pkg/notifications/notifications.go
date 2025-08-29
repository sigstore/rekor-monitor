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

// This file details the named fields of OID extensions supported by Fulcio.
// A list of OID extensions supported by Fulcio can be found here:
// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
// Named fields in this file have been imported from this file in the Fulcio repository:
// https://github.com/sigstore/fulcio/blob/main/pkg/certificate/extensions.go
// Updates to the Fulcio repository extensions file should be matched here accordingly and vice-versa.

package notifications

import (
	"context"
	"fmt"
	"regexp"

	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
)

type NotificationContextNew func() NotificationContext

// NotificationContext provides context information for notifications
type NotificationContext struct {
	MonitorType string `json:"monitorType"` // e.g., "rekor-monitor", "ct-monitor"
	Subject     string `json:"subject"`     // Custom subject line
}

// NotificationBodyConverter defines an interface for payloads that can convert themselves to a notification body string
type NotificationBodyConverter interface {
	ToNotificationBody() ([]byte, error)
}

// NotificationData represents the data to be sent in a notification
type NotificationData struct {
	Context NotificationContext       `json:"context"`
	Payload NotificationBodyConverter `json:"payload"` // The actual data to notify about
}

// NotificationPlatform provides the Send() method to handle alerting logic
// for the respective notification platform extending the interface.
type NotificationPlatform interface {
	Send(context.Context, NotificationData) error
}

// CreateNotificationContext creates a custom notification context
func CreateNotificationContext(monitorType, subject string) NotificationContext {
	return NotificationContext{
		MonitorType: monitorType,
		Subject:     subject,
	}
}

// ConfigMonitoredValues holds a set of values to compare against a given entry.
// ConfigMonitoredValues holds Object Identifier extensions and associated values
// that can be constructed either directly from asn1.ObjectIdentifier,
// via OID extensions supported by Fulcio, or via dot notation.
type ConfigMonitoredValues struct {
	// CertificateIdentities contains a list of subjects and issuers
	CertificateIdentities []identity.CertificateIdentity `yaml:"certIdentities"`
	// Fingerprints contains a list of key fingerprints. Values are as follows:
	// For keys, certificates, and minisign, hex-encoded SHA-256 digest
	// of the DER-encoded PKIX public key or certificate
	// For SSH and PGP, the standard for each ecosystem:
	// For SSH, unpadded base-64 encoded SHA-256 digest of the key
	// For PGP, hex-encoded SHA-1 digest of a key, which can be either
	// a primary key or subkey
	Fingerprints []string `yaml:"fingerprints"`
	// Subjects contains a list of subjects that are not specified in a
	// certificate, such as a SSH key or PGP key email address
	Subjects []string `yaml:"subjects"`
	// OIDMatchers represents a list of OID extension fields and associated values,
	// which includes those constructed directly, those supported by Fulcio, and any constructed via dot notation.
	// These OIDMatchers are parsed into one list of OID extensions and matching values before being passed into MatchedIndices.
	OIDMatchers extensions.OIDMatchers `yaml:"oidMatchers"`
}

// IdentityMonitorConfiguration holds the configuration settings for an identity monitor workflow run.
type IdentityMonitorConfiguration struct {
	StartIndex                *int                       `yaml:"startIndex"`
	EndIndex                  *int                       `yaml:"endIndex"`
	MonitoredValues           ConfigMonitoredValues      `yaml:"monitoredValues"`
	OutputIdentitiesFile      string                     `yaml:"outputIdentities"`
	LogInfoFile               string                     `yaml:"logInfoFile"`
	IdentityMetadataFile      *string                    `yaml:"identityMetadataFile"`
	GitHubIssue               *GitHubIssueInput          `yaml:"githubIssue"`
	EmailNotificationSMTP     *EmailNotificationInput    `yaml:"emailNotificationSMTP"`
	EmailNotificationMailgun  *MailgunNotificationInput  `yaml:"emailNotificationMailgun"`
	EmailNotificationSendGrid *SendGridNotificationInput `yaml:"emailNotificationSendGrid"`
}

func (c *IdentityMonitorConfiguration) Validate() error {
	// Validate CertificateIdentities CertSubject and Issuers regexes
	for _, certIdentity := range c.MonitoredValues.CertificateIdentities {
		if _, err := regexp.Compile(certIdentity.CertSubject); err != nil {
			return fmt.Errorf("invalid certSubject regex %s: %v", certIdentity.CertSubject, err)
		}
		for _, issuer := range certIdentity.Issuers {
			if _, err := regexp.Compile(issuer); err != nil {
				return fmt.Errorf("invalid issuer regex %s: %v", issuer, err)
			}
		}
	}
	// Validate Subjects regexes
	for _, subject := range c.MonitoredValues.Subjects {
		if _, err := regexp.Compile(subject); err != nil {
			return fmt.Errorf("invalid subject regex %s: %v", subject, err)
		}
	}
	return nil
}

func CreateNotificationPool(config IdentityMonitorConfiguration) []NotificationPlatform {
	// update this as new notification platforms are implemented within rekor-monitor
	notificationPlatforms := []NotificationPlatform{}
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

func TriggerNotifications(notificationPlatforms []NotificationPlatform, data NotificationData) error {
	// update this as new notification platforms are implemented within rekor-monitor
	for _, notificationPlatform := range notificationPlatforms {
		if err := notificationPlatform.Send(context.Background(), data); err != nil {
			return fmt.Errorf("error sending notification from platform: %v", err)
		}
	}

	return nil
}
