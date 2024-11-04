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
	"time"

	"github.com/sigstore/rekor-monitor/pkg/fulcio/extensions"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/notifications"
)

// MonitoredValues holds a set of values to compare against a given entry
type MonitoredValues struct {
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
	// OIDMatchers contains a list of OID extension fields and associated values
	// ex. Build Signer URI, associated with specific workflow URIs
	OIDMatchers extensions.OIDMatchers `yaml:"oidMatchers"`
}

type IdentityMonitorConfiguration struct {
	StartIndex                *int                                    `yaml:"startIndex"`
	EndIndex                  *int                                    `yaml:"endIndex"`
	MonitoredValues           MonitoredValues                         `yaml:"monitoredValues"`
	ServerURL                 string                                  `yaml:"serverURL"`
	OutputIdentitiesFile      string                                  `yaml:"outputIdentities"`
	LogInfoFile               string                                  `yaml:"logInfoFile"`
	IdentityMetadataFile      *string                                 `yaml:"identityMetadataFile"`
	GitHubIssue               notifications.GitHubIssueInput          `yaml:"githubIssue"`
	EmailNotificationSMTP     notifications.EmailNotificationInput    `yaml:"emailNotificationSMTP"`
	EmailNotificationMailgun  notifications.MailgunNotificationInput  `yaml:"emailNotificationMailgun"`
	EmailNotificationSendGrid notifications.SendGridNotificationInput `yaml:"emailNotificationSendGrid"`
	Interval                  *time.Duration                          `yaml:"interval"`
}
