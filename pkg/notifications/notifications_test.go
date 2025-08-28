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

func TestIdentityMonitorConfiguration_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  IdentityMonitorConfiguration
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid configuration with empty monitored values",
			config: IdentityMonitorConfiguration{
				MonitoredValues: ConfigMonitoredValues{},
			},
			wantErr: false,
		},
		{
			name: "valid configuration with valid regex patterns",
			config: IdentityMonitorConfiguration{
				MonitoredValues: ConfigMonitoredValues{
					CertificateIdentities: []identity.CertificateIdentity{
						{
							CertSubject: `^test\.example\.com$`,
							Issuers:     []string{`^Test CA$`, `^Test Org$`},
						},
						{
							CertSubject: `.*\.example\.com`,
							Issuers:     []string{`^.*CA$`},
						},
					},
					Subjects: []string{
						`^test@example\.com$`,
						`.*@example\.com`,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid certSubject regex",
			config: IdentityMonitorConfiguration{
				MonitoredValues: ConfigMonitoredValues{
					CertificateIdentities: []identity.CertificateIdentity{
						{
							CertSubject: `[invalid regex`,
							Issuers:     []string{`^Test CA$`},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid certSubject regex [invalid regex",
		},
		{
			name: "invalid issuer regex",
			config: IdentityMonitorConfiguration{
				MonitoredValues: ConfigMonitoredValues{
					CertificateIdentities: []identity.CertificateIdentity{
						{
							CertSubject: `^test\.example\.com$`,
							Issuers:     []string{`[invalid issuer regex`},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid issuer regex [invalid issuer regex",
		},
		{
			name: "invalid subject regex",
			config: IdentityMonitorConfiguration{
				MonitoredValues: ConfigMonitoredValues{
					Subjects: []string{
						`[invalid subject regex`,
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid subject regex [invalid subject regex",
		},
		{
			name: "multiple invalid patterns - first certSubject error",
			config: IdentityMonitorConfiguration{
				MonitoredValues: ConfigMonitoredValues{
					CertificateIdentities: []identity.CertificateIdentity{
						{
							CertSubject: `[invalid certSubject`,
							Issuers:     []string{`[invalid issuer`},
						},
					},
					Subjects: []string{
						`[invalid subject`,
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid certSubject regex [invalid certSubject",
		},
		{
			name: "valid certSubject but invalid issuer",
			config: IdentityMonitorConfiguration{
				MonitoredValues: ConfigMonitoredValues{
					CertificateIdentities: []identity.CertificateIdentity{
						{
							CertSubject: `^test\.example\.com$`,
							Issuers:     []string{`^Test CA$`, `[invalid issuer`},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid issuer regex [invalid issuer",
		},
		{
			name: "complex valid regex patterns",
			config: IdentityMonitorConfiguration{
				MonitoredValues: ConfigMonitoredValues{
					CertificateIdentities: []identity.CertificateIdentity{
						{
							CertSubject: `^([a-zA-Z0-9\-\.]+)\.example\.com$`,
							Issuers:     []string{`^([A-Za-z\s]+) CA$`, `^([A-Za-z\s]+)$`},
						},
					},
					Subjects: []string{
						`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
						`^[a-z]+@example\.com$`,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty strings are valid regex patterns",
			config: IdentityMonitorConfiguration{
				MonitoredValues: ConfigMonitoredValues{
					CertificateIdentities: []identity.CertificateIdentity{
						{
							CertSubject: ``,
							Issuers:     []string{``, `^Test CA$`},
						},
					},
					Subjects: []string{``, `^test@example\.com$`},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error but got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error = %v", err)
				}
			}
		})
	}
}
