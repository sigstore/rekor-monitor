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
	"strings"
	"testing"

	smtpmock "github.com/mocktools/go-smtp-mock/v2"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/wneessen/go-mail"
)

func TestEmailSendFailureCases(t *testing.T) {
	emailNotificationInputs := []EmailNotificationInput{
		{
			RecipientEmailAddress: "test-recipient@example.com",
			SenderEmailAddress:    "test-sender@example.com",
			SenderSMTPUsername:    "example-username",
			SenderSMTPPassword:    "example-password",
			SMTPHostURL:           "smtp.gmail.com",
			SMTPAuthType:          mail.SMTPAuthPlain,
		},
		{
			RecipientEmailAddress: "",
			SenderEmailAddress:    "test-sender@example.com",
			SenderSMTPUsername:    "example-username",
			SenderSMTPPassword:    "example-password",
			SMTPHostURL:           "smtp.gmail.com",
			SMTPAuthType:          mail.SMTPAuthPlain,
		},
		{
			RecipientEmailAddress: "test-recipient",
			SenderEmailAddress:    "",
			SenderSMTPUsername:    "example-username",
			SenderSMTPPassword:    "example-password",
			SMTPHostURL:           "smtp.gmail.com",
			SMTPAuthType:          mail.SMTPAuthPlain,
		},
		{
			RecipientEmailAddress: "test-recipient",
			SenderEmailAddress:    "example@mail.com",
			SenderSMTPUsername:    "example-username",
			SenderSMTPPassword:    "example-password",
			SMTPHostURL:           "smtp.mail.com",
			SMTPAuthType:          mail.SMTPAuthNoAuth,
		},
	}
	monitoredIdentity := identity.MonitoredIdentity{
		Identity: "test-identity",
		FoundIdentityEntries: []identity.RekorLogEntry{
			{
				CertSubject: "test-cert-subject",
				UUID:        "test-uuid",
				Index:       0,
			},
		},
	}

	for _, emailNotificationInput := range emailNotificationInputs {
		err := emailNotificationInput.Send(context.Background(), []identity.MonitoredIdentity{monitoredIdentity})
		if err == nil {
			t.Errorf("expected error, received nil")
		}
	}
}

func TestEmailSendMockSMTPServerSuccess(t *testing.T) {
	server := smtpmock.New(smtpmock.ConfigurationAttr{
		HostAddress: "localhost",
	})
	if err := server.Start(); err != nil {
		t.Errorf("error starting server: %v", err)
	}
	monitoredIdentity := identity.MonitoredIdentity{
		Identity: "test-identity",
		FoundIdentityEntries: []identity.RekorLogEntry{
			{
				CertSubject: "test-cert-subject",
				UUID:        "test-uuid",
				Index:       0,
			},
		},
	}
	customPort := server.PortNumber()
	emailNotificationInput := EmailNotificationInput{
		RecipientEmailAddress: "test-recipient@mail.com",
		SenderEmailAddress:    "example_sender@mail.com",
		SMTPHostURL:           "localhost",
		SMTPAuthType:          mail.SMTPAuthNoAuth,
		CustomPort:            &customPort,
	}

	err := emailNotificationInput.Send(context.Background(), []identity.MonitoredIdentity{monitoredIdentity})
	if err != nil {
		t.Errorf("expected nil, received error %v", err)
	}
}

func TestEmailSendMockSMTPServerFailure(t *testing.T) {
	server := smtpmock.New(smtpmock.ConfigurationAttr{
		HostAddress:               "localhost",
		BlacklistedMailfromEmails: []string{"example_sender@mail.com"},
	})
	if err := server.Start(); err != nil {
		t.Errorf("error starting server: %v", err)
	}
	monitoredIdentity := identity.MonitoredIdentity{
		Identity: "test-identity",
		FoundIdentityEntries: []identity.RekorLogEntry{
			{
				CertSubject: "test-cert-subject",
				UUID:        "test-uuid",
				Index:       0,
			},
		},
	}
	customPort := server.PortNumber()
	emailNotificationInput := EmailNotificationInput{
		RecipientEmailAddress: "test-recipient@mail.com",
		SenderEmailAddress:    "example_sender@mail.com",
		SMTPHostURL:           "localhost",
		SMTPAuthType:          mail.SMTPAuthNoAuth,
		CustomPort:            &customPort,
	}

	err := emailNotificationInput.Send(context.Background(), []identity.MonitoredIdentity{monitoredIdentity})
	if err == nil || !strings.Contains(err.Error(), "421 Service not available") {
		t.Errorf("expected 421 Service not available, received error %v", err)
	}
}
