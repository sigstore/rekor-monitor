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

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/wneessen/go-mail"
)

// EmailNotificationInput extends the NotificationPlatform interface to support
// found identity notification by sending emails to a specified user.
type EmailNotificationInput struct {
	RecipientEmailAddress string
	SenderEmailAddress    string
	SenderSMTPUsername    string
	SenderSMTPPassword    string
	SMTPHostURL           string
	SMTPAuthType          mail.SMTPAuthType
	CustomPort            *int
}

func GenerateEmailBody(monitoredIdentities []identity.MonitoredIdentity) (string, error) {
	body, err := identity.PrintMonitoredIdentities(monitoredIdentities)
	if err != nil {
		return "", err
	}
	return "<pre>" + string(body) + "</pre>", nil
}

// Send takes in an EmailNotification input and attempts to send the
// following list of found identities to the given email address.
// It returns an error in the case of failure.
func (emailNotificationInput EmailNotificationInput) Send(ctx context.Context, monitoredIdentities []identity.MonitoredIdentity) error {
	email := mail.NewMsg()
	if err := email.From(emailNotificationInput.SenderEmailAddress); err != nil {
		return err
	}
	if err := email.To(emailNotificationInput.RecipientEmailAddress); err != nil {
		return err
	}
	emailSubject := NotificationSubject
	email.Subject(emailSubject)
	emailBody, err := GenerateEmailBody(monitoredIdentities)
	if err != nil {
		return err
	}
	email.SetBodyString(mail.TypeTextHTML, emailBody)
	var client *mail.Client
	if emailNotificationInput.CustomPort != nil {
		client, err = mail.NewClient(emailNotificationInput.SMTPHostURL,
			mail.WithSMTPAuth(emailNotificationInput.SMTPAuthType), mail.WithTLSPortPolicy(mail.NoTLS),
			mail.WithUsername(emailNotificationInput.SenderSMTPUsername), mail.WithPassword(emailNotificationInput.SenderSMTPPassword),
			mail.WithPort(*emailNotificationInput.CustomPort),
		)
	} else {
		client, err = mail.NewClient(emailNotificationInput.SMTPHostURL,
			mail.WithSMTPAuth(emailNotificationInput.SMTPAuthType), mail.WithTLSPortPolicy(mail.DefaultTLSPolicy),
			mail.WithUsername(emailNotificationInput.SenderSMTPUsername), mail.WithPassword(emailNotificationInput.SenderSMTPPassword),
		)
	}
	if err != nil {
		return err
	}
	err = client.DialAndSendWithContext(ctx, email)
	client.Close()
	return err
}
