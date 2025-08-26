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

	"github.com/wneessen/go-mail"
)

// EmailNotificationInput extends the NotificationPlatform interface to support
// found identity notification by sending emails to a specified user.
type EmailNotificationInput struct {
	RecipientEmailAddress string        `yaml:"recipientEmailAddress"`
	SenderEmailAddress    string        `yaml:"senderEmailAddress"`
	SenderSMTPUsername    string        `yaml:"senderSMTPUsername"`
	SenderSMTPPassword    string        `yaml:"senderSMTPPassword"`
	SMTPHostURL           string        `yaml:"SMTPHostURL"`
	SMTPCustomOptions     []mail.Option `yaml:"SMTPCustomOptions"`
}

// generateEmailBody generates email body for generic notification data
func generateEmailBody(data NotificationData) (string, error) {
	body, err := data.Payload.ToNotificationBody()
	if err != nil {
		return "", err
	}
	return "<pre>" + body + "</pre>", nil
}

// Send implements the NotificationPlatform interface
func (emailNotificationInput EmailNotificationInput) Send(ctx context.Context, data NotificationData) error {
	email := mail.NewMsg()
	if err := email.From(emailNotificationInput.SenderEmailAddress); err != nil {
		return err
	}
	if err := email.To(emailNotificationInput.RecipientEmailAddress); err != nil {
		return err
	}
	emailSubject := data.Context.Subject
	email.Subject(emailSubject)
	emailBody, err := generateEmailBody(data)
	if err != nil {
		return err
	}
	email.SetBodyString(mail.TypeTextHTML, emailBody)
	var client *mail.Client
	defaultOpts := []mail.Option{
		mail.WithUsername(emailNotificationInput.SenderSMTPUsername),
		mail.WithPassword(emailNotificationInput.SenderSMTPPassword),
	}
	defaultOpts = append(defaultOpts, emailNotificationInput.SMTPCustomOptions...)
	client, err = mail.NewClient(emailNotificationInput.SMTPHostURL, defaultOpts...)
	if err != nil {
		return err
	}
	err = client.DialAndSendWithContext(ctx, email)
	client.Close()
	return err
}
