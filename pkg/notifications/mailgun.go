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

	"github.com/mailgun/mailgun-go/v4"
)

// MailgunNotificationInput extends the NotificationPlatform interface to support
// found identity notification by sending emails to a specified user via Mailgun.
type MailgunNotificationInput struct {
	RecipientEmailAddress string `yaml:"recipientEmailAddress"`
	SenderEmailAddress    string `yaml:"senderEmailAddress"`
	MailgunAPIKey         string `yaml:"mailgunAPIKey"`
	MailgunDomainName     string `yaml:"mailgunDomainName"`
}

// Send implements the NotificationPlatform interface
func (mailgunNotificationInput MailgunNotificationInput) Send(ctx context.Context, data NotificationData) error {
	subject := data.Context.Subject
	emailHTMLBody, err := generateEmailBody(data)
	if err != nil {
		return err
	}
	mg := mailgun.NewMailgun(mailgunNotificationInput.MailgunDomainName, mailgunNotificationInput.MailgunAPIKey)
	email := mailgun.NewMessage(mailgunNotificationInput.SenderEmailAddress, subject, "", mailgunNotificationInput.RecipientEmailAddress)
	email.SetHTML(emailHTMLBody)
	_, _, err = mg.Send(ctx, email)
	return err
}
