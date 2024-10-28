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

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/sigstore/rekor-monitor/pkg/identity"
)

// SendGrid extends the NotificationPlatform interface to support
// found identity notification by sending emails to a specified user via SendGrid.
type SendGridNotificationInput struct {
	RecipientName         string `yaml:"recipientName"`
	RecipientEmailAddress string `yaml:"recipientEmailAddress"`
	SenderName            string `yaml:"senderName"`
	SenderEmailAddress    string `yaml:"senderEmailAddress"`
	SendGridAPIKey        string `yaml:"sendGridAPIKey"`
}

// Send takes in an SendGridNotificationInput and attempts to send the
// following list of found identities to the given email address.
// It returns an error in the case of failure.
func (sendGridNotificationInput SendGridNotificationInput) Send(ctx context.Context, monitoredIdentities []identity.MonitoredIdentity) error {
	from := mail.NewEmail(sendGridNotificationInput.SenderName, sendGridNotificationInput.SenderEmailAddress)
	to := mail.NewEmail(sendGridNotificationInput.RecipientName, sendGridNotificationInput.RecipientEmailAddress)
	subject := NotificationSubject
	emailHTMLBody, err := GenerateEmailBody(monitoredIdentities)
	if err != nil {
		return err
	}
	email := mail.NewSingleEmail(from, subject, to, "", emailHTMLBody)
	client := sendgrid.NewSendClient(sendGridNotificationInput.SendGridAPIKey)
	_, err = client.SendWithContext(ctx, email)
	return err
}
