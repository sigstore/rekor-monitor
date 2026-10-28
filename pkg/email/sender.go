// Copyright 2026 The Sigstore Authors.
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

package email

import (
	"context"
	"fmt"

	"github.com/wneessen/go-mail"
)

// Config holds the SMTP connection parameters.
type Config struct {
	Host         string
	Port         int
	Username     string
	SMTPPassword string
	From         string
	UseTLS       bool
	SMTPHELO     string
	SMTPAuthType string
}

// Sender sends emails via SMTP.
type Sender struct {
	cfg    Config
	client *mail.Client
}

// NewSender returns a Sender configured with cfg.
func NewSender(cfg Config) (*Sender, error) {
	if cfg.SMTPHELO == "" {
		cfg.SMTPHELO = "localhost"
	}
	if cfg.SMTPAuthType == "" {
		cfg.SMTPAuthType = string(mail.SMTPAuthPlain)
	}
	opts := []mail.Option{
		mail.WithPort(cfg.Port),
		mail.WithHELO(cfg.SMTPHELO),
	}
	if cfg.Username != "" {
		authType := mail.SMTPAuthType(cfg.SMTPAuthType)
		switch authType {
		case mail.SMTPAuthPlain, mail.SMTPAuthXOAUTH2:
		default:
			return nil, fmt.Errorf(
				"unsupported SMTP auth type %q: must be one of: %s, %s",
				cfg.SMTPAuthType, mail.SMTPAuthPlain, mail.SMTPAuthXOAUTH2,
			)
		}
		opts = append(opts,
			mail.WithSMTPAuth(authType),
			mail.WithUsername(cfg.Username),
			mail.WithPassword(cfg.SMTPPassword),
		)
	}
	if cfg.UseTLS {
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	} else {
		opts = append(opts, mail.WithTLSPolicy(mail.TLSOpportunistic))
	}

	client, err := mail.NewClient(cfg.Host, opts...)
	if err != nil {
		return nil, err
	}
	return &Sender{cfg: cfg, client: client}, nil
}

// Send delivers a single HTML email to the given address.
func (s *Sender) Send(
	ctx context.Context,
	to, subject, body string,
) error {
	msg := mail.NewMsg()
	if err := msg.From(s.cfg.From); err != nil {
		return fmt.Errorf("setting from address: %w", err)
	}
	if err := msg.To(to); err != nil {
		return fmt.Errorf("setting to address: %w", err)
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextHTML, body)

	if err := s.client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("sending email: %w", err)
	}
	return nil
}
