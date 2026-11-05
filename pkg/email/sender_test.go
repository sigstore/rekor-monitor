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
	"testing"
	"time"

	smtpmock "github.com/mocktools/go-smtp-mock/v2"
)

func startMockServer(t *testing.T, cfg smtpmock.ConfigurationAttr) *smtpmock.Server {
	t.Helper()
	server := smtpmock.New(cfg)
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start mock SMTP server: %v", err)
	}
	t.Cleanup(func() { _ = server.Stop() })
	return server
}

func TestSendSuccess(t *testing.T) {
	server := startMockServer(t,
		smtpmock.ConfigurationAttr{
			LogToStdout:       false,
			LogServerActivity: false,
		},
	)

	sender, err := NewSender(Config{
		Host: "127.0.0.1",
		Port: server.PortNumber(),
		From: "sender@example.com",
	})
	if err != nil {
		t.Fatalf("expected no error during sender init")
	}

	err = sender.Send(
		context.Background(),
		"recipient@example.com",
		"Test Subject",
		"<p>Hello</p>",
	)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Ask for more than the expected messages to ensure we don't get more
	// emails than expected
	messages, _ := server.WaitForMessages(2, 3*time.Second)
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
}

func TestSendWithAuthFailsWhenUnsupported(t *testing.T) {
	server := startMockServer(t, smtpmock.ConfigurationAttr{
		LogToStdout:       false,
		LogServerActivity: false,
	})

	sender, err := NewSender(Config{
		Host:         "127.0.0.1",
		Port:         server.PortNumber(),
		From:         "sender@example.com",
		Username:     "user",
		SMTPPassword: "pass",
		SMTPHELO:     "localhost",
	})
	if err != nil {
		t.Fatalf("expected no error during sender init")
	}

	err = sender.Send(
		context.Background(),
		"recipient@example.com",
		"Auth Test",
		"<p>With credentials</p>",
	)
	if err == nil {
		t.Fatal("expected error when server does not support AUTH")
	}
}

func TestSendInvalidRecipient(t *testing.T) {
	sender, err := NewSender(Config{
		Host: "127.0.0.1",
		Port: 1,
		From: "sender@example.com",
	})
	if err != nil {
		t.Fatalf("expected no error during sender init")
	}

	err = sender.Send(
		context.Background(),
		"not-an-email",
		"Test",
		"<p>body</p>",
	)
	if err == nil {
		t.Fatal("expected error for invalid recipient, got nil")
	}
}
