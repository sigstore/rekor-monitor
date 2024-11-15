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

//go:build ct_e2e
// +build ct_e2e

package ct_e2e

import (
	"os"
	"testing"

	"net/http"

	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/sigstore/rekor-monitor/pkg/ct"
)

const (
	rekorURL          = "http://127.0.0.1:3000"
	subject           = "subject@example.com"
	issuer            = "oidc-issuer@domain.com"
	extValueString    = "test cert value"
	SubmissionCertB64 = "MIIEijCCA3KgAwIBAgICEk0wDQYJKoZIhvcNAQELBQAwKzEpMCcGA1UEAwwgY2Fja2xpbmcgY3J5cHRvZ3JhcGhlciBmYWtlIFJPT1QwHhcNMTUxMDIxMjAxMTUyWhcNMjAxMDE5MjAxMTUyWjAfMR0wGwYDVQQDExRoYXBweSBoYWNrZXIgZmFrZSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIKR3maBcUSsncXYzQT13D5Nr+Z3mLxMMh3TUdt6sACmqbJ0btRlgXfMtNLM2OU1I6a3Ju+tIZSdn2v21JBwvxUzpZQ4zy2cimIiMQDZCQHJwzC9GZn8HaW091iz9H0Go3A7WDXwYNmsdLNRi00o14UjoaVqaPsYrZWvRKaIRqaU0hHmS0AWwQSvN/93iMIXuyiwywmkwKbWnnxCQ/gsctKFUtcNrwEx9Wgj6KlhwDTyI1QWSBbxVYNyUgPFzKxrSmwMO0yNff7ho+QT9x5+Y/7XE59S4Mc4ZXxcXKew/gSlN9U5mvT+D2BhDtkCupdfsZNCQWp27A+b/DmrFI9NqsCAwEAAaOCAcIwggG+MBIGA1UdEwEB/wQIMAYBAf8CAQAwQwYDVR0eBDwwOqE4MAaCBC5taWwwCocIAAAAAAAAAAAwIocgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwDgYDVR0PAQH/BAQDAgGGMH8GCCsGAQUFBwEBBHMwcTAyBggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3RpZC5vY3NwLmlkZW50cnVzdC5jb20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlkZW50cnVzdC5jb20vcm9vdHMvZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFOmkP+6epeby1dd5YDyTpi4kjpeqMFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQBgt8TAQEBMDAwLgYIKwYBBQUHAgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3QuY29tL0RTVFJPT1RDQVgzQ1JMLmNybDAdBgNVHQ4EFgQU+3hPEvlgFYMsnxd/NBmzLjbqQYkwDQYJKoZIhvcNAQELBQADggEBAA0YAeLXOklx4hhCikUUl+BdnFfn1g0W5AiQLVNIOL6PnqXu0wjnhNyhqdwnfhYMnoy4idRh4lB6pz8Gf9pnlLd/DnWSV3gS+/I/mAl1dCkKby6H2V790e6IHmIK2KYm3jm+U++FIdGpBdsQTSdmiX/rAyuxMDM0adMkNBwTfQmZQCz6nGHw1QcSPZMvZpsC8SkvekzxsjF1otOrMUPNPQvtTWrVx8GlR2qfx/4xbQa1v2frNvFBCmO59goz+jnWvfTtj2NjwDZ7vlMBsPm16dbKYC840uvRoZjxqsdc3ChCZjqimFqlNG/xoPA8+dTicZzCXE9ijPIcvW6y1aa3bGw="
)

func TestCTConsistencyCheck(t *testing.T) {
	fulcioClient, err := ctclient.New("http://localhost:8080/testlog", http.DefaultClient, jsonclient.Options{})
	if err != nil {
		t.Errorf("error instantiating ct client: %v", err)
	}

	tempDir := t.TempDir()
	tempLogInfoFile, err := os.CreateTemp(tempDir, "")
	if err != nil {
		t.Errorf("failed to create temp log file: %v", err)
	}
	tempLogInfoFileName := tempLogInfoFile.Name()
	defer os.Remove(tempLogInfoFileName)

	err = ct.RunConsistencyCheck(fulcioClient, tempLogInfoFileName)
	if err != nil {
		t.Errorf("failed to successfully complete consistency check: %v", err)
	}
}
