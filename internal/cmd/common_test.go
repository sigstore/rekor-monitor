//
// Copyright 2025 The Sigstore Authors.
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

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/notifications"
)

// Helper functions for creating pointers to values
func intPtr(v int) *int {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

// validateConfigValues validates that the loaded configuration matches the expected values
func validateConfigValues(t *testing.T, config *notifications.IdentityMonitorConfiguration, expected *notifications.IdentityMonitorConfiguration) {
	// Validate basic fields
	if expected.StartIndex != nil {
		if config.StartIndex == nil {
			t.Errorf("LoadMonitorConfig() expected StartIndex %d, got nil", *expected.StartIndex)
		} else if *config.StartIndex != *expected.StartIndex {
			t.Errorf("LoadMonitorConfig() StartIndex = %d, want %d", *config.StartIndex, *expected.StartIndex)
		}
	}

	if expected.EndIndex != nil {
		if config.EndIndex == nil {
			t.Errorf("LoadMonitorConfig() expected EndIndex %d, got nil", *expected.EndIndex)
		} else if *config.EndIndex != *expected.EndIndex {
			t.Errorf("LoadMonitorConfig() EndIndex = %d, want %d", *config.EndIndex, *expected.EndIndex)
		}
	}

	if expected.LogInfoFile != "" {
		if config.LogInfoFile != expected.LogInfoFile {
			t.Errorf("LoadMonitorConfig() LogInfoFile = %s, want %s", config.LogInfoFile, expected.LogInfoFile)
		}
	}

	if expected.IdentityMetadataFile != nil {
		if config.IdentityMetadataFile == nil {
			t.Errorf("LoadMonitorConfig() expected IdentityMetadataFile %s, got nil", *expected.IdentityMetadataFile)
		} else if *config.IdentityMetadataFile != *expected.IdentityMetadataFile {
			t.Errorf("LoadMonitorConfig() IdentityMetadataFile = %s, want %s", *config.IdentityMetadataFile, *expected.IdentityMetadataFile)
		}
	}

	// Validate monitored values
	validateMonitoredValues(t, config.MonitoredValues, expected.MonitoredValues)
}

// validateMonitoredValues validates the monitored values in the configuration
func validateMonitoredValues(t *testing.T, actual, expected notifications.ConfigMonitoredValues) {
	// Validate certificate identities
	if len(expected.CertificateIdentities) != len(actual.CertificateIdentities) {
		t.Errorf("LoadMonitorConfig() certificate identities count = %d, want %d",
			len(actual.CertificateIdentities), len(expected.CertificateIdentities))
		return
	}

	for i, expectedCert := range expected.CertificateIdentities {
		if i >= len(actual.CertificateIdentities) {
			t.Errorf("LoadMonitorConfig() missing certificate identity at index %d", i)
			continue
		}
		actualCert := actual.CertificateIdentities[i]
		if actualCert.CertSubject != expectedCert.CertSubject {
			t.Errorf("LoadMonitorConfig() certificate subject at index %d = %s, want %s",
				i, actualCert.CertSubject, expectedCert.CertSubject)
		}
		if len(actualCert.Issuers) != len(expectedCert.Issuers) {
			t.Errorf("LoadMonitorConfig() certificate issuers count at index %d = %d, want %d",
				i, len(actualCert.Issuers), len(expectedCert.Issuers))
		} else {
			for j, expectedIssuer := range expectedCert.Issuers {
				if j >= len(actualCert.Issuers) {
					t.Errorf("LoadMonitorConfig() missing issuer at index %d for certificate %d", j, i)
					continue
				}
				if actualCert.Issuers[j] != expectedIssuer {
					t.Errorf("LoadMonitorConfig() certificate issuer at index %d for certificate %d = %s, want %s",
						j, i, actualCert.Issuers[j], expectedIssuer)
				}
			}
		}
	}

	// Validate fingerprints
	if len(expected.Fingerprints) != len(actual.Fingerprints) {
		t.Errorf("LoadMonitorConfig() fingerprints count = %d, want %d",
			len(actual.Fingerprints), len(expected.Fingerprints))
	} else {
		for i, expectedFp := range expected.Fingerprints {
			if actual.Fingerprints[i] != expectedFp {
				t.Errorf("LoadMonitorConfig() fingerprint at index %d = %s, want %s",
					i, actual.Fingerprints[i], expectedFp)
			}
		}
	}

	// Validate subjects
	if len(expected.Subjects) != len(actual.Subjects) {
		t.Errorf("LoadMonitorConfig() subjects count = %d, want %d",
			len(actual.Subjects), len(expected.Subjects))
	} else {
		for i, expectedSub := range expected.Subjects {
			if actual.Subjects[i] != expectedSub {
				t.Errorf("LoadMonitorConfig() subject at index %d = %s, want %s",
					i, actual.Subjects[i], expectedSub)
			}
		}
	}
}

func TestLoadMonitorConfig(t *testing.T) {
	tests := []struct {
		name              string
		flags             *MonitorFlags
		defaultOutputFile string
		wantErr           bool
		expectedOutput    string
		expectedConfig    *notifications.IdentityMonitorConfiguration
		setupFiles        func(t *testing.T) (string, func())
	}{
		{
			name: "both config file and config yaml specified should error",
			flags: &MonitorFlags{
				ConfigFile: "test.yaml",
				ConfigYaml: "test: yaml",
			},
			defaultOutputFile: "default.txt",
			wantErr:           true,
			expectedConfig:    nil,
		},
		{
			name: "config file with valid yaml",
			flags: &MonitorFlags{
				ConfigFile: "test.yaml",
			},
			defaultOutputFile: "default.txt",
			wantErr:           false,
			expectedOutput:    "custom.txt",
			expectedConfig: &notifications.IdentityMonitorConfiguration{
				MonitoredValues: notifications.ConfigMonitoredValues{
					CertificateIdentities: []identity.CertificateIdentity{
						{
							CertSubject: "test-subject",
							Issuers:     []string{"test-issuer"},
						},
					},
					Fingerprints: []string{"test-fingerprint"},
					Subjects:     []string{"test-subject"},
				},
			},
			setupFiles: func(t *testing.T) (string, func()) {
				content := `outputIdentities: custom.txt
monitoredValues:
  certIdentities:
    - certSubject: "test-subject"
      issuers: ["test-issuer"]
  fingerprints: ["test-fingerprint"]
  subjects: ["test-subject"]`

				tmpDir := t.TempDir()
				configFile := filepath.Join(tmpDir, "test.yaml")
				err := os.WriteFile(configFile, []byte(content), 0644)
				if err != nil {
					t.Fatalf("failed to write test config file: %v", err)
				}

				return configFile, func() {}
			},
		},
		{
			name: "config file with invalid yaml",
			flags: &MonitorFlags{
				ConfigFile: "test.yaml",
			},
			defaultOutputFile: "default.txt",
			wantErr:           true,
			expectedConfig:    nil,
			setupFiles: func(t *testing.T) (string, func()) {
				content := `invalid: yaml: content: with: too: many: colons`

				tmpDir := t.TempDir()
				configFile := filepath.Join(tmpDir, "test.yaml")
				err := os.WriteFile(configFile, []byte(content), 0644)
				if err != nil {
					t.Fatalf("failed to write test config file: %v", err)
				}

				return configFile, func() {}
			},
		},
		{
			name: "config file does not exist",
			flags: &MonitorFlags{
				ConfigFile: "nonexistent.yaml",
			},
			defaultOutputFile: "default.txt",
			wantErr:           true,
			expectedConfig:    nil,
		},
		{
			name: "config yaml with valid content",
			flags: &MonitorFlags{
				ConfigYaml: `outputIdentities: custom.txt
monitoredValues:
  certIdentities:
    - certSubject: "test-subject"
      issuers: ["test-issuer"]
  fingerprints: ["test-fingerprint"]
  subjects: ["test-subject"]`,
			},
			defaultOutputFile: "default.txt",
			wantErr:           false,
			expectedOutput:    "custom.txt",
			expectedConfig: &notifications.IdentityMonitorConfiguration{
				MonitoredValues: notifications.ConfigMonitoredValues{
					CertificateIdentities: []identity.CertificateIdentity{
						{
							CertSubject: "test-subject",
							Issuers:     []string{"test-issuer"},
						},
					},
					Fingerprints: []string{"test-fingerprint"},
					Subjects:     []string{"test-subject"},
				},
			},
		},
		{
			name: "config yaml with invalid content",
			flags: &MonitorFlags{
				ConfigYaml: `invalid: yaml: content: with: too: many: colons`,
			},
			defaultOutputFile: "default.txt",
			wantErr:           true,
			expectedConfig:    nil,
		},
		{
			name: "neither config file nor config yaml specified",
			flags: &MonitorFlags{
				ConfigFile: "",
				ConfigYaml: "",
			},
			defaultOutputFile: "default.txt",
			wantErr:           false,
			expectedOutput:    "default.txt",
			expectedConfig:    &notifications.IdentityMonitorConfiguration{},
		},
		{
			name: "config yaml with empty output identities should use default",
			flags: &MonitorFlags{
				ConfigYaml: `monitoredValues:
  certIdentities:
    - certSubject: "test-subject"
  fingerprints: ["test-fingerprint"]`,
			},
			defaultOutputFile: "default.txt",
			wantErr:           false,
			expectedOutput:    "default.txt",
			expectedConfig: &notifications.IdentityMonitorConfiguration{
				MonitoredValues: notifications.ConfigMonitoredValues{
					CertificateIdentities: []identity.CertificateIdentity{
						{
							CertSubject: "test-subject",
							Issuers:     []string{},
						},
					},
					Fingerprints: []string{"test-fingerprint"},
				},
			},
		},
		{
			name: "config yaml with complex configuration",
			flags: &MonitorFlags{
				ConfigYaml: `startIndex: 100
endIndex: 200
outputIdentities: complex.txt
logInfoFile: log.txt
identityMetadataFile: metadata.txt
monitoredValues:
  certIdentities:
    - certSubject: "CN=test.example.com"
      issuers: ["O=Test Org", "O=Another Org"]
    - certSubject: "CN=another.example.com"
      issuers: ["O=Test Org"]
  fingerprints: 
    - "sha256:abcdef1234567890"
    - "sha256:fedcba0987654321"
  subjects:
    - "test@example.com"
    - "admin@example.com"
githubIssue:
  repositoryOwner: "test"
  repositoryName: "repo"
emailNotificationSMTP:
  SMTPHostURL: "smtp.example.com"`,
			},
			defaultOutputFile: "default.txt",
			wantErr:           false,
			expectedOutput:    "complex.txt",
			expectedConfig: &notifications.IdentityMonitorConfiguration{
				StartIndex:           intPtr(100),
				EndIndex:             intPtr(200),
				LogInfoFile:          "log.txt",
				IdentityMetadataFile: stringPtr("metadata.txt"),
				MonitoredValues: notifications.ConfigMonitoredValues{
					CertificateIdentities: []identity.CertificateIdentity{
						{
							CertSubject: "CN=test.example.com",
							Issuers:     []string{"O=Test Org", "O=Another Org"},
						},
						{
							CertSubject: "CN=another.example.com",
							Issuers:     []string{"O=Test Org"},
						},
					},
					Fingerprints: []string{"sha256:abcdef1234567890", "sha256:fedcba0987654321"},
					Subjects:     []string{"test@example.com", "admin@example.com"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test files if needed
			if tt.setupFiles != nil {
				configFile, cleanup := tt.setupFiles(t)
				defer cleanup()
				tt.flags.ConfigFile = configFile
			}

			config, err := LoadMonitorConfig(tt.flags, tt.defaultOutputFile)

			if tt.wantErr {
				if err == nil {
					t.Errorf("LoadMonitorConfig() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("LoadMonitorConfig() unexpected error: %v", err)
				return
			}

			if config == nil {
				t.Errorf("LoadMonitorConfig() returned nil config")
				return
			}

			if config.OutputIdentitiesFile != tt.expectedOutput {
				t.Errorf("LoadMonitorConfig() output file = %v, want %v", config.OutputIdentitiesFile, tt.expectedOutput)
			}

			// Validate monitored values if expected config is provided
			if tt.expectedConfig != nil {
				validateConfigValues(t, config, tt.expectedConfig)
			}
		})
	}
}

func TestLoadMonitorConfig_ConfigFilePermissions(t *testing.T) {
	// Test with a file that has no read permissions
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "no-read.yaml")

	// Create file with no read permissions
	err := os.WriteFile(configFile, []byte("test: content"), 0000)
	if err != nil {
		t.Fatalf("failed to write test config file: %v", err)
	}

	flags := &MonitorFlags{
		ConfigFile: configFile,
	}

	_, err = LoadMonitorConfig(flags, "default.txt")
	if err == nil {
		t.Errorf("LoadMonitorConfig() expected error for file with no read permissions but got none")
	}
}

func TestLoadMonitorConfig_EmptyConfigFile(t *testing.T) {
	// Test with an empty config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "empty.yaml")

	err := os.WriteFile(configFile, []byte(""), 0644)
	if err != nil {
		t.Fatalf("failed to write test config file: %v", err)
	}

	flags := &MonitorFlags{
		ConfigFile: configFile,
	}

	config, err := LoadMonitorConfig(flags, "default.txt")
	if err != nil {
		t.Errorf("LoadMonitorConfig() unexpected error for empty file: %v", err)
		return
	}

	if config.OutputIdentitiesFile != "default.txt" {
		t.Errorf("LoadMonitorConfig() output file = %v, want default.txt", config.OutputIdentitiesFile)
	}

	if config.MonitoredValues.CertificateIdentities != nil {
		t.Errorf("LoadMonitorConfig() expected nil monitored values, got %v", config.MonitoredValues)
	}

	if config.MonitoredValues.Fingerprints != nil {
		t.Errorf("LoadMonitorConfig() expected nil monitored values, got %v", config.MonitoredValues)
	}

	if config.MonitoredValues.Subjects != nil {
		t.Errorf("LoadMonitorConfig() expected nil monitored values, got %v", config.MonitoredValues)
	}
}

func TestLoadMonitorConfig_ConfigYamlWithSpecialCharacters(t *testing.T) {
	// Test with YAML containing special characters
	flags := &MonitorFlags{
		ConfigYaml: `outputIdentities: "file with spaces.txt"
monitoredValues:
  subjects:
    - "user@domain.com"
    - "user+tag@domain.com"
    - "user.name@domain.com"`,
	}

	config, err := LoadMonitorConfig(flags, "default.txt")
	if err != nil {
		t.Errorf("LoadMonitorConfig() unexpected error for YAML with special characters: %v", err)
		return
	}

	if config.OutputIdentitiesFile != "file with spaces.txt" {
		t.Errorf("LoadMonitorConfig() output file = %v, want 'file with spaces.txt'", config.OutputIdentitiesFile)
	}

	if len(config.MonitoredValues.Subjects) != 3 {
		t.Errorf("LoadMonitorConfig() expected 3 subjects, got %d", len(config.MonitoredValues.Subjects))
	}
}

func TestMonitorLoop_BasicExecution(t *testing.T) {
	// Test basic execution with callbacks being called correctly
	callCount := 0
	consistencyCheckCalled := false
	identitySearchCalled := false

	params := MonitorLoopParams{
		Interval: 10 * time.Millisecond, // Very short interval for testing
		Config: &notifications.IdentityMonitorConfiguration{
			StartIndex: intPtr(1),
			EndIndex:   intPtr(10),
		},
		MonitoredValues: identity.MonitoredValues{
			CertificateIdentities: []identity.CertificateIdentity{
				{CertSubject: "test-subject", Issuers: []string{"test-issuer"}},
			},
			Fingerprints: []string{"sha256:abcdef1234567890"},
			Subjects:     []string{"test@example.com"},
		},
		Once: true, // Run once to avoid infinite loop
		NotificationContextNewFn: func() notifications.NotificationContext {
			return notifications.NotificationContext{
				MonitorType: "test-monitor",
				Subject:     "test-subject",
			}
		},
		RunConsistencyCheckFn: func(_ context.Context) (Checkpoint, LogInfo, error) {
			consistencyCheckCalled = true
			callCount++
			// Return mock checkpoint and log info
			return "prev-checkpoint", "current-checkpoint", nil
		},
		GetStartIndexFn: func(_ Checkpoint, _ LogInfo) *int {
			callCount++
			return intPtr(1)
		},
		GetEndIndexFn: func(_ LogInfo) *int {
			callCount++
			return intPtr(10)
		},
		IdentitySearchFn: func(_ context.Context, _ *notifications.IdentityMonitorConfiguration, monitoredValues identity.MonitoredValues) ([]identity.MonitoredIdentity, error) {
			identitySearchCalled = true
			callCount++

			// Verify that the monitored values are passed correctly
			if len(monitoredValues.CertificateIdentities) != 1 {
				t.Errorf("Expected 1 certificate identity, got %d", len(monitoredValues.CertificateIdentities))
			}
			if len(monitoredValues.Fingerprints) != 1 {
				t.Errorf("Expected 1 fingerprint, got %d", len(monitoredValues.Fingerprints))
			}
			if len(monitoredValues.Subjects) != 1 {
				t.Errorf("Expected 1 subject, got %d", len(monitoredValues.Subjects))
			}

			// Return some found identities to trigger notifications
			return []identity.MonitoredIdentity{
				{
					Identity: "test-identity",
					FoundIdentityEntries: []identity.LogEntry{
						{CertSubject: "test-subject", Index: 5, UUID: "test-uuid"},
					},
				},
			}, nil
		},
	}

	// Run MonitorLoop
	MonitorLoop(params)

	// Verify callbacks were called
	if !consistencyCheckCalled {
		t.Error("RunConsistencyCheckFn was not called")
	}
	if !identitySearchCalled {
		t.Error("IdentitySearchFn was not called")
	}
	if callCount != 2 {
		t.Errorf("Expected exactly 2 callback calls, got %d", callCount)
	}
}

func TestMonitorLoop_ConsistencyCheckError(t *testing.T) {
	// Test that MonitorLoop handles consistency check errors correctly
	consistencyCheckCalled := false

	params := MonitorLoopParams{
		Interval: 10 * time.Millisecond,
		Config: &notifications.IdentityMonitorConfiguration{
			StartIndex: intPtr(1),
			EndIndex:   intPtr(10),
		},
		MonitoredValues: identity.MonitoredValues{
			CertificateIdentities: []identity.CertificateIdentity{
				{CertSubject: "test-subject", Issuers: []string{"test-issuer"}},
			},
		},
		Once: true, // Run once to avoid infinite loop
		RunConsistencyCheckFn: func(_ context.Context) (Checkpoint, LogInfo, error) {
			consistencyCheckCalled = true
			return nil, nil, fmt.Errorf("consistency check failed")
		},
		GetStartIndexFn: func(_ Checkpoint, _ LogInfo) *int {
			return intPtr(1)
		},
		GetEndIndexFn: func(_ LogInfo) *int {
			return intPtr(10)
		},
		IdentitySearchFn: func(_ context.Context, _ *notifications.IdentityMonitorConfiguration, _ identity.MonitoredValues) ([]identity.MonitoredIdentity, error) {
			t.Error("IdentitySearchFn should not be called when consistency check fails")
			return nil, nil
		},
	}

	// Run MonitorLoop - it should return immediately due to error
	MonitorLoop(params)

	if !consistencyCheckCalled {
		t.Error("RunConsistencyCheckFn was not called")
	}
}

func TestMonitorLoop_NoMonitoredValues(t *testing.T) {
	// Test that MonitorLoop skips identity search when no monitored values exist
	consistencyCheckCalled := false
	identitySearchCalled := false
	startIndexCalled := false
	endIndexCalled := false

	params := MonitorLoopParams{
		Interval: 10 * time.Millisecond,
		Config: &notifications.IdentityMonitorConfiguration{
			StartIndex: intPtr(1),
			EndIndex:   intPtr(10),
		},
		MonitoredValues: identity.MonitoredValues{}, // Empty monitored values
		Once:            true,                       // Run once to avoid infinite loop
		RunConsistencyCheckFn: func(_ context.Context) (Checkpoint, LogInfo, error) {
			consistencyCheckCalled = true
			return "prev-checkpoint", "current-checkpoint", nil
		},
		GetStartIndexFn: func(_ Checkpoint, _ LogInfo) *int {
			startIndexCalled = true
			t.Error("GetStartIndexFn should not be called when no monitored values exist")
			return intPtr(1)
		},
		GetEndIndexFn: func(_ LogInfo) *int {
			endIndexCalled = true
			t.Error("GetEndIndexFn should not be called when no monitored values exist")
			return intPtr(10)
		},
		IdentitySearchFn: func(_ context.Context, _ *notifications.IdentityMonitorConfiguration, _ identity.MonitoredValues) ([]identity.MonitoredIdentity, error) {
			identitySearchCalled = true
			t.Error("IdentitySearchFn should not be called when no monitored values exist")
			return nil, nil
		},
	}

	// Run MonitorLoop
	MonitorLoop(params)

	if !consistencyCheckCalled {
		t.Error("RunConsistencyCheckFn was not called")
	}
	if identitySearchCalled {
		t.Error("IdentitySearchFn should not be called when no monitored values exist")
	}
	if startIndexCalled {
		t.Error("GetStartIndexFn should not be called when no monitored values exist")
	}
	if endIndexCalled {
		t.Error("GetEndIndexFn should not be called when no monitored values exist")
	}
}

func TestMonitorLoop_InvalidIndexRange(t *testing.T) {
	// Test that MonitorLoop handles invalid index ranges correctly
	consistencyCheckCalled := false
	identitySearchCalled := false

	params := MonitorLoopParams{
		Interval: 10 * time.Millisecond,
		Config: &notifications.IdentityMonitorConfiguration{
			StartIndex: intPtr(20), // Start > End
			EndIndex:   intPtr(10),
		},
		MonitoredValues: identity.MonitoredValues{
			CertificateIdentities: []identity.CertificateIdentity{
				{CertSubject: "test-subject", Issuers: []string{"test-issuer"}},
			},
		},
		Once: true, // Run once to avoid infinite loop
		RunConsistencyCheckFn: func(_ context.Context) (Checkpoint, LogInfo, error) {
			consistencyCheckCalled = true
			return "prev-checkpoint", "current-checkpoint", nil
		},
		GetStartIndexFn: func(_ Checkpoint, _ LogInfo) *int {
			return intPtr(20)
		},
		GetEndIndexFn: func(_ LogInfo) *int {
			return intPtr(10)
		},
		IdentitySearchFn: func(_ context.Context, _ *notifications.IdentityMonitorConfiguration, _ identity.MonitoredValues) ([]identity.MonitoredIdentity, error) {
			identitySearchCalled = true
			t.Error("IdentitySearchFn should not be called when start index > end index")
			return nil, nil
		},
	}

	// Run MonitorLoop - it should return immediately due to invalid index range
	MonitorLoop(params)

	if !consistencyCheckCalled {
		t.Error("RunConsistencyCheckFn was not called")
	}
	if identitySearchCalled {
		t.Error("IdentitySearchFn should not be called when start index > end index")
	}
}

func TestMonitorLoop_OnceFlag(t *testing.T) {
	// Test that MonitorLoop exits after one iteration when Once flag is true
	iterationCount := 0
	identitySearchCalled := false

	params := MonitorLoopParams{
		Interval: 10 * time.Millisecond,
		Config: &notifications.IdentityMonitorConfiguration{
			StartIndex: intPtr(1),
			EndIndex:   intPtr(10),
		},
		MonitoredValues: identity.MonitoredValues{
			CertificateIdentities: []identity.CertificateIdentity{
				{CertSubject: "test-subject", Issuers: []string{"test-issuer"}},
			},
		},
		Once: true, // This should cause it to run only once
		RunConsistencyCheckFn: func(_ context.Context) (Checkpoint, LogInfo, error) {
			iterationCount++
			return "prev-checkpoint", "current-checkpoint", nil
		},
		GetStartIndexFn: func(_ Checkpoint, _ LogInfo) *int {
			return intPtr(1)
		},
		GetEndIndexFn: func(_ LogInfo) *int {
			return intPtr(10)
		},
		IdentitySearchFn: func(_ context.Context, _ *notifications.IdentityMonitorConfiguration, _ identity.MonitoredValues) ([]identity.MonitoredIdentity, error) {
			identitySearchCalled = true
			return []identity.MonitoredIdentity{}, nil
		},
	}

	// Run MonitorLoop
	MonitorLoop(params)

	if iterationCount != 1 {
		t.Errorf("Expected 1 iteration, got %d", iterationCount)
	}
	if !identitySearchCalled {
		t.Error("IdentitySearchFn should be called even when Once is true")
	}
}

func TestMonitorLoop_EndIndexSpecified(t *testing.T) {
	// Test that MonitorLoop exits when EndIndex is specified in config
	iterationCount := 0
	identitySearchCalled := false

	params := MonitorLoopParams{
		Interval: 10 * time.Millisecond,
		Config: &notifications.IdentityMonitorConfiguration{
			StartIndex: intPtr(1),
			EndIndex:   intPtr(10), // This should cause it to exit after one iteration
		},
		MonitoredValues: identity.MonitoredValues{
			CertificateIdentities: []identity.CertificateIdentity{
				{CertSubject: "test-subject", Issuers: []string{"test-issuer"}},
			},
		},
		Once: false, // Not once, but should still exit due to EndIndex
		RunConsistencyCheckFn: func(_ context.Context) (Checkpoint, LogInfo, error) {
			iterationCount++
			return "prev-checkpoint", "current-checkpoint", nil
		},
		GetStartIndexFn: func(_ Checkpoint, _ LogInfo) *int {
			return intPtr(1)
		},
		GetEndIndexFn: func(_ LogInfo) *int {
			return intPtr(10)
		},
		IdentitySearchFn: func(_ context.Context, _ *notifications.IdentityMonitorConfiguration, _ identity.MonitoredValues) ([]identity.MonitoredIdentity, error) {
			identitySearchCalled = true
			return []identity.MonitoredIdentity{}, nil
		},
	}

	// Run MonitorLoop
	MonitorLoop(params)

	if iterationCount != 1 {
		t.Errorf("Expected 1 iteration, got %d", iterationCount)
	}
	if !identitySearchCalled {
		t.Error("IdentitySearchFn should be called even when EndIndex is specified")
	}
}
