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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/notifications"
	"gopkg.in/yaml.v2"
	"sigs.k8s.io/release-utils/version"
)

// MonitorFlags contains all the command-line flags for monitor applications
type MonitorFlags struct {
	ConfigFile    string
	ConfigYaml    string
	Once          bool
	LogInfoFile   string
	ServerURL     string
	Interval      time.Duration
	UserAgent     string
	TUFRepository string
	TUFRootPath   string
}

// MonitorLoopParams contains the parameters for the LoopLogs function
type MonitorLoopParams struct {
	Interval                 time.Duration
	Config                   *notifications.IdentityMonitorConfiguration
	MonitoredValues          identity.MonitoredValues
	Once                     bool
	NotificationContextNewFn notifications.NotificationContextNew
	RunConsistencyCheckFn    func(ctx context.Context) (Checkpoint, LogInfo, error)
	GetStartIndexFn          func(prev Checkpoint, cur LogInfo) *int
	GetEndIndexFn            func(cur LogInfo) *int
	IdentitySearchFn         func(ctx context.Context, config *notifications.IdentityMonitorConfiguration, monitoredValues identity.MonitoredValues) ([]identity.MonitoredIdentity, []identity.FailedLogEntry, error)
}

type Checkpoint interface{}
type LogInfo interface{}

// ParseMonitorFlags parses command-line flags and returns a MonitorFlags struct
func ParseMonitorFlags(defaultServerURL, defaultTUFRepository string, baseUserAgentName string) *MonitorFlags {
	configFilePath := flag.String("config-file", "", "path to yaml configuration file containing identity monitor settings")
	configYamlInput := flag.String("config", "", "string with YAML configuration containing identity monitor settings")
	once := flag.Bool("once", true, "whether to run the monitor on a repeated interval or once")
	logInfoFile := flag.String("file", "", "path to the initial log info checkpoint file to be read from")
	serverURL := flag.String("url", defaultServerURL, "URL to the server that is to be monitored")
	interval := flag.Duration("interval", 5*time.Minute, "Length of interval between each periodical consistency check")
	userAgentString := flag.String("user-agent", "", "details to include in the user agent string")
	tufRepository := flag.String("tuf-repository", defaultTUFRepository, "TUF repository to use. Can be 'default', 'staging' or a custom TUF repository URL.")
	tufRootPath := flag.String("tuf-root-path", "", "path to the trusted root file (passed out of bounds), if custom TUF repository is used")
	flag.Parse()

	finalUserAgent := strings.TrimSpace(fmt.Sprintf("%s/%s (%s; %s) %s",
		baseUserAgentName,
		version.GetVersionInfo().GitVersion,
		runtime.GOOS,
		runtime.GOARCH,
		*userAgentString,
	))

	return &MonitorFlags{
		ConfigFile:    *configFilePath,
		ConfigYaml:    *configYamlInput,
		Once:          *once,
		LogInfoFile:   *logInfoFile,
		ServerURL:     *serverURL,
		Interval:      *interval,
		UserAgent:     finalUserAgent,
		TUFRepository: *tufRepository,
		TUFRootPath:   *tufRootPath,
	}
}

// LoadMonitorConfig loads the monitor configuration from flags
func LoadMonitorConfig(flags *MonitorFlags, defaultOutputFile string) (*notifications.IdentityMonitorConfiguration, error) {
	var config notifications.IdentityMonitorConfiguration

	if flags.ConfigFile != "" && flags.ConfigYaml != "" {
		return nil, fmt.Errorf("error: only one of --config and --config-file should be specified")
	}

	if flags.ConfigFile != "" {
		readConfig, err := os.ReadFile(flags.ConfigFile)
		if err != nil {
			return nil, fmt.Errorf("error reading from identity monitor configuration file: %v", err)
		}

		configString := string(readConfig)
		if err := yaml.Unmarshal([]byte(configString), &config); err != nil {
			return nil, fmt.Errorf("error parsing identities: %v", err)
		}
	}

	if flags.ConfigYaml != "" {
		if err := yaml.Unmarshal([]byte(flags.ConfigYaml), &config); err != nil {
			return nil, fmt.Errorf("error parsing identities: %v", err)
		}
	}

	if config.OutputIdentitiesFile == "" {
		config.OutputIdentitiesFile = defaultOutputFile
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return &config, nil
}

// ParseAndLoadConfig is a convenience function that parses flags and loads config
func ParseAndLoadConfig(defaultServerURL, defaultTUFRepository, defaultOutputFile, baseUserAgentName string) (*MonitorFlags, *notifications.IdentityMonitorConfiguration, error) {
	flags := ParseMonitorFlags(defaultServerURL, defaultTUFRepository, baseUserAgentName)
	config, err := LoadMonitorConfig(flags, defaultOutputFile)
	if err != nil {
		return nil, nil, err
	}
	return flags, config, nil
}

// PrintMonitoredValues prints the monitored values to the console
func PrintMonitoredValues(monitoredValues identity.MonitoredValues) {
	for _, certID := range monitoredValues.CertificateIdentities {
		if len(certID.Issuers) == 0 {
			fmt.Printf("Monitoring certificate subject %s\n", certID.CertSubject)
		} else {
			fmt.Printf("Monitoring certificate subject %s for issuer(s) %s\n", certID.CertSubject, strings.Join(certID.Issuers, ","))
		}
	}
	for _, fp := range monitoredValues.Fingerprints {
		fmt.Printf("Monitoring fingerprint %s\n", fp)
	}
	for _, sub := range monitoredValues.Subjects {
		fmt.Printf("Monitoring subject %s\n", sub)
	}
}

func MonitorLoop(params MonitorLoopParams) {
	ticker := time.NewTicker(params.Interval)
	defer ticker.Stop()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	config := params.Config

	// To get an immediate first tick, for-select is at the end of the loop
	for {
		fmt.Fprint(os.Stderr, "New monitor run at ", time.Now().Format(time.RFC3339), "\n")
		inputEndIndex := config.EndIndex

		prevCheckpoint, curCheckpoint, err := params.RunConsistencyCheckFn(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error running consistency check: %v", err)
			return
		}

		if identity.MonitoredValuesExist(params.MonitoredValues) {
			if config.StartIndex == nil {
				if prevCheckpoint != nil {
					config.StartIndex = params.GetStartIndexFn(prevCheckpoint, curCheckpoint)
				} else {
					fmt.Fprintf(os.Stderr, "no start index set and no log checkpoint, just saving checkpoint\n")
				}
			}

			if config.EndIndex == nil {
				config.EndIndex = params.GetEndIndexFn(curCheckpoint)
			}

			if config.StartIndex != nil && config.EndIndex != nil {
				if *config.StartIndex > *config.EndIndex {
					fmt.Fprintf(os.Stderr, "start index %d must be less or equal than end index %d", *config.StartIndex, *config.EndIndex)
					return
				}

				foundEntries, failedEntries, err := params.IdentitySearchFn(ctx, config, params.MonitoredValues)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to successfully complete identity search: %v", err)
					return
				}

				if len(foundEntries) > 0 || len(failedEntries) > 0 {
					notificationPool := notifications.CreateNotificationPool(*config)

					if len(foundEntries) > 0 {
						notificationData := notifications.NotificationData{
							Context: params.NotificationContextNewFn(),
							Payload: identity.MonitoredIdentityList(foundEntries),
						}

						err = notifications.TriggerNotifications(notificationPool, notificationData)
						if err != nil {
							// continue running consistency check if notifications fail to trigger
							fmt.Fprintf(os.Stderr, "failed to trigger notifications for found entries: %v", err)
						}
					}
					if len(failedEntries) > 0 {
						fmt.Fprintf(os.Stderr, "failed to parse some log entries: %v", failedEntries)

						notificationData := notifications.NotificationData{
							Context: params.NotificationContextNewFn(),
							Payload: identity.FailedLogEntryList(failedEntries),
						}

						err = notifications.TriggerNotifications(notificationPool, notificationData)
						if err != nil {
							// continue running consistency check if notifications fail to trigger
							fmt.Fprintf(os.Stderr, "failed to trigger notifications for failed entries: %v", err)
						}
					}
				}

				config.StartIndex = config.EndIndex
				config.EndIndex = nil
			}
		}

		if params.Once || inputEndIndex != nil {
			return
		}

		select {
		case <-ticker.C:
			continue
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "Shutting down gracefully...")
			return
		}
	}
}
