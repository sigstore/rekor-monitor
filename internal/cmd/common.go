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
	"github.com/sigstore/rekor-monitor/pkg/server"
	"gopkg.in/yaml.v2"
	"sigs.k8s.io/release-utils/version"
)

// MonitorFlags contains all the command-line flags for monitor applications
type MonitorFlags struct {
	ConfigFile          string
	ConfigYaml          string
	Once                bool
	LogInfoFile         string
	ServerURL           string
	Interval            time.Duration
	UserAgent           string
	TUFRepository       string
	TUFRootPath         string
	MonitorPort         int
	CARootsFile         string
	CAIntermediatesFile string
	HTTPSCertChainFile  string
}

// MonitorLogic is the interface for the monitor loop logic
type MonitorLogic interface {
	Interval() time.Duration
	Config() *notifications.IdentityMonitorConfiguration
	MonitoredValues() identity.MonitoredValues
	Once() bool
	MonitorPort() int
	NotificationContextNew() notifications.NotificationContext
	RunConsistencyCheck(ctx context.Context) (Checkpoint, LogInfo, error)
	WriteCheckpoint(prev Checkpoint, cur LogInfo) error
	GetStartIndex(prev Checkpoint, cur LogInfo) *int64
	GetEndIndex(cur LogInfo) *int64
	IdentitySearch(ctx context.Context, monitoredValues identity.MonitoredValues, startIndex, endIndex int64, opts ...identity.SearchOption) ([]identity.MonitoredIdentity, []identity.FailedLogEntry, error)
}

type Checkpoint interface{}
type LogInfo interface{}

// ParseMonitorFlags parses command-line flags and returns a MonitorFlags struct
func ParseMonitorFlags(defaultServerURL, defaultTUFRepository string, baseUserAgentName string) (*MonitorFlags, error) {
	configFilePath := flag.String("config-file", "", "path to yaml configuration file containing identity monitor settings")
	configYamlInput := flag.String("config", "", "string with YAML configuration containing identity monitor settings")
	once := flag.Bool("once", true, "whether to run the monitor on a repeated interval or once")
	logInfoFile := flag.String("file", "", "path to the initial log info checkpoint file to be read from")
	monitorPort := flag.Int("monitor-port", 9464, "Port for the Prometheus metrics server")
	serverURL := flag.String("url", defaultServerURL, "URL to the server that is to be monitored")
	interval := flag.Duration("interval", 5*time.Minute, "Length of interval between each periodical consistency check")
	userAgentString := flag.String("user-agent", "", "details to include in the user agent string")
	tufRepository := flag.String("tuf-repository", defaultTUFRepository, "TUF repository to use. Can be 'default', 'staging' or a custom TUF repository URL.")
	tufRootPath := flag.String("tuf-root-path", "", "path to the trusted root file (passed out of bounds), if custom TUF repository is used")
	caRootsFilePath := flag.String("ca-roots", "", "path to a bundle file of CA certificates in PEM format")
	caIntermediatesFilePath := flag.String("ca-intermediates", "", "path to a bundle file of CA intermediate certificates in PEM format. The flag must be used together with --ca-roots")
	httpsChainPath := flag.String("https-cert-chain", "", "path to a list of CA certificates in PEM format for the HTTPS connection to the log server")
	flag.Parse()

	if *caIntermediatesFilePath != "" && *caRootsFilePath == "" {
		return nil, fmt.Errorf("ca-intermediates must be used together with --ca-roots")
	}

	finalUserAgent := strings.TrimSpace(fmt.Sprintf("%s/%s (%s; %s) %s",
		baseUserAgentName,
		version.GetVersionInfo().GitVersion,
		runtime.GOOS,
		runtime.GOARCH,
		*userAgentString,
	))

	return &MonitorFlags{
		ConfigFile:          *configFilePath,
		ConfigYaml:          *configYamlInput,
		Once:                *once,
		LogInfoFile:         *logInfoFile,
		MonitorPort:         *monitorPort,
		ServerURL:           *serverURL,
		Interval:            *interval,
		UserAgent:           finalUserAgent,
		TUFRepository:       *tufRepository,
		TUFRootPath:         *tufRootPath,
		CARootsFile:         *caRootsFilePath,
		CAIntermediatesFile: *caIntermediatesFilePath,
		HTTPSCertChainFile:  *httpsChainPath,
	}, nil
}

// LoadMonitorConfig loads the monitor configuration from flags
func LoadMonitorConfig(flags *MonitorFlags) (*notifications.IdentityMonitorConfiguration, error) {
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

	// If outputIdentities is set, ensure format is also set
	if config.OutputIdentitiesFile != nil {
		if config.OutputIdentitiesFormat == nil {
			// Infer format from file extension
			var format string
			switch {
			case strings.HasSuffix(*config.OutputIdentitiesFile, ".txt"):
				format = "text"
			case strings.HasSuffix(*config.OutputIdentitiesFile, ".json"):
				format = "json"
			default:
				// Default to text format
				format = "text"
			}
			config.OutputIdentitiesFormat = &format
		}
	}

	if flags.CARootsFile != "" {
		config.CARootsFile = flags.CARootsFile
	}

	if flags.CAIntermediatesFile != "" {
		config.CAIntermediatesFile = flags.CAIntermediatesFile
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return &config, nil
}

// ParseAndLoadConfig is a convenience function that parses flags and loads config
func ParseAndLoadConfig(defaultServerURL, defaultTUFRepository, baseUserAgentName string) (*MonitorFlags, *notifications.IdentityMonitorConfiguration, error) {
	flags, err := ParseMonitorFlags(defaultServerURL, defaultTUFRepository, baseUserAgentName)
	if err != nil {
		return nil, nil, err
	}
	config, err := LoadMonitorConfig(flags)
	if err != nil {
		return nil, nil, err
	}
	return flags, config, nil
}

// PrintMonitoredValues prints the monitored values to the console
func PrintMonitoredValues(monitoredValues identity.MonitoredValues) {
	for _, mv := range monitoredValues {
		fmt.Println("Monitoring: " + mv.String())
	}
}

func MonitorLoop(loopLogic MonitorLogic) {
	ticker := time.NewTicker(loopLogic.Interval())
	defer ticker.Stop()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !loopLogic.Once() {
		if err := server.StartMetricsServer(ctx, loopLogic.MonitorPort()); err != nil {
			fmt.Fprintf(os.Stderr, "failed to start Prometheus metrics server: %v\n", err)
		}
	}

	config := loopLogic.Config()

	// To get an immediate first tick, for-select is at the end of the loop
	for {
		fmt.Fprint(os.Stderr, "New monitor run at ", time.Now().Format(time.RFC3339), "\n")
		server.IncLogIndexVerificationTotal()
		inputEndIndex := config.EndIndex

		prevCheckpoint, curCheckpoint, err := loopLogic.RunConsistencyCheck(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error running consistency check: %v\n", err)
			if loopLogic.Once() {
				return
			}
			server.IncLogIndexVerificationFailure()
			goto waitForTick
		}

		if len(loopLogic.MonitoredValues()) > 0 {
			if config.StartIndex == nil {
				if prevCheckpoint != nil {
					config.StartIndex = loopLogic.GetStartIndex(prevCheckpoint, curCheckpoint)
				} else {
					fmt.Fprintf(os.Stderr, "no start index set and no log checkpoint, just saving checkpoint\n")
				}
			}

			if config.EndIndex == nil {
				config.EndIndex = loopLogic.GetEndIndex(curCheckpoint)
			}

			if config.StartIndex != nil && config.EndIndex != nil {
				if *config.StartIndex > *config.EndIndex {
					fmt.Fprintf(os.Stderr, "start index %d must be less or equal than end index %d", *config.StartIndex, *config.EndIndex)
					return
				}

				foundEntries, failedEntries, err := loopLogic.IdentitySearch(
					ctx,
					loopLogic.MonitoredValues(),
					*config.StartIndex,
					*config.EndIndex,
					identity.WithCARootsFile(config.CARootsFile),
					identity.WithCAIntermediatesFile(config.CAIntermediatesFile),
					identity.WithOutputIdentitiesFile(config.OutputIdentitiesFile, config.OutputIdentitiesFormat),
					identity.WithIdentityMetadataFile(config.IdentityMetadataFile),
				)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to successfully complete identity search: %v\n", err)
					return
				}

				if len(foundEntries) > 0 || len(failedEntries) > 0 {
					notificationPool := notifications.CreateNotificationPool(*config)

					if len(foundEntries) > 0 {
						notificationData := notifications.NotificationData{
							Context: loopLogic.NotificationContextNew(),
							Payload: identity.MonitoredIdentityList(foundEntries),
						}

						err = notifications.TriggerNotifications(notificationPool, notificationData)
						if err != nil {
							fmt.Fprintf(os.Stderr, "failed to trigger notifications for found entries: %v", err)
							return
						}
					}
					if len(failedEntries) > 0 {
						fmt.Fprintf(os.Stderr, "failed to parse some log entries: %v", failedEntries)

						notificationData := notifications.NotificationData{
							Context: loopLogic.NotificationContextNew(),
							Payload: identity.FailedLogEntryList(failedEntries),
						}

						err = notifications.TriggerNotifications(notificationPool, notificationData)
						if err != nil {
							fmt.Fprintf(os.Stderr, "failed to trigger notifications for failed entries: %v", err)
							return
						}
					}
				}
			}

			config.StartIndex = config.EndIndex
			config.EndIndex = nil
		}

		// Write checkpoint after identity search to ensure identities are
		// always searched even if something fails in the middle
		if err := loopLogic.WriteCheckpoint(prevCheckpoint, curCheckpoint); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write checkpoint: %v", err)
			return
		}

		if loopLogic.Once() || inputEndIndex != nil {
			return
		}

	waitForTick:
		select {
		case <-ticker.C:
			continue
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "Shutting down gracefully...")
			return
		}
	}
}
