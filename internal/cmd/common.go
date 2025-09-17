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
	"encoding/pem"
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
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"gopkg.in/yaml.v2"
	"sigs.k8s.io/release-utils/version"
)

// MonitorFlags contains all the command-line flags for monitor applications
type MonitorFlags struct {
	ConfigFile      string
	ConfigYaml      string
	Once            bool
	LogInfoFile     string
	ServerURL       string
	Interval        time.Duration
	UserAgent       string
	TUFRepository   string
	TUFRootPath     string
	CARoots         string
	CAIntermediates string
}

// MonitorLogic is the interface for the monitor loop logic
type MonitorLogic interface {
	Interval() time.Duration
	Config() *notifications.IdentityMonitorConfiguration
	MonitoredValues() identity.MonitoredValues
	Once() bool
	NotificationContextNew() notifications.NotificationContext
	RunConsistencyCheck(ctx context.Context) (Checkpoint, LogInfo, error)
	WriteCheckpoint(prev Checkpoint, cur LogInfo) error
	GetStartIndex(prev Checkpoint, cur LogInfo) *int64
	GetEndIndex(cur LogInfo) *int64
	IdentitySearch(ctx context.Context, config *notifications.IdentityMonitorConfiguration, monitoredValues identity.MonitoredValues) ([]identity.MonitoredIdentity, []identity.FailedLogEntry, error)
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
	caRoots := flag.String("ca-roots", "", "path to a bundle file of CA certificates in PEM format")
	caIntermediates := flag.String("ca-intermediates", "", "path to a bundle file of CA intermediate certificates in PEM format")
	flag.Parse()

	finalUserAgent := strings.TrimSpace(fmt.Sprintf("%s/%s (%s; %s) %s",
		baseUserAgentName,
		version.GetVersionInfo().GitVersion,
		runtime.GOOS,
		runtime.GOARCH,
		*userAgentString,
	))

	return &MonitorFlags{
		ConfigFile:      *configFilePath,
		ConfigYaml:      *configYamlInput,
		Once:            *once,
		LogInfoFile:     *logInfoFile,
		ServerURL:       *serverURL,
		Interval:        *interval,
		UserAgent:       finalUserAgent,
		TUFRepository:   *tufRepository,
		TUFRootPath:     *tufRootPath,
		CARoots:         *caRoots,
		CAIntermediates: *caIntermediates,
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

	if flags.CARoots != "" {
		config.CARoots = flags.CARoots
	}

	if flags.CAIntermediates != "" {
		config.CAIntermediates = flags.CAIntermediates
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

// GetTUFClient gets a TUF client based on the flags
func GetTUFClient(flags *MonitorFlags) (*tuf.Client, error) {
	switch flags.TUFRepository {
	case "default":
		if flags.TUFRootPath != "" {
			return nil, fmt.Errorf("tuf-root-path is not supported when using the default TUF repository")
		}
		return tuf.DefaultClient()
	case "staging":
		if flags.TUFRootPath != "" {
			return nil, fmt.Errorf("tuf-root-path is not supported when using the staging TUF repository")
		}
		options := tuf.DefaultOptions().WithRoot(tuf.StagingRoot()).WithRepositoryBaseURL(tuf.StagingMirror)
		return tuf.New(options)
	default:
		fmt.Printf("Using custom TUF repository: %s\n", flags.TUFRepository)
		if flags.TUFRootPath == "" {
			return nil, fmt.Errorf("tuf-root-path is required when using a custom TUF repository")
		}
		rootBytes, err := os.ReadFile(flags.TUFRootPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read TUF root path: %w", err)
		}
		options := tuf.DefaultOptions().WithRoot(rootBytes).WithRepositoryBaseURL(flags.TUFRepository)
		return tuf.New(options)
	}
}

// ConfigureTrustedCAs configures the root/intermediate CAs for the monitor, by either
// using the configured CAs or, if they were not explicitly defined, using the
// default ones from the TUF data.
func ConfigureTrustedCAs(config *notifications.IdentityMonitorConfiguration, trustedRoot *root.TrustedRoot) (func(), error) {
	if config.CARoots == "" && config.CAIntermediates == "" {
		return func() {}, nil
	}

	var fulcioRootFile, fulcioIntermediateFile *os.File
	var err error
	if config.CARoots == "" {
		fulcioRootFile, err = os.CreateTemp("", "fulcio-root-*.pem")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file for Fulcio CA: %w", err)
		}
		config.CARoots = fulcioRootFile.Name()

		if config.CAIntermediates == "" {
			fulcioIntermediateFile, err = os.CreateTemp("", "fulcio-intermediate-*.pem")
			if err != nil {
				return nil, fmt.Errorf("failed to create temp file for Fulcio CA intermediate: %w", err)
			}
			config.CAIntermediates = fulcioIntermediateFile.Name()
		}
	}

	for _, ca := range trustedRoot.FulcioCertificateAuthorities() {
		fulcioCA := ca.(*root.FulcioCertificateAuthority)

		if fulcioRootFile != nil {
			// Get the root certificate from TUF
			if err := pem.Encode(fulcioRootFile, &pem.Block{Type: "CERTIFICATE", Bytes: fulcioCA.Root.Raw}); err != nil {
				if fulcioIntermediateFile != nil {
					fulcioIntermediateFile.Close()
					os.Remove(fulcioIntermediateFile.Name())
				}
				fulcioRootFile.Close()
				os.Remove(fulcioRootFile.Name())
				return nil, fmt.Errorf("failed to write Fulcio CA root to temp file: %w", err)
			}

			if fulcioIntermediateFile != nil {
				// Get the intermediate certificates from TUF
				for _, intermediate := range fulcioCA.Intermediates {
					if err := pem.Encode(fulcioIntermediateFile, &pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Raw}); err != nil {
						if fulcioIntermediateFile != nil {
							fulcioIntermediateFile.Close()
							os.Remove(fulcioIntermediateFile.Name())
						}
						fulcioRootFile.Close()
						os.Remove(fulcioRootFile.Name())
						return nil, fmt.Errorf("failed to write Fulcio CA intermediate to temp file: %w", err)
					}
				}
			}
		}
	}
	if fulcioRootFile != nil {
		fulcioRootFile.Close()
	}
	if fulcioIntermediateFile != nil {
		fulcioIntermediateFile.Close()
	}

	cleanup := func() {
		if fulcioRootFile != nil {
			os.Remove(fulcioRootFile.Name())
		}
		if fulcioIntermediateFile != nil {
			os.Remove(fulcioIntermediateFile.Name())
		}
	}

	return cleanup, nil
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

func MonitorLoop(loopLogic MonitorLogic) {
	ticker := time.NewTicker(loopLogic.Interval())
	defer ticker.Stop()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	config := loopLogic.Config()

	// To get an immediate first tick, for-select is at the end of the loop
	for {
		fmt.Fprint(os.Stderr, "New monitor run at ", time.Now().Format(time.RFC3339), "\n")
		inputEndIndex := config.EndIndex

		prevCheckpoint, curCheckpoint, err := loopLogic.RunConsistencyCheck(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error running consistency check: %v", err)
			return
		}

		if identity.MonitoredValuesExist(loopLogic.MonitoredValues()) {
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

				foundEntries, failedEntries, err := loopLogic.IdentitySearch(ctx, config, loopLogic.MonitoredValues())
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to successfully complete identity search: %v", err)
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

		select {
		case <-ticker.C:
			continue
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "Shutting down gracefully...")
			return
		}
	}
}
