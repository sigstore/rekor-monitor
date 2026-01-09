//
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

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"time"

	ctgo "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/sigstore/rekor-monitor/internal/cmd"
	v1ct "github.com/sigstore/rekor-monitor/pkg/ct/v1"
	v2ct "github.com/sigstore/rekor-monitor/pkg/ct/v2"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/notifications"
	"github.com/sigstore/rekor-monitor/pkg/tiles"
	"github.com/sigstore/rekor-monitor/pkg/util"
	"github.com/sigstore/rekor-monitor/pkg/util/file"
	"github.com/sigstore/sigstore-go/pkg/root"
	tdlog "github.com/transparency-dev/formats/log"
)

// Default values for monitoring job parameters
const (
	publicCTServerURL        = "https://ctfe.sigstore.dev/2022"
	logInfoFileName          = "ctLogInfo"
	outputIdentitiesFileName = "ctIdentities"
	TUFRepository            = "default"
)

type CTMonitorLogic struct {
	ctlogClient     *ctclient.LogClient
	flags           *cmd.MonitorFlags
	config          *notifications.IdentityMonitorConfiguration
	monitoredValues identity.MonitoredValues
	trustedRoot     *root.TrustedRoot
}

func (l CTMonitorLogic) Interval() time.Duration {
	return l.flags.Interval
}

func (l CTMonitorLogic) Config() *notifications.IdentityMonitorConfiguration {
	return l.config
}

func (l CTMonitorLogic) MonitoredValues() identity.MonitoredValues {
	return l.monitoredValues
}

func (l CTMonitorLogic) Once() bool {
	return l.flags.Once
}

func (l CTMonitorLogic) MonitorPort() int {
	return l.flags.MonitorPort
}

func (l CTMonitorLogic) NotificationContextNew() notifications.NotificationContext {
	return notifications.CreateNotificationContext(
		"ct-monitor",
		fmt.Sprintf("ct-monitor workflow results for %s", time.Now().Format(time.RFC822)),
	)
}

func (l CTMonitorLogic) RunConsistencyCheck(_ context.Context) (cmd.Checkpoint, cmd.LogInfo, error) {
	prev, cur, err := v1ct.RunConsistencyCheck(l.ctlogClient, l.flags.LogInfoFile, l.trustedRoot)
	if err != nil {
		return nil, nil, err
	}
	var prevCheckpoint cmd.Checkpoint
	if prev != nil {
		prevCheckpoint = prev
	}
	var curLogInfo cmd.LogInfo
	if cur != nil {
		curLogInfo = cur
	}
	return prevCheckpoint, curLogInfo, nil
}

func (l CTMonitorLogic) WriteCheckpoint(prev cmd.Checkpoint, cur cmd.LogInfo) error {
	prevCheckpoint, ok := prev.(*ctgo.SignedTreeHead)
	if !ok && prev != nil {
		return fmt.Errorf("prev is not a SignedTreeHead")
	}
	curCheckpoint, ok := cur.(*ctgo.SignedTreeHead)
	if !ok {
		return fmt.Errorf("cur is not a SignedTreeHead")
	}
	if err := file.WriteCTSignedTreeHead(curCheckpoint, prevCheckpoint, l.flags.LogInfoFile, false); err != nil {
		return fmt.Errorf("failed to write checkpoint: %v", err)
	}
	return nil
}

func (l CTMonitorLogic) GetStartIndex(prev cmd.Checkpoint, _ cmd.LogInfo) *int64 {
	prevSTH := prev.(*ctgo.SignedTreeHead)
	checkpointStartIndex := int64(prevSTH.TreeSize) - 1 //nolint: gosec // G115, log will never be large enough to overflow
	return &checkpointStartIndex
}

func (l CTMonitorLogic) GetEndIndex(cur cmd.LogInfo) *int64 {
	currentSTH := cur.(*ctgo.SignedTreeHead)
	checkpointEndIndex := int64(currentSTH.TreeSize) //nolint: gosec // G115
	return &checkpointEndIndex
}

func (l CTMonitorLogic) IdentitySearch(ctx context.Context, config *notifications.IdentityMonitorConfiguration, monitoredValues identity.MonitoredValues) ([]identity.MonitoredIdentity, []identity.FailedLogEntry, error) {
	return v1ct.IdentitySearch(ctx, l.ctlogClient, config, monitoredValues)
}

type CTMonitorLogicStaticAPI struct {
	ctlogClient     *v2ct.Client
	flags           *cmd.MonitorFlags
	config          *notifications.IdentityMonitorConfiguration
	monitoredValues identity.MonitoredValues
	trustedRoot     *root.TrustedRoot
}

func (l CTMonitorLogicStaticAPI) Interval() time.Duration {
	return l.flags.Interval
}

func (l CTMonitorLogicStaticAPI) Config() *notifications.IdentityMonitorConfiguration {
	return l.config
}

func (l CTMonitorLogicStaticAPI) MonitoredValues() identity.MonitoredValues {
	return l.monitoredValues
}

func (l CTMonitorLogicStaticAPI) Once() bool {
	return l.flags.Once
}

func (l CTMonitorLogicStaticAPI) MonitorPort() int {
	return l.flags.MonitorPort
}

func (l CTMonitorLogicStaticAPI) NotificationContextNew() notifications.NotificationContext {
	return notifications.CreateNotificationContext(
		"ct-monitor",
		fmt.Sprintf("ct-monitor workflow results for %s", time.Now().Format(time.RFC822)),
	)
}

func (l CTMonitorLogicStaticAPI) RunConsistencyCheck(ctx context.Context) (cmd.Checkpoint, cmd.LogInfo, error) {
	//TODO: deal with shards. For now, assume there is only one shard.
	prev, cur, err := v2ct.RunConsistencyCheck(ctx, l.ctlogClient, l.flags.LogInfoFile)
	if err != nil {
		return nil, nil, err
	}
	var prevCheckpoint cmd.Checkpoint
	if prev != nil {
		prevCheckpoint = prev
	}
	var curLogInfo cmd.LogInfo
	if cur != nil {
		curLogInfo = cur
	}
	return prevCheckpoint, curLogInfo, nil
}

func (l CTMonitorLogicStaticAPI) WriteCheckpoint(prev cmd.Checkpoint, cur cmd.LogInfo) error {
	prevCheckpoint, ok := prev.(*tdlog.Checkpoint)
	if !ok && prev != nil {
		return fmt.Errorf("prev is not a SignedTreeHead")
	}
	curCheckpoint, ok := cur.(*tdlog.Checkpoint)
	if !ok {
		return fmt.Errorf("cur is not a SignedTreeHead")
	}
	if err := file.WriteCheckpointRekorV2(curCheckpoint, prevCheckpoint, l.flags.LogInfoFile, false); err != nil {
		return fmt.Errorf("failed to write checkpoint: %v", err)
	}
	return nil
}

func (l CTMonitorLogicStaticAPI) GetStartIndex(prev cmd.Checkpoint, _ cmd.LogInfo) *int64 {
	prevCP := prev.(*tdlog.Checkpoint)
	if prevCP.Size <= 0 || prevCP.Size > math.MaxInt64 {
		return nil
	}
	checkpointStartIndex := int64(prevCP.Size) - 1 //nolint: gosec // G115, overflow checked above
	return &checkpointStartIndex
}

func (l CTMonitorLogicStaticAPI) GetEndIndex(cur cmd.LogInfo) *int64 {
	currentCP := cur.(*tdlog.Checkpoint)
	if currentCP.Size <= 0 || currentCP.Size > math.MaxInt64 {
		return nil
	}
	checkpointEndIndex := int64(currentCP.Size) - 1 //nolint: gosec // G115
	return &checkpointEndIndex
}

func (l CTMonitorLogicStaticAPI) IdentitySearch(ctx context.Context, config *notifications.IdentityMonitorConfiguration, monitoredValues identity.MonitoredValues) ([]identity.MonitoredIdentity, []identity.FailedLogEntry, error) {
	return v2ct.IdentitySearch(ctx, l.ctlogClient, config, monitoredValues)
}

type kind int

const (
	unknown kind = iota
	rfc6962
	staticCT
)

func getCTKind(httpClient *http.Client, baseURL string) (kind, error) {
	url := baseURL + "/ct/v1/get-sth"
	resp, err := httpClient.Get(url)
	if err != nil {
		return unknown, fmt.Errorf("looking for RFC6962 API: %w", err)
	}
	if resp.StatusCode == 200 {
		return rfc6962, nil
	}
	url = baseURL + "/checkpoint"
	resp, err = httpClient.Get(url)
	if err != nil {
		return unknown, fmt.Errorf("looking for Static CT API: %w", err)
	}
	if resp.StatusCode == 200 {
		return staticCT, nil
	}
	return unknown, nil
}

// This main function performs a periodic identity search.
// Upon starting, any existing latest snapshot data is loaded and the function runs
// indefinitely to perform identity search for every time interval that was specified.
func mainWithReturn() int {
	flags, config, err := cmd.ParseAndLoadConfig(publicCTServerURL, TUFRepository, outputIdentitiesFileName, "ct-monitor")
	if err != nil {
		log.Fatalf("error parsing flags and loading config: %v", err)
	}
	if flags.LogInfoFile == "" {
		logInfoFileName := fmt.Sprintf("%s.txt", logInfoFileName)
		flags.LogInfoFile = logInfoFileName
	}

	tufClient, err := cmd.GetTUFClient(flags)
	if err != nil {
		log.Fatal(err)
	}

	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		log.Fatal(err)
	}

	cleanupTrustedCAs, err := cmd.ConfigureTrustedCAs(config, trustedRoot)
	if err != nil {
		log.Fatal(err)
	}
	defer cleanupTrustedCAs()

	httpClient := http.DefaultClient
	var tlsConfig *tls.Config
	if flags.HTTPSCertChainFile != "" {
		var err error
		tlsConfig, err = util.TLSConfigForCA(flags.HTTPSCertChainFile)
		if err != nil {
			log.Printf("error getting TLS config: %v", err)
			return 1
		}
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}

	ctKind, err := getCTKind(httpClient, flags.ServerURL)
	if err != nil {
		log.Printf("error checking CT API version: %v", err)
		return 1
	}
	switch ctKind {
	case rfc6962:
		return rfc6962MainLoop(flags, httpClient, config, trustedRoot)
	case staticCT:
		// get shards?
		return staticCTMainLoop(flags, tlsConfig, config, trustedRoot)
	default:
		log.Print("Unsupported CT API, only RFC 6962 and Static CT APIs are supported.\n")
		return 1
	}
}

func rfc6962MainLoop(flags *cmd.MonitorFlags, httpClient *http.Client, config *notifications.IdentityMonitorConfiguration, trustedRoot *root.TrustedRoot) int {
	ctlogClient, err := ctclient.New(flags.ServerURL, httpClient, jsonclient.Options{
		UserAgent: flags.UserAgent,
	})
	if err != nil {
		log.Printf("getting CT client: %v", err)
		return 1
	}

	allOIDMatchers, err := config.MonitoredValues.OIDMatchers.RenderOIDMatchers()
	if err != nil {
		fmt.Printf("error parsing OID matchers: %v", err)
	}

	monitoredValues := identity.MonitoredValues{
		CertificateIdentities: config.MonitoredValues.CertificateIdentities,
		OIDMatchers:           allOIDMatchers,
	}

	cmd.PrintMonitoredValues(monitoredValues)

	ctMonitorLogic := CTMonitorLogic{
		ctlogClient:     ctlogClient,
		flags:           flags,
		config:          config,
		monitoredValues: monitoredValues,
		trustedRoot:     trustedRoot,
	}
	cmd.MonitorLoop(ctMonitorLogic)
	return 0
}

func staticCTMainLoop(flags *cmd.MonitorFlags, tlsConfig *tls.Config, config *notifications.IdentityMonitorConfiguration, trustedRoot *root.TrustedRoot) int {
	origin, err := tiles.GetOrigin(flags.Origin, flags.ServerURL)
	if err != nil {
		fmt.Printf("failed to parse origin: %v", err)
		return 1
	}
	ctlogClient, err := v2ct.NewClient(flags.ServerURL, origin, flags.UserAgent, tlsConfig, trustedRoot)
	if err != nil {
		log.Printf("getting CT client: %v", err)
		return 1
	}

	allOIDMatchers, err := config.MonitoredValues.OIDMatchers.RenderOIDMatchers()
	if err != nil {
		fmt.Printf("error parsing OID matchers: %v", err)
	}
	monitoredValues := identity.MonitoredValues{
		CertificateIdentities: config.MonitoredValues.CertificateIdentities,
		OIDMatchers:           allOIDMatchers,
	}

	cmd.PrintMonitoredValues(monitoredValues)

	ctMonitorLogic := CTMonitorLogicStaticAPI{
		ctlogClient:     ctlogClient,
		flags:           flags,
		config:          config,
		monitoredValues: monitoredValues,
		trustedRoot:     trustedRoot,
	}
	cmd.MonitorLoop(ctMonitorLogic)
	return 0
}

func main() {
	os.Exit(mainWithReturn())
}
