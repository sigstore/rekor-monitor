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

// This file details the named fields of OID extensions supported by Fulcio.
// A list of OID extensions supported by Fulcio can be found here:
// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
// Named fields in this file have been imported from this file in the Fulcio repository:
// https://github.com/sigstore/fulcio/blob/main/pkg/certificate/extensions.go
// Updates to the Fulcio repository extensions file should be matched here accordingly and vice-versa.

package extensions

import (
	"encoding/asn1"
	"slices"

	"github.com/sigstore/rekor-monitor/pkg/identity"
)

var fulcioOIDPrefix = []int{1, 3, 6, 1, 4, 1, 57264}

// createFulcioOID creates an extension with the Fulcio OID prefix (1.3.6.1.4.1.57264) and an extension input.
func createFulcioOID(ext []int) asn1.ObjectIdentifier {
	extension := slices.Concat(fulcioOIDPrefix, ext)
	return asn1.ObjectIdentifier(extension)
}

var (
	OIDIssuer                   asn1.ObjectIdentifier
	OIDGitHubWorkflowTrigger    asn1.ObjectIdentifier
	OIDGitHubWorkflowSHA        asn1.ObjectIdentifier
	OIDGitHubWorkflowName       asn1.ObjectIdentifier
	OIDGitHubWorkflowRepository asn1.ObjectIdentifier
	OIDGitHubWorkflowRef        asn1.ObjectIdentifier

	OIDOtherName asn1.ObjectIdentifier
	OIDIssuerV2  asn1.ObjectIdentifier

	// CI extensions
	OIDBuildSignerURI                      asn1.ObjectIdentifier
	OIDBuildSignerDigest                   asn1.ObjectIdentifier
	OIDRunnerEnvironment                   asn1.ObjectIdentifier
	OIDSourceRepositoryURI                 asn1.ObjectIdentifier
	OIDSourceRepositoryDigest              asn1.ObjectIdentifier
	OIDSourceRepositoryRef                 asn1.ObjectIdentifier
	OIDSourceRepositoryIdentifier          asn1.ObjectIdentifier
	OIDSourceRepositoryOwnerURI            asn1.ObjectIdentifier
	OIDSourceRepositoryOwnerIdentifier     asn1.ObjectIdentifier
	OIDBuildConfigURI                      asn1.ObjectIdentifier
	OIDBuildConfigDigest                   asn1.ObjectIdentifier
	OIDBuildTrigger                        asn1.ObjectIdentifier
	OIDRunInvocationURI                    asn1.ObjectIdentifier
	OIDSourceRepositoryVisibilityAtSigning asn1.ObjectIdentifier
)

func init() {
	// Deprecated: Use OIDIssuerV2
	OIDIssuer = createFulcioOID([]int{1, 1})
	// Deprecated: Use OIDBuildTrigger
	OIDGitHubWorkflowTrigger = createFulcioOID([]int{1, 2})
	// Deprecated: Use OIDSourceRepositoryDigest
	OIDGitHubWorkflowSHA = createFulcioOID([]int{1, 3})
	// Deprecated: Use OIDBuildConfigURI or OIDBuildConfigDigest
	OIDGitHubWorkflowName = createFulcioOID([]int{1, 4})
	// Deprecated: Use SourceRepositoryURI
	OIDGitHubWorkflowRepository = createFulcioOID([]int{1, 5})
	// Deprecated: Use OIDSourceRepositoryRef
	OIDGitHubWorkflowRef = createFulcioOID([]int{1, 6})
	OIDOtherName = createFulcioOID([]int{1, 7})
	OIDIssuerV2 = createFulcioOID([]int{1, 8})
	OIDBuildSignerURI = createFulcioOID([]int{1, 9})
	OIDBuildSignerDigest = createFulcioOID([]int{1, 10})
	OIDRunnerEnvironment = createFulcioOID([]int{1, 11})
	OIDSourceRepositoryURI = createFulcioOID([]int{1, 12})
	OIDSourceRepositoryDigest = createFulcioOID([]int{1, 13})
	OIDSourceRepositoryRef = createFulcioOID([]int{1, 14})
	OIDSourceRepositoryIdentifier = createFulcioOID([]int{1, 15})
	OIDSourceRepositoryOwnerURI = createFulcioOID([]int{1, 16})
	OIDSourceRepositoryOwnerIdentifier = createFulcioOID([]int{1, 17})
	OIDBuildConfigURI = createFulcioOID([]int{1, 18})
	OIDBuildConfigDigest = createFulcioOID([]int{1, 19})
	OIDBuildTrigger = createFulcioOID([]int{1, 20})
	OIDRunInvocationURI = createFulcioOID([]int{1, 21})
	OIDSourceRepositoryVisibilityAtSigning = createFulcioOID([]int{1, 22})
}

// FulcioExtensions contains all custom X.509 extensions defined by Fulcio.
type FulcioExtensions struct {
	// The OIDC issuer. Should match `iss` claim of ID token or, in the case of
	// a federated login like Dex it should match the issuer URL of the
	// upstream issuer. The issuer is not set the extensions are invalid and
	// will fail to render.
	Issuer []string // OID 1.3.6.1.4.1.57264.1.8 and 1.3.6.1.4.1.57264.1.1 (Deprecated)

	// Deprecated
	// Triggering event of the Github Workflow. Matches the `event_name` claim of ID
	// tokens from Github Actions
	GithubWorkflowTrigger []string `json:"GithubWorkflowTrigger,omitempty" yaml:"github-workflow-trigger,omitempty"` // OID 1.3.6.1.4.1.57264.1.2

	// Deprecated
	// SHA of git commit being built in Github Actions. Matches the `sha` claim of ID
	// tokens from Github Actions
	GithubWorkflowSHA []string `json:"GithubWorkflowSHA,omitempty" yaml:"github-workflow-sha,omitempty"` // OID 1.3.6.1.4.1.57264.1.3

	// Deprecated
	// Name of Github Actions Workflow. Matches the `workflow` claim of the ID
	// tokens from Github Actions
	GithubWorkflowName []string `json:"GithubWorkflowName,omitempty" yaml:"github-workflow-name,omitempty"` // OID 1.3.6.1.4.1.57264.1.4

	// Deprecated
	// Repository of the Github Actions Workflow. Matches the `repository` claim of the ID
	// tokens from Github Actions
	GithubWorkflowRepository []string `json:"GithubWorkflowRepository,omitempty" yaml:"github-workflow-repository,omitempty"` // OID 1.3.6.1.4.1.57264.1.5

	// Deprecated
	// Git Ref of the Github Actions Workflow. Matches the `ref` claim of the ID tokens
	// from Github Actions
	GithubWorkflowRef []string `json:"GithubWorkflowRef,omitempty" yaml:"github-workflow-ref,omitempty"` // 1.3.6.1.4.1.57264.1.6

	// Reference to specific build instructions that are responsible for signing.
	BuildSignerURI []string `json:"BuildSignerURI,omitempty" yaml:"build-signer-uri,omitempty"` // 1.3.6.1.4.1.57264.1.9

	// Immutable reference to the specific version of the build instructions that is responsible for signing.
	BuildSignerDigest []string `json:"BuildSignerDigest,omitempty" yaml:"build-signer-digest,omitempty"` // 1.3.6.1.4.1.57264.1.10

	// Specifies whether the build took place in platform-hosted cloud infrastructure or customer/self-hosted infrastructure.
	RunnerEnvironment []string `json:"RunnerEnvironment,omitempty" yaml:"runner-environment,omitempty"` // 1.3.6.1.4.1.57264.1.11

	// Source repository URL that the build was based on.
	SourceRepositoryURI []string `json:"SourceRepositoryURI,omitempty" yaml:"source-repository-uri,omitempty"` // 1.3.6.1.4.1.57264.1.12

	// Immutable reference to a specific version of the source code that the build was based upon.
	SourceRepositoryDigest []string `json:"SourceRepositoryDigest,omitempty" yaml:"source-repository-digest,omitempty"` // 1.3.6.1.4.1.57264.1.13

	// Source Repository Ref that the build run was based upon.
	SourceRepositoryRef []string `json:"SourceRepositoryRef,omitempty" yaml:"source-repository-ref,omitempty"` // 1.3.6.1.4.1.57264.1.14

	// Immutable identifier for the source repository the workflow was based upon.
	SourceRepositoryIdentifier []string `json:"SourceRepositoryIdentifier,omitempty" yaml:"source-repository-identifier,omitempty"` // 1.3.6.1.4.1.57264.1.15

	// Source repository owner URL of the owner of the source repository that the build was based on.
	SourceRepositoryOwnerURI []string `json:"SourceRepositoryOwnerURI,omitempty" yaml:"source-repository-owner-uri,omitempty"` // 1.3.6.1.4.1.57264.1.16

	// Immutable identifier for the owner of the source repository that the workflow was based upon.
	SourceRepositoryOwnerIdentifier []string `json:"SourceRepositoryOwnerIdentifier,omitempty" yaml:"source-repository-owner-identifier,omitempty"` // 1.3.6.1.4.1.57264.1.17

	// Build Config URL to the top-level/initiating build instructions.
	BuildConfigURI []string `json:"BuildConfigURI,omitempty" yaml:"build-config-uri,omitempty"` // 1.3.6.1.4.1.57264.1.18

	// Immutable reference to the specific version of the top-level/initiating build instructions.
	BuildConfigDigest []string `json:"BuildConfigDigest,omitempty" yaml:"build-config-digest,omitempty"` // 1.3.6.1.4.1.57264.1.19

	// Event or action that initiated the build.
	BuildTrigger []string `json:"BuildTrigger,omitempty" yaml:"build-trigger,omitempty"` // 1.3.6.1.4.1.57264.1.20

	// Run Invocation URL to uniquely identify the build execution.
	RunInvocationURI []string `json:"RunInvocationURI,omitempty" yaml:"run-invocation-uri,omitempty"` // 1.3.6.1.4.1.57264.1.21

	// Source repository visibility at the time of signing the certificate.
	SourceRepositoryVisibilityAtSigning []string `json:"SourceRepositoryVisibilityAtSigning,omitempty" yaml:"source-repository-visibility-at-signing,omitempty"` // 1.3.6.1.4.1.57264.1.22
}

func (e FulcioExtensions) RenderFulcioOIDMatchers() ([]identity.OIDMatcher, error) {
	var exts []identity.OIDMatcher

	// BEGIN: Deprecated
	if len(e.Issuer) != 0 {
		// deprecated issuer extension due to incorrect encoding
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDIssuer,
			ExtensionValues:  e.Issuer,
		})
	}

	if len(e.GithubWorkflowTrigger) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDGitHubWorkflowTrigger,
			ExtensionValues:  e.GithubWorkflowTrigger,
		})
	}
	if len(e.GithubWorkflowSHA) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDGitHubWorkflowSHA,
			ExtensionValues:  e.GithubWorkflowSHA,
		})
	}
	if len(e.GithubWorkflowName) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDGitHubWorkflowName,
			ExtensionValues:  e.GithubWorkflowName,
		})
	}
	if len(e.GithubWorkflowRepository) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDGitHubWorkflowRepository,
			ExtensionValues:  e.GithubWorkflowRepository,
		})
	}
	if len(e.GithubWorkflowRef) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDGitHubWorkflowRef,
			ExtensionValues:  e.GithubWorkflowRef,
		})
	}
	// END: Deprecated

	// duplicate issuer with correct RFC 5280 encoding
	if len(e.Issuer) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDIssuerV2,
			ExtensionValues:  e.Issuer,
		})
	}

	if len(e.BuildSignerURI) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDBuildSignerURI,
			ExtensionValues:  e.BuildSignerURI,
		})
	}
	if len(e.BuildSignerDigest) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDBuildSignerDigest,
			ExtensionValues:  e.BuildSignerDigest,
		})
	}
	if len(e.RunnerEnvironment) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDRunnerEnvironment,
			ExtensionValues:  e.RunnerEnvironment,
		})
	}
	if len(e.SourceRepositoryURI) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDSourceRepositoryURI,
			ExtensionValues:  e.SourceRepositoryURI,
		})
	}
	if len(e.SourceRepositoryDigest) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDSourceRepositoryDigest,
			ExtensionValues:  e.SourceRepositoryDigest,
		})
	}
	if len(e.SourceRepositoryRef) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDSourceRepositoryRef,
			ExtensionValues:  e.SourceRepositoryRef,
		})
	}
	if len(e.SourceRepositoryIdentifier) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDSourceRepositoryIdentifier,
			ExtensionValues:  e.SourceRepositoryIdentifier,
		})
	}
	if len(e.SourceRepositoryOwnerURI) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDSourceRepositoryOwnerURI,
			ExtensionValues:  e.SourceRepositoryOwnerURI,
		})
	}
	if len(e.SourceRepositoryOwnerIdentifier) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDSourceRepositoryOwnerIdentifier,
			ExtensionValues:  e.SourceRepositoryOwnerIdentifier,
		})
	}
	if len(e.BuildConfigURI) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDBuildConfigURI,
			ExtensionValues:  e.BuildConfigURI,
		})
	}
	if len(e.BuildConfigDigest) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDBuildConfigDigest,
			ExtensionValues:  e.BuildConfigDigest,
		})
	}
	if len(e.BuildTrigger) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDBuildTrigger,
			ExtensionValues:  e.BuildTrigger,
		})
	}
	if len(e.RunInvocationURI) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDRunInvocationURI,
			ExtensionValues:  e.RunInvocationURI,
		})
	}
	if len(e.SourceRepositoryVisibilityAtSigning) != 0 {
		exts = append(exts, identity.OIDMatcher{
			ObjectIdentifier: OIDSourceRepositoryVisibilityAtSigning,
			ExtensionValues:  e.SourceRepositoryVisibilityAtSigning,
		})
	}

	return exts, nil
}
