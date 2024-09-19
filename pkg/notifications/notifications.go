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

package notifications

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-github/v65/github"
	"github.com/sigstore/rekor-monitor/pkg/identity"
)

var (
	notificationPlatformGitHubIssueBodyHeaderText = "Rekor-monitor found the following pairs of monitored identities and matching log entries: "
	notificationPlatformGitHubIssueLabels         = []string{"rekor-monitor", "automatically generated"}
)

// NotificationPlatform provides the Send() method to handle alerting logic
// for the respective notification platform extending the interface.
type NotificationPlatform interface {
	Send([]identity.MonitoredIdentity) error
}

// GitHubIssueInput extends the NotificationPlatform interface to support found identity
// notification via creating new GitHub issues in a given repo.
type GitHubIssueInput struct {
	GitHubAssigneeUsername string
	GitHubOwnerUsername    string
	GitHubRepositoryName   string
	// The PAT or other access token to authenticate creating an issue.
	// The authentication token requires repo write and push access.
	AuthenticationToken string
	// For users who want to pass in a custom client.
	// If nil, a default client with the given authentication token will be instantiated.
	GitHubClient *github.Client
}

func generateGitHubIssueBody(monitoredIdentities []identity.MonitoredIdentity) (string, error) {
	header := notificationPlatformGitHubIssueBodyHeaderText
	body, err := identity.ParseMonitoredIdentitiesAsJSON(monitoredIdentities)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{header, "```\n" + string(body) + "\n```"}, "\n"), nil
}

func (gitHubIssueInput GitHubIssueInput) Send(monitoredIdentities []identity.MonitoredIdentity) error {
	issueTitle := fmt.Sprintf("rekor-monitor workflow results for %s", time.Now().Format(time.RFC822))
	issueBody, err := generateGitHubIssueBody(monitoredIdentities)
	if err != nil {
		return err
	}
	var client *github.Client
	if gitHubIssueInput.GitHubClient == nil {
		client = github.NewClient(nil).WithAuthToken(gitHubIssueInput.AuthenticationToken)
	} else {
		client = gitHubIssueInput.GitHubClient
	}
	ctx := context.Background()
	labels := notificationPlatformGitHubIssueLabels

	issueRequest := &github.IssueRequest{
		Title:    &issueTitle,
		Body:     &issueBody,
		Labels:   &labels,
		Assignee: &gitHubIssueInput.GitHubAssigneeUsername,
	}
	_, _, err = client.Issues.Create(ctx, gitHubIssueInput.GitHubOwnerUsername, gitHubIssueInput.GitHubRepositoryName, issueRequest)
	return err
}
