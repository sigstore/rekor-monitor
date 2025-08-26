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

package notifications

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v65/github"
)

var (
	notificationPlatformGitHubIssueBodyHeaderText = "%s found the following pairs of monitored identities and matching log entries: "
)

// GitHubIssueInput extends the NotificationPlatform interface to support found identity
// notification via creating new GitHub issues in a given repo.
type GitHubIssueInput struct {
	AssigneeUsername string `yaml:"assigneeUsername"`
	RepositoryOwner  string `yaml:"repositoryOwner"`
	RepositoryName   string `yaml:"repositoryName"`
	// The PAT or other access token to authenticate creating an issue.
	// The authentication token requires repo write and push access.
	AuthenticationToken string `yaml:"authenticationToken"`
	// For users who want to pass in a custom client.
	// If nil, a default client with the given authentication token will be instantiated.
	GitHubClient *github.Client `yaml:"githubClient"`
}

// generateGitHubIssueBody generates a GitHub issue body for generic notification data
func generateGitHubIssueBody(data NotificationData) (string, error) {
	// Use custom header if available in metadata, otherwise use default
	header := fmt.Sprintf(notificationPlatformGitHubIssueBodyHeaderText, data.Context.MonitorType)

	// Try to use the payload as a NotificationBodyConverter
	body, err := data.Payload.ToNotificationBody()
	if err != nil {
		return "", err
	}
	return strings.Join([]string{header, "```\n" + string(body) + "\n```"}, "\n"), nil
}

// Send implements the NotificationPlatform interface
func (gitHubIssueInput GitHubIssueInput) Send(ctx context.Context, data NotificationData) error {
	issueTitle := data.Context.Subject
	issueBody, err := generateGitHubIssueBody(data)
	if err != nil {
		return err
	}

	var client *github.Client
	if gitHubIssueInput.GitHubClient == nil {
		client = github.NewClient(nil).WithAuthToken(gitHubIssueInput.AuthenticationToken)
	} else {
		client = gitHubIssueInput.GitHubClient
	}
	labels := []string{data.Context.MonitorType, "automatically generated"}

	issueRequest := &github.IssueRequest{
		Title:    &issueTitle,
		Body:     &issueBody,
		Labels:   &labels,
		Assignee: &gitHubIssueInput.AssigneeUsername,
	}
	_, _, err = client.Issues.Create(ctx, gitHubIssueInput.RepositoryOwner, gitHubIssueInput.RepositoryName, issueRequest)
	return err
}
