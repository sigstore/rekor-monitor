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
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v90/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/sigstore/rekor-monitor/pkg/identity"
)

func TestGitHubIssueInputSend401BadCredentialsFailure(t *testing.T) {
	gitHubIssuesInput := GitHubIssueInput{
		AssigneeUsername:    "test-assignee",
		RepositoryOwner:     "test-owner",
		RepositoryName:      "test-repo",
		AuthenticationToken: "",
	}
	ctx := context.Background()
	notificationData := NotificationData{
		Context: CreateNotificationContext("test-monitor", "test-subject"),
		Payload: identity.MonitoredIdentityList{},
	}
	err := gitHubIssuesInput.Send(ctx, notificationData)
	if err == nil {
		t.Errorf("expected 401 Bad Credentials, received error %v", err)
	}
}

func TestGitHubIssueInputMockSendSuccess(t *testing.T) {
	testIssueTitle := "test-issue"
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.PostReposIssuesByOwnerByRepo,
			&github.Issue{
				ID:     github.Ptr(int64(1)),
				Number: github.Ptr(1),
				Title:  &testIssueTitle,
			},
			&github.Response{
				Response: &http.Response{
					StatusCode: http.StatusAccepted,
				},
			},
			nil,
		),
	)
	mockGitHubClient, err := github.NewClient(github.WithHTTPClient(mockedHTTPClient))
	if err != nil {
		t.Fatalf("failed to create github client: %v", err)
	}
	gitHubIssuesInput := GitHubIssueInput{
		AssigneeUsername:    "test-assignee",
		RepositoryOwner:     "test-owner",
		RepositoryName:      "test-repo",
		AuthenticationToken: "",
		GitHubClient:        mockGitHubClient,
	}
	ctx := context.Background()
	notificationData := NotificationData{
		Context: CreateNotificationContext("test-monitor", "test-subject"),
		Payload: identity.MonitoredIdentityList{},
	}
	err = gitHubIssuesInput.Send(ctx, notificationData)
	if err != nil {
		t.Errorf("expected nil, received error %v", err)
	}
}

func TestGitHubIssueInputMockSendFailure(t *testing.T) {
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatchHandler(
			mock.PostReposIssuesByOwnerByRepo,
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				mock.WriteError(
					w,
					http.StatusInternalServerError,
					"400 Bad Request",
				)
			}),
		),
	)
	mockGitHubClient, err := github.NewClient(github.WithHTTPClient(mockedHTTPClient))
	if err != nil {
		t.Fatalf("failed to create github client: %v", err)
	}
	gitHubIssuesInput := GitHubIssueInput{
		AssigneeUsername:    "test-assignee",
		RepositoryOwner:     "test-owner",
		RepositoryName:      "test-repo",
		AuthenticationToken: "",
		GitHubClient:        mockGitHubClient,
	}
	ctx := context.Background()
	notificationData := NotificationData{
		Context: CreateNotificationContext("test-monitor", "test-subject"),
		Payload: identity.MonitoredIdentityList{},
	}
	err = gitHubIssuesInput.Send(ctx, notificationData)
	if err == nil || !strings.Contains(err.Error(), "400 Bad Request") {
		t.Errorf("expected 400 Bad Request, received %v", err)
	}
}
