#!/usr/bin/env bash
#
# Copyright 2022 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

# Gets the name of the currently running workflow file.
# Note: this requires GITHUB_TOKEN to be set in the workflows.
this_file() {
    gh api -H "Accept: application/vnd.github.v3+json" "/repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID" | jq -r '.path' | cut -d '/' -f3
}

# File is BODY in current directory.
create_issue_body() {
    RUN_DATE=$(date --utc)

    # see https://docs.github.com/en/actions/learn-github-actions/environment-variables
    # https://docs.github.com/en/actions/learn-github-actions/contexts.
    cat <<EOF >BODY
Repo: https://github.com/$GITHUB_REPOSITORY/tree/$GITHUB_REF_NAME
Run: https://github.com/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID
Workflow file: https://github.com/$GITHUB_REPOSITORY/tree/main/.github/workflows/$THIS_FILE
Workflow runs: https://github.com/$GITHUB_REPOSITORY/actions/workflows/$THIS_FILE
Trigger: $GITHUB_EVENT_NAME
Branch: $GITHUB_REF_NAME
Date: $RUN_DATE
EOF
}

create_issue_success_body() {
    create_issue_body

    echo "" >>./BODY
    echo "**Tests are passing now. Closing this issue.**" >>./BODY
}

THIS_FILE=$(this_file)
create_issue_success_body

ISSUE_ID=$(gh -R "$ISSUE_REPOSITORY" issue list --label "bug" --state open -S "$THIS_FILE" --json number | jq '.[0]' | jq -r '.number' | jq 'select (.!=null)')

if [[ -n "$ISSUE_ID" ]]; then
    echo gh -R "$ISSUE_REPOSITORY" issue close "$ISSUE_ID" -c "$(cat ./BODY)"
    GH_TOKEN=$GITHUB_TOKEN gh -R "$ISSUE_REPOSITORY" issue close "$ISSUE_ID" -c "$(cat ./BODY)"
fi
