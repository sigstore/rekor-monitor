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
	"time"

	"github.com/sigstore/rekor-monitor/pkg/identity"
)

var (
	NotificationSubject = fmt.Sprintf("rekor-monitor workflow results for %s", time.Now().Format(time.RFC822))
)

// NotificationPlatform provides the Send() method to handle alerting logic
// for the respective notification platform extending the interface.
type NotificationPlatform interface {
	Send(context.Context, []identity.MonitoredIdentity) error
}
