//
// Copyright 2026 The Sigstore Authors.
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
	"fmt"
	"html/template"
	"log"
	"strings"
)

// RenderMatchEmail renders the Subject header and HTML body for a
// match-notification digest. Untrusted Rekor content is auto-escaped by
// html/template, so it cannot inject markup or scripts into the recipient's
// mail client. The caller delivers the result through its email transport.
func RenderMatchEmail(payload NotificationPayload) (subject, body string) {
	return emailSubject(payload.Data.Entries), buildMatchEmailBody(payload)
}

// emailSubject summarizes the batch for the mail Subject header.
func emailSubject(matches []NotificationMatch) string {
	if len(matches) == 1 {
		return fmt.Sprintf("Rekor Watch: identity match detected (log index %d)", matches[0].LogIndex)
	}
	return fmt.Sprintf("Rekor Watch: %d identity matches detected", len(matches))
}

// matchEmailTmpl renders the HTML body for a match-notification digest.
// All field values are auto-escaped by html/template, so untrusted Rekor
// content cannot inject markup or scripts into the recipient's mail client.
var matchEmailTmpl = template.Must(template.New("match_email").Parse(
	`<h2>Rekor Watch: Identity Match Detected</h2>
<p>New entries matching your subscription were found in the Rekor transparency log.</p>
<p><strong>Subscription:</strong> {{.SubscriptionName}}</p>
{{- if .MonitoredValue}}
<p><strong>Monitored value:</strong> {{.MonitoredValue}}</p>
{{- end}}
{{- range .Matches}}
<table style="border-collapse:collapse;margin-bottom:16px;">
{{- if .Origin}}
<tr><td style="padding:4px 8px;"><strong>Origin</strong></td><td style="padding:4px 8px;">{{.Origin}}</td></tr>
{{- end}}
<tr><td style="padding:4px 8px;"><strong>Log Index</strong></td><td style="padding:4px 8px;">{{.LogIndex}}</td></tr>
{{- if .UUID}}
<tr><td style="padding:4px 8px;"><strong>UUID</strong></td><td style="padding:4px 8px;">{{.UUID}}</td></tr>
{{- end}}
{{- if .CertSubject}}
<tr><td style="padding:4px 8px;"><strong>Cert Subject</strong></td><td style="padding:4px 8px;">{{.CertSubject}}</td></tr>
{{- end}}
{{- if .Issuer}}
<tr><td style="padding:4px 8px;"><strong>Issuer</strong></td><td style="padding:4px 8px;">{{.Issuer}}</td></tr>
{{- end}}
{{- if .Fingerprint}}
<tr><td style="padding:4px 8px;"><strong>Fingerprint</strong></td><td style="padding:4px 8px;">{{.Fingerprint}}</td></tr>
{{- end}}
{{- if .Subject}}
<tr><td style="padding:4px 8px;"><strong>Subject</strong></td><td style="padding:4px 8px;">{{.Subject}}</td></tr>
{{- end}}
{{- if .OIDExtension}}
<tr><td style="padding:4px 8px;"><strong>OID Extension</strong></td><td style="padding:4px 8px;">{{.OIDExtension}}</td></tr>
{{- end}}
{{- if .ExtensionValue}}
<tr><td style="padding:4px 8px;"><strong>Extension Value</strong></td><td style="padding:4px 8px;">{{.ExtensionValue}}</td></tr>
{{- end}}
</table>
{{- end}}`))

func buildMatchEmailBody(payload NotificationPayload) string {
	var b strings.Builder
	data := struct {
		SubscriptionName string
		MonitoredValue   string
		Matches          []NotificationMatch
	}{payload.Data.SubscriptionName, string(payload.Data.MonitoredValue), payload.Data.Entries}
	if err := matchEmailTmpl.Execute(&b, data); err != nil {
		// Fixed template + payload data — Execute should not fail; if it
		// does, send a minimal body rather than nothing.
		log.Printf("Failed to render match email body: %v", err)
		return "Rekor Watch: identity match detected (see web UI for details)."
	}
	return b.String()
}
