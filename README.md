# Rekor Log Monitor

Rekor Log Monitor provides an easy-to-use monitor to verify log consistency,
that the log is immutable and append-only. Monitoring is critical to
the transparency log ecosystem, as logs are tamper-evident but not tamper-proof.
Rekor Log Monitor also provides a monitor to search for identities within a log,
and send a list of found identities via various notification platforms.

## Building and Running

### Building the monitors

To build both monitors, use the provided Makefile:

```bash
make build
```

This will create `rekor_monitor` and `ct_monitor` binaries in the current directory.

### Configuration file format

The configuration file uses YAML format and supports monitoring specific identities and certificate attributes. Here's the structure:

```yaml
# Optional: Specify start and end log indices for searching
startIndex: 1000
endIndex: 2000

# Values to monitor for
monitoredValues:
  # Certificate identities to monitor (subject and optional issuers)
  certIdentities:
    # certSubject is a regular expression
    - certSubject: user@domain\.com
    - certSubject: otheruser@domain\.com
      issuers:
        # issuers are regular expressions
        - https://accounts\.google\.com
        - https://github\.com/login
    - certSubject: https://github\.com/actions/starter-workflows/blob/main/\.github/workflows/lint\.yaml@.*
      issuers:
        - https://token\.actions\.githubusercontent\.com

  # Non-certificate subjects (for SSH, PGP keys, etc.)
  # subjects are regular expressions
  subjects:
    - subject@domain\.com

  # Key/certificate fingerprints to monitor
  fingerprints:
    - A0B1C2D3E4F5

  # OID extension matchers (see OID Extension Matchers section below for details)
  oidMatchers:
    # Fulcio extensions using human-readable field names
    fulcioExtensions:
      build-config-uri:
        - https://example.com/owner/repository/build-config.yml

    # OID extensions using integer array format
    oidExtensions:
      - objectIdentifier: [1, 3, 6, 1, 4, 1, 57264, 1, 1]
        extensionValues:
          - https://github.com/login/oauth

    # Custom OID extensions using dot notation (more human-readable)
    customExtensions:
      - objectIdentifier: 1.3.6.1.4.1.57264.1.9
        extensionValues:
          - https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.4.0

# Optional: Output file for found identities
outputIdentities: identities.txt
# Optional: Output format for found identities (`text` or `json`)
outputIdentitiesFormat: text

# Optional: Output file for last checkpoint
logInfoFile: logInfo.txt

# Optional: Identity metadata output file
identityMetadataFile: metadata.json
```

### Example Usage

Monitor specific certificate subjects:
```bash
./rekor_monitor --config-file config.yaml --once=false --interval=1h
```

Monitor with inline YAML configuration:
```bash
./rekor_monitor --config 'monitoredValues:
  certIdentities:
    - certSubject: user@example\.com'
```

Run ct-monitor against a specific CT log:
```bash
./ct_monitor --url https://ctfe.sigstore.dev/2022 --config-file ct-config.yaml
```

## GitHub workflow setup
We provide reusable GitHub workflows for monitoring the Rekor and the
Certificate Transparency logs.

### Consistency check

To run, create a GitHub Actions workflow that uses the
[reusable monitoring workflow](https://github.com/sigstore/rekor-monitor/blob/main/.github/workflows/reusable_monitoring.yml).
It is recommended to run the log monitor every hour for optimal performance.

Example workflow:

```yaml
name: Rekor log monitor
on:
  schedule:
    - cron: '0 * * * *' # every hour

permissions: read-all

jobs:
  run_consistency_proof:
    permissions:
      contents: read # Needed to checkout repositories
      issues: write # Needed if you set "file_issue: true"
    uses: sigstore/rekor-monitor/.github/workflows/reusable_monitoring.yml@main
    with:
      file_issue: true # Strongly recommended: Files an issue on monitoring failure
      artifact_retention_days: 14 # Optional, default is 14: Must be longer than the cron job frequency
```

Caveats:

* The log monitoring job should not be run concurrently with other log monitoring jobs in the same repository
* If running as a cron job, `artifact_retention_days` must be longer than the cron job frequency

### Identity monitoring

You can also specify a list of identities to monitor. Currently, only identities from the certificate's
Subject Alternative Name (SAN) field will be matched, and only for the hashedrekord Rekor entry type.

Note: `certIdentities.certSubject`, `certIdentities.issuers` and `subjects` are expecting regular expression.
Please read [this](https://github.com/google/re2/wiki/Syntax) for syntax reference.

Note: The log monitor only starts monitoring from the latest checkpoint. If you want to search previous
entries, you will need to query the log.

To run, create a GitHub Actions workflow that uses the
[reusable monitoring workflow](https://github.com/sigstore/rekor-monitor/blob/main/.github/workflows/reusable_monitoring.yml).
and passes the identities to monitor as part of the `config` input.
It is recommended to run the log monitor every hour for optimal performance.

Example workflow below:

```yaml
name: Rekor log and identity monitor
on:
  schedule:
    - cron: '0 * * * *' # every hour

permissions: read-all

jobs:
  run_consistency_proof:
    permissions:
      contents: read # Needed to checkout repositories
      issues: write # Needed if you set "file_issue: true"
    uses: sigstore/rekor-monitor/.github/workflows/reusable_monitoring.yml@main
    with:
      file_issue: true # Strongly recommended: Files an issue on monitoring failure
      artifact_retention_days: 14 # Optional, default is 14: Must be longer than the cron job frequency
      config: |
        monitoredValues:
          certIdentities:
            - certSubject: user@domain\.com
            - certSubject: otheruser@domain\.com
              issuers:
                - https://accounts\.google\.com
                - https://github\.com/login
            - certSubject: https://github\.com/actions/starter-workflows/blob/main/\.github/workflows/lint\.yaml@.*
              issuers:
                - https://token\.actions\.githubusercontent\.com
          subjects:
            - subject@domain\.com
          fingerprints:
            - A0B1C2D3E4F5
          oidMatchers:
            fulcioExtensions:
              build-config-uri:
                - https://example.com/owner/repository/build-config.yml
            oidExtensions:
              - objectIdentifier: [1, 3, 6, 1, 4, 1, 57264, 1, 1]
                extensionValues:
                  - https://github.com/login/oauth
            customExtensions:
              - objectIdentifier: 1.3.6.1.4.1.57264.1.9
                extensionValues:
                  - https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.4.0
```

In this example, the monitor will log:

* Entries that contain a certificate whose SAN is `user@domain.com`
* Entries whose SAN is `otheruser@domain.com` and the OIDC provider specified in a [custom extension](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726418--issuer-v2) matches one of the specified issuers (Google or GitHub in this example)
* Entries whose SAN start by `https://github.com/actions/starter-workflows/blob/main/.github/workflows/lint.yaml@` and the OIDC provider matches `https://token.actions.githubusercontent.com`
* Non-certificate entries, such as PGP or SSH keys, whose subject matches `subject@domain.com`
* Entries whose key or certificate fingerprint matches `A0B1C2D3E4F5`
* Entries that contain a certificate with a Build Config URI Extension matching `https://example.com/owner/repository/build-config.yml`
* Entries that contain a certificate with the deprecated Fulcio Issuer OID (`1.3.6.1.4.1.57264.1.1`) matching `https://github.com/login/oauth`
* Entries that contain a certificate with OID extension `1.3.6.1.4.1.57264.1.9` (Fulcio OID for Build Signer URI) and an extension value matching `https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.4.0`

Fingerprint values are as follows:

* For keys, certificates, and minisign, hex-encoded SHA-256 digest of the DER-encoded PKIX public key or certificate
* For SSH and PGP, the standard for each ecosystem:
   * For SSH, unpadded base-64 encoded SHA-256 digest of the key
	 * For PGP, hex-encoded SHA-1 digest of a key, which can be either a primary key or subkey

### OID Extension Matchers

The monitor supports matching certificates based on X.509 OID extensions. This is useful for monitoring
certificates issued by Fulcio that contain specific CI/CD workflow information. OID matchers can be
specified in two ways: using named Fulcio extensions or custom OID extensions.

Note: Extension values are matched exactly (not as regular expressions).

#### Fulcio Extensions

Fulcio extensions provide a convenient way to match well-known Fulcio OID extensions using human-readable
YAML field names. The full list of Fulcio OID extensions is documented at
[sigstore/fulcio OID Info](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md).

Example configuration:

```yaml
monitoredValues:
  oidMatchers:
    fulcioExtensions:
      # Match certificates signed by a specific GitHub Actions workflow
      build-signer-uri:
        - https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v1.4.0
      # Match certificates from a specific source repository
      source-repository-uri:
        - https://github.com/sigstore/cosign
      # Match certificates with specific runner environment
      runner-environment:
        - github-hosted
```


#### OID Extensions (Array Format)

For programmatic use cases or when you prefer specifying OIDs as integer arrays,
use the `oidExtensions` format:

```yaml
monitoredValues:
  oidMatchers:
    oidExtensions:
      # OID specified as an array of integers
      - objectIdentifier: [1, 3, 6, 1, 4, 1, 57264, 1, 1]
        extensionValues:
          - https://github.com/login/oauth
      - objectIdentifier: [1, 3, 6, 1, 4, 1, 57264, 1, 8]
        extensionValues:
          - https://accounts.google.com
```

Note: The `objectIdentifier` is specified as a YAML array of integers representing the OID components.
For example, `[1, 3, 6, 1, 4, 1, 57264, 1, 8]` is equivalent to `1.3.6.1.4.1.57264.1.8` in dot notation.

#### Custom OID Extensions (Dot Notation)

For OID extensions not covered by the Fulcio named fields, or for non-Fulcio OID extensions,
use the `customExtensions` format with the OID specified in dot notation (more human-readable):

```yaml
monitoredValues:
  oidMatchers:
    customExtensions:
      # Match the Fulcio Issuer extension (OID 1.3.6.1.4.1.57264.1.1)
      - objectIdentifier: 1.3.6.1.4.1.57264.1.1
        extensionValues:
          - https://github.com/login/oauth
          - https://accounts.google.com
      # Match a custom OID extension
      - objectIdentifier: 1.3.6.1.4.1.57264.1.9
        extensionValues:
          - https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.4.0
```

Note: Each custom extension entry requires both `objectIdentifier` (in dot notation) and `extensionValues` (a list of values to match).

Upcoming features:

* Creating issues when identities are found
* Support for other identities
   * CI identity values in Fulcio certificates

### Certificate transparency log monitoring

Certificate transparency log instances can also be monitored. To run, create a GitHub Actions workflow that uses the
[reusable certificate transparency log monitoring workflow](https://github.com/sigstore/rekor-monitor/blob/main/.github/workflows/ct_reusable_monitoring.yml).
It is recommended to run the log monitor every hour for optimal performance.

Example workflow below:

```yaml
name: Fulcio log and identity monitor
on:
  schedule:
    - cron: '0 * * * *' # every hour

permissions: read-all

jobs:
  run_consistency_proof:
    permissions:
      contents: read # Needed to checkout repositories
      issues: write # Needed if you set "file_issue: true"
    uses: sigstore/rekor-monitor/.github/workflows/ct_reusable_monitoring.yml@main
    with:
      file_issue: true # Strongly recommended: Files an issue on monitoring failure
      artifact_retention_days: 14 # Optional, default is 14: Must be longer than the cron job frequency
      config: |
        monitoredValues:
          certIdentities:
            - certSubject: user@domain\.com
            - certSubject: otheruser@domain\.com
              issuers:
                - https://accounts\.google\.com
                - https://github\.com/login
            - certSubject: https://github\.com/actions/starter-workflows/blob/main/\.github/workflows/lint\.yaml@.*
              issuers:
                - https://token\.actions\.githubusercontent\.com
          subjects:
            - subject@domain\.com
          fingerprints:
            - A0B1C2D3E4F5
          oidMatchers:
            fulcioExtensions:
              build-config-uri:
                - https://example.com/owner/repository/build-config.yml
            oidExtensions:
              - objectIdentifier: [1, 3, 6, 1, 4, 1, 57264, 1, 1]
                extensionValues:
                  - https://github.com/login/oauth
            customExtensions:
              - objectIdentifier: 1.3.6.1.4.1.57264.1.9
                extensionValues:
                  - https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.4.0
```

## Running Rekor Watch with Docker Compose

Rekor Watch can be run using Docker Compose. The default configuration works
for local development out of the box, using [mailpit](https://mailpit.axigen.com/)
as a local email server.

### Quick start

```bash
docker compose --profile watch up --build
```

This starts the web UI at <http://localhost:8080> and the mailpit inbox at
<http://localhost:8025>.

### Configuration

All settings are configurable via a `.env` file. Copy the provided template
and edit as needed:

```bash
cp .env.example .env
```

Key configuration groups:

| Group | Variables | Notes |
|-------|-----------|-------|
| Core | `REKOR_WATCH_INTERVAL`, `REKOR_WATCH_BASE_URL`, `REKOR_WATCH_MONITOR_CONFIG` | Polling frequency, public URL, monitor config |
| SMTP | `REKOR_WATCH_SMTP_HOST`, `_PORT`, `_FROM`, `_USERNAME`, `_PASSWORD`, `_USE_TLS` | Point to a real SMTP server for production |
| Security | `REKOR_WATCH_ALLOW_PRIVATE_WEBHOOKS`, `REKOR_WATCH_TRUST_PROXY_HEADERS` | Disable private webhooks and enable proxy headers in production |
| Ports | `REKOR_WATCH_LISTEN`, `REKOR_WATCH_HOST_PORT`, `MAILPIT_LISTEN` | Bind address and port mapping |

See `.env.example` for the full list of options with descriptions.

### Production notes

For production deployments, at minimum set:

- `REKOR_WATCH_BASE_URL` to the public URL of your instance
- `REKOR_WATCH_SMTP_*` variables to a real mail server with TLS
- `REKOR_WATCH_LISTEN` to the external IP address if the service should be reachable externally
- `REKOR_WATCH_TRUST_PROXY_HEADERS=true` if running behind a reverse proxy

## Webhook payload

Each notification cycle sends at most **one POST per subscription**, carrying
up to **100 matches** per request. A subscription with a larger backlog drains
over successive polling cycles, preserving consumer backpressure. The wire
format is stable JSON:

```json
{
  "type": "rekor.match.created",
  "timestamp": "2026-06-22T11:30:00Z",
  "data": {
    "subscription_name": "Production signing certs",
    "monitored_value": { "subject": "user@example.com" },
    "entries": [
      {
        "origin": "rekor.sigstore.dev - 1193050959916656506",
        "log_index": 12345,
        "uuid": "...",
        "cert_subject": "user@example.com",
        "issuer": "https://accounts.example.com",
        "fingerprint": "...",
        "subject": "...",
        "oid_extension": "...",
        "extension_value": "..."
      }
    ]
  }
}
```

The payload follows the [Standard Webhooks](https://www.standardwebhooks.com/)
envelope shape: switch on the top-level `type` (only `rekor.match.created`
today) and read `timestamp` (RFC3339, UTC) as the delivery time. Under `data`,
`subscription_name` is the subscription's human-readable name, `monitored_value`
mirrors the subscription's matcher, and `entries` is a list with up to 100
elements. Order within `entries` is unspecified.

### Deduplication contract

The same match may be delivered more than once if a previous delivery's
response was lost (for example, a network timeout after the consumer
successfully processed the payload). Consumers **must** deduplicate by the
`(monitored_value, origin, log_index)` tuple, which is stable across
redeliveries.

## Security

Please report any vulnerabilities following Sigstore's [security process](https://github.com/sigstore/.github/blob/main/SECURITY.md).
