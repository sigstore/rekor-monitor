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

  # Fulcio extensions to monitor
  fulcioExtensions:
    build-config-uri:
      - https://example.com/owner/repository/build-config.yml

  # Custom OID extensions
  customExtensions:
    - objectIdentifier: 1.3.6.1.4.1.57264.1.9
      extensionValues: https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.4.0

# Optional: Output file for found identities
outputIdentities: identities.txt

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

```
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
      id-token: write # Needed to detect the current reusable repository and ref
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

```
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
      id-token: write # Needed to detect the current reusable repository and ref
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
          fulcioExtensions:
            build-config-uri:
              - https://example.com/owner/repository/build-config.yml
          customExtensions:
            - objectIdentifier: 1.3.6.1.4.1.57264.1.9
              extensionValues: https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.4.0
```

In this example, the monitor will log:

* Entries that contain a certificate whose SAN is `user@domain.com`
* Entries whose SAN is `otheruser@domain.com` and the OIDC provider specified in a [custom extension](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726418--issuer-v2) matches one of the specified issuers (Google or GitHub in this example)
* Entries whose SAN start by `https://github.com/actions/starter-workflows/blob/main/.github/workflows/lint.yaml@` and the OIDC provider matches `https://token.actions.githubusercontent.com`
* Non-certificate entries, such as PGP or SSH keys, whose subject matches `subject@domain.com`
* Entries whose key or certificate fingerprint matches `A0B1C2D3E4F5`
* Entries that contain a certificate with a Build Config URI Extension matching `https://example.com/owner/repository/build-config.yml`
* Entries that contain a certificate with OID extension `1.3.6.1.4.1.57264.1.9` (Fulcio OID for Build Signer URI) and an extension value matching `https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.4.0`

Fingerprint values are as follows:

* For keys, certificates, and minisign, hex-encoded SHA-256 digest of the DER-encoded PKIX public key or certificate
* For SSH and PGP, the standard for each ecosystem:
   * For SSH, unpadded base-64 encoded SHA-256 digest of the key
	 * For PGP, hex-encoded SHA-1 digest of a key, which can be either a primary key or subkey

Upcoming features:

* Creating issues when identities are found
* Support for other identities
   * CI identity values in Fulcio certificates

### Certificate transparency log monitoring

Certificate transparency log instances can also be monitored. To run, create a GitHub Actions workflow that uses the
[reusable certificate transparency log monitoring workflow](https://github.com/sigstore/rekor-monitor/blob/main/.github/workflows/ct_reusable_monitoring.yml).
It is recommended to run the log monitor every hour for optimal performance.

Example workflow below:

```
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
      id-token: write # Needed to detect the current reusable repository and ref
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
          fulcioExtensions:
            build-config-uri:
              - https://example.com/owner/repository/build-config.yml
          customExtensions:
            - objectIdentifier: 1.3.6.1.4.1.57264.1.9
              extensionValues: https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.4.0
```

## Security

Please report any vulnerabilities following Sigstore's [security process](https://github.com/sigstore/.github/blob/main/SECURITY.md).
