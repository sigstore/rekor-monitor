# Rekor Log Monitor

Rekor Log Monitor provides an easy-to-use monitor to verify log consistency,
that the log is immutability and append-only. Monitoring is critical to
the transparency log ecosystem, as logs are tamper-evident but not tamper-proof.

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
    uses: sigstore/rekor-monitor/.github/workflows/reusable_monitoring.yaml@main
    with:
      file_issue: true # Strongly recommended: Files an issue on monitoring failure
      artifact_retention_days: 14 # Optional, default is 14: Must be longer than the cron job frequency
```

Caveats:

* The log monitoring job should not be run concurrently with other log monitoring jobs in the same repository
* If running as a cron job, `artifact_retention_days` must be longer than the cron job frequency

## Identity monitoring

You can also specify a list of identities to monitor. Currently, only identities from the certificate's
Subject Alternative Name (SAN) field will be matched, and only for the hashedrekord Rekor entry type.

Note: The log monitor only starts monitoring from the latest checkpoint. If you want to search previous
entries, you will need to query the log.

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
    uses: sigstore/rekor-monitor/.github/workflows/reusable_monitoring.yaml@main
    with:
      file_issue: true # Strongly recommended: Files an issue on monitoring failure
      artifact_retention_days: 14 # Optional, default is 14: Must be longer than the cron job frequency
      identities: |
        user@domain.com
        otheruser@domain.com https://accounts.google.com https://github.com/login
```

In this example, the monitor will log any entries that contain a certificate whose SAN
is `user@domain.com`. It will also log any entries whose SAN is `otheruser@domain.com`
and the OIDC provider specified in a
[custom extension](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726411--issuer)
matches one of the specified issuers (Google or GitHub in this example).

Upcoming features:

* Creating issues when identities are found
* Support for all Rekor types
* Support for other identities
   * Key/certificate fingerprints
   * CI identity values in Fulcio certificates
   * Regular expressions

## Security

Please report any vulnerabilities following Sigstore's [security process](https://github.com/sigstore/.github/blob/main/SECURITY.md).
