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
    uses: sigstore/rekor-monitor/.github/workflows/reusable_monitoring.yml@main
    with:
      file_issue: true # Strongly recommended: Files an issue on monitoring failure
      artifact_retention_days: 14 # Optional, default is 14: Must be longer than the cron job frequency
```

Caveats:

* The log monitoring job should not be run concurrently with other log monitoring jobs in the same repository
* If running as a cron job, `artifact_retention_days` must be longer than the cron job frequency

## Security

Please report any vulnerabilities following Sigstore's [security process](https://github.com/sigstore/.github/blob/main/SECURITY.md).
