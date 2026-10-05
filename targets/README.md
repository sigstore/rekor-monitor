# Local TUF targets

Files here stand in for TUF targets that are not yet published by the sigstore
root-signing repositories. Once they are shipped in TUF, these copies should be
deleted and fetched through the TUF client instead.

## `monitor_config.json`

A `dev.sigstore.monitor.v1.MonitorConfig` message
([`sigstore_monitor.proto`](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_monitor.proto)),
serialized as protojson — the same encoding the existing `trusted_root.json` and
`signing_config.v0.2.json` targets use (lowerCamelCase field names, no
comments). Parse it with `protojson` into the generated Go type from
`github.com/sigstore/protobuf-specs/gen/pb-go/monitor/v1`, available since
protobuf-specs v0.5.2.

`MonitorConfig` has no `media_type` field, so unlike `signing_config` the file
name carries no version suffix.

`rekor_watch` reads one of these files instead of the signing config to discover
the shards to follow, selected with `--monitor-config` (or
`REKOR_WATCH_MONITOR_CONFIG`), and defaulting to the staging file to match the
default TUF repository:

    rekor_watch --monitor-config targets/prod/monitor_config.json \
                --tuf-repository default

The file is re-read on every refresh, so adding a shard to it is picked up
without restarting the watcher.

Monitors need this because the trusted root and signing config can no longer be
joined on URL: the signing config now advertises a global load balancer for
writes, which does not serve reads. Staging shows the divergence today —
`https://global.rekor.sigstage.dev` (the v2 URL in the staging
`signing_config.v0.2.json`) answers read requests with
`501 method GetCheckpoint not implemented`, while the log's checkpoints and
tiles are served from `https://log2026-1.us-east4.rekor.sigstage.dev`, which is
also the checkpoint origin.

### Provenance

Only `rekorLogs` is populated; CT logs are not covered.

Entries were derived from the `tlogs` of `trusted_root.json` in
[sigstore/root-signing](https://github.com/sigstore/root-signing) and
[sigstore/root-signing-staging](https://github.com/sigstore/root-signing-staging),
and every `logOrigin` was confirmed against the log's live checkpoint
(`/api/v2/checkpoint` for v2, the `signedTreeHead` note for v1). Logs are listed
newest first, matching the ordering convention of `signing_config.v0.2.json`.
The v1 `logOrigin` is the full checkpoint note origin, which embeds the tree ID.

Retired shards are included: `MonitorConfig` has no validity window, and a
monitor still needs them to verify historical entries.
