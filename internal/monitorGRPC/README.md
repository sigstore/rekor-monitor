# Monitor gRPC Service
Provides remote procedure calls that other future services can utilize

## Defined RPCs

### `GetLastSnapshot`
- Returns lastest log info (tree size and root hash) that has been verified by the monitor

## Defined message types

### `LastSnapshotRequest`
- Empty input payload to `GetLastSnapshot` call

### `LastSnapshotResponse`
- Response payload from `GetLastSnapshot` containing tree size and root hash of last verified log info

## Compile and Generate gRPC code
```make proto```
