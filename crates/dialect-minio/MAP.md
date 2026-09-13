# MAP — rustfs-gateway-dialect-minio

Agent entry point. File → responsibility → when you need to open it.

This crate is clean-room protocol code. It must never be derived from MinIO server source.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Public concrete lifecycle dialect and its registered `DelMarkerExpiration` field. | Wiring or reviewing the lifecycle extension. |
| `src/replication.rs` | `minio:PutObjectReplica`: the replica write that names its version id, its route row, authorisation and codec. | Wiring replication into an assembly, or changing who may choose a version id. |
| `tests/integration.rs` | Exact lifecycle round-trip and persisted fail-closed matrix; registers the replication suite. | Changing field placement, parsing, or RMW safety. |
| `tests/replication.rs` | Replica routing matrix with and without the dialect, its two actions, floor and codec. | Changing the replica row, its selector, or its codec. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-dialect-minio
```
