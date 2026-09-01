# MAP — rustfs-gateway-dialect-minio

Agent entry point. File → responsibility → when you need to open it.

This crate is clean-room protocol code. It must never be derived from MinIO server source.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Public concrete lifecycle dialect and its registered `DelMarkerExpiration` field. | Wiring or reviewing the lifecycle extension. |
| `tests/integration.rs` | Exact lifecycle round-trip and persisted fail-closed matrix. | Changing field placement, parsing, or RMW safety. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-dialect-minio
```
