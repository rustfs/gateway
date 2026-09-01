# MAP — rustfs-gateway-fs

Agent entry point. File → responsibility → when you need to open it.

| File | Responsibility | Read it when |
|---|---|---|
| `README.md` | Scope fence and supported-operation summary. | Deciding whether this reference backend fits a use case. |
| `src/lib.rs` | Filesystem paths, capability authority, bucket CRUD, and five multipart handlers. | Changing shared storage behavior or the registered operation set. |
| `src/listing.rs` | Current-object filtering, delimiter rollup, and scoped ListObjectsV2 pagination. | Changing ordinary object listing or continuation semantics. |
| `src/versioning.rs` | Persistent version states, object versions, delete markers, and version census handlers. | Changing version selection, retention, or listing semantics. |
| `tests/crud.rs` | Signed production-service CRUD, multipart, and storage-boundary evidence. | Changing a handler, path rule, or public assembly API. |
| `tests/crud/listing.rs` | Restarted V2 pages, prefix/delimiter, URL encoding, and cursor/path refusals. | Changing ordinary listing behavior or its persisted source. |
| `tests/crud/versioning.rs` | Enabled, suspended, restart, corruption, and symlink versioning evidence. | Changing versioned object behavior or persistence. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-fs
```
