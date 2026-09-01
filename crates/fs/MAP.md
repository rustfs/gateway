# MAP — rustfs-gateway-fs

Agent entry point. File → responsibility → when you need to open it.

| File | Responsibility | Read it when |
|---|---|---|
| `README.md` | Scope fence and supported-operation summary. | Deciding whether this reference backend fits a use case. |
| `src/lib.rs` | Filesystem paths, capability authority, bucket CRUD, and five multipart handlers. | Changing shared storage behavior or the registered operation set. |
| `src/listing.rs` | Object/upload filtering, delimiter rollup, V1/paired markers, and scoped V2 cursors. | Changing object or upload listing pagination semantics. |
| `src/uploads.rs` | Multipart record decoding, path validation, and active-upload enumeration. | Changing upload capability persistence or upload listing authority. |
| `src/versioning.rs` | Persistent version states, object versions, delete markers, and version census handlers. | Changing version selection, retention, or listing semantics. |
| `tests/crud.rs` | Signed production-service CRUD, multipart, and storage-boundary evidence. | Changing a handler, path rule, or public assembly API. |
| `tests/crud/listing.rs` | Restarted V1/V2 pages, prefix/delimiter, URL encoding, and cursor/path refusals. | Changing ordinary listing behavior or its persisted source. |
| `tests/crud/multipart_listing.rs` | Restarted upload pages, paired markers, rollup, retirement, and path refusals. | Changing upload listing or its persisted authority. |
| `tests/crud/versioning.rs` | Enabled, suspended, restart, corruption, and symlink versioning evidence. | Changing versioned object behavior or persistence. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-fs
```
