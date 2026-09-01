# MAP — rustfs-gateway-fs

Agent entry point. File → responsibility → when you need to open it.

| File | Responsibility | Read it when |
|---|---|---|
| `README.md` | Scope fence and supported-operation summary. | Deciding whether this reference backend fits a use case. |
| `src/lib.rs` | Filesystem paths, capability authority, bucket CRUD, and five multipart handlers. | Changing shared storage behavior or the registered operation set. |
| `src/lifecycle.rs` | Durable lifecycle documents, filter evaluation, and one-shot current-object expiration. | Changing lifecycle configuration or expiration semantics. |
| `src/listing.rs` | Object/upload filtering, delimiter rollup, V1/paired markers, and scoped V2 cursors. | Changing object or upload listing pagination semantics. |
| `src/tagging.rs` | Durable per-version object tag replacement, reads, deletion, and storage safety. | Changing object-tagging operations or lifecycle tag inputs. |
| `src/uploads.rs` | Multipart record/checksum decoding, path validation, and active-upload enumeration. | Changing upload capability persistence, checksum negotiation, or upload listing authority. |
| `src/versioning.rs` | Persistent version states, shared object publication, delete markers, and version census handlers. | Changing PUT/multipart publication, version selection, retention, or listing semantics. |
| `tests/crud.rs` | Signed production-service CRUD, multipart, and storage-boundary evidence. | Changing a handler, path rule, or public assembly API. |
| `tests/crud/listing.rs` | Restarted V1/V2 pages, prefix/delimiter, URL encoding, and cursor/path refusals. | Changing ordinary listing behavior or its persisted source. |
| `tests/crud/lifecycle.rs` | Full-rule lifecycle replacement, restart, validation, deletion, and storage-boundary evidence. | Changing lifecycle configuration behavior or its durable authority. |
| `tests/crud/lifecycle_expiration.rs` | Debug-day, version-aware expiration, selection, and preflight evidence. | Changing lifecycle execution or its fail-closed boundaries. |
| `tests/crud/multipart_listing.rs` | Restarted upload pages, paired markers, rollup, retirement, and path refusals. | Changing upload listing or its persisted authority. |
| `tests/crud/multipart_checksums.rs` | Negotiated part validation, restart, retry, and completion checksum evidence. | Changing multipart checksum persistence or verification. |
| `tests/crud/multipart_sizing.rs` | Multipart minimum-part rejection, retryability, and boundary evidence. | Changing completion part-size validation. |
| `tests/crud/multipart_versioning.rs` | Multipart publication into enabled, suspended, and null version lineages. | Changing completion/version integration or its failure boundaries. |
| `tests/crud/object_tagging.rs` | Restarted current/version tag operations and lifecycle filter consumption. | Changing object tags or tag-selected lifecycle expiration. |
| `tests/crud/versioning.rs` | Enabled, suspended, restart, corruption, and symlink versioning evidence. | Changing versioned object behavior or persistence. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-fs
```
