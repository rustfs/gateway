# MAP — rustfs-gateway-fs

Agent entry point. File → responsibility → when you need to open it.

| File | Responsibility | Read it when |
|---|---|---|
| `README.md` | Scope fence and supported-operation summary. | Deciding whether this reference backend fits a use case. |
| `src/lib.rs` | Filesystem paths, capability authority, served region and owner, and five multipart handlers. | Changing shared storage behavior or the registered operation set. |
| `src/copy.rs` | Authorized source selection, source conditions, metadata directives, self-copy classification, and destination publication. | Changing server-side object-copy behavior. |
| `src/buckets.rs` | Bucket creation and removal, the `LocationConstraint` a creation may name, and the region `HeadBucket`/`GetBucketLocation` report. | Changing bucket lifetime or the region this backend serves. |
| `src/lifecycle.rs` | Durable lifecycle documents, filter evaluation, and one-shot current-object expiration. | Changing lifecycle configuration or expiration semantics. |
| `src/lifecycle_scheduler.rs` | Repeated lifecycle cadence, failure accounting, and bounded shutdown. | Changing automatic expiration scheduling or worker lifetime. |
| `src/listing.rs` | Object/upload filtering, owner projection, delimiter rollup, V1/paired markers, and scoped V2 cursors. | Changing object or upload listing pagination semantics. |
| `src/records.rs` | The on-disk grammar of one version record, the versioned trailing section carrying user metadata, and the storability rules a metadata pair must pass. | Changing the persisted record format or the user-metadata rules. |
| `src/reads.rs` | Representation selection for `GetObject`/`HeadObject` and the `Range` window `evaluate_range` decides. | Changing ranged or version-selected reads. |
| `src/tagging.rs` | Durable per-version object tag replacement, reads, deletion, and storage safety. | Changing object-tagging operations or lifecycle tag inputs. |
| `src/transitions.rs` | One-shot current-object transition selection and storage-class mutation. | Changing lifecycle transition eligibility or class persistence. |
| `src/uploads.rs` | Durable upload-ID allocation, multipart record/checksum decoding, path validation, and active-upload enumeration. | Changing upload capability persistence, checksum negotiation, or upload listing authority. |
| `src/versioning.rs` | Persistent version states, shared object publication, delete markers, and owner-bearing version census handlers. | Changing PUT/multipart publication, version selection, retention, or listing semantics. |
| `tests/crud.rs` | Signed production-service CRUD, multipart, and storage-boundary evidence. | Changing a handler, path rule, or public assembly API. |
| `tests/crud/bucket_location.rs` | Null and named location answers as exact bytes, the `EU` alias, constraint refusals, and region agreement with `HeadBucket`. | Changing `GetBucketLocation` or the served region. |
| `tests/crud/listing.rs` | Restarted V1/V2 pages, fixed-owner projection, prefix/delimiter, URL encoding, and cursor/path refusals. | Changing ordinary listing behavior or its persisted source. |
| `tests/crud/range_reads.rs` | Ranged `GET`/`HEAD` boundaries: suffix, clamp, single byte, `416`, multi-range, `If-Range`, `partNumber` conflict. | Changing ranged reads or their wire headers. |
| `tests/crud/lifecycle.rs` | Full-rule lifecycle replacement, restart, validation, deletion, and storage-boundary evidence. | Changing lifecycle configuration behavior or its durable authority. |
| `tests/crud/lifecycle_expiration.rs` | Debug-day, version-aware expiration, selection, and preflight evidence. | Changing lifecycle execution or its fail-closed boundaries. |
| `tests/crud/lifecycle_scheduler.rs` | Automatic cadence and scheduler shutdown evidence. | Changing lifecycle worker startup, recovery, or shutdown. |
| `tests/crud/lifecycle_transitions.rs` | Transition due-time, size-default, restart, projection, and preflight evidence. | Changing current-object transition execution. |
| `tests/crud/multipart_listing.rs` | Restarted upload pages, paired markers, rollup, retirement, and path refusals. | Changing upload listing or its persisted authority. |
| `tests/crud/multipart_checksums.rs` | Negotiated part validation, restart, retry, and completion checksum evidence. | Changing multipart checksum persistence or verification. |
| `tests/crud/multipart_sizing.rs` | Multipart minimum-part rejection, retryability, and boundary evidence. | Changing completion part-size validation. |
| `tests/crud/multipart_upload_ids.rs` | Restarted upload-ID uniqueness and allocator corruption, exhaustion, and symlink refusals. | Changing multipart capability allocation or its durable counter. |
| `tests/crud/multipart_versioning.rs` | Multipart publication into enabled, suspended, and null version lineages. | Changing completion/version integration or its failure boundaries. |
| `tests/crud/object_metadata.rs` | Restarted `x-amz-meta-*` persistence, initiation-time multipart metadata, size and storability refusals, and the pre-section record fixture. | Changing user-metadata persistence or the record's compatibility story. |
| `tests/crud/object_tagging.rs` | Restarted current/version tag operations and lifecycle filter consumption. | Changing object tags or tag-selected lifecycle expiration. |
| `tests/fixtures/version-record-v0/**` | One version directory captured verbatim from the build that wrote eight-line records. | Proving this build still reads what the pre-metadata-section build wrote. |
| `tests/crud/versioning.rs` | Enabled, suspended, owner reporting, restart, corruption, and symlink versioning evidence. | Changing versioned object behavior or persistence. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-fs
```
