# MAP — rustfs-gateway-fs

Agent entry point. File → responsibility → when you need to open it.

| File | Responsibility | Read it when |
|---|---|---|
| `README.md` | Scope fence and supported-operation summary. | Deciding whether this reference backend fits a use case. |
| `src/lib.rs` | Filesystem paths, capability authority, served region and owner, and five multipart handlers. | Changing shared storage behavior or the registered operation set. |
| `src/deletes.rs` | `DeleteObjects`: every requested key through the single-key deletion, reported once as deleted or as an error; quiet mode. | Changing batch deletion or its per-key report. |
| `src/post_object.rs` | Browser `POST` Object: the accepted form's file, media type and metadata stored through ordinary publication. | Changing what a form upload stores. |
| `src/content_headers.rs` | The six stored representation headers, the default media type, the request reader macro, and the `headers/1` section grammar. | Changing which headers an object stores or how they persist. |
| `src/copy.rs` | Authorized source selection, source conditions, metadata directives, self-copy classification, and destination publication. | Changing server-side object-copy behavior. |
| `src/buckets.rs` | Bucket creation and removal, the `ListBuckets` census and cursor, the `LocationConstraint` a creation may name, and the region `HeadBucket`/`GetBucketLocation` report. | Changing bucket lifetime, bucket listing, or the region this backend serves. |
| `src/lifecycle.rs` | Durable lifecycle documents, filter evaluation, and one-shot current-object expiration. | Changing lifecycle configuration or expiration semantics. |
| `src/lifecycle_scheduler.rs` | Repeated lifecycle cadence, failure accounting, and bounded shutdown. | Changing automatic expiration scheduling or worker lifetime. |
| `src/listing.rs` | Object/upload filtering, owner projection, delimiter rollup, V1/paired markers, and scoped V2 cursors. | Changing object or upload listing pagination semantics. |
| `src/records.rs` | The on-disk grammar of one version record, the versioned trailing sections carrying user metadata and stored representation headers, and the storability rules both must pass. | Changing the persisted record format or the user-metadata rules. |
| `src/reads.rs` | Representation selection for `GetObject`/`HeadObject` and the `Range` window `evaluate_range` decides. | Changing ranged or version-selected reads. |
| `src/encryption.rs` | Default-encryption configuration, and the managed encryption an object write records (request, else bucket default) and reads report, with RustFS's refusals; nothing is encrypted (rustfs/gateway#812). | Changing `Put/Get/DeleteBucketEncryption`, object SSE-S3/SSE-KMS reporting, or the read-side SSE refusal. |
| `src/policy/evaluate.rs` | Bucket-policy matching, `StringEquals`/`StringNotEquals`/`Null` on `s3:x-amz-acl` and `s3:x-amz-server-side-encryption`, and explicit unsupported-condition boundaries. | Changing policy condition interpretation. |
| `src/conditions.rs` | RFC 9110 conditional requests for `GetObject`, `HeadObject` and `PutObject`: the request's four conditions as the contract's `Preconditions`, and the contract's verdict — against the representation or its absence — as `304`, `412` or proceed. | Changing a conditional read or write (rustfs/gateway#808). |
| `src/tagging.rs` | Durable per-version object tag replacement, reads, deletion, and storage safety. | Changing object-tagging operations or lifecycle tag inputs. |
| `src/transitions.rs` | One-shot current-object transition selection and storage-class mutation. | Changing lifecycle transition eligibility or class persistence. |
| `src/upload_part_copy.rs` | `UploadPartCopy`: authorized source, copy-source conditions, `x-amz-copy-source-range` span stored as a part. | Changing part copies. |
| `src/uploads.rs` | Durable upload-ID allocation, multipart record/checksum decoding, path validation, and active-upload enumeration. | Changing upload capability persistence, checksum negotiation, or upload listing authority. |
| `src/versioning.rs` | Persistent version states, shared object publication, delete markers, and owner-bearing version census handlers. | Changing PUT/multipart publication, version selection, retention, or listing semantics. |
| `tests/crud.rs` | Signed production-service CRUD, multipart, and storage-boundary evidence. | Changing a handler, path rule, or public assembly API. |
| `tests/crud/bucket_location.rs` | Null and named location answers as exact bytes, the `EU` alias, constraint refusals, and region agreement with `HeadBucket`. | Changing `GetBucketLocation` or the served region. |
| `tests/crud/listing.rs` | Restarted V1/V2 pages, fixed-owner projection, prefix/delimiter, URL encoding, and cursor/path refusals. | Changing ordinary listing behavior or its persisted source. |
| `tests/crud/bucket_encryption.rs` | Default-encryption round trip, restart, replacement, absent `404`, idempotent `204`, shared and RustFS refusals, and the record leaving with its bucket. | Changing the default-encryption family. |
| `tests/crud/object_encryption.rs` | Explicit and default SSE-S3/SSE-KMS reported by writes, `GET` and `HEAD` across restart, multipart and copy; RustFS's write refusals storing nothing; reads naming an algorithm refused; the unencrypted control. | Changing object-level encryption reporting. |
| `tests/crud/upload_part_copy.rs` | Whole and ranged part copies of an explicit version completing into the expected bytes; bad ranges, missing upload/source and failed conditions writing no part. | Changing `UploadPartCopy`. |
| `tests/crud/conditional_requests.rs` | `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since` on `GET`/`HEAD` (`412`, `304` with validators and no body, evaluated before a miss), conditional `PUT` writing nothing on a false condition, and sixteen racing `If-None-Match: *` writers with one winner. | Changing conditional requests. |
| `tests/crud/range_reads.rs` | Ranged `GET`/`HEAD` boundaries: suffix, clamp, single byte, `416`, multi-range, `If-Range`, `partNumber` conflict. | Changing ranged reads or their wire headers. |
| `tests/crud/lifecycle.rs` | Full-rule lifecycle replacement, restart, validation, deletion, and storage-boundary evidence. | Changing lifecycle configuration behavior or its durable authority. |
| `tests/crud/lifecycle_expiration.rs` | Debug-day, version-aware expiration, selection, and preflight evidence. | Changing lifecycle execution or its fail-closed boundaries. |
| `tests/crud/lifecycle_scheduler.rs` | Automatic cadence and scheduler shutdown evidence. | Changing lifecycle worker startup, recovery, or shutdown. |
| `tests/crud/lifecycle_transitions.rs` | Transition due-time, size-default, restart, projection, and preflight evidence. | Changing current-object transition execution. |
| `tests/crud/multipart_conditions.rs` | `If-Match`/`If-None-Match` on `CompleteMultipartUpload`: publish when they hold, `412` leaving object and upload in place. | Changing conditional completion. |
| `tests/crud/multipart_listing.rs` | Restarted upload pages, paired markers, rollup, retirement, and path refusals. | Changing upload listing or its persisted authority. |
| `tests/crud/multipart_checksums.rs` | Negotiated part validation, restart, retry, and completion checksum evidence. | Changing multipart checksum persistence or verification. |
| `tests/crud/multipart_trailer_checksums.rs` | Part checksums carried by an unsigned `aws-chunked` trailer (aws-sdk-java-v2): accepted and combined at completion; wrong value, other algorithm, absent trailer, header-plus-trailer and malformed value refused with no part stored. | Changing how a part checksum reaches the multipart authority. |
| `tests/crud/multipart_sizing.rs` | Multipart minimum-part rejection, retryability, and boundary evidence. | Changing completion part-size validation. |
| `tests/crud/multipart_upload_ids.rs` | Restarted upload-ID uniqueness, allocator corruption, exhaustion, and symlink refusals, and bucket deletion discarding only pending uploads. | Changing multipart capability allocation, its durable counter, or what `DeleteBucket` discards. |
| `tests/crud/multipart_versioning.rs` | Multipart publication into enabled, suspended, and null version lineages. | Changing completion/version integration or its failure boundaries. |
| `tests/crud/object_metadata.rs` | Restarted `x-amz-meta-*` persistence, initiation-time multipart metadata, size and storability refusals, and the pre-section record fixture. | Changing user-metadata persistence or the record's compatibility story. |
| `tests/crud/content_headers.rs` | Restarted `Content-Type` and standard stored headers, the untyped default, per-version answers, multipart initiation headers, and COPY/REPLACE. | Changing stored representation headers. |
| `tests/crud/list_buckets.rs` | Bucket census order, owner, prefix/region filters, `max-buckets` paging, and cursor/page-size refusals. | Changing `ListBuckets`. |
| `tests/crud/delete_objects.rs` | Batch deletion across versioning states, quiet mode, explicit versions, per-key errors, and whole-request refusals. | Changing `DeleteObjects` or single-key deletion. |
| `tests/crud/write_attributes.rs` | `PutObject` tags and storage class, `CopyObject` class and tagging directive, and the bare copy-source `If-None-Match` refusal. | Changing what a write or copy stores besides bytes and metadata. |
| `tests/crud/post_object.rs` | Anonymous form uploads stored and read back, versions reported, storage refusals, and a SigV4-signed form without a `bucket` field bound to its routed bucket. | Changing POST Object storage or the signed-form path. |
| `tests/crud/object_tagging.rs` | Restarted current/version tag operations and lifecycle filter consumption. | Changing object tags or tag-selected lifecycle expiration. |
| `tests/fixtures/version-record-v0/**` | One version directory captured verbatim from the build that wrote eight-line records. | Proving this build still reads what the pre-metadata-section build wrote. |
| `tests/crud/versioning.rs` | Enabled, suspended, owner reporting, restart, corruption, symlink, version-cursor pairing, and vanished-cursor resume evidence. | Changing versioned object behavior, persistence, or version-listing cursors. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-fs
```
