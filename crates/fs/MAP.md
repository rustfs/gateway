# MAP — rustfs-gateway-fs

Agent entry point. File → responsibility → when you need to open it.

| File | Responsibility | Read it when |
|---|---|---|
| `README.md` | Scope fence and supported-operation summary. | Deciding whether this reference backend fits a use case. |
| `src/lib.rs` | Filesystem paths, capability authority, served region and owner, and four multipart handlers (`CreateMultipartUpload`, `UploadPart`, `ListParts`, `AbortMultipartUpload`). | Changing shared storage behavior or the registered operation set. |
| `src/deletes.rs` | `DeleteObjects`: every requested key through the single-key deletion, reported once as deleted or as an error; quiet mode; the keys a stood-in storage refuses answered alone and left alone (`refusing_batch_deletes_of`). | Changing batch deletion or its per-key report. |
| `src/post_object.rs` | Browser `POST` Object: the accepted form's file, media type, metadata and other `PutObject` members stored through ordinary publication as RustFS stores them, or refused. | Changing what a form upload stores. |
| `src/content_headers.rs` | The six stored representation headers, the default media type, the request reader macro, the legacy `Content-Encoding` normalization (`normalizing_content_encoding`), and the `headers/1` section grammar. | Changing which headers an object stores or how they persist. |
| `src/checksums.rs` | A stored checksum's explicit type marker and its GET, HEAD, COPY and replay projection. | Changing stored checksum reporting. |
| `src/copy.rs` | Authorized source selection, source conditions, metadata directives, self-copy classification, and destination publication. | Changing server-side object-copy behavior. |
| `src/bucket_cors.rs` | `Put/Get/DeleteBucketCors` (stored, `NoSuchCORSConfiguration`, idempotent delete) and the backend's `CorsSource`. | Changing bucket CORS storage or what feeds the gateway's CORS answers. |
| `src/bucket_tagging.rs` | `Put/Get/DeleteBucketTagging` as RustFS answers them: stored set, `NoSuchTagSet`, idempotent delete. | Changing bucket tags. |
| `src/buckets.rs` | Bucket creation and removal, the `ListBuckets` census and cursor, the `LocationConstraint` a creation may name, and the region `HeadBucket`/`GetBucketLocation` report. | Changing bucket lifetime, bucket listing, or the region this backend serves. |
| `src/lifecycle.rs` | Durable lifecycle documents, filter evaluation, one-shot object/version/marker expiration, and the `x-amz-expiration` a current version answers. | Changing lifecycle configuration or expiration semantics. |
| `src/lifecycle_scheduler.rs` | Repeated lifecycle cadence, failure accounting, and bounded shutdown. | Changing automatic expiration scheduling or worker lifetime. |
| `src/listing.rs` | Object/upload filtering, owner projection, delimiter rollup, V1/paired markers, and scoped V2 cursors. | Changing object or upload listing pagination semantics. |
| `src/object_attributes.rs` | Selected GetObjectAttributes metadata and stored checksums; refuses unavailable multipart detail. | Changing attribute selection or version-aware metadata. |
| `src/part_lengths.rs` | Completed part lengths, record validation and GET/HEAD window projection through the core resolver. | Changing persisted part boundaries or partNumber reads. |
| `src/records.rs` | The on-disk version grammar, optional metadata, representation headers and checksum sections, including explicit multipart types and completed part lengths. | Changing persisted object attributes or record compatibility. |
| `src/reads.rs` | Representation selection for `GetObject`/`HeadObject`, the `Range` window `evaluate_range` decides, and whether the version read is current (for `x-amz-expiration`). | Changing ranged or version-selected reads. |
| `src/encryption.rs` | Default-encryption configuration, and the managed encryption an object write records (request, else bucket default) and reads report, with RustFS's refusals; nothing is encrypted (rustfs/gateway#812). | Changing `Put/Get/DeleteBucketEncryption`, object SSE-S3/SSE-KMS reporting, or the read-side SSE refusal. |
| `src/rustfs_parity.rs` | The legacy-RustFS answers a deployment asks for by name — `evaluating_delete_if_match`, `sorting_object_tags`, `normalizing_completed_parts`, `normalizing_content_encoding`, and the switch behind `refusing_batch_deletes_of` — each off by default. | Adding or changing a RustFS-profile option of this backend. |
| `src/policy/evaluate.rs` | Bucket-policy matching, equality operators with optional `IfExists`, `Null`, and explicit unsupported-condition boundaries. | Changing policy condition interpretation. |
| `src/policy/ifexists_tests.rs` | Missing/present condition keys, deny precedence and unsupported-block controls. | Changing `IfExists` equality operators. |
| `src/completion.rs` | `CompleteMultipartUpload`: checksum negotiation, the part list (order, entity tags, sizes, checksums), the composite entity tag, write conditions, and the publication that retires the upload; a gone upload goes to the replay. | Changing how an upload completes. |
| `src/completion_replay.rs` | Completion receipts and the RustFS-style replay of a repeated `CompleteMultipartUpload` (same parts replay, other parts `InvalidPart`, else `NoSuchUpload`). | Changing completion retries. |
| `src/conditions.rs` | RFC 9110 conditional requests for `GetObject`, `HeadObject` and `PutObject`: the request's four conditions as the contract's `Preconditions`, and the contract's verdict — against the representation or its absence — as `304`, `412` or proceed. | Changing a conditional read or write (rustfs/gateway#808). |
| `src/tagging.rs` | Durable per-version object tag replacement, reads (in key order under `sorting_object_tags`), deletion, and storage safety. | Changing object-tagging operations or lifecycle tag inputs. |
| `src/transitions.rs` | One-shot current-object transition selection and storage-class mutation. | Changing lifecycle transition eligibility or class persistence. |
| `src/upload_part_copy.rs` | `UploadPartCopy`: authorized source, copy-source conditions, `x-amz-copy-source-range` span stored as a part. | Changing part copies. |
| `src/uploads.rs` | Durable upload-ID allocation, multipart record/checksum decoding, path validation, active-upload enumeration, and a completion's part-list order and its legacy normalization (`normalizing_completed_parts`). | Changing upload capability persistence, checksum negotiation, upload listing authority, or how a completion's part list is read. |
| `src/versioning.rs` | Persistent version states, shared object publication, delete markers, and owner-bearing version census handlers. | Changing PUT/multipart publication, version selection, retention, or listing semantics. |
| `src/versioning/lifecycle.rs` | Noncurrent-version and orphan-marker eligibility, history preflight, and deletion rechecked under the version lock. | Changing version-history expiration or its retention boundaries. |
| `src/versioning/configuration.rs` | Every member of a versioning configuration persisted in legacy RustFS's form, and MinIO's excluded prefixes and folders applied to writes and deletes as legacy RustFS applies them, with its wildcard match (rustfs/gateway#1078). | Changing which keys a bucket versions, or what a versioning configuration stores. |
| `src/versioning/delete_conditions.rs` | `If-Match` on `DeleteObject` read and judged as legacy RustFS does: stripped quotes, markers and missing keys failing, a versioned bucket's missing key left unjudged (rustfs/gateway#1191). | Changing conditional deletes. |
| `tests/crud.rs` | Signed production-service CRUD, multipart, and storage-boundary evidence. | Changing a handler, path rule, or public assembly API. |
| `tests/crud/bucket_location.rs` | Null and named location answers as exact bytes, the `EU` alias, constraint refusals, and region agreement with `HeadBucket`. | Changing `GetBucketLocation` or the served region. |
| `tests/crud/listing.rs` | Restarted V1/V2 pages, fixed-owner projection, prefix/delimiter, URL encoding, and cursor/path refusals. | Changing ordinary listing behavior or its persisted source. |
| `tests/crud/bucket_cors.rs` | CORS document round trip across restart, `CorsSource` answers, refusals, missing/recreated buckets. | Changing bucket CORS. |
| `tests/crud/bucket_encryption.rs` | Default-encryption round trip, restart, replacement, absent `404`, idempotent `204`, shared and RustFS refusals, and the record leaving with its bucket. | Changing the default-encryption family. |
| `tests/crud/object_encryption.rs` | Explicit and default SSE-S3/SSE-KMS reported by writes, `GET` and `HEAD` across restart, multipart and copy; RustFS's write refusals storing nothing; reads naming an algorithm refused; the unencrypted control. | Changing object-level encryption reporting. |
| `tests/crud/tag_order.rs` | Object tags answered in written order by default and in key byte order under `sorting_object_tags` on every write path and a named version; the stored document, bucket tags and the tag count left alone. | Changing the order of a tag answer. |
| `tests/crud/upload_part_copy.rs` | Whole and ranged part copies of an explicit version completing into the expected bytes; bad ranges, missing upload/source and failed conditions writing no part. | Changing `UploadPartCopy`. |
| `tests/crud/bucket_tagging.rs` | Bucket tag set round trip across restart, `NoSuchTagSet`, idempotent delete, shared refusals, missing/recreated buckets. | Changing bucket tagging. |
| `tests/crud/completion_parts.rs` | Under `normalizing_completed_parts`: the last entry per part number kept (resent part, verbatim repeat, `[2, 1, 2]`, checksum uploads), order and range refusals judged between the bucket and the upload, stale kept entries, and retries normalized before replay. | Changing how a completion's part list is read. |
| `tests/crud/conditional_requests.rs` | `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since` on `GET`/`HEAD` (`412`, `304` with validators and no body, evaluated before a miss), conditional `PUT` writing nothing on a false condition, and sixteen racing `If-None-Match: *` writers with one winner. | Changing conditional requests. |
| `tests/crud/range_reads.rs` | Ranged `GET`/`HEAD` boundaries: suffix, clamp, single byte, `416`, multi-range, `If-Range`, `partNumber` conflict. | Changing ranged reads or their wire headers. |
| `tests/crud/expiration_header.rs` | `x-amz-expiration` on `PUT`/`HEAD`/`GET`: earliest rule, tags added later, `Date` and `Days` in real days, versioned current versions; nothing for no, disabled or non-expiring rules, sizes out of range, noncurrent versions, copy/completion responses, or an unreadable record. | Changing the expiration a response answers. |
| `tests/crud/lifecycle.rs` | Full-rule lifecycle replacement, restart, validation, deletion, and storage-boundary evidence. | Changing lifecycle configuration behavior or its durable authority. |
| `tests/crud/lifecycle_rustfs_rules.rs` | RustFS's lifecycle write rules: `Status` exactly `Enabled`/`Disabled` else `MalformedXML`; generated `rule-<index>` ids. | Changing lifecycle write validation. |
| `tests/crud/lifecycle_expiration.rs` | Debug-day, version-aware expiration, selection, and preflight evidence. | Changing lifecycle execution or its fail-closed boundaries. |
| `tests/crud/lifecycle_version_expiration.rs` | Historical-version age/retention, orphan markers, restart, legacy files, and whole-sweep preflight refusals. | Changing historical lifecycle deletion. |
| `tests/crud/lifecycle_scheduler.rs` | Automatic cadence and scheduler shutdown evidence. | Changing lifecycle worker startup, recovery, or shutdown. |
| `tests/crud/lifecycle_transitions.rs` | Transition due-time, size-default, restart, projection, and preflight evidence. | Changing current-object transition execution. |
| `tests/crud/multipart_conditions.rs` | `If-Match`/`If-None-Match` on `CompleteMultipartUpload`: publish when they hold, `412` leaving object and upload in place. | Changing conditional completion. |
| `tests/crud/multipart_replay.rs` | Repeated completion replays the committed object across restart; other parts, overwrite, other key and a later upload stay refused. | Changing completion retries. |
| `tests/crud/multipart_listing.rs` | Restarted upload pages, paired markers, rollup, retirement, and path refusals. | Changing upload listing or its persisted authority. |
| `tests/crud/paging_limits.rs` | Populated upload/part ceilings, invalid numeric limits, and cursor progress. | Changing reference-backend pagination bounds. |
| `tests/crud/multipart_checksums.rs` | Negotiated part validation, restart, retry, and completion checksum evidence. | Changing multipart checksum persistence or verification. |
| `tests/crud/multipart_object_checksums.rs` | Completed checksum/type persistence, restarted replay, COPY type rules, read suppression and corrupt typed-record refusals. | Changing stored multipart checksums. |
| `tests/crud/multipart_trailer_checksums.rs` | Part checksums carried by an unsigned `aws-chunked` trailer (aws-sdk-java-v2): accepted and combined at completion; wrong value, other algorithm, absent trailer, header-plus-trailer and malformed value refused with no part stored. | Changing how a part checksum reaches the multipart authority. |
| `tests/crud/multipart_sizing.rs` | Multipart minimum-part rejection, retryability, and boundary evidence. | Changing completion part-size validation. |
| `tests/crud/multipart_upload_ids.rs` | Restarted upload-ID uniqueness, allocator corruption, exhaustion, and symlink refusals, and bucket deletion discarding only pending uploads. | Changing multipart capability allocation, its durable counter, or what `DeleteBucket` discards. |
| `tests/crud/multipart_versioning.rs` | Multipart publication into enabled, suspended, and null version lineages. | Changing completion/version integration or its failure boundaries. |
| `tests/crud/object_metadata.rs` | Restarted `x-amz-meta-*` persistence, initiation-time multipart metadata, size and storability refusals, and the pre-section record fixture. | Changing user-metadata persistence or the record's compatibility story. |
| `tests/crud/head_parts.rs` | HEAD part lengths/counts, version isolation and selector refusal statuses; registered under object_parts. | Changing HEAD partNumber support. |
| `tests/crud/object_parts.rs` | Restarted GET part windows, version isolation, ordinary objects and malformed or missing part tables. | Changing GET partNumber support. |
| `tests/crud/object_attributes.rs` | Selected metadata, checksums, versions and unsupported multipart detail. | Changing GetObjectAttributes. |
| `tests/crud/object_checksums.rs` | Header/trailer checksums, restarted reads, version isolation, copy preservation/recalculation and corrupt-record refusals. | Changing stored full-object checksums. |
| `tests/crud/content_encoding.rs` | Under `normalizing_content_encoding`: `aws-chunked` members dropped from an unframed upload's stored value, the rest joined with `, `, on `PutObject`, multipart and `REPLACE` copies; values without the token, lookalikes, `COPY` sources and other headers kept; the default stores the value as sent. | Changing how a stored `Content-Encoding` is written. |
| `tests/crud/content_headers.rs` | Restarted `Content-Type` and standard stored headers, the untyped default, per-version answers, multipart initiation headers, and COPY/REPLACE. | Changing stored representation headers. |
| `tests/crud/list_buckets.rs` | Bucket census order, owner, prefix/region filters, `max-buckets` paging, and cursor/page-size refusals. | Changing `ListBuckets`. |
| `tests/crud/delete_conditions.rs` | `If-Match` on `DeleteObject`: unread by default; with the option, `412` keeping objects, markers and missing keys, `204` on the own tag or `*`, legacy spellings, the unjudged versioned missing key, plain files, and a racing writer. | Changing conditional deletes. |
| `tests/crud/delete_objects.rs` | Batch deletion across versioning states, quiet mode, explicit versions, per-key errors, whole-request refusals, and refused keys answered alone with no delete marker. | Changing `DeleteObjects` or single-key deletion. |
| `tests/crud/write_attributes.rs` | `PutObject` tags and storage class, `CopyObject` class and tagging directive, and the bare copy-source `If-None-Match` refusal. | Changing what a write or copy stores besides bytes and metadata. |
| `tests/crud/post_object.rs` | Anonymous form uploads stored and read back, versions reported, storage refusals, and a SigV4-signed form without a `bucket` field bound to its routed bucket. | Changing POST Object storage or the signed-form path. |
| `tests/crud/object_tagging.rs` | Restarted current/version tag operations and lifecycle filter consumption. | Changing object tags or tag-selected lifecycle expiration. |
| `tests/fixtures/version-record-v0/**` | One version directory captured verbatim from the build that wrote eight-line records. | Proving this build still reads what the pre-metadata-section build wrote. |
| `tests/crud/versioning.rs` | Enabled, suspended, owner reporting, restart, corruption, symlink, version-cursor pairing, and vanished-cursor resume evidence. | Changing versioned object behavior, persistence, or version-listing cursors. |
| `tests/crud/versioning_exclusions.rs` | Excluded keys written as null versions and deleted without markers, every member persisted and surviving restart, the status-only answer, clearing, and fail-closed corruption. | Changing versioning exclusions or the persisted configuration. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-fs
```
