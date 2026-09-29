# rustfs-gateway-types crate map

Agent entry point for handwritten protocol scalars and the mounted generated DTO surface.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Scalar modules and generated DTO mounts. | Start here for a types task. |
| `src/ext.rs` | Runtime XML extension vtables, borrowed codec policy, typed values, and persisted rewrite guard. | Registering an extension field, selecting unknown-element behavior, or preventing lossy persisted XML replacement. |
| `src/persistence.rs` | Feature-independent persisted bucket-configuration codecs and decision seams for the implemented families. | Adding a persistence family or changing production metadata behavior. |
| `src/persistence/dto_bridge.rs` | Lossless bridges between generated HTTP DTOs and historical persistence shapes. | Connecting a generated configuration DTO to persisted XML without duplicating a codec. |
| `src/persistence/dto_bridge/cors_object_lock.rs` | Generated DTO bridges for the CORS and Object Lock persistence families. | Connecting either family to persisted XML or auditing lossless field mapping. |
| `src/persistence/dto_bridge/lifecycle.rs` | Generated DTO bridge for Lifecycle persistence. | Connecting Lifecycle metadata to generated DTOs or auditing old-only field loss. |
| `src/persistence/dto_bridge/logging_website.rs` | Generated DTO bridges for Bucket Logging and Website persistence. | Connecting either family to persisted XML or auditing nested-field loss. |
| `src/persistence/dto_bridge/notification.rs` | Generated DTO bridge for Notification persistence. | Connecting notification metadata to generated DTOs or auditing destination/filter loss. |
| `src/persistence/dto_bridge/replication.rs` | Generated DTO bridge for Replication persistence. | Connecting Replication metadata to generated DTOs or auditing nested-field loss. |
| `src/persistence/accelerate_payment.rs` | Production Accelerate and Request Payment persistence codecs and runtime decisions. | Changing those two metadata families or their historical XML compatibility. |
| `src/persistence/lifecycle.rs` | Full Lifecycle persistence structure, parser, timestamp normalization, and old-order writer. | Changing Lifecycle metadata compatibility or action semantics. |
| `../dialect-minio/src/lib.rs` | Clean-room concrete `DelMarkerExpiration` registration consuming the generic lifecycle extension point. | Reviewing the first real runtime extension consumer without putting a vendor type in this crate. |
| `src/cors_tagging.rs` | Persisted CORS and Tagging codecs plus runtime behavior projections. | Changing stored CORS rules, tag sets, or their migration evidence. |
| `src/persistence/notification.rs` | Full Notification persistence structure, old-order writer, bounded parser, and routing decisions. | Changing Notification metadata compatibility or event-routing semantics. |
| `src/compat.rs` | Milestone-bounded s3s facade: `OracleRevision`, per-thread revision selection, shared observations, dispatch to one adapter compilation per pinned s3s revision (`compat-s3s`), and the migration seam compiled per revision as `s3s_0_17_0` (`compat-s3s-0-17-0`, what RustFS links) and `s3s_9c4690d8`, with the one per-revision hook (`expires`) and the shared `ConversionError`. | Auditing which s3s revisions admission measures, how a revision is selected, or which seam revision the RustFS adapter links. |
| `src/compat/seam/put_object.rs` | Pure PutObject conversion, compiled once per seam revision: gateway input to s3s input, s3s output to gateway output (with the answer's own headers, `answer_from_legacy`), live body moved unread. | Auditing the single-operation migration seam or a member the goldens decode/encode diff names. |
| `src/compat/seam/get_bucket_location.rs` | Pure, total GetBucketLocation conversion, compiled once per seam revision: gateway input to s3s input, s3s constraint to gateway output with its exact spelling. | Auditing the M1 GetBucketLocation seam. |
| `src/compat/seam/request_context.rs` | Pure request-context conversion, compiled once per seam revision: the facts a handler's request context holds (method, raw target, raw header lines, principal with its handed-over secret, verified scope, host region) to the `s3s::S3Request` context, refusing trailers, a missing secret and malformed values by member name; no extensions. | Auditing what a RustFS app body reads besides its input, or a context member the goldens context diff names. |
| `src/compat/seam/error.rs` | The handler-error seam, compiled once per seam revision: an s3s error from a RustFS body to a `Refusal` verdict naming one gateway constructor, reading a `304`'s `ETag`, a `416`'s `Content-Range: bytes */<length>` and a delete marker's flag, version id and `Last-Modified` from the error's own headers, and refusing everything else by member name; and the legacy decoder's own refusal for a member only it reads (`refusal_from_conversion`). | Mapping a RustFS body error in the ring-2 adapter, or auditing why one answers `500` through it. |
| `src/compat/seam/leaf.rs` | Hand-written leaf conversions the generated seam calls (timestamps, entity tags and conditions, checksum fan-out, names, ranges, copy sources, upload ids, body streams both ways, and the members only the legacy decoder reads, decoded from the raw query and headers with its grammar), `s3s_0_17_0` only. | A generated seam member fails on a scalar, or a body crosses the seam. |
| `src/compat/seam/census_tests.rs` | The generated member census against the pinned structures: differences named exactly (nested, per element, one-sided as a whole), present members exactly, every named path in `PATHS`. | Changing the census generator or reading a census path. |
| `src/compat/seam/generated_tests.rs` | Leaf round trips and refusals, and generated operation conversions (members, nested shapes, event-hold refusal, upload ids) against s3s 0.17.0. | Changing a leaf or the seam generator. |
| `src/compat/tests.rs` | Proves the manifest pins exactly the named revisions and that selection reaches a different compilation in both directions. | Changing a pinned oracle revision or the selector. |
| `src/compat/oracle/bucket_configs.rs` | Old-codec adapters for Versioning, Object Lock, Bucket Encryption, CORS, Public Access Block, Tagging, Logging and Website, compiled once per revision. | Auditing the old side of those families' D1-D5 evidence. |
| `src/compat/oracle/accelerate_payment.rs` | Independent old-codec observations for Accelerate and Request Payment, compiled once per revision. | Auditing the old side of either family’s D1-D5 evidence. |
| `src/compat/oracle/lifecycle.rs` | Old-codec Lifecycle translation and decision observation, compiled once per revision. | Auditing Lifecycle D1-D5 against the old codec. |
| `src/compat/oracle/notification.rs` | Independent old-codec Notification structure and routing observations, compiled once per revision. | Auditing Notification D1-D5 against the old codec. |
| `src/persistence/logging_website.rs` | Bucket Logging and Website persisted structures, codecs, and runtime decision seams. | Auditing either family without loading unrelated persistence implementations. |
| `src/persistence/replication.rs` | Full Replication persistence structure, permissive top-level parser, strict nested parser, and old-order writer. | Changing Replication metadata compatibility or rule semantics. |
| `src/compat/oracle/replication.rs` | Old-codec Replication translation, exact writer, and runtime rule observation, compiled once per revision. | Auditing Replication D1-D5 against the old codec. |
| `src/scalar/naming.rs` | The single normalisation, the key and bucket floors, `SlashPolicy`, `NamePolicy`, and the `NameValidator` extension point. | A client-chosen key or bucket is decoded, folded or refused wrongly. |
| `src/scalar/slash.rs` | The two slash rewrites (`Collapse`, and legacy RustFS's fold of a key that starts with `/`). | A run of slashes is folded wrongly. |
| `src/scalar/key_floor.rs` | `KeyFloor`: the unconditional floor, or legacy RustFS's key rule for a deployment fronting RustFS (#1107). | A key reaches the backend, or is refused, under the wrong floor. |
| `src/scalar/bucket.rs` | Validated bucket names. | Bucket syntax or display changes. |
| `src/scalar/key.rs` | Lossless object-key bytes. | Key normalization/encoding changes. |
| `src/scalar/etag.rs` | Context-typed entity tags. | ETag quoting or comparison changes. |
| `src/scalar/checksum.rs` | Checksum algorithms and values. | Integrity fields change. |
| `src/scalar/checksummer.rs` | Streaming digests for the ten checksum algorithms. | A digest backend or its byte order changes. |
| `src/scalar/timestamp.rs` | S3 timestamp forms. | A date parses or renders wrongly. |
| `src/scalar/tests/timestamp_corpus_tests.rs` | Complete data-driven Smithy timestamp compatibility check. | Timestamp parsing or exact rendering changes. |
| `tests/data/` | Pinned Smithy timestamp corpus plus source, license, digest and format mapping. | Refreshing or auditing `c-ts-0001` evidence. |
| `src/scalar/cursor.rs` | Server-minted pagination cursors. | Continuation tokens change. |
| `src/scalar/range.rs` | Range parsing and length-dependent resolution, driven by generated typed range inputs. | A byte-range form or boundary changes. |
| `src/scalar/error_code.rs` | `ErrorCode` itself: the newtype, `custom`, `known`, and the include of the generated status table. No status is written here — the rows live in `model/overlays/error-status.toml` and reach this file through `generated/error_status.rs`. | Add an error code, or change how one is constructed. |
| `src/tests/dto_tests.rs` | Generated DTO semantic contracts. | Codegen changes DTO shape. |
| `benches/checksum.rs` | CRC hardware-calculator gate and checksum throughput records. | A checksum backend or `crc-fast` feature changes. |
| `../../OPERATIONS.md` | Generated operation/field index. | Inspect operation shapes without reading generated code. |
| `../../spec/operations/` | Generated field-binding facts. | Inspect one binding without reading generated code. |
| `generated/**` | Mounted generated DTO implementation. | Never read; use `OPERATIONS.md` and `spec/operations/`. |
