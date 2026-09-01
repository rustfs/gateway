# rustfs-gateway-types crate map

Agent entry point for handwritten protocol scalars and the mounted generated DTO surface.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Scalar modules and generated DTO mounts. | Start here for a types task. |
| `src/ext.rs` | Runtime XML extension vtables, borrowed codec policy, typed values, and persisted rewrite guard. | Registering an extension field, selecting unknown-element behavior, or preventing lossy persisted XML replacement. |
| `src/persistence.rs` | Feature-independent persisted bucket-configuration codecs and decision seams for the implemented families. | Adding a persistence family or changing production metadata behavior. |
| `src/persistence/dto_bridge.rs` | Lossless bridges between generated HTTP DTOs and historical persistence shapes. | Connecting a generated configuration DTO to persisted XML without duplicating a codec. |
| `src/persistence/dto_bridge/cors_object_lock.rs` | Generated DTO bridges for the CORS and Object Lock persistence families. | Connecting either family to persisted XML or auditing lossless field mapping. |
| `src/persistence/dto_bridge/logging_website.rs` | Generated DTO bridges for Bucket Logging and Website persistence. | Connecting either family to persisted XML or auditing nested-field loss. |
| `src/persistence/dto_bridge/notification.rs` | Generated DTO bridge for Notification persistence. | Connecting notification metadata to generated DTOs or auditing destination/filter loss. |
| `src/persistence/dto_bridge/replication.rs` | Generated DTO bridge for Replication persistence. | Connecting Replication metadata to generated DTOs or auditing nested-field loss. |
| `src/persistence/accelerate_payment.rs` | Production Accelerate and Request Payment persistence codecs and runtime decisions. | Changing those two metadata families or their historical XML compatibility. |
| `src/persistence/lifecycle.rs` | Full Lifecycle persistence structure, parser, timestamp normalization, and old-order writer. | Changing Lifecycle metadata compatibility or action semantics. |
| `../dialect-minio/src/lib.rs` | Clean-room concrete `DelMarkerExpiration` registration consuming the generic lifecycle extension point. | Reviewing the first real runtime extension consumer without putting a vendor type in this crate. |
| `src/cors_tagging.rs` | Persisted CORS and Tagging codecs plus runtime behavior projections. | Changing stored CORS rules, tag sets, or their migration evidence. |
| `src/persistence/notification.rs` | Full Notification persistence structure, old-order writer, bounded parser, and routing decisions. | Changing Notification metadata compatibility or event-routing semantics. |
| `src/compat.rs` | Milestone-bounded adapters to the pinned-s3s persistence oracle for the implemented families. | Auditing old-read or rollback behavior for D1-D5. |
| `src/compat/accelerate_payment.rs` | Independent pinned-s3s observations for Accelerate and Request Payment. | Auditing the old side of either family’s D1-D5 evidence. |
| `src/compat/lifecycle.rs` | Pinned-s3s Lifecycle translation and decision observation. | Auditing Lifecycle D1-D5 against the old codec. |
| `src/compat/notification.rs` | Independent pinned-s3s Notification structure and routing observations. | Auditing Notification D1-D5 against the old codec. |
| `src/persistence/logging_website.rs` | Bucket Logging and Website persisted structures, codecs, and runtime decision seams. | Auditing either family without loading unrelated persistence implementations. |
| `src/persistence/replication.rs` | Full Replication persistence structure, permissive top-level parser, strict nested parser, and old-order writer. | Changing Replication metadata compatibility or rule semantics. |
| `src/compat/replication.rs` | Pinned-s3s Replication translation, exact writer, and runtime rule observation. | Auditing Replication D1-D5 against the old codec. |
| `src/scalar/bucket.rs` | Validated bucket names. | Bucket syntax or display changes. |
| `src/scalar/key.rs` | Lossless object-key bytes. | Key normalization/encoding changes. |
| `src/scalar/etag.rs` | Context-typed entity tags. | ETag quoting or comparison changes. |
| `src/scalar/checksum.rs` | Checksum algorithms and values. | Integrity fields change. |
| `src/scalar/timestamp.rs` | S3 timestamp forms. | A date parses or renders wrongly. |
| `src/scalar/tests/timestamp_corpus_tests.rs` | Complete data-driven Smithy timestamp compatibility check. | Timestamp parsing or exact rendering changes. |
| `tests/data/` | Pinned Smithy timestamp corpus plus source, license, digest and format mapping. | Refreshing or auditing `c-ts-0001` evidence. |
| `src/scalar/cursor.rs` | Server-minted pagination cursors. | Continuation tokens change. |
| `src/scalar/range.rs` | Range parsing and length-dependent resolution, driven by generated typed range inputs. | A byte-range form or boundary changes. |
| `src/scalar/error_code.rs` | `ErrorCode` itself: the newtype, `custom`, `known`, and the include of the generated status table. No status is written here — the rows live in `model/overlays/error-status.toml` and reach this file through `generated/error_status.rs`. | Add an error code, or change how one is constructed. |
| `src/tests/dto_tests.rs` | Generated DTO semantic contracts. | Codegen changes DTO shape. |
| `../../OPERATIONS.md` | Generated operation/field index. | Inspect operation shapes without reading generated code. |
| `../../spec/operations/` | Generated field-binding facts. | Inspect one binding without reading generated code. |
| `generated/**` | Mounted generated DTO implementation. | Never read; use `OPERATIONS.md` and `spec/operations/`. |
