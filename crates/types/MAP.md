# rustfs-gateway-types crate map

Agent entry point for handwritten protocol scalars and the mounted generated DTO surface.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Scalar modules and generated DTO mounts. | Start here for a types task. |
| `src/persistence.rs` | Feature-independent persisted bucket-configuration codecs and decision seams. | Adding a persistence family or changing production metadata behavior. |
| `src/persistence/lifecycle.rs` | Full Lifecycle persistence structure, parser, timestamp normalization, and old-order writer. | Changing Lifecycle metadata compatibility or action semantics. |
| `src/compat.rs` | Milestone-bounded adapters to the pinned-s3s persistence oracle. | Auditing old-read or rollback behavior for D1-D5. |
| `src/compat/lifecycle.rs` | Pinned-s3s Lifecycle translation and decision observation. | Auditing Lifecycle D1-D5 against the old codec. |
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
