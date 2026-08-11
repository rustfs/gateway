# rustfs-gateway-types crate map

Agent entry point for handwritten protocol scalars and the mounted generated DTO surface.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Scalar modules and generated DTO mounts. | Start here for a types task. |
| `src/scalar/bucket.rs` | Validated bucket names. | Bucket syntax or display changes. |
| `src/scalar/key.rs` | Lossless object-key bytes. | Key normalization/encoding changes. |
| `src/scalar/etag.rs` | Context-typed entity tags. | ETag quoting or comparison changes. |
| `src/scalar/checksum.rs` | Checksum algorithms and values. | Integrity fields change. |
| `src/scalar/timestamp.rs` | S3 timestamp forms. | A date parses or renders wrongly. |
| `src/scalar/tests/timestamp_corpus_tests.rs` | Complete data-driven Smithy timestamp compatibility check. | Timestamp parsing or exact rendering changes. |
| `tests/data/` | Pinned Smithy timestamp corpus plus source, license, digest and format mapping. | Refreshing or auditing `c-ts-0001` evidence. |
| `src/scalar/cursor.rs` | Server-minted pagination cursors. | Continuation tokens change. |
| `src/error.rs` | Public S3 error-code vocabulary. | Add or map an error code. |
| `src/compat.rs` | Temporary s3s conversion feature. | Work on the milestone-bounded compatibility seam. |
| `src/tests/dto_tests.rs` | Generated DTO semantic contracts. | Codegen changes DTO shape. |
| `../../OPERATIONS.md` | Generated operation/field index. | Inspect operation shapes without reading generated code. |
| `../../spec/operations/` | Generated field-binding facts. | Inspect one binding without reading generated code. |
| `generated/**` | Mounted generated DTO implementation. | Never read; use `OPERATIONS.md` and `spec/operations/`. |
