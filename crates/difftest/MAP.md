# MAP — rustfs-gateway-difftest

Agent entry point. File → responsibility → when you need to open it.

Migration-only (rustfs/backlog#1762): read `README.md` first for what one diff compares and why
this is not an in-process dual stack.

| File | Responsibility | Read it when |
| --- | --- | --- |
| `README.md` | What is compared, the register rule, the five reasons against a dual stack, what is not covered. | Starting any task here. |
| `known-diffs.toml` | Every accepted difference between the stacks, with reason and review date. | A finding is reported, or a difference went away. |
| `src/lib.rs` | Module wiring and the public surface. | Start here for code. |
| `src/request.rs` | One raw request as both stacks receive it. | A request needs another shape (bytes, pieces, TLS). |
| `src/probe.rs` | The body both stacks read, and the one-thread executor. | A stack reads the body differently than the harness offers it. |
| `src/gateway.rs` | The assembled gateway, its recording handler, and the gateway route lookup. | The gateway side is driven or observed wrongly. |
| `src/resolver.rs` | The gateway's host resolver: path-style, or reading object paths as bucket paths under the misroute fault. | The misroute control, or how the gateway side classifies a host. |
| `src/oracle.rs` | The pinned s3s service, its access hook and recording backend. | The s3s side is driven or observed wrongly. |
| `src/decode.rs` | `decode_diff`, `Differ`, the four compared items, findings and their priority, the faults. | A finding is reported wrongly or ranked wrongly. |
| `src/fields.rs` | Member paths and the one canonical spelling of every value type. | A value is spelled differently on the two sides for the same meaning. |
| `src/known.rs` | Reads the register strictly and judges findings against it. | An entry is refused, or matches too much or too little. |
| `src/project/mod.rs` | The diffed-operation table, both projection macros, the s3s recording methods. | Adding an operation to the member diff. |
| `src/project/object.rs` | GetObject, HeadObject, PutObject, DeleteObject, DeleteObjects, CopyObject projections. | One of those operations' members is compared wrongly. |
| `src/project/listing.rs` | ListObjects, ListObjectsV2, ListObjectVersions, ListMultipartUploads projections. | A listing member is compared wrongly. |
| `src/project/multipart.rs` | CreateMultipartUpload, UploadPart, CompleteMultipartUpload, AbortMultipartUpload, ListParts projections. | A multipart member is compared wrongly. |
| `src/project/bucket.rs` | CreateBucket, DeleteBucket, HeadBucket, ListBuckets, GetBucketLocation, Get/PutBucketVersioning projections. | A bucket member is compared wrongly. |
| `src/tests/rows.rs` | The request matrix: each row and the exact register ids its findings must match. | Adding a row, or a row's differences changed. |
| `src/tests/matrix.rs` | Judges the matrix: exact ids per row, no stale entry, every member (shared, one-sided, list element) exercised. | A matrix check fails, or the census rule changes. |
| `src/tests/controls.rs` | The injected faults (misroute, one byte eaten, one member skewed) and the finding rules. | Auditing that a difference cannot go unreported. |
| `src/tests/register.rs` | Every register refusal and matching rule. | Changing the register format. |
| `src/tests/census.rs` | Each gateway projection held to the generated DTO field count. | A DTO gains a member. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-difftest
```
