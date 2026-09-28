# MAP — rustfs-gateway-difftest

Agent entry point. File → responsibility → when you need to open it.

Migration-only (rustfs/backlog#1762): read `README.md` first for what a decode and an encode diff
compare and why this is not an in-process dual stack.

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
| `src/encode.rs` | `Differ::encode`: one s3s output through both stacks, answers normalised and compared (status, headers, body structure then bytes); the encoder faults. | An answer is compared or reported wrongly. |
| `src/normalize.rs` | The closed placeholder table and the exact format each replaced value is held to. | A stamped header or an id is normalised or checked wrongly. |
| `src/xmltree.rs` | The structural XML comparison: attributes, empty-element spelling, child order, presence, text, by element path. | An XML difference is named at the wrong path, or missed. |
| `src/convert/mod.rs` | Output-conversion helpers and `Unconvertible`. | A member converts wrongly across every operation. |
| `src/convert/object.rs` | GetObject, HeadObject, PutObject (seam), DeleteObject, DeleteObjects, CopyObject outputs. | One of those outputs converts wrongly. |
| `src/convert/listing.rs` | ListObjects, ListObjectsV2, ListObjectVersions, ListMultipartUploads, ListBuckets outputs. | A listing output converts wrongly. |
| `src/convert/multipart.rs` | CreateMultipartUpload, UploadPart, CompleteMultipartUpload, AbortMultipartUpload, ListParts outputs. | A multipart output converts wrongly. |
| `src/convert/bucket.rs` | CreateBucket, DeleteBucket, HeadBucket, GetBucketLocation (seam), Get/PutBucketVersioning outputs. | A bucket output converts wrongly. |
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
| `src/tests/outputs.rs` | The object output samples and the fixtures every sample shares. | Adding an object output sample. |
| `src/tests/outputs_more.rs` | The listing, multipart and bucket output samples. | Adding one of those samples. |
| `src/tests/encoding.rs` | Judges the output samples: exact ids per sample, no stale encode entry, every s3s output member set. | An encode matrix check fails. |
| `src/tests/encode_controls.rs` | The encoder faults (order, xmlns, empty spelling, upload id, extra header, request id), Content-Length, and every format both ways. | Auditing that an encode difference cannot go unreported. |
| `src/tests/register.rs` | Every register refusal and matching rule. | Changing the register format. |
| `src/tests/census.rs` | Each gateway projection held to the generated DTO field count. | A DTO gains a member. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-difftest
```
