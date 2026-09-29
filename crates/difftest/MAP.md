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
| `src/samples/mod.rs` | The built-in inputs both runners and the tests share, and their fixtures. | Adding a sample kind. |
| `src/samples/requests.rs` | The request matrix: each row and the exact register ids its findings must match. | Adding a row, or a row's differences changed. |
| `src/samples/outputs.rs` | The object output samples. | Adding an object output sample. |
| `src/samples/outputs_more.rs` | The listing, multipart and bucket output samples. | Adding one of those samples. |
| `src/corpus.rs` | A recorded corpus entry as a request, with each adjustment and skip named. | A recorded request is changed, skipped, or replayed wrongly. |
| `src/runner.rs` | The runners' command line, sampling, budget, report and exit statuses. | A runner exits with the wrong status or reports wrongly. |
| `src/bin/decode-diff.rs`, `src/bin/encode-diff.rs` | The two runner binaries. | Never; they only call `runner::main`. |
| `src/tests/matrix.rs` | Judges the matrix: exact ids per row, no stale entry, every member (shared, one-sided, list element) exercised. | A matrix check fails, or the census rule changes. |
| `src/tests/controls.rs` | The injected faults (misroute, one byte eaten, one member skewed) and the finding rules. | Auditing that a difference cannot go unreported. |
| `src/tests/encoding.rs` | Judges the output samples: exact ids per sample, no stale encode entry, every s3s output member set. | An encode matrix check fails. |
| `src/tests/encode_controls.rs` | The encoder faults (order, xmlns, empty spelling, upload id, extra header, request id), Content-Length, and every format both ways. | Auditing that an encode difference cannot go unreported. |
| `src/tests/register.rs` | Every register refusal and matching rule. | Changing the register format. |
| `src/tests/runner.rs` | Empty and missing corpus, unregistered corpus difference, sampling, budget, command line, every corpus adjustment and skip. | A runner or corpus behaviour changes. |
| `src/fuzz.rs` | The fuzz input format (a raw request) and the two fuzz properties, with the known classes each input domain leaves out. | A fuzz target reports something, or its input domain changes. |
| `src/fuzz_case.rs` | A decode_diff fuzz artifact as a conformance case draft under `conformance/cases/_from_fuzz/`. | Converting a fuzz finding into a case. |
| `src/bin/fuzz-to-case.rs` | The converter's command line. | Never; it only calls `fuzz_case::draft`. |
| `src/tests/fuzz.rs` | The stable replay of both properties (committed seeds, fixed-seed samplers), the reader, the converter, and both properties failing on injected faults. | A fuzz property or the converter changes. |
| `src/tee.rs` | The shadow proxy's copy of a connection read back as HTTP/1.1 requests: framing, pipelining, caps, and giving up on what is not HTTP. | A copied request is cut, merged or lost wrongly. |
| `src/shadow.rs` | The shadow proxy: byte-for-byte forwarding, the never-waited-on judging queue, and the verdict per request. | The proxy changes traffic, or a verdict is wrong. |
| `src/bin/shadow-proxy.rs` | The proxy's command line. | Changing its options. |
| `src/tests/shadow.rs` | The copy's framing cases, bytes unchanged both ways, a stalled diff never slowing traffic, the verdicts. | The proxy or its copy changes. |
| `src/tests/census.rs` | Each gateway projection held to the generated DTO field count. | A DTO gains a member. |
| `src/seam/mod.rs` | The seam decode diff (rustfs/gateway#1076): what the RustFS app layer is handed on each stack, compared whole with the generated member census. | A seam finding is reported wrongly. |
| `src/seam/stacks.rs` | Both stacks of the seam diff: the assembled gateway converting through the production seam, the pinned legacy service recording its input. | A side is driven or recorded wrongly. |
| `src/seam/table.rs` | Every covered operation, how the RustFS adapter converts it (supplied copy source, patched delete list, raw request for legacy-only members), and its census lookups. | An operation joins the seam or its adapter step changes. |
| `src/seam/samples.rs` | The seam register (`sd-*` findings with RustFS evidence), unreached members, and the row helpers. | Classifying a difference, or adding a row family. |
| `src/seam/samples/*.rs` | The seam rows: object writes, configuration writes, bucket lifecycle and reads, and one row per finding. | Adding a row. |
| `src/tests/seam.rs` | Judges the seam diff: rows as declared, matrix differences registered, every legacy input member accounted for, empty optional headers, no stale finding, negative controls. | A seam judgement fails. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-difftest
```
