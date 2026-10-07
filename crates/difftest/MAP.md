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
| `src/gateway.rs` | The assembled gateway, its recording handler, the gateway route lookup, and the RustFS profile's addressing switches. | The gateway side is driven or observed wrongly. |
| `src/resolver.rs` | The gateway's host resolver: path-style, or reading object paths as bucket paths under the misroute fault. | The misroute control, or how the gateway side classifies a host. |
| `src/oracle.rs` | The pinned s3s service, its access hook and recording backend. | The s3s side is driven or observed wrongly. |
| `src/decode.rs` | `decode_diff`, `Differ`, the four compared items, findings and their priority, the faults, and the `Profile` pairing (`rustfs_decode_diff`). | A finding is reported wrongly or ranked wrongly, or the RustFS pairing builds the wrong stacks. |
| `src/encode.rs` | `Differ::encode`: one s3s output through both stacks, answers normalised and compared (status, headers, body structure then bytes); the encoder faults. | An answer is compared or reported wrongly. |
| `src/normalize.rs` | The closed placeholder table and the exact format each replaced value is held to. | A stamped header or an id is normalised or checked wrongly. |
| `src/xmltree.rs` | The structural XML comparison: attributes, empty-element spelling, child order, presence, text, by element path; and every value a document holds below its root, entities resolved, for the answer diff's containment check. | An XML difference is named at the wrong path, or missed. |
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
| `src/samples/rustfs.rs` | The RustFS-profile request matrix: rows whose bucket and key both stacks must hand their handlers identically under `Profile::Rustfs`. | Adding a RustFS-profile row, or one of its differences changed. |
| `src/samples/outputs.rs` | The object output samples. | Adding an object output sample. |
| `src/samples/outputs_more.rs` | The listing, multipart and bucket output samples. | Adding one of those samples. |
| `src/corpus.rs` | A recorded corpus entry as a request, with each adjustment and skip named. | A recorded request is changed, skipped, or replayed wrongly. |
| `src/runner.rs` | The runners' command line, sampling, budget, report and exit statuses. | A runner exits with the wrong status or reports wrongly. |
| `src/bin/decode-diff.rs`, `src/bin/encode-diff.rs` | The two runner binaries. | Never; they only call `runner::main`. |
| `src/tests/matrix.rs` | Judges the matrix: exact ids per row, no stale entry, every member (shared, one-sided, list element) exercised. | A matrix check fails, or the census rule changes. |
| `src/tests/rustfs_profile.rs` | Judges the RustFS-profile matrix: exact ids per row, the key each handler was handed, and the mismatched-profile controls. | A RustFS-profile row or control fails. |
| `src/tests/controls.rs` | The injected faults (misroute, one byte eaten, one member skewed) and the finding rules. | Auditing that a difference cannot go unreported. |
| `src/tests/encoding.rs` | Judges the output samples: exact ids per sample, no stale encode entry, every s3s output member set. | An encode matrix check fails. |
| `src/tests/encode_controls.rs` | The encoder faults (order, xmlns, empty spelling, upload id, extra header, request id), Content-Length, and every format both ways. | Auditing that an encode difference cannot go unreported. |
| `src/tests/calendar.rs` | Calendar, weekday and clock bounds for independently checked output dates. | Auditing a date hidden by normalization. |
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
| `src/seam/mod.rs` | The seam decode diff (rustfs/gateway#1076): what the RustFS app layer is handed on each stack, compared whole with the generated member census; and the seam answer diff, one legacy output written by both stacks and compared finding by finding and value by value. | A seam finding is reported wrongly, or an answer value is lost unnoticed. |
| `src/seam/stacks.rs` | Both stacks of the seam diff: the assembled gateway converting through the production seam, the pinned legacy service recording its input. | A side is driven or recorded wrongly. |
| `src/seam/table.rs` | Every covered operation, how the RustFS adapter converts it (supplied copy source, patched delete list, raw request for legacy-only members, an upload's trailer handle and legacy checksum algorithm), and its census lookups. | An operation joins the seam or its adapter step changes. |
| `src/seam/trailers.rs` | The trailer handle each stack hands a RustFS upload body, read once the body ended, and the adapter's attach step (rustfs/gateway#1148). | A trailer difference is reported wrongly. |
| `src/seam/samples.rs` | The seam register (`sd-*` findings with RustFS evidence), unreached members, and the row helpers. | Classifying a difference, or adding a row family. |
| `src/seam/samples/*.rs` | The seam rows: object writes, configuration writes, bucket lifecycle and reads, one row per finding, every checksum-required write with no integrity claim (`omitted.rs`, rustfs/backlog#1677 R5), and trailer uploads (`trailers.rs`, rustfs/gateway#1148). | Adding a row. |
| `src/seam/answers.rs` | The seam answer rows' types and helpers, the answer register (`sa-*` findings: wire differences outside the encode matrix, pinned and reported), and the output members no row can set. | Classifying an answer difference, or adding an answer row family. |
| `src/seam/answers/*.rs` | The seam answer rows: bucket configurations, object sub-resources, and the nested checksum members per algorithm. | Adding an answer row. |
| `src/tests/seam_answers.rs` | Every kind of header a RustFS answer sets beside its output, written by both stacks as the same lines through the seam's `answer_from_legacy`, the one replacing an output member's header included. | An answer header is written differently or refused. |
| `src/tests/seam_overrides.rs` | The census of the seam generator's overrides: every entry of `overrides.rs` read from source and proven lossless or fail-closed by a finding, a row, the fact table or a named test. | An override is added or its proof moves. |
| `src/tests/seam.rs` | Judges the seam diff: rows as declared, matrix differences registered, every legacy input member accounted for, empty optional headers, no stale finding, negative controls. | A seam judgement fails. |
| `src/tests/seam_outputs.rs` | Judges the seam answer diff: every answer row and every encode-matrix sample through the production seam as declared (the samples the RustFS profile answers otherwise pinned beside), no value the legacy answer holds missing from the gateway's, every legacy output member written or refused by name, no stale answer finding, negative controls. | A seam answer judgement fails. |
| `src/tests/seam_switches.rs` | The switch census of the RustFS profile: every call of the gateway's two `rustfs_profile` preset halves and of `compat/sut`'s builder chain beside them, but the assembly the seam diff replaces, is turned on by the seam stack; the source reading's negative controls. | The RustFS profile gains a switch, or the preset's switches are read wrongly. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-difftest
```
