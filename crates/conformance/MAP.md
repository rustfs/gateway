# `rustfs-gateway-conformance` — agent map

The data-driven S3 conformance suite. The corpus lives in `conformance/` at the repository root
(`case.schema.json`, `cases/**/*.toml`, `goldens/`); this crate is the runner that executes it and
can be pointed at any S3 implementation.

Two third-party dependencies, and only two: `http` and `bytes`. They are the parameter types of the
facade's own entry point — `S3Service::call_bytes(http::Request<bytes::Bytes>)` — so a caller
cannot name that call without them. Everything else is still hand-written here, because this crate
is a product other implementations run against themselves and every dependency it carries is one
they inherit: the TOML reader, JSON reader, schema evaluator, pattern matcher, SHA-256, MD5,
CRC-32 and the single-threaded executor are all in this crate, small and unit-tested.

## Entry points

```bash
cargo run -p rustfs-gateway-conformance --bin rustfs-gateway-conformance -- validate
cargo run -p rustfs-gateway-conformance --bin rustfs-gateway-conformance -- run --filter 'etag/'
cargo run -p rustfs-gateway-conformance --bin rustfs-gateway-conformance -- baseline > conformance/baseline.json
cargo xtask conformance run --baseline conformance/baseline.json
```

Exit codes: `0` ok, `1` a regression against the baseline, `2` usage, `3` environment — including a
run in which nothing executed. An environment failure is never `1`, because a run that could not
reach its target must not be recordable as a run whose assertions failed.

## Files

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/lib.rs` | The four properties the crate is built around, and the module list | First. It is ten lines of orientation |
| `src/value.rs` | The order-preserving document model shared by TOML and JSON | You need to read a field out of a case |
| `src/toml.rs` | The TOML 1.0 subset the schema can express; bare datetimes are refused by name | A case file will not parse |
| `src/json.rs` | JSON reader for `case.schema.json` and the baseline | Rarely |
| `src/pattern.rs` | The regular-expression subset the schema's `pattern` keyword needs | A schema `pattern` is refused at load |
| `src/schema.rs` | JSON Schema draft 2020-12 subset, evaluated against the parsed TOML | A case is rejected and you want to know by which keyword |
| `src/corpus.rs` | Finding `conformance/`, loading every case, schema-checking it | The corpus will not load, or you are adding a discovery rule |
| `src/lint.rs` | The conventions the schema cannot express: naming, goldens, capture wiring, tag vocabulary | A case fails with a `lint/` rule |
| `src/interpolate.rs` | `${capture.<name>}` substitution, and the refusal of every other form | You are looking at a computed-value request |
| `src/observation.rs` | What a transport observed: head, body, trailers, the two byte counters, timing | You are writing a transport |
| `src/sut.rs` | The `Sut` trait, `Transport`/`Profile`, and `REQUIRED_FACADE_EXPORTS` | You are wiring a real target |
| `src/expect.rs` (+ `expect/tests.rs`) | One `[expect]` block judged against one `Observation` | An assertion did not fire, or you are adding one |
| `src/xml.rs` | The response-body scanner: root, xmlns, child order, empty-element style, redaction | A body assertion misreads a response |
| `src/sha256.rs` | SHA-256 for `expect.body.sha256`. Never authenticates anything | Rarely |
| `src/md5.rs` | MD5, because an S3 entity tag is one. The fixture stamps objects with it | An `If-Match` case disagrees about a tag |
| `src/crc32.rs` | CRC-32/ISO-HDLC for `x-amz-checksum-crc32`. Written out because the facade exports `ChecksumSpec` but not the `Checksummer` trait, so the framework's own implementation cannot be reached from outside the workspace | A multipart checksum case disagrees about a digest |
| `src/time.rs` | `[clock] fixed` / `request_time` into a Unix second and a SigV4 stamp | A clock-pinned case is an hour out |
| `src/exec.rs` | Twenty lines of `std` that run one future to completion | Never, unless a run hangs |
| `src/fixture.rs` | **The stub backend**: what `[setup]` established, and the answers built out of it — the six listings with their pagination and cursors, the copy family with its source parser, source gate and span rule, the multipart family with its upload-id ownership check, part-order and part-digest rules, size floor and composite entity tag, and the shape of its refusals (`unsatisfiable`, `precondition`/`sole_condition`, `no_such_key`) | A case fails on a value the fixture chose, or an error document is missing an element |
| `src/inprocess.rs` | **The wired target**: request in, signature, `call_bytes`, `Observation` out | A case is skipped, or signs wrongly |
| `src/runner.rs` (+ `runner/tests.rs`) | Selection, interpolation, driving exchanges, one verdict per case | A case reached the wrong conclusion |
| `src/report.rs` | Verdicts, grouping by capability domain, baseline comparison, text/JSON/JUnit output | You are changing what fails a run |
| `src/cli.rs` | Argument parsing and the exit codes | You are adding a flag |
| `src/bin/rustfs-gateway-conformance.rs` | The product binary. Contains no decisions | Never |
| `tests/corpus.rs` | The gate: the whole corpus loads, validates, and concludes — through the public API only | It goes red |
| `tests/wired.rs` | The other gate: a target is wired and cases really executed, not skipped | It goes red |

## Where a verdict comes from

```text
corpus   read cases/**/*.toml  -> parse error or schema violation = Failed (phase load/schema)
lint     naming, goldens, captures, tags  -> a `deny` rule = Failed (phase convention)
runner   interpolate ${capture.*}, drive exchanges  -> SutError = Skipped, with the reason
expect   judge each [expect]  -> any failing assertion = Failed (phase execute)
report   group, compare to the baseline, choose the exit code
```

Every case reaches one of `passed` / `failed` / `skipped`, and a skip always carries its reason.
"Did not run" and "ran and was red" are different facts; a report that conflates them is how a
suite stops asserting anything without anyone noticing.

## Current state — read this before concluding anything from a red run

A target **is** wired. `inprocess::InProcess` assembles a service from the `rustfs-gateway` facade,
signs each request with `rustfs_gateway::sig::Signer`, drives `S3Service::call_bytes`, and hands the
response head — in wire order — to the expectation engine. `sut::Unwired` is retained only as the
"no target" record and as the runner's own test double.

The baseline on disk is older than the current run:

```text
conformance/baseline.json   195 cases: 87 passed, 103 failed, 5 skipped
current                     195 cases: 161 passed, 29 failed, 5 skipped
```

Regenerate it with `baseline > conformance/baseline.json` in the same change that moves the
numbers, or the tolerance meant for the old failures starts hiding new ones.

Run with `--baseline conformance/baseline.json` and the exit code is `0` until something regresses.
Without the baseline the run exits `1`, which is correct and is the point: the red is real.
**The cases were written from the AWS documentation, not from this implementation**, so a run is
expected to be red, and the baseline exists to freeze how red rather than to excuse it.

### What the red is made of, in descending order

1. **`encoding-type` is decoded, echoed, and never applied.** `spec/operations/ListObjects.toml`,
   `ListObjectsV2.toml`, `ListObjectVersions.toml` and `ListMultipartUploads.toml` each declare
   `url_encoded_fields`, and no generated codec reads it — nor does anything call
   `ObjectKey::needs_url_encoding`, which exists for exactly this. `c-list-0017`, `c-list-0035` and
   `c-mpu-0013` are the cases that see it. The fixture deliberately does **not** encode on the way
   out: doing it in a backend would hide a code-generator gap behind code every other backend would
   then have to write too.
2. **`ListBuckets` nests its entries the wrong way round.** The generated codec opens `Bucket` once
   and writes a `Buckets` element per entry, so the body reads
   `<Bucket><Buckets><Name>…</Name></Buckets></Bucket>` where AWS reads
   `<Buckets><Bucket><Name>…</Name></Bucket></Buckets>`. `c-list-0015` is the case that sees it.
3. **A refusal can now carry its own headers and elements, and the fixture uses them.** `HandlerError`
   gained `with_header(ErrorHeader)` / `with_detail(ErrorDetail)` and the two whole-refusal
   constructors, both closed sets so that a backend names a *fact* and the framework spells the
   header — see `crates/core/src/fault.rs`. `fixture` answers a `416` with
   `ErrorHeader::UnsatisfiedRange` plus `<ActualObjectSize>`, a `412` with `<Condition>`, and a
   `404` with `<Key>`, which closed `c-range-0009`, `c-range-0014`, `c-object-0014`,
   `c-object-0007` and `c-cond-0001`. Two remainders, both framework rather than backend:
   * **`<RangeRequested>` cannot be filled.** `HandlerError::unsatisfiable_range` takes the `Range`
     header *as it arrived*, and no handler ever sees that text — the codec parsed it into
     `rustfs_gateway_types::ByteRange`, the facade does not re-export the type, and the type offers
     no way back to its own bytes. This is finding 11's gap on the refusal path. `fixture`
     therefore does not call `unsatisfiable_range` at all and emits the one element it can know;
     `c-range-0010` asserts the document byte for byte and stays red. Re-spelling the range out of
     the parsed value would be a mirror of a parser, and the test
     `an_unsatisfiable_range_invents_no_requested_range` is what keeps one from appearing.
   * **`<Condition>` is only nameable for a single-condition request.**
     `ConditionalOutcome::PreconditionFailed` says that a condition failed and not which, so
     `fixture::sole_condition` names the header only when exactly one arrived — a fact, not a
     deduction. Attributing a multi-condition failure means re-deriving RFC 9110 §13.2.2's
     precedence in a backend, which is the mirror the `evaluate` export exists to remove. No case
     currently needs it; one that did would stay red.

   The `304` half of this was a fixture bug rather than a framework one and is fixed — a
   not-modified answer is a `Resp::with_status(_, 304)` carrying the validators, never a
   `HandlerError`, because the codec already strips the body and the framing header at that status.
4. **No response carries `Server` or `Date`.** Nothing in the facade or the codec writes either,
   and no dto declares them, so no backend can supply them. `c-list-0044` is the case that sees it.
5. **Genuine protocol disagreements**, which is what the suite is for. Among them:
   `partNumber > 10000` is accepted; `DeleteObjects` does not require an integrity header;
   `MaxMessageLengthExceeded` where AWS says `InvalidArgument`. A `HEAD` refusal carrying an XML
   body was in this list and is now finding 17, because it is the *only* thing left in two cases.
6. **The facade exports `ChecksumSpec` but not `Checksummer`.** `ChecksumAlgorithm::checksummer`
   returns `Box<dyn Checksummer>` and the trait is not re-exported, so the method on that box
   cannot be called from outside the workspace and no backend can produce an `x-amz-checksum-*`
   value without vendoring a digest. `src/crc32.rs` is this suite's copy; every other backend will
   write one too. `fixture::read_checksum` is what it is for on the read path — a whole read that
   sent `x-amz-checksum-mode: ENABLED` gets the CRC-32 of its bytes, a `206` gets none, which is
   `c-range-0016`'s two exchanges.
7. **`GetObjectAttributes` is not implemented**, so `GET …?attributes` falls through to
   `GetObject` and is answered wrongly rather than refused. `c-etag-0001` is the case that sees it.
   `CopyObject` and `UploadPartCopy` were in this list and no longer are: both are registered by
   `inprocess` and answered by `fixture`.
8. **The copy-source contract is not reachable through the facade.**
   `crates/core/src/ops/shared/copy_source.rs` holds the split rule, the two ARN grammars, the
   source-authorization type state, the self-copy classification and the copy range rule, and the
   facade exports none of it. `fixture` therefore *mirrors* the module rather than calling it — see
   its module documentation — and so will every other backend. Two divergences inside that module
   are pinned by `fixture`'s own tests rather than smoothed over:
   `resolve_copy_range` answers a span outside the source with `InvalidRange` (416) where AWS and
   `c-copy-0036` say `InvalidArgument` (400), and its doc comment says an overlong span is "not
   clamped, it is refused" while `ByteRange::resolve` clamps the end.
9. **A copy cannot fail after its head is committed.** A `HandlerResult` is a status *or* an
   answer, so there is no way for a backend to commit a `200` and then stream an `Error` document
   — the shape AWS uses for a long copy, and the shape `c-copy-0038` asserts. It is a facade
   capability rather than a backend decision, and the fixture does not approximate it.
10. **Object tagging has no operation at all.** `GetObjectTagging` and `PutObjectTagging` are absent
   from the model, so `x-amz-tagging` and `x-amz-tagging-directive` can be sent and never read
   back. `c-copy-0008` copies with `TaggingDirective: REPLACE` and its read-back reaches
   `GetObject`, which is the case that sees it.
11. **`evaluate_range` is exported but not callable.** `RangeSelectors::range` is the *raw* `Range`
   header (`Option<&str>`) and `RangeSelectors::if_range` is an `IfRange`. A backend can supply
   neither: the generated decoder has already parsed the header into `ByteRange`, which the facade
   does not re-export and which offers no way back to the text it came from; `Req` carries the
   decoded input and no header map; and **no dto declares `if-range` at all**, so the value never
   leaves the wire. The conditional half of the same module — `evaluate` over `Preconditions` and
   `ObjectValidators` — is fully reachable and `fixture` now calls it, which is what makes the
   contrast the finding rather than a preference. `c-range-0015` (`Range` and `partNumber` together
   is a 400 the contract already states) and `c-range-0018` (a stale `If-Range` drops the range)
   are the two cases that see it. The fixture does **not** re-derive either rule by hand: the
   mirror it used to carry is exactly what this exercise removed.
12. **The contract states a rule the decoder makes unreachable.** `Preconditions` documents that an
   `If-Modified-Since` which is not an HTTP-date "must arrive here as `None`", because RFC 9110
   requires the field to be ignored. The generated codec instead does
   `value::timestamp(raw, TimestampFormat::HttpDate, "IfModifiedSince")?`, so the request is
   refused with a `400` before any handler runs and the rule can never fire. `c-cond-0020` is the
   case that sees it. The neighbouring `Range` binding is `value::byte_range(raw)` with no `?`,
   which is the shape the date bindings would need. Two `Range` headers are likewise refused at the
   wire layer where `RangeParse` would answer the whole object — `c-range-0017`.
13. **A completion naming no part is `MalformedXML` before any handler runs.**
   `generated/codec/ops/complete_multipart_upload.rs::read_completed_multipart_upload` refuses an
   empty `Parts` list as a decode failure, so the `InvalidPart` the fixture answers for the same
   input is unreachable — the request never arrives. `c-mpu-0019` (an empty
   `<CompleteMultipartUpload/>`) and `c-mpu-0034` (a body that parses and names no part) are the
   cases that see it, and both are about a *semantic* refusal rather than a syntactic one: the
   document is well-formed and the client is told it is not. Fixing it is a change to the list
   arity the generator emits, not to a backend.
14. **The `ETag` element of a body is written with escaped quotes.** The codec renders it through
   `XmlWriter::element_quoting`, whose `escape_text_and_quotes` turns the entity tag's own `"` into
   `&quot;`, so a completion answers `<ETag>&quot;…-3&quot;</ETag>`. `c-mpu-0002` and `c-mpu-0003`
   assert the literal quote, which is what an SDK's tag comparison reads. The decision is
   `crates/xml`'s and applies to every quoting element, so no backend can change it and the fixture
   does not try.
15. **A completion cannot fail after its head is committed.** The multipart form of finding 9, and
   the one AWS documents most loudly: `CompleteMultipartUpload` answers `200` and then streams
   either a result or an `<Error>` document, holding the connection with whitespace while it
   assembles. `HandlerResult` is a status *or* an answer, so `c-mpu-0001` (the error document
   inside a `200`), `c-mpu-0040` (an abrupt close when progress stops) and `c-mpu-0038` (the
   whitespace prologue, which also forbids the XML declaration `XmlWriter::document` always writes)
   have no shape a backend could answer in. The fixture answers a plain `400`, which is honest and
   red, rather than an approximation that would read green.
16. **`c-mpu-0018` disagrees with its own fixture.** It asserts
   `etag: "88d1a0e3f0d0eb1b06e0d9c8bd6f6d5f"` for the part body `the exact bytes of part one`,
   whose MD5 is `48df983668c1507a42914184ecc64d4a` — the value the fixture returns. Nothing in the
   implementation can satisfy it. Cases are the contract and are not edited from the runner side,
   so this is a maintainer decision; the `lint/hand-computed-digest` gap under "Known gaps" is the
   same problem one layer up.
17. **A refusal to a `HEAD` still carries the `<Error>` document.** `render` does not know the
   request method, and the refusal path never reaches `EncodedResponse::enforce_http_invariants`,
   where "a `HEAD` response has no content" lives for the success path. `c-cond-0023` and
   `c-object-0008` are now red for *only* this — every other assertion in both is green, including
   the `<Condition>` and `<Key>` elements finding 3 closed. Fixing it means threading the method
   into `render`, which changes a public signature and is therefore not a backend's to do; see
   `crates/gateway/MAP.md`'s "Known gaps".
18. **`c-range-0007` needs a fixture vocabulary the schema does not have.** It declares
   `[[setup.multipart_uploads]]` with two parts and then reads the key with `?partNumber=2`,
   expecting `206` and `x-amz-mp-parts-count: 2`. But `setup.multipart_uploads` creates an
   **in-progress** upload — that is what `capture_upload_id_as` is for, and what every `c-mpu-*`
   case relies on — and an in-progress upload has no object to read, so the fixture answers
   `NoSuchKey`. Satisfying the case needs a *completed* multipart object in `[setup]`, which
   schema version 1 cannot express. Neither side is edited here: the case is the contract and the
   schema is frozen, so this is a maintainer decision like finding 16.

### What this target cannot measure, and never pretends to

There is no socket, so three assertion families have no honest answer. `inprocess`'s module
documentation states each one once; in summary: `connection_after` is always reported `open`,
`request_progress` always reports the whole body as sent, and `timing` bounds are met trivially.
Three cases are red for this reason alone. A request shape that needs a socket — a control chunk,
a raw head, an h2 frame script — is **skipped with the capability named**, never approximated; five
cases are skipped that way. Wiring `--endpoint` to a real socket transport is what removes both
limits, and until then `--endpoint` is refused rather than silently ignored.

## Known gaps, deliberately left as gaps

- **Computed interpolation.** Schema version 1 has only `${capture.<name>}`. Cases that need a
  digest of their own body write it by hand (`content-md5`, `x-amz-checksum-*`), which the
  `lint/hand-computed-digest` warning reports. Inventing an expression syntax here would be a
  second, undocumented grammar inside a frozen format — it belongs in the schema change procedure.
- **`--endpoint`** parses but has no transport behind it, and the CLI now exits `3` rather than
  running the in-process target under a flag that says otherwise. A real one writes raw bytes on a
  socket, never through an SDK: an SDK normalises away the malformed framing a negative case exists
  to send.
- **`--transport hyper|conn`** is injected and reported but cannot yet differ, for the same reason.
- **Streaming and presigned signing.** `sign.mode` is honoured for `sigv4_header`,
  `sigv4_unsigned_payload`, `anonymous` and `none`. The streaming modes need aws-chunked framing on
  the wire, which is the socket transport's, and the corpus uses one of them once.
- **`connection.reuse`, `connection.read_window_bytes`, chunk `delay_ms`** are parsed and handed to
  the target; honouring them is a socket transport's job.
