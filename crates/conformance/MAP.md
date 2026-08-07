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
| `src/observation.rs` | What a transport observed: head, body, trailers, the two byte counters, timing — plus `late_error_offset`, the one classification every transport must make identically | You are writing a transport, or a `stream_error` case reached the wrong `kind` |
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
conformance/baseline.json   195 cases: 166 passed, 24 failed, 5 skipped
current                     195 cases: 170 passed, 20 failed, 5 skipped
```

The four are `c-range-0010`, `c-range-0018`, `c-object-0013` and `c-range-0015`, all improvements,
so the run still exits `0`.

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
   `c-object-0007` and `c-cond-0001`. It had two remainders; one is now closed and one is not:
   * ~~**`<RangeRequested>` cannot be filled.**~~ **Closed.** The codec binds `Range` to
     `RangeSpec`, which is the parse *plus the header bytes verbatim*, so the text a handler needs
     now reaches it. `fixture` calls `HandlerError::unsatisfiable_range` with
     `RangeDecision::Unsatisfiable`'s own `range_requested`, and `c-range-0010` passes. The test
     that used to pin the omission is replaced by
     `an_unsatisfiable_range_echoes_the_header_rather_than_re_spelling_the_parse`, which keeps the
     rule the old one was really protecting: the element is the client's bytes, not a re-spelling of
     the parse. `bytes=20-30` and `  bytes=20-30  ` parse identically and only one is what was sent.
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
9. **`c-copy-0038` and `c-copy-0026`/`c-copy-0034` ask for two different answers to one request.**
   The framework gap this finding used to record is closed: `Resp::commit` exists, and
   `fixture::copy_object` uses it — the source is named, resolved, gated and condition-checked, both
   sets of conditions are evaluated, and *then* the head is committed, with the destination write
   below the boundary. `every_copy_refusal_happens_before_the_head_is_committed` pins that split.

   What is left is a disagreement inside the corpus. `c-copy-0026` (`/conf-copy/../../etc/passwd`)
   and `c-copy-0034` (`/conf-copy/src/missing.txt`) each assert a **404 `NoSuchKey`** for a source
   that is not there. `c-copy-0038` sends `/conf-copy/src/vanishes`, declared `absent = true` in its
   own `[setup]`, and asserts a **200 with `NoSuchKey` in the body**. The three requests are the same
   request — a copy whose source does not exist — and no implementation can answer one of them
   differently without reading the *setup file* rather than the request.

   AWS's own rule is the one this fixture follows, and it is the one that satisfies two of the three:
   *"if the error occurs before the copy action starts, you receive a standard Amazon S3 error"*. A
   source that cannot be opened is discovered before the copy starts. `c-copy-0038`'s comment says
   the source "vanishes", which would be a failure *during* the copy and would indeed be a `200` —
   but schema version 1 has no vocabulary for an object that disappears mid-operation, and
   `absent = true` means "not there when the case began". This is a maintainer decision of the same
   kind as findings 16 and 18: either the case needs a setup vocabulary that does not exist, or it
   contradicts its two neighbours. Neither side is edited from the runner.
10. **Object tagging has no operation at all.** `GetObjectTagging` and `PutObjectTagging` are absent
   from the model, so `x-amz-tagging` and `x-amz-tagging-directive` can be sent and never read
   back. `c-copy-0008` copies with `TaggingDirective: REPLACE` and its read-back reaches
   `GetObject`, which is the case that sees it.
11. ~~**`evaluate_range` is exported but not callable.**~~ **Closed, with one ordering remainder.**
   Both inputs a backend could not supply now reach it: `Range` binds to `RangeSpec`, which keeps
   the header bytes beside the parse, and `if-range` is declared on `GetObject` and read through
   `IfRange::parse`, which is total so that an unreadable validator cannot decay into "no `If-Range`
   was sent". `fixture::resolve_range` calls the contract and the hand-rolled window arithmetic it
   replaced — including `window_of`, which used to read the offsets back out of the `Content-Range`
   the contract had just rendered — is deleted. `c-range-0018` passes.

   `HeadObject` declares no `If-Range` binding, so a `HEAD` and a `GET` of the same object still
   disagree about a stale validator. That is the model's, not a backend's, and `head_object` passes
   `None` rather than inventing one. **`c-range-0015` is closed, and it was an ordering problem
   rather than the vocabulary one it looked like.** The diagnosis on the previous pass — that the
   case's `[setup]` declares an upload rather than an object, as in finding 18 — described why the
   *wrong* answer was `NoSuchKey` specifically, not why there was a wrong answer at all. `Range` and
   `partNumber` together is a contradiction in the request head; no object needs to exist for it to
   be one, so the refusal is owed before the key is resolved and the setup vocabulary never enters
   into it. `fixture::refuse_conflicting_selectors` calls the contract's own `evaluate_range` for its
   refusal alone and runs at the top of `get_object` and `head_object`, above the bucket and the key.
   Finding 18 is untouched: `c-range-0007` sends `partNumber` *without* a `Range` and really does
   need a completed multipart object in `[setup]`.
12. **The contract states a rule the decoder makes unreachable.** `Preconditions` documents that an
   `If-Modified-Since` which is not an HTTP-date "must arrive here as `None`", because RFC 9110
   requires the field to be ignored. The generated codec instead does
   `value::timestamp(raw, TimestampFormat::HttpDate, "IfModifiedSince")?`, so the request is
   refused with a `400` before any handler runs and the rule can never fire. `c-cond-0020` is the
   case that sees it. The neighbouring `Range` binding is `value::range_spec(raw)` with no `?`,
   which is the shape the date bindings would need. The two-`Range`-headers half of this is closed:
   `Range` is no longer in `SINGLE_VALUED_HEADERS`, so a repeated one is ignored and the whole
   representation served, and `c-range-0017` passes.
13. ~~**A completion naming no part is `MalformedXML` before any handler runs.**~~ **Closed.** The
   fabricated `required` on `CompletedMultipartUpload.Parts` is gone from the overlay, so an empty
   part list reaches the handler and the fixture's `InvalidPart` is the answer. `c-mpu-0019` and
   `c-mpu-0034` pass. The rule it settled is worth keeping in view: a decoder may say "this is not
   the document" and nothing else, and the moment an operation owes a different code the decision is
   the operation's.
14. **The `ETag` element of a body is written with escaped quotes.** The codec renders it through
   `XmlWriter::element_quoting`, whose `escape_text_and_quotes` turns the entity tag's own `"` into
   `&quot;`, so a completion answers `<ETag>&quot;…-3&quot;</ETag>`. `c-mpu-0002` and `c-mpu-0003`
   assert the literal quote, which is what an SDK's tag comparison reads. The decision is
   `crates/xml`'s and applies to every quoting element, so no backend can change it and the fixture
   does not try.
15. **The three late-failure completion cases each want something a different case forbids.** The
   framework gap is closed and `fixture::complete_multipart_upload` commits: the bucket, the upload's
   ownership of its bucket and key, the part list's arity and order, the write's conditional headers
   and every named part's presence, size and digest are checked *above* `Resp::commit`; the
   concatenation, the composite entity tag, the part checksums and the write are below it.
   `every_completion_refusal_happens_before_the_head_is_committed` is the test that keeps a check
   from drifting below the boundary, where its status would silently become the committed `200`.

   Each of the three is now red for its own reason, and none of them is the framework:
   * **`c-mpu-0001` contradicts `c-mpu-0022` and `c-mpu-0023`.** All three send a completion naming
     a part digest that is not the digest on file. `c-mpu-0022` and `c-mpu-0023` assert **400
     `InvalidPart`**; `c-mpu-0001` asserts **200 with `InvalidPart` in the body**. The requests are
     the same request. A digest mismatch is knowable before any byte is assembled, so it is a
     refusal, and moving it below the commit to satisfy `c-mpu-0001` turns two green cases into
     cases that report green while sending the wrong status line — the exact defect `c-mpu-0001`'s
     own rationale is about. `c-mpu-0026` (`EntityTooSmall`) and `c-mpu-0020`/`c-mpu-0021`
     (`InvalidPartOrder`) sit on the same side of the boundary.
   * **`c-mpu-0038` contradicts `c-mpu-0001` and `c-copy-0038`.** This is the contradiction that was
     already known and is unchanged by the commit seam: the prologue is written before the outcome
     is known, so it is the same bytes in both. `c-mpu-0001` and `c-copy-0038` pin
     `body_bytes_before_error = 39` and name those 39 bytes as the XML declaration;
     `c-mpu-0038` asserts `declaration = false` on a successful body. `gateway::commit::PROLOGUE` is
     the declaration, following the two-against-one reading, and `c-mpu-0038` is red for exactly one
     assertion because of it. Nothing in this change gives the contradiction a new reading.
   * **`c-mpu-0040` needs a progress deadline nothing drives, and a socket.**
     `gateway::commit::KEEPALIVE_BYTE` and `KEEPALIVE_INTERVAL_SECONDS` declare the cadence, and no
     code reads the interval — there is no bound on time-between-progress, so a stalled completion
     is not cut off. Nor could the fixture stall honestly: `[setup]` has no vocabulary for a backend
     that stops making progress, and inventing one from the case's key name would be reading the
     setup file instead of the request. The case also asserts `connection_after = "closed"` and
     `stream_termination = "abrupt_close"`, neither of which an in-process transport can produce.
16. **`c-mpu-0018` disagrees with its own fixture.** It asserts
   `etag: "88d1a0e3f0d0eb1b06e0d9c8bd6f6d5f"` for the part body `the exact bytes of part one`,
   whose MD5 is `48df983668c1507a42914184ecc64d4a` — the value the fixture returns. Nothing in the
   implementation can satisfy it. Cases are the contract and are not edited from the runner side,
   so this is a maintainer decision; the `lint/hand-computed-digest` gap under "Known gaps" is the
   same problem one layer up.
17. ~~**A refusal to a `HEAD` still carries the `<Error>` document.**~~ **Closed.** The method now
   reaches the refusal path and a `HEAD` never carries a body. `c-cond-0023` and `c-object-0008`
   pass.
18. **`c-range-0007` needs a fixture vocabulary the schema does not have.** It declares
   `[[setup.multipart_uploads]]` with two parts and then reads the key with `?partNumber=2`,
   expecting `206` and `x-amz-mp-parts-count: 2`. But `setup.multipart_uploads` creates an
   **in-progress** upload — that is what `capture_upload_id_as` is for, and what every `c-mpu-*`
   case relies on — and an in-progress upload has no object to read, so the fixture answers
   `NoSuchKey`. Satisfying the case needs a *completed* multipart object in `[setup]`, which
   schema version 1 cannot express. Neither side is edited here: the case is the contract and the
   schema is frozen, so this is a maintainer decision like finding 16.

19. **Two cases are red for `connection_after` and nothing else.** `c-sig-0001` and `c-object-0015`
   now agree with the corpus on the status, the code, the document and both `request_progress`
   counters; what is left is whether the connection was closed afterwards, which needs a socket. It
   is *not* answered from a `Connection: close` header, and the framework does not write one — see
   the note in `crates/gateway/MAP.md`. The discriminator is not obvious either: `c-object-0013` also
   leaves its body unread and asserts `open`, so "an unread body closes the connection" is refuted by
   the corpus itself and the rule needs a maintainer's decision before either side moves.

### The blind spot the instrument had, and what closed it

`inprocess` used to report `Outcome::Response` and `body_bytes_before_error: None` **unconditionally**.
Every `expect.kind = "stream_error"`, every `stream_termination` and every `body_bytes_before_error`
in the corpus was therefore judged against a constant. Those assertions could not have failed no
matter what the server did, and a suite whose instrument cannot fail an assertion reports the
assertion as satisfied. That is worse than an unimplemented feature: an unimplemented feature is red,
and this was invisible.

Two facts are read off the exchange now, both in `observation::late_error_offset` so a socket
transport will decide them identically:

* A response that arrived intact whose **status line and body disagree** — a `2xx` over an `<Error>`
  document — is `stream_error` / `error_document`, and `body_bytes_before_error` is the offset at
  which that document begins. A `4xx` or `5xx` over an `<Error>` is an ordinary refusal and is not
  reclassified; `<ErrorDocument>` is not `<Error>`.
* A body that could not be drained is `stream_error` / `abrupt_close`, and no longer an
  *environment* failure that skipped the case. A skipped case asserts nothing.

A third blind spot of the same family is closed, in the transport rather than in the observation.
`sign.tamper` rewrites one canonical component **after** a correct signature exists, and two of its
eleven components — `canonical_path` and `canonical_query` — live in the request target rather than
in a header. `sign_request` handed back only the header list, so a target-side tamper was computed
and then thrown away: `c-sig-0001` signed correctly, rewrote `x-id`, sent the *untouched* request,
and was answered `200`. Every assertion in that case was being judged against a request nobody meant
to send. `sign_request` now returns the target beside the headers.

No corpus case exercises the first path yet, and that is finding 9 and finding 15 rather than a gap
here: the only two operators that commit a head have no failure the corpus lets them discover after
committing. The byte count on the second path is still unrecorded — `collect` discards what it had
read when the stream failed — so a case pinning it stays red and says so.

`Answer` and `CommitWork` are not re-exported by the facade, so a backend can *build* a committed
response but nothing outside this workspace can drive its continuation. `fixture`'s commit tests
assert `Resp::is_committed` and the status; the continuation is only ever driven through a real
request.

### What this target cannot measure, and never pretends to

There is no socket, so two assertion families have no honest answer. `inprocess`'s module
documentation states each one once; in summary: `connection_after` is always reported `open`, and
`timing` bounds are met trivially. `stream_termination = "reset"` and `"trailer_error"` are likewise
unreachable.

`request_progress` **has left this list.** The body is handed to the service as a
`rustfs_gateway::ObservedBody` that counts what the service pulls out of it, one frame per chunk and
per repetition, so `body_bytes_sent_at_response` and `body_fully_sent` are read off the exchange.
The caveat is stated in `inprocess`'s module docs: on a socket, "bytes the client had written" and
"bytes the server had asked for" are two numbers, and this reports the server-side one — the tighter
of the two, and the one a case about early refusal is about. `c-object-0013` went green on it, and
`c-sig-0001` and `c-object-0015` are now red for `connection_after` and nothing else. A request shape that
needs a socket — a control chunk, a raw head, an h2 frame script — is **skipped with the capability
named**, never approximated; five cases are skipped that way. Wiring `--endpoint` to a real socket
transport is what removes both limits, and until then `--endpoint` is refused rather than silently
ignored.

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
