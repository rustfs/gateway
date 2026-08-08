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
cargo run -p rustfs-gateway-conformance --bin rustfs-gateway-conformance -- audit-keys
scripts/check_case_keys_honoured.sh
```

Exit codes: `0` ok, `1` a regression against the baseline, `2` usage, `3` environment — including a
run in which nothing executed. An environment failure is never `1`, because a run that could not
reach its target must not be recordable as a run whose assertions failed.

## Files

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/lib.rs` | The four properties the crate is built around, and the module list | First. It is ten lines of orientation |
| `src/value.rs` | The order-preserving document model shared by TOML and JSON | You need to read a field out of a case |
| `src/keys.rs` (+ `keys/tests.rs`) | **The honesty ledger**: every key the frozen schema declares, which of them the harness read and from where, and the audit that fails when one is read by nothing. `Value::read` lives here | You are reading a new field out of a case, or `check_case_keys_honoured.sh` went red |
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
| `src/fixture.rs` | **The stub backend**: what `[setup]` established, and the answers built out of it — the six listings with their pagination and cursors, the copy family with its source parser, source gate and span rule, the multipart family with its upload-id ownership check, part-order and part-digest rules, size floor and composite entity tag, the per-bucket CORS, lifecycle, default-encryption, replication and object-lock documents (stored exactly as sent, validated only through the facade's `validate_cors` / `validate_lifecycle` / `validate_encryption` / `validate_replication` / `validate_lock_configuration`, `None` answering the operation-specific 404), the per-object restore state beside them (an archive class decides whether a retrieval is a question at all, `RestoreState` decides the status, and how long a retrieval takes is this stub's own dial — Expedited is back immediately and every other tier is still running, which is how a case reaches all four outcomes), the select request validated through the facade's `validate_select` and then refused `501` because the framed response has no response shape to travel in, the per-object retention and legal-hold documents beside the tag set on the object entry (validated through `validate_retention` against **the case's** clock and `validate_legal_hold`, refused outright on a bucket without object lock, `None` answering the object-level `NoSuchObjectLockConfiguration` — and never *enforced*: no delete or overwrite here consults them), the bucket lifecycle with its `home_region`, per-bucket region, other-owner flag and emptiness rule (versions **and** uploads; a deletion drops the bucket's CORS, tag, lifecycle, encryption, replication and object-lock documents with the `BucketState` they live in), and the shape of its refusals (`unsatisfiable`, `precondition`/`sole_condition`, `no_such_key`, `redirect_if_elsewhere`) | A case fails on a value the fixture chose, or an error document is missing an element |
| `src/inprocess.rs` | **The wired target**: request in, signature, `call_bytes`, `Observation` out | A case is skipped, or signs wrongly |
| `src/socket.rs` | **The connection-level pieces**: a listener on a kernel-chosen port serving the same service over hand-rolled HTTP/1.1, a raw client, and `observe_connection` — which asks the *socket* what state it is in and never a response header. The four-corner proof that it does so lives in its tests | You are working on `expect.connection_after`, or on anything that needs a real socket |
| `src/runner.rs` (+ `runner/tests.rs`) | Selection, interpolation, driving exchanges, one verdict per case | A case reached the wrong conclusion |
| `src/report.rs` | Verdicts, grouping by capability domain, baseline comparison, text/JSON/JUnit output | You are changing what fails a run |
| `src/cli.rs` | Argument parsing and the exit codes | You are adding a flag |
| `src/bin/rustfs-gateway-conformance.rs` | The product binary. Contains no decisions | Never |
| `tests/corpus.rs` | The gate: the whole corpus loads, validates, and concludes — through the public API only | It goes red |
| `tests/wired.rs` | The other gate: a target is wired and cases really executed, not skipped | It goes red |
| `tests/tagging.rs` | 1 positive / 14 negative — the object `?tagging` band end to end over its own hand-assembled service; the corpus's `tagging/` domain now exercises the same family through `inprocess.rs`, both scopes | You changed the tagging half of `fixture.rs` |
| `tests/bucket_lifecycle.rs` | 4 positive / 11 negative — the half of the bucket lifecycle matrix the corpus cannot reach, because `inprocess.rs` serves one region and `[setup]` declares no second account: the 409 outside us-east-1, the other owner's 409, and the `EU` alias where eu-west-1 *is* served — plus the rule that a deleted bucket takes its CORS, tag, lifecycle, encryption, replication and object-lock documents with it. The us-east-1 halves of the same contrasts are `conformance/cases/bkt/` | A region-dependent status changed, or you are asking why these are not cases |

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

The baseline on disk is regenerated in the same change that moves the numbers:

```text
conformance/baseline.json   195 cases: 174 passed, 16 failed, 5 skipped
current                     195 cases: 175 passed, 14 failed, 6 skipped
```

The two disagree, and the disagreement is an improvement in both directions: `c-object-0011`
passes now that `setup.buckets[].object_lock` reaches the backend, and `c-cond-0013` is *skipped
with its reason* rather than failing against a race that never happened. Neither is a regression —
the run still exits `0` against the baseline — but the baseline is stale and should be regenerated
by whoever takes this change.

Regenerate it with `baseline > conformance/baseline.json` in the same change that moves the
numbers, or the tolerance meant for the old failures starts hiding new ones.

Run with `--baseline conformance/baseline.json` and the exit code is `0` until something regresses.
Without the baseline the run exits `1`, which is correct and is the point: the red is real.
**The cases were written from the AWS documentation, not from this implementation**, so a run is
expected to be red, and the baseline exists to freeze how red rather than to excuse it.

### What the red is made of, in descending order

0. **Resolved — the tagging family is registered.** All six tagging operations (both scopes) are
   in `inprocess.rs::assemble`'s `ServiceBuilder` chain, `fixture.rs` holds a per-bucket tag set
   beside the per-object one, and `c-copy-0008` is green. The entry is kept at number zero because
   it records the shape the next family lands in: handlers, routes and codecs can all exist while
   the assembly serves none of it, and the corpus is what notices.
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
   `partNumber > 10000` is accepted; `DeleteObjects` does not require an integrity header. A `HEAD`
   refusal carrying an XML body was in this list and is now finding 17, because it is the *only*
   thing left in two cases. `MaxMessageLengthExceeded` where AWS says `InvalidArgument` was in it
   too and is finding 22, now closed in `crates/http`.
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
8. **The copy-source contract is reachable now; `fixture` still mirrors half of it.** The facade
   re-exports `CopySource`, `authorize_source`, `classify_self_copy` and `resolve_copy_range`, so
   the reachability half of this finding is closed. What is left is that `fixture`'s
   `parse_copy_source` / `parse_source_path` / `parse_source_arn` are still a *hand-written copy* of
   the split rule and the two ARN grammars, and every backend that copies them can hold them
   differently — which is what both advisories on this family were.

   The copy **range** is no longer among them, and the state it was in is the argument for finishing
   the job. `fixture::resolve_copy_span` is a call to `resolve_copy_range` now; the arithmetic it
   replaced had drifted from the contract in one direction and the contract had drifted from its own
   doc comment in the other. Both are fixed rather than pinned: an overlong span is **refused, never
   trimmed** — `ByteRange::resolve` would answer `bytes=0-100` over a ten-byte source with `0-9` and
   `bytes=-100` with all ten, which is a part the client committed a length to and did not get — and
   the refusal is `InvalidArgument` (400), which is what AWS answers and what `c-copy-0036` asserts.
   A `416` belongs to a read whose window could not be served, and a copy is not serving one. An
   unparseable value is refused too, for the same reason a read ignores one and a copy must not:
   ignoring it copies the whole source under a header that asked for part of it. `c-copy-0036`
   passes and `c-copy-0013`, `c-copy-0014`, `c-copy-0037` and `c-range-0006` are unaffected.
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
   `GetObject`, which is the case that sees it — the copy exchange passes, and
   `GET /conf-copy/dst/0008?tagging` comes back with the object's bytes rather than a tag set. The
   fall-through is the second finding on this file's list (see the deferred-route entry in
   `crates/core/MAP.md`, tracked as issue 16); the missing operation is `model/**` and `generated/**`,
   which no backend and no runner edit can reach.
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
12. ~~**The contract states a rule the decoder makes unreachable.**~~ **Closed in the generator.**
   `Preconditions` documents that an `If-Modified-Since` which is not an HTTP-date "must arrive here
   as `None`", because RFC 9110 requires the field to be ignored; the generated codec used to bind
   it with `value::timestamp(raw, TimestampFormat::HttpDate, "IfModifiedSince")?`, so the request
   was refused with a `400` before any handler ran and the rule could never fire. `q-cond-0050` is
   now carried on both date members of both read operations, codegen emits a tolerant binding for
   them, and an unreadable date arrives as `None`. `c-cond-0020` passes.

   The two-`Range`-headers half of this was closed earlier: `Range` is no longer in
   `SINGLE_VALUED_HEADERS`, so a repeated one is ignored and the whole representation served, and
   `c-range-0017` passes.
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
19. ~~**`expect.body.redact` was applied to the byte-exact assertions only.**~~ **Closed, and it
   was an instrument bug rather than an implementation one.** `contains_utf8` and
   `not_contains_utf8` were judged against the raw bytes, so
   `contains_utf8 = ["<NextContinuationToken>__REDACTED__</NextContinuationToken>"]` — the only
   spelling by which a case can assert *where* a server-minted value sits — could not be satisfied
   by any response. `c-list-0042` was red for it while the fixture had been writing a correct
   cursor all along. `contains_utf8` now runs against the redacted body, with the needle redacted
   too. Two rules keep the fix from weakening anything:
   * `not_contains_utf8` deliberately keeps reading the raw bytes. A prohibition is about what went
     on the wire, and redacting first would excuse a leaked credential for appearing inside exactly
     the element the case chose to redact.
   * `xml::redact` no longer fills an empty element. `<X></X>` stays `<X></X>`, so "present and not
     empty" — the whole of `c-list-0042`'s title — is still sayable, and a blank opaque value
     fails both halves of the assertion instead of satisfying the first.
20. **`c-cond-0013` needs a race the in-process transport cannot stage — and now says so.** Two
   pipelined conditional creates; the loser must be told `409 ConditionalRequestConflict` ("retry")
   rather than `412` ("your condition was false"). The case's own rationale says pipelining is what
   reaches the race. `connection.pipeline` used to be parsed, handed to the target, and honoured by
   nothing — the runner drives exchange two only after exchange one's response has been read, and
   the fixture serialises behind one mutex besides — so the loser met an object that was simply
   there and `412` was the honest answer to a question the case had not asked. The case was
   therefore **failing for the wrong reason**, which reads in a report exactly like failing for the
   right one.

   `inprocess::read_connection` now refuses `pipeline = true` by name and the case is **skipped with
   the reason**, so the report says "this was not measured" instead of "this was measured and the
   answer was wrong". Closing it properly needs a socket transport that really pipelines *and* a
   store with a window between evaluating a condition and committing under it. Neither is
   approximated: a fixture that answered `409` because the key had been created during this run
   rather than by `[setup]` would be reading the setup file instead of the request.
21. **`c-cond-0027` contradicts itself, and the rule it is about holds.** Its first exchange copies
   `sides/source` onto `sides/target` and asserts `200`; a copy preserves the entity tag, so from
   then on the two objects carry the *same* tag. The second exchange then offers that tag to the
   destination's `if-match` and expects `412` — but the destination really does carry it by then, so
   `200` is correct for any implementation, and no ordering of the two evaluators changes that. The
   rule the case exists for is separately asserted by
   `fixture::each_side_of_a_copy_is_judged_against_its_own_object`, against two objects that stay
   different, one side varied at a time, in both directions. Maintainer decision of the same kind as
   findings 9, 16 and 18; neither side is edited here.
22. ~~**`c-list-0030` is refused at the wire's query budget instead of at the cursor ceiling.**~~
   **Closed in `crates/http`.** The 4 KiB token still puts the query string over
   `Limits::max_query_bytes`, and being refused at the limit is the right answer — that bounded
   refusal is what the case is really measuring. What was wrong was the *code* and the *message*:
   every limit collapsed into `MaxMessageLengthExceeded`, and `<Message>` carried
   `WireReject`'s internal reason string (`limit-exceeded`) out to a client. `crates/http`'s
   `limits.rs` and `reject.rs` now keep the limit kinds apart and render wording a client can read,
   so an over-long query is `InvalidArgument`. The half that was always in reach was done earlier
   and still holds: `fixture::read_token` calls `CursorSpec::accept` rather than carrying its own
   ceiling at 2304 bytes beside the contract's 2048 — one ceiling, applied before the token is
   decoded, for this backend and every other.
23. ~~**`c-object-0011` needs a retained version `[setup]` cannot declare.**~~ **Closed, and the
   diagnosis was half wrong.** The key that cannot be deleted always appeared in `<Error>` with
   `<Key>`, `<VersionId>`, `<Code>` and `<Message>` in the pinned order. The delta was the code:
   `NoSuchVersion` where the case says `AccessDenied`. `inprocess::prepare` was dropping
   `setup.buckets[].object_lock` on the floor, so the precondition never reached the backend — the
   case was asserting about a lock-enabled bucket while running against a bucket with no lock.

   The flag now reaches `fixture::Fixture`, and `delete_objects` refuses a *version* delete on a
   lock-enabled bucket with `AccessDenied`. That is not the fixture guessing at retention state: on
   a lock-enabled bucket, removing a version needs `s3:BypassGovernanceRetention`, and the refusal
   is an authorisation decision taken *before* the version is looked up — so it neither knows nor
   discloses whether `held` exists. Without object lock the same request is still the per-key
   `NoSuchVersion` the store actually knows.

19. **Two cases are red for `connection_after` and nothing else.** `c-sig-0001` and `c-object-0015`
   now agree with the corpus on the status, the code, the document and both `request_progress`
   counters; what is left is whether the connection was closed afterwards, which needs a socket. It
   is *not* answered from a `Connection: close` header, and the framework does not write one — see
   the note in `crates/gateway/MAP.md`. The discriminator is not obvious either: `c-object-0013` also
   leaves its body unread and asserts `open`, so "an unread body closes the connection" is refuted by
   the corpus itself and the rule needs a maintainer's decision before either side moves.

### Every declaration is read, or says in writing why not

`src/keys.rs` holds the ledger and `scripts/check_case_keys_honoured.sh` is the gate — it runs the
corpus through `audit-keys` and audits what the run read. The gate is a run rather than a `cargo
test` because the ledger is per process: a unit test that pokes at one field would otherwise stand
in for the runner having read it. The schema is
frozen and enumerates every key a case may write, so a key nothing reads is a key a case can declare
into the void — which is how `setup.buckets[].object_lock` and `connection.pipeline` came to be
parsed, schema-checked and then dropped, each leaving a case measuring a scenario other than the one
it described.

`Value::read` takes the *schema location* of a field, records it, and fetches the TOML key derived
from that location, so a call cannot record one name and read another. The audit then requires that
every location the schema declares is in the ledger or in `keys::DECLARED` with a reason. Four rules
stop the ledger from becoming the unfalsifiable thing it is checking:

* a recorded name the schema does not declare is a finding — coverage cannot be invented;
* one source location may claim one key — a `for key in EVERY_KEY` loop is rejected, which is why
  the loops that read `("message_present", "Message")` and its siblings from array literals are
  written out;
* a `DECLARED` entry the ledger contradicts is a finding, so the exemption list cannot become
  fiction;
* `BehindRefusal` must name a key that *is* read, and `Unexercised` must name a container no case
  writes — both self-invalidate the moment they stop being true.

What it still cannot prove is that a value which was read changed anything. `Value::read` is
`#[must_use]`, so discarding it does not survive `-D warnings`, and what is left needs a deliberate
`let _ =` visible in a diff. That is stated in the module rather than papered over.

Everything the audit currently excuses is listed by `audit-keys`, with the cases that declare each
one. `Unhonoured` entries also put a warning on every case that declares them, so a gap appears on
the case it affects rather than nowhere.

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
named**, never approximated; six cases are skipped that way. Wiring `--endpoint` to a real socket
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
- **`--transport conn` exits `3` rather than running.** `src/socket.rs` now holds the pieces a
  socket run needs — a listener on a kernel-chosen port serving the same `S3Service` over its own
  HTTP/1.1 framing, a raw client, and `observe_connection`, which asks the socket what state it is
  in and never reads a response header. What is *not* there is a `Sut` wired to them, and it is
  deliberately absent rather than half-written, because two things a socket run must report cannot
  be reported honestly yet:
    - **A paced request body.** `dataChunk.delay_ms` is still unhonoured. Written into a loopback
      socket unpaced, the whole body lands in the kernel buffer before the server has read a byte,
      so a client-side `body_bytes_sent_at_response` measures the buffer rather than the server —
      and every early-refusal assertion in the corpus inverts while still reading as measured.
      `c-sig-0001` asserts `0` here, and would be handed the whole body.
    - **The close rule.** See the entry below.
  Until then the flag is refused. It used to parse, print `transport conn` in the report header,
  and run every case in process — a run naming one assembly path while measuring the other.
- **The rule separating `connection_after = "closed"` from `"open"` is unsettled**, and
  `src/socket.rs::ClosePolicy` is a parameter rather than a constant because of it. What the corpus
  says, which is more than issue #20 records:
    - `c-sig-0001` (`closed`) is a **signature failure**. It is neither a `WireReject` nor a
      `ChunkReject`, so wiring both `must_close_connection` flags — which is what issue #20 asks
      for — cannot reach it. A third leg is needed: an authentication failure closes because the
      peer is not who the connection assumed.
    - `c-object-0015` (`closed`) is an over-cap body, and `c-object-0013` (`open`) is a
      contradictory-checksum refusal. Both leave the body unread, so "an undrained body closes" is
      not the rule.
    - Size does not separate them either: `c-sig-0001`'s body is 24 bytes and `c-object-0013`'s is
      11, so any lingering-drain budget that keeps one connection open keeps the other open too.
  The rule that fits all three is *which refusal fired*, which is what `WireReject::must_close_connection`
  already encodes and what nothing carries out of the pipeline. `render.rs` turns a `WireReject`
  into an `S3Error` and drops the flag, so no layer that could act on it ever sees it.
  `rfc9112_lingering_close` is the RFC-grounded default and is documented as disagreeing with
  `c-object-0013` rather than tuned to agree with it.
- **`half_closed` is never reported by the client-side observation.** From one end of a TCP
  connection a peer that shut down its write side and one that closed both are indistinguishable:
  each gives end-of-stream on a read. Telling them apart means writing, and a write that succeeds
  corrupts the next exchange while one that fails costs the `RST` that changes the state being
  measured. A case asserting `half_closed` is red here for that stated reason, which is better than
  the alternative — a zero-length write, which on most platforms never touches the socket and
  therefore reports `closed` unconditionally while reading like a measurement.
- **Streaming and presigned signing.** `sign.mode` is honoured for `sigv4_header`,
  `sigv4_unsigned_payload`, `anonymous` and `none`. The streaming modes need aws-chunked framing on
  the wire, which is the socket transport's, and the corpus uses one of them once.
- **Chunk `delay_ms` and `flush`** are declared by cases and this transport cannot carry them out:
  nothing in an in-process call observes wall-clock pacing, and there is no write buffer to flush.
  They are the two `Unhonoured` entries in `keys::DECLARED`, so every case that declares one now
  carries a `harness/unhonoured` warning naming the key and the reason. Honouring them by sleeping
  would make the `timing` assertions depend on the load of the build machine; honouring them
  properly is a socket transport's job. **Worth a maintainer's eye**: `c-sig-0001`'s rationale says
  its body is "deliberately paced with `delay_ms`", so what that case measures here is not quite
  what it describes.
- **`connection.read_window_bytes`, `connection.idle_timeout_ms`, `[connection.tls]`,
  `connection.reuse = false`, `clock.presign_expires_s`, `clock.advance_ms_between_exchanges`,
  `sign.signed_headers`, `sign.expires_s`, `sign.credential = "expired_session"`, a `payload_hash`
  of `streaming`/`streaming_trailer`/`base64`/`literal`, `setup.cleanup = "none"`,
  `setup.buckets[].versioning = "suspended"` and a `setup.buckets[].region` other than
  `us-east-1`** are each **refused by name**, so a case declaring one is skipped with the reason
  instead of being answered from an approximation. `connection.reuse = true` is the one instruction
  here that is carried out, and it is carried out by construction: every exchange of a case runs
  against one service value and one fixture.
