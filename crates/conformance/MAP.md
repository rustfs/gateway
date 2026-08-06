# `rustfs-gateway-conformance` — agent map

The data-driven S3 conformance suite. The corpus lives in `conformance/` at the repository root
(`case.schema.json`, `cases/**/*.toml`, `goldens/`); this crate is the runner that executes it and
can be pointed at any S3 implementation.

Two third-party dependencies, and only two: `http` and `bytes`. They are the parameter types of the
facade's own entry point — `S3Service::call_bytes(http::Request<bytes::Bytes>)` — so a caller
cannot name that call without them. Everything else is still hand-written here, because this crate
is a product other implementations run against themselves and every dependency it carries is one
they inherit: the TOML reader, JSON reader, schema evaluator, pattern matcher, SHA-256, MD5 and the
single-threaded executor are all in this crate, small and unit-tested.

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
| `src/time.rs` | `[clock] fixed` / `request_time` into a Unix second and a SigV4 stamp | A clock-pinned case is an hour out |
| `src/exec.rs` | Twenty lines of `std` that run one future to completion | Never, unless a run hangs |
| `src/fixture.rs` | **The stub backend**: what `[setup]` established, and the answers built out of it — including the six listings, their pagination and their cursors | A case fails on a value the fixture chose |
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
conformance/baseline.json   157 cases: 21 passed, 131 failed, 5 skipped
current                     157 cases: 79 passed,  73 failed, 5 skipped
```

Regenerate it with `baseline > conformance/baseline.json` in the same change that moves the
numbers, or the tolerance meant for the old failures starts hiding new ones.

Run with `--baseline conformance/baseline.json` and the exit code is `0` until something regresses.
Without the baseline the run exits `1`, which is correct and is the point: the red is real.
**The cases were written from the AWS documentation, not from this implementation**, so a run is
expected to be red, and the baseline exists to freeze how red rather than to excuse it.

### What the red is made of, in descending order

1. **Error documents carry no `<RequestId>` or `<HostId>`.** `render::render` emits `<Code>`,
   `<Message>` and an optional `<Resource>` and stops — deliberately, and its own unit test pins
   that ("a rendered refusal echoes nothing from the request"). 48 cases assert
   `error.request_id_present = true`, and 15 of them fail on nothing else. This is a design
   decision in conflict with a documented AWS invariant, and only a maintainer can resolve it: a
   request id is minted by the server, not echoed from the request, so emitting one leaks nothing.
2. **`encoding-type` is decoded, echoed, and never applied.** `spec/operations/ListObjects.toml`,
   `ListObjectsV2.toml`, `ListObjectVersions.toml` and `ListMultipartUploads.toml` each declare
   `url_encoded_fields`, and no generated codec reads it — nor does anything call
   `ObjectKey::needs_url_encoding`, which exists for exactly this. `c-list-0017`, `c-list-0035` and
   `c-mpu-0013` are the cases that see it. The fixture deliberately does **not** encode on the way
   out: doing it in a backend would hide a code-generator gap behind code every other backend would
   then have to write too.
3. **An XML entity tag is written with literal quotes where AWS writes `&quot;`.**
   `EtagRender::XmlQuoted` renders `"tag"` and `xml::escape_text` does not escape `"`, so the wire
   carries `<ETag>"…"</ETag>`. Both types document the opposite in their own doc comments.
   `c-list-0001`, `c-list-0021` and `c-etag-0001` are the cases that see it.
4. **`ListBuckets` nests its entries the wrong way round.** The generated codec opens `Bucket` once
   and writes a `Buckets` element per entry, so the body reads
   `<Bucket><Buckets><Name>…</Name></Buckets></Bucket>` where AWS reads
   `<Buckets><Bucket><Name>…</Name></Bucket></Buckets>`. `c-list-0015` is the case that sees it.
5. **Genuine protocol disagreements**, which is what the suite is for. Among them:
   `partNumber > 10000` is accepted; `DeleteObjects` does not require an integrity header; a `304`
   and a `HEAD` refusal both carry an XML body; a `416` carries no `Content-Range`;
   `MaxMessageLengthExceeded` where AWS says `InvalidArgument`.
4. **Three operations the corpus exercises are not implemented at all** — `CopyObject`,
   `UploadPartCopy`, `GetObjectAttributes` — so their requests fall through to a neighbouring route
   (`PUT /{bucket}/{key}` → `PutObject`, `GET …?attributes` → `GetObject`) and are answered wrongly
   rather than refused. `c-etag-0001`, `c-cond-0004`, `c-range-0006` are the cases that see it.

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
