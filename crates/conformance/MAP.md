# `rustfs-gateway-conformance` — agent map

The data-driven S3 conformance suite. The corpus lives in `conformance/` at the repository root
(`case.schema.json`, `cases/**/*.toml`, `goldens/`); this crate is the runner that executes it and
can be pointed at any S3 implementation.

Zero third-party dependencies, by design: this crate is a product other implementations run against
themselves, and every dependency it carries is one they inherit. The TOML reader, JSON reader,
schema evaluator and pattern matcher are therefore in this crate, small and unit-tested.

## Entry points

```bash
cargo run -p rustfs-gateway-conformance --bin rustfs-gateway-conformance -- validate
cargo run -p rustfs-gateway-conformance --bin rustfs-gateway-conformance -- run --filter 'etag/'
cargo run -p rustfs-gateway-conformance --bin rustfs-gateway-conformance -- baseline > baseline.json
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
| `src/runner.rs` (+ `runner/tests.rs`) | Selection, interpolation, driving exchanges, one verdict per case | A case reached the wrong conclusion |
| `src/report.rs` | Verdicts, grouping by capability domain, baseline comparison, text/JSON/JUnit output | You are changing what fails a run |
| `src/cli.rs` | Argument parsing and the exit codes | You are adding a flag |
| `src/bin/rustfs-gateway-conformance.rs` | The product binary. Contains no decisions | Never |
| `tests/corpus.rs` | The gate: the whole corpus loads, validates, and concludes — through the public API only | It goes red |

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

## Current state — read this before concluding the suite is green

No target is wired. `sut::Unwired` is the default and fails every exchange with `NotWired`, so a
`run` reports every case as **skipped** and exits `3`. `validate` exercises loading, the frozen
schema and the conventions, and exits `0`.

The blocker is the layering, not an oversight: `check_layer_dependencies.sh` allows this crate the
`rustfs-gateway` facade and nothing else internal, and the facade re-exports nothing yet. The list
of public items that would unblock execution is `sut::REQUIRED_FACADE_EXPORTS`, and it is printed
at the end of every run rather than buried in a comment.

Two of those are not merely re-exports:

- **A client-side signer.** `rustfs-gateway-sig` verifies signatures; it cannot produce one. Every
  case in the corpus declares `sign.mode`, so nothing can be sent until the facade can sign.
- **A service entry point.** `rustfs-gateway-core` states that HTTP transport assembly belongs to
  the facade, and the facade is currently a doc comment.

## Known gaps, deliberately left as gaps

- **Computed interpolation.** Schema version 1 has only `${capture.<name>}`. Cases that need a
  digest of their own body write it by hand (`content-md5`, `x-amz-checksum-*`), which the
  `lint/hand-computed-digest` warning reports. Inventing an expression syntax here would be a
  second, undocumented grammar inside a frozen format — it belongs in the schema change procedure.
- **`--endpoint`** parses but has no transport behind it. A real one writes raw bytes on a socket,
  never through an SDK: an SDK normalises away the malformed framing a negative case exists to send.
- **`--transport hyper|conn`** is injected and reported but cannot yet differ, for the same reason.
- **`clock`, `connection` and `chunks`** are parsed, schema-checked and handed to the target in
  `ExchangePlan`; honouring them is a transport's job.
- **`conformance/baseline.json`** does not exist yet. `--baseline` reads one if given, and the
  `baseline` subcommand prints one; checking the file in is a maintainer decision because the first
  committed baseline defines what the ratchet tolerates.
