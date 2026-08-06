# rustfs-gateway — crate map

The public facade. Assembles the protocol kernel into a non-generic `S3Service`, and re-exports
everything a consumer needs so that nothing downstream depends on `-core`, `-sig`, `-http`,
`-stream` or `-types` directly. Ring 1: no rustfs crate, ever.

**Start here**: `src/lib.rs` for the export list, `src/service.rs` for the request pipeline.

## Files

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/lib.rs` | Module mounting and the whole re-export list; the assembly example in rustdoc | You need to know what the facade publishes, or something downstream cannot name a type |
| `src/builder.rs` | `ServiceBuilder`: registration, extension points, and the assembly-time refusals | You are adding a builder knob, or `build()` refused and you want to know which check fired |
| `src/service.rs` | `S3Service` and the ordered pipeline (mint identifiers and read the clock → accept → resolve → route → govern → read body → admit → authenticate → decode → authorize → dispatch → encode → stamp the framework headers) | A request reached the wrong stage, or you are moving a stage — the module docs say which positions are load-bearing |
| `src/dispatch.rs` | Codec-aware erasure of one `(operation, backend)` pair, and the per-operation table | A request routes but cannot be decoded, or you are wondering why the body is offered as a stream first |
| `src/adapt.rs` | The `tower::Service` and `hyper::service::Service` implementations | You are wiring the service into a server, or wondering why `Error = Infallible` |
| `src/assembly.rs` | `AssemblyError` and the `asm-*` `RuleRef` every refusal carries | You are adding an assembly-time rule; it needs a rule reference |
| `src/render.rs` | The one place any refusal becomes an `<Error>` document; `document()` is that document without a head and `document_body()` is it without a declaration either, for the 200-then-fail path that has neither | You are adding a stage that can refuse, checking that a rejection body echoes nothing, or asking where a refusal's own headers are written |
| `src/invariants.rs` | The RFC 9110 body rules applied once to every response, answered or refused: a `HEAD` loses its content and **keeps** its `Content-Length`, a `1xx`/`204`/`205`/`304` loses both | A response carried content it must not have, or you are asking why the rule is not a parameter of `render` |
| `src/commit.rs` | The wire shape of a response whose head went out before its outcome was known: the prologue, the keep-alive contract, and the trailing declaration-less document | A committed `200` answered a failure and you are asking who wrote which byte, or you are changing the keep-alive cadence |
| `src/stamp.rs` | The four headers the framework guarantees on **every** response — `x-amz-request-id`, `x-amz-id-2`, `Server`, `Date` — written once and last, plus `is_reserved`, the complement a backend may not set | A response is missing `Date` or `Server`, or you are asking which headers a backend is refused and how |
| `src/trace.rs` | `RequestId`, `HostId`, `RequestTrace`, `TraceSource`, `MintedTraces`, `FixedTrace`; one identifier per request, minted server-side | A response is missing `x-amz-request-id`, a case needs a pinned identifier, or you are asking why a source cannot echo one the caller sent |
| `src/wire.rs` | `WireResponse`: a drained response with its **header order preserved** | You are asserting on a response, above all in the conformance runner |
| `src/clock.rs` | `Clock`, `FixedClock`; one reading per request | A case needs a fixed timestamp, or you are tempted to read the clock twice |
| `src/transport.rs` | `Transport` — which assembly path a run used | You are adding a path, or a runner has to name one |
| `src/sig.rs` | The signature vocabulary re-exported through the facade, including `sig::Signer` (the client-side `SigV4Signer`) | You need to name a `Verdict`, a `SecurityFloor` or an `AuthError`, or a test harness has to sign a request |
| `src/ext/mod.rs` | The extension-point roster, and the table of which have defaults and what each default costs | You are choosing what to install, or adding an extension point |
| `src/ext/authenticator.rs` | `Authenticator` (no default), and `SigV4Authenticator` assembled from `-sig`'s public primitives | Authentication behaved unexpectedly, or you are replacing the scheme |
| `src/ext/authorizer.rs` | `Authorizer` (no default), `AuthzRequest`, `Denial`, `allow_when` | You are writing a policy, or asking why there is no default |
| `src/ext/credentials.rs` | `Credentials`, `CredentialProvider`, `StaticCredentials` | You are wiring an IAM store, or a secret appeared somewhere it should not |
| `src/ext/host.rs` | `HostResolver` (synchronous), `PathStyleOnly` | Virtual-hosted addressing is not working — the default does not read the host |
| `src/ext/governor.rs` | `Governor`, `Unlimited`; the hook that runs after routing and before the body | You are adding a quota, or checking the hook's position |
| `src/ext/observer.rs` | `Observer` (synchronous), `NoObserver`, and the `RequestEvent` that carries the request identifier | You are wiring an audit trail, or joining a log line to the identifier a caller quoted |

## Tests and examples

| Path | What it holds |
| --- | --- |
| `tests/support/mod.rs` | The shared fixtures: an anonymously-reachable vendor operation, its `HEAD`/content twins covering every response shape (content, refusal, `304`, commit-then-answer, commit-then-fail), backends, a body that counts what was read |
| `tests/assembly.rs` | What `build()` refuses; 11 negative, 3 positive |
| `tests/pipeline.rs` | What a request does, the request identifier included, the RFC 9110 body rules on both paths, and the commit seam; 25 negative, 6 positive |
| `tests/facade_probe.rs` | Every export the conformance runner's `REQUIRED_FACADE_EXPORTS` names, checked by naming it |
| `tests/backend_reachability.rs` | Every argument of the range contract, built from a decoded request and never from a literal; 5 negative, 1 positive. Read this before adding a constructor a backend is meant to call |
| `examples/minimal.rs` | The whole assembly in one file, asserting one answered request and one refused one |

## Known gaps, recorded rather than discovered

- **Nothing in this crate drives a signed request.** `sig::Signer` is re-exported but unused here;
  every AWS operation is header-signatures-only, and the tests reach a handler through a vendor
  operation that declares itself anonymously reachable instead.
- **`rustfs_gateway_core::registry::ErasedCodec` supersedes `src/dispatch.rs`.** The core registry
  gained its own codec erasure after this crate's was written; folding one into the other is a
  follow-up, not a behaviour change.
- **The request body is buffered.** Capped by `DEFAULT_MAX_BUFFERED_BODY_BYTES` (64 MiB); the
  streaming ingest path is not wired through the facade.
- **`aws-chunked` framing is not decoded here.** A streaming `x-amz-content-sha256` value is
  refused rather than mis-framed.
- **The header map is cloned once per request**, because `WireRequest` publishes no way back to it
  and `SecurityFloor` is defined over the raw map.
- **The conformance runner does not pin the request identifier yet.** `FixedTrace` and
  `ServiceBuilder::trace_source` exist for it, and every case that compares an error document byte
  for byte redacts `RequestId`/`HostId` today, so nothing is red for want of the injection — but a
  case that wanted to assert the literal identifier cannot until `crates/conformance` installs one.
- **`x-amz-id-2` is 32 hexadecimal digits, not AWS's longer base64-shaped token.** Opaque either
  way; the closed alphabet is worth more here than the resemblance. See `src/trace.rs`.
- **The `HEAD` and `304` body rules now run once, in `src/invariants.rs`, on both paths.** The
  decision itself is `rustfs_gateway_core::body_allowance`, a function of the method and the status,
  so `EncodedResponse::enforce_http_invariants` and this crate enforce one rule over two response
  types rather than holding two copies of it. `render`'s signature is unchanged — threading the
  method into it would have put the rule in two places, which is the drift the single point exists
  to prevent. `c-cond-0023` and `c-object-0008` are green. **`Content-Length` is kept on a `HEAD`**
  (RFC 9110 §9.3.2: it is the answer the request asked for) and dropped only on the bodyless
  statuses, which is what `c-cond-0005`, `c-cond-0007`, `c-cond-0010`, `c-cond-0017` and
  `c-cond-0022` pin.
- **The commit seam exists and no in-tree backend uses it.** `Resp::commit` lets a handler flush a
  status before its outcome is known, and `src/commit.rs` writes the result; the four cases that
  measure it — `c-mpu-0001`, `c-mpu-0038`, `c-mpu-0040`, `c-copy-0038` — cannot move, because the
  only backend in this repository is `crates/conformance/src/fixture.rs` and the only transport is
  `crates/conformance/src/inprocess.rs`, which reports `Outcome::Response` and
  `body_bytes_before_error: None` unconditionally. Both are outside this change's file scope. See
  "Open for maintainer review" below.
- **The keep-alive cadence is declared and not driven.** `commit::KEEPALIVE_BYTE` and
  `commit::KEEPALIVE_INTERVAL_SECONDS` are the observable contract and have one home, but nothing
  writes a keep-alive byte: emitting one every N seconds while a future is pending needs a timer,
  and this crate has no runtime dependency (`tokio` is dev-only in the workspace manifest). The
  committed body is therefore assembled once the outcome is known. A deployment behind a client
  with a short read timeout will see the timeout, not the whitespace.
- **`Server` is the bare product name.** No version, deliberately: see the security note in
  `src/stamp.rs`. A deployment that wants a different name has no knob for it yet — that would be a
  `ServiceBuilder` option, and nothing has asked for one.
- **`Date` is omitted rather than wrong when the clock reading cannot be an `IMF-fixdate`.** Only
  reachable with a `FixedClock` set outside the four-digit year range; the system clock cannot get
  there.
