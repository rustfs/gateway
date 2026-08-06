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
| `src/render.rs` | The one place any refusal becomes an `<Error>` document; `document()` is that document without a head, for the 200-then-fail path that has none | You are adding a stage that can refuse, checking that a rejection body echoes nothing, or asking where a refusal's own headers are written |
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
| `tests/support/mod.rs` | The shared fixtures: an anonymously-reachable vendor operation, backends, a body that counts what was read |
| `tests/assembly.rs` | What `build()` refuses; 11 negative, 3 positive |
| `tests/pipeline.rs` | What a request does, the request identifier included; 16 negative, 5 positive |
| `tests/facade_probe.rs` | Every export the conformance runner's `REQUIRED_FACADE_EXPORTS` names, checked by naming it |
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
- **A refusal to a `HEAD` still carries the `<Error>` document.** `render` does not know the
  method, and the refusal path never reaches `EncodedResponse::enforce_http_invariants`, which is
  where the "a `HEAD` response has no content" rule lives for the success path. So the second
  exchange of `c-cond-0023` — the same 412 under `HEAD`, asserting `size = 0` — stays red for a
  reason unrelated to what a `HandlerError` can express. Closing it means threading the request
  method into `render`, which changes its public signature; recorded rather than done here.
- **`Server` is the bare product name.** No version, deliberately: see the security note in
  `src/stamp.rs`. A deployment that wants a different name has no knob for it yet — that would be a
  `ServiceBuilder` option, and nothing has asked for one.
- **`Date` is omitted rather than wrong when the clock reading cannot be an `IMF-fixdate`.** Only
  reachable with a `FixedClock` set outside the four-digit year range; the system clock cannot get
  there.
