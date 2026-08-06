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
| `src/service.rs` | `S3Service` and the ordered pipeline (accept → resolve → route → govern → read body → admit → authenticate → decode → authorize → dispatch → encode) | A request reached the wrong stage, or you are moving a stage — the module docs say which positions are load-bearing |
| `src/dispatch.rs` | Codec-aware erasure of one `(operation, backend)` pair, and the per-operation table | A request routes but cannot be decoded, or you are wondering why the body is offered as a stream first |
| `src/adapt.rs` | The `tower::Service` and `hyper::service::Service` implementations | You are wiring the service into a server, or wondering why `Error = Infallible` |
| `src/assembly.rs` | `AssemblyError` and the `asm-*` `RuleRef` every refusal carries | You are adding an assembly-time rule; it needs a rule reference |
| `src/render.rs` | The one place any refusal becomes an `<Error>` document | You are adding a stage that can refuse, or checking that a rejection body echoes nothing |
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
| `src/ext/observer.rs` | `Observer` (synchronous), `NoObserver` | You are wiring an audit trail |

## Tests and examples

| Path | What it holds |
| --- | --- |
| `tests/support/mod.rs` | The shared fixtures: an anonymously-reachable vendor operation, backends, a body that counts what was read |
| `tests/assembly.rs` | What `build()` refuses; 11 negative, 3 positive |
| `tests/pipeline.rs` | What a request does; 11 negative, 3 positive |
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
