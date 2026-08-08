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
| `src/gate.rs` | `Authenticated`, `SealedBody`, `BodyCeilings`: the proof a stage must hold before it may read a request body, the one bounded read, and the two ceilings it is subject to | You are moving a stage relative to the body read, adding a per-operation body cap, or asking why the read is not just a `collect()` |
| `src/probe.rs` | `ObservedBody`/`BodyProgress`: a request body that reports how much of itself the service asked for | You need `expect.request_progress` to be a measurement, or you are writing a test about when a refusal happened |
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
| `src/close.rs` | `ConnectionIntent` and the per-stage table that produces one: which refusals end the connection, which rows are RFC 9112 §9.3/§6.1/§6.3 and which are this service's judgement | A refusal closed a connection it should not have, or you are adding a stage that can refuse and have to say what it does to the connection |
| `src/chunked.rs` | `ChunkIngest`: whether the `aws-chunked` parser runs for a request, the material it runs with, and the pass itself | A framed upload stored the wrong bytes, or you are asking which side of the decode the ceilings count |
| `src/transport.rs` | `Transport` — which assembly path a run used | You are adding a path, or a runner has to name one |
| `src/sig.rs` | The signature vocabulary re-exported through the facade, including `sig::Signer` (the client-side `SigV4Signer`) | You need to name a `Verdict`, a `SecurityFloor` or an `AuthError`, or a test harness has to sign a request |
| `src/ext/mod.rs` | The extension-point roster, and the table of which have defaults and what each default costs | You are choosing what to install, or adding an extension point |
| `src/ext/authenticator.rs` | `Authenticator` (no default), and `SigV4Authenticator` assembled from `-sig`'s public primitives | Authentication behaved unexpectedly, or you are replacing the scheme |
| `src/ext/authorizer.rs` | `Authorizer` (no default), `AuthzRequest`, `Denial`, `allow_when` | You are writing a policy, or asking why there is no default |
| `src/ext/credentials.rs` | `Credentials`, `CredentialProvider`, `StaticCredentials` | You are wiring an IAM store, or a secret appeared somewhere it should not |
| `src/ext/host.rs` | `HostResolver` (synchronous), the `Addressing`/`TargetOrigin`/`VhostHint` vocabulary its answer is written in, and the default `PathStyleOnly` | You are asking where the bucket in a request came from, or why a `501` came back with a sentence about virtual hosts |
| `src/ext/vhost.rs` | `VirtualHostStyle`: label-boundary matching against configured `BaseDomain`s, the bucket/region prefix table, and the unconditional path-style fallback | Virtual-hosted addressing is not working, a host resolved to a bucket you did not expect, or you are configuring base domains and `new()` refused one |
| `src/ext/governor.rs` | `Governor`, `Unlimited`; the hook that runs after routing and before the body | You are adding a quota, or checking the hook's position |
| `src/ext/observer.rs` | `Observer` (synchronous), `NoObserver`, and the `RequestEvent` that carries the request identifier | You are wiring an audit trail, or joining a log line to the identifier a caller quoted |
| `src/ext/filter.rs` | `StageFilter` and its three synchronous seams — `on_wire` (the head, mutable, before acceptance), `on_routed` (read-only), `on_response` (mutable, before the invariants) — plus `WireHead`, `RoutedView`, `ResponseView`, the frozen `Host` header, and the three closure adapters | A deployment needs to rewrite a request or a response without a typed input, or you are asking why a filter cannot answer, cannot touch a signature and cannot choose the target. `docs/middleware.md` is the decision tree |
| `src/ext/oplayer.rs` | `OpLayer<O>`, the one-shot continuation `Next<'a, O>`, the `op_layer` closure adapter, and `OpLayerSlot` — the typed box that lets a per-operation layer live in a registry that has forgotten the operation | You want one operation's decoded input or typed output, or you are asking how a typed layer is stored and reached. The chain is built in `src/dispatch.rs`, the last place `O` exists |

## Tests and examples

| Path | What it holds |
| --- | --- |
| `tests/support/mod.rs` | The shared fixtures: an anonymously-reachable vendor operation, its `HEAD`/content twins covering every response shape (content, refusal, `304`, commit-then-answer, commit-then-fail), backends, a body that counts what was read |
| `tests/assembly.rs` | What `build()` refuses; 11 negative, 3 positive |
| `tests/pipeline.rs` | What a request does, the request identifier included, the RFC 9110 body rules on both paths, the commit seam, and the four measurements that say a refusal happened before the payload was asked for; 29 negative, 7 positive |
| `tests/refusal_order_guards.rs` | Source guards on the body gate: the proof keeps one real constructor, the read still demands it, the pipeline seals above the verifier and reads below it, and nothing else in the crate drains a request body; 5 negative, each paired with a proof it can fire |
| `tests/connection_teardown.rs` | That the connection verdict branches and reaches the response, that the two `403`s do not share one, and that nothing here claims to have observed a socket; 9 negative, 1 positive |
| `tests/facade_probe.rs` | Every export the conformance runner's `REQUIRED_FACADE_EXPORTS` names, checked by naming it |
| `tests/backend_reachability.rs` | Every argument of the range contract, built from a decoded request and never from a literal; 5 negative, 1 positive. Read this before adding a constructor a backend is meant to call |
| `tests/vhost_resolution.rs` | Which byte of a `Host` header may become a bucket name: the label boundary that separates `bucket.s3.example.com` from `evils3.example.com`, the prefix table, the base-domain refusals, and the two properties of the diagnostic — it fires only when a request really looks virtual-hosted, and it never changes the resolution. 18 negative, 8 positive. Read it before changing anything in `src/ext/vhost.rs`; the resolution *shape* is what no response can show |
| `tests/middleware.rs` | The three `StageFilter` seams and `OpLayer<O>`: that each seam runs, that registration order is observable in both directions, that a refusal ends the request, that a layer reaches its own operation and not a sibling, and the two halves of "a filter cannot reach a signature" — a forged `Authorization` changes nothing, and a deleted one does not break a request that really is signed; 20 negative, 12 positive |
| `tests/patch_layer_landings.rs` | Exactly nine tests, one per RustFS tower patch layer, asserting that the landing `docs/middleware.md` claims for it is real. `scripts/check_patch_layer_map.sh` requires the two sets to match in both directions, and `P10-06` deletes the nine layers against this list |
| `tests/replication_token.rs` | That `x-amz-bucket-object-lock-token` reaches a handler off a decoded `PutBucketReplication`, present **and** absent; 2 negative, 1 positive. It exists because a header parsed and then dropped answers 200 exactly like one that arrived, so the conformance case could not tell them apart |
| `tests/select_restore_intent.rs` | Two things no response can see: that a select's and a restore's decoded members reach a handler — the scan range, the progress switch, the version selector, the nested select-on-restore query, each asserted present **and** absent — and that the exported event-stream frames read back under a CRC-32 written in the test file itself, with every single-byte corruption of a frame refused; 5 negative, 6 positive |
| `examples/minimal.rs` | The whole assembly in one file, asserting one answered request and one refused one |

## Known gaps, recorded rather than discovered

- **Nothing in this crate drives a signed request.** `sig::Signer` is re-exported but unused here;
  every AWS operation is header-signatures-only, and the tests reach a handler through a vendor
  operation that declares itself anonymously reachable instead.
- **`rustfs_gateway_core::registry::ErasedCodec` supersedes `src/dispatch.rs`.** The core registry
  gained its own codec erasure after this crate's was written; folding one into the other is a
  follow-up, not a behaviour change.
- **The request body is buffered.** Capped by `DEFAULT_MAX_BUFFERED_BODY_BYTES` (64 MiB); the
  streaming ingest path is not wired through the facade. The ceiling is now applied *inside* the
  frame loop rather than to the collected result, so the refusal arrives at the frame that crosses
  the line and the rest is never buffered — but the bytes up to that point still are.
- **The per-operation body cap lives in the wrong crate.** `gate::declared_body_cap` is a two-line
  table in this crate with one entry (`DeleteObjects`, 2 MiB, from the documented thousand-entry
  limit). It belongs on `rustfs_gateway_core::Operation`, beside `spec()` and `floor()`, so that an
  operation with a bounded body cannot be added without stating its bound. It is here because a
  table with one honest entry beats an assembly that enforces nothing, and `crates/core/src/op.rs`
  was outside the change that needed the enforcement.
- **The connection verdict is a declared table, and three of its rows are judgement calls.**
  `src/close.rs` holds it. The rule it applies is RFC 9112 §9.3 — *a server MUST read the entire
  request message body or close the connection after sending its response* — so this service never
  chooses to close; it chooses whether it will drain, and the close follows. Both
  `must_close_connection` flags now branch (they returned a constant `true`, so every assertion that
  read one passed for every input), `render.rs` carries the verdict onto the response as
  `Connection: close` and publishes it as `S3Error::connection_intent`, and an authentication
  failure is the third leg `c-sig-0001` needed — it is an `AuthError`, so neither flag could ever
  have reached it. What is **not** RFC-derived, and is marked as such at each site: "an
  unauthenticated peer's body is not drained", "a body refused for its size is not drained", and
  the 64 KiB drain budget in `rustfs_gateway_http::MAX_LINGER_DRAIN_BYTES`. `c-mpu-0045` is a
  documented disagreement rather than an encoded row; see the module docs.
- **Nothing in this crate closes a socket, and nothing in it claims to.** The verdict is a value on
  the response. Whether the connection actually ends is the transport's, and `c-sig-0001`,
  `c-object-0015` and `c-chunked-0001` stay red or skipped until a transport reads it — the
  in-process target reports `connection_after = "open"` unconditionally, and that file is
  `crates/conformance`'s.
- **`aws-chunked` framing is decoded here now, for one mode.** `src/chunked.rs` runs
  `rustfs_gateway_http::IngestPipeline` inside the body read, after the verifier, so a
  `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` body is decoded rather than stored with its own framing in
  it — which is what happened before, silently and with a `200`. Both ceilings count **wire** bytes,
  before decoding; the reasoning is in that module. Trailered modes answer `501`, because
  `IngestPipeline::commit_allowed` stays `false` until the trailer is verified and that is P3-04's.
  Signed chunk verification needs `k_signing`, which no `Verdict` carries, so it travels beside the
  verdict through `ext::ChunkSink` — additive, and an existing `Authenticator` simply never fills it.
- **Virtual-hosted addressing resolves, and three things around it do not yet.** `VirtualHostStyle`
  reads the bucket and the region out of a host and `MetaView::addressed` applies them, so
  `Host: bucket.s3.example.com` with `GET /key` reaches `bucket`. What is *not* wired: the region
  the host carried is published on `ResolvedHost` and read by nobody — `SigV4Authenticator` verifies
  against the `RegionSet` a deployment configured, which is the right source for a signature, and no
  consumer has yet asked "which region did the endpoint claim"; `HostClass` is always `Standard`,
  because the Object Lambda, S3 Express, Outposts, Accelerate, Dualstack and website host shapes are
  a routing-predicate question and no built-in resolver produces those values; and `TargetOrigin` is
  computable from `ResolvedHost` but is not yet in `RequestEvent`, so an audit trail cannot say "this
  bucket name came out of the Host header" without asking the resolver again. The last one is the
  smallest and the most worth doing.
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
