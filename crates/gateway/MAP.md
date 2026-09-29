# rustfs-gateway facade crate map

The public facade assembles the protocol kernel into one non-generic `S3Service` and re-exports the
consumer surface. Ring 1: no rustfs crate dependency. Start at `src/lib.rs`; read `src/service.rs`
for request order and `docs/assembly-order.md` for extension call counts.

## Runtime and assembly

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/lib.rs` | Modules and public re-exports | A downstream caller cannot name a type |
| `src/builder.rs`, `src/builder/assembly_update.rs`, `src/builder/client_quirks.rs`, `src/builder/view_policy.rs` | Registration, validated assemblies, the MinIO-client (#916) and s3cmd ACL (#912) checksum waivers, and `view_policy.rs`'s RustFS-profile readings of every routed view (the `max-keys` ceiling, rustfs/backlog#1677) | Adding a knob, diagnosing candidate validation, or changing a client waiver or RustFS-profile reading |
| `src/config.rs`, `src/routing.rs` | One atomic settings, routing, and middleware snapshot | Updating a live generation or checking one-load-per-request |
| `src/service.rs`, `src/service/update.rs` | Ordered pipeline and atomic assembly publication; ADR-0024's service-level addressing, secret opt-in and typed path values, and ADR-0025/0026's bound bucket (template or query) and subjects, are decided in `src/routed_facts.rs`; the route stage asks one question per action and per account | Moving a stage, replacing middleware, or tracing a response |
| `src/service_tests.rs` | The pipeline's own unit suite, split out at the 800-line limit | Changing what is decidable without a request |
| `src/adapt.rs`, `src/request_end.rs` | tower and hyper adapters; whether the request body ended before the answer (marks the response for the server's lingering close) | Wiring a server, checking `Infallible`, or a head-decided refusal ending in `RST` on the Hyper driver |
| `src/conn/**`, `src/conn/response_tests.rs`, `src/conn/request_tests.rs`, `src/conn/request_cost_tests.rs`, `src/file_fallback.rs` | Optional plaintext HTTP/1.1 framing and response transport, with bounded-vector, partial-write, and scripted request scan controls; file-region bodies copied on every other transport | Auditing the self-held socket path, changing response fallback writes, or a file body failing on Hyper |
| `src/assembly.rs` | `AssemblyError` and `asm-*` rule refs | Adding an assembly refusal |
| `src/dispatch.rs` | Codec-aware operation erasure and dispatch table | A route cannot decode or invoke |
| `src/gate.rs` | Authentication proof, sealed body, the two ceilings' and two deadlines' values, and the four refusals they produce | Moving work around the body read |
| `src/gate_tests.rs` | The body read's own unit suite, split out at the 800-line limit | Changing a ceiling, a deadline or a framed refusal code |
| `src/wire_read.rs` | The one bounded, deadlined source of a body's wire frames, and the pull-model view the chunk pipeline reads through | A limit stops being applied per frame, or the framed path holds the wire body |
| `src/probe.rs` | Observable request-body progress | Testing whether a refusal read bytes |
| `src/chunked.rs`, `src/chunked_trailer_tests.rs` | `aws-chunked` ingest execution and trailer commit tests | A framed upload stores wrong bytes |
| `src/integrity.rs` | What an `x-amz-checksum-*` header is the digest *of*, per operation, and how an integrity verdict renders | A body digest is compared against the wrong bytes, or not at all |
| `src/payload_header.rs` | Signed payload and trailer declaration parsing | A request head selects the wrong payload mode |
| `src/render.rs`, `src/response.rs`, `src/select_frames.rs` | S3 error rendering, encoded-success-to-HTTP conversion, and `frame_records`, the lazy one-frame-per-read select event-stream body | Changing final response bytes or headers, or select framing memory |
| `src/commit.rs` | 200-then-answer/error response shape | Work continues after the head commits |
| `src/commit_task.rs` | Detached committed-work task ownership | Work stops after its response body is dropped |
| `src/invariants.rs` | HEAD/bodyless and SSE-C response rules | A forbidden body or key reaches the wire |
| `src/monomorphic.rs` | Concrete-backend service and type-level operation set | Building or auditing static dispatch |
| `src/operation_mode.rs` | Dynamic/static adapters for the common pipeline | Auditing how a routed operation reaches its codec and handler |
| `src/panic_boundary.rs` | Panic isolation for deployment-provided futures | An extension panic escapes the request boundary |
| `src/posture.rs`, `src/dialect_posture.rs` | Startup-only security posture rendering and the public assembly snapshot; `dialect_posture.rs` renders the `DIALECT_POSTURE` line (claimed prefixes, caller-secret operations) | Auditing deployment security visibility |
| `src/request_deadline.rs` | Runtime-independent policy and failure-floor deadlines | Editing timeout mechanics used by the request pipeline |
| `src/request_body.rs`, `src/post_object.rs` | Live verified body producer, terminal verdict, and bounded POST Object adapter | A streaming upload crosses the codec or handler boundary |
| `src/stamp.rs` | Framework-owned response headers | A response lacks IDs, `Server`, or `Date` |
| `src/trace.rs` | Request IDs and trace sources | Joining an answer to an audit record |
| `src/clock.rs` | Wall and monotonic clock sources | A request reads time twice |
| `src/close.rs` | Connection intent table | A refusal changes reuse behavior |
| `src/wire.rs` | Drained response preserving header order | Asserting exact response shape |
| `src/transport.rs` | Assembly-path vocabulary | A runner names its transport |
| `src/sig.rs` | Signature re-exports | A caller needs signing vocabulary |
## Extension points

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/ext/mod.rs` | Extension roster and safe defaults | Choosing or adding an extension |
| `src/ext/authenticator.rs`, `src/ext/authenticator_switches.rs` | `Authenticator`, SigV4 implementation; its opt-in switches (ADR-0022 secret hand-off, ADR-0023 any signing region) | Replacing authentication, or enabling either switch |
| `src/ext/authenticator_tests.rs` | The authenticator's own unit suite, split out at the 800-line limit | Changing an authenticator contract |
| `src/ext/sigv2.rs` | `SigV2Authentication` and the SigV2 half of the built-in authenticator | A SigV2 client fails to authenticate |
| `src/ext/authorizer.rs` | Two-stage authorization contract | Writing policy decisions |
| `src/ext/authz_audit.rs` | Read-only decision audit sink | Recording authorization outcomes |
| `src/ext/bucket_owner.rs` | Fail-closed bucket-owner lookup for expected-owner assertions | Wiring bucket metadata ownership into request admission |
| `src/ext/policy.rs` | One policy snapshot per request | Two stages disagree on policy |
| `src/ext/credentials.rs` | Credential provider and secret-safe values | Wiring IAM or STS credentials |
| `src/ext/credential_guard.rs` | Provider timeout, panic isolation, negative cache | Bounding credential lookup work |
| `src/ext/host.rs` | Host resolution and path-style default | Locating the bucket source |
| `src/ext/vhost.rs` | Virtual-host label-boundary matching | Configuring served domains |
| `src/ext/governor.rs` | Governor contract and request dimensions | Adding deployment quotas |
| `src/ext/governor/default.rs`, `src/ext/governor/allocation_tests.rs` | Mandatory layered token buckets and their isolated allocator/RSS probes | Tuning shipped limits or the address table's storage |
| `src/ext/governor/meter.rs` | Atomic token-bucket meter | Changing quota accounting |
| `src/ext/governor/rates.rs` | Validated default rates | Changing capacity defaults |
| `src/ext/cors.rs` | Cached bucket CORS source | Serving browser requests |
| `src/ext/cors/cache.rs` | Bounded LRU entries and recency metadata | Changing CORS cache eviction |
| `src/ext/observer.rs` | Final response observer | Wiring logs or metrics |
| `src/ext/filter.rs` | Wire, routed, and response seams | Rewriting untyped HTTP shape |
| `src/ext/oplayer.rs` | Typed per-operation middleware | Rewriting one DTO |
## Tests and examples

| Path | Contract |
| --- | --- |
| `tests/assembly.rs` | Assembly refusals, one-Arc service, required extensions |
| `tests/assembly_order.rs` | Aggregate extension call order and counts |
| `tests/service_clone_allocations.rs` | Zero-allocation connection clones |
| `tests/service_concurrency.rs` | One hundred concurrent clones and requests |
| `tests/service_config.rs`, `tests/operation_registry_hot_update.rs`, `tests/assembly_snapshot.rs` | Settings, routing, and middleware updates retain one in-flight generation and preserve concurrent partial updates |
| `tests/handler_panic.rs`, `tests/observer_panic.rs` | Handler panic becomes 500 and the next request still runs; an observer panic changes neither an ordinary response nor a committed terminal document |
| `tests/pipeline.rs`, `tests/post_object_runtime.rs`, `tests/post_object_streaming.rs` | End-to-end ordering, response shapes, POST byte ownership and allocation bounds |
| `tests/authz_contract.rs`, `tests/authz_contract/headers.rs` | Two authorization stages, audit, failure floor, and borrowed headers without Debug disclosure |
| `tests/governor_runtime.rs` | Limits run before expensive work and recover |
| `tests/cors_runtime.rs`, `tests/cors_runtime/headerless.rs` | Headerless OPTIONS rejection, preflight and actual-response CORS behavior |
| `tests/middleware.rs`, `tests/extra_response_headers.rs`, `tests/response_invariants.rs`, `tests/response_stream_termination.rs`, `tests/select_frame_records.rs` | Filter seams, handler extra response headers on both dispatch paths, runtime correction metrics, malformed response refusal, how a filter-installed stream ends on a real socket, and `frame_records` with its c-sel-0012 peak-RSS bound |
| `tests/sse_runtime.rs`, `tests/sse_runtime/context.rs` | TLS gate, key hygiene, multipart consistency and JSON context admission |
| `tests/vhost_resolution.rs`, `tests/host_resolve_replay.rs` | Host boundary and fallback behavior; the `host_resolve` fuzz property over its committed seeds and 100,000 fixed-seed samples |
| `tests/connection_teardown.rs`, `tests/self_held_http1.rs` | Connection intent and production self-held HTTP/1.1 wire controls |
| `tests/payload_transport.rs`, `tests/unread_body_refusal.rs`, `tests/file_responses.rs` | Payload framing and cancellation observed through real HTTP/1 sockets; a handler refusal before the body is read is the answer on every entry |
| `tests/compat_aliases.rs` | Input-parameterized compatibility aliases remain identical to operation requests |
| `tests/refusal_order_guards.rs` | Body-proof source guards |
| `tests/precondition_contract.rs` | Real adapter controls for conditional-race and completed-part contract inputs |
| `tests/custom_signature_verifier.rs` | Custom verifier wiring and AWS sealed-path isolation |
| `tests/support/mod.rs` | Shared operations, backends, signing, probes |
| `examples/minimal.rs`, `benches/post_object.rs` | Minimal assembly example and production POST Object throughput measurement |
## Known gaps

- Request bodies are buffered, bounded by `ServiceConfig::max_buffered_body_bytes` and operation caps.
- `SseEnforced` crosses dynamic and monomorphic dispatch on `Req<O>` under ADR-0017.
- Hyper consumes connection intent in the server runtime; the optional self-held driver observes it on its owned socket.
- The header map is cloned once because `WireRequest` does not expose the accepted signing view.
- `x-amz-id-2` is a fixed uppercase-hex token, intentionally not AWS-shaped.
