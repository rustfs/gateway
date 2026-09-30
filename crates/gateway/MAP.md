# rustfs-gateway facade crate map

The public facade assembles the protocol kernel into one non-generic `S3Service` and re-exports the
consumer surface. Ring 1: no rustfs crate dependency. Start at `src/lib.rs`; read `src/service.rs`
for request order and `docs/assembly-order.md` for extension call counts.

## Runtime and assembly

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/lib.rs`, `src/sig.rs` | Modules and public re-exports; `sig.rs` re-exports the signing vocabulary | A downstream caller cannot name a type or needs signing vocabulary |
| `src/builder.rs`, `src/builder/assembly_update.rs`, `src/builder/cors.rs`, `src/builder/client_quirks.rs`, `src/builder/view_policy.rs`, `src/builder/anonymous_framing.rs`, `src/builder/names.rs`, `src/builder/operation_selection.rs` | Registration, validated assemblies, `cors.rs`'s CORS settings (source, cache, credential posture), the MinIO-client (#916), s3cmd ACL (#912) and every-operation (rustfs/backlog#1677, R5; whole-service cases in `tests/checksum_omissions.rs`) checksum waivers, `view_policy.rs`'s RustFS-profile switches (the `max-keys` ceiling, the `BadDigest` integrity codes, rustfs/backlog#1677; an empty upload without `Content-Length`, rustfs/rustfs#6849; the pre-lookup refusals of a header signature and a presigned URL, rustfs/gateway#1130; request documents read and response documents written as legacy RustFS does, rustfs/gateway#1078), the RustFS-profile switch that leaves an anonymous aws-chunked body undecoded (#1060), and `names.rs`'s naming switches (the naming policy, its validator and slash rule, and the RustFS-profile legacy key floor, #1107, and legacy path addressing, #1115), and `operation_selection.rs`'s RustFS-profile legacy operation selection (#1127) | Adding a knob, diagnosing candidate validation, or changing a client waiver or RustFS-profile reading |
| `src/config.rs`, `src/routing.rs` | One atomic settings, routing, and middleware snapshot | Updating a live generation or checking one-load-per-request |
| `src/service.rs`, `src/service/update.rs`, `src/service/cors.rs`, `src/legacy_addressing.rs`, `src/classify.rs` | Ordered pipeline and atomic assembly publication, and the pipeline's CORS stage (the preflight branch and an ordinary response's decoration); ADR-0024's service-level addressing, secret opt-in and typed path values, and ADR-0025/0026's bound bucket (template or query) and subjects, are decided in `src/routed_facts.rs`; the route stage asks one question per action and per account; `legacy_addressing.rs` is the RustFS profile's `GET //` rewrite and pre-routing path judgement (#1115); `classify.rs` walks the same pre-authentication steps to classify a request head (#1141) | Moving a stage, replacing middleware, or tracing a response |
| `src/service_tests.rs` | The pipeline's own unit suite, split out at the 800-line limit | Changing what is decidable without a request |
| `src/adapt.rs`, `src/request_end.rs` | tower and hyper adapters; whether the request body ended before the answer (marks the response for the server's lingering close) | Wiring a server, checking `Infallible`, or a head-decided refusal ending in `RST` on the Hyper driver |
| `src/conn/**`, `src/conn/response_tests.rs`, `src/conn/request_tests.rs`, `src/conn/request_cost_tests.rs`, `src/file_fallback.rs` | Optional plaintext HTTP/1.1 framing and response transport, with bounded-vector, partial-write, and scripted request scan controls; file-region bodies copied on every other transport | Auditing the self-held socket path, changing response fallback writes, or a file body failing on Hyper |
| `src/assembly.rs` | `AssemblyError` and `asm-*` rule refs | Adding an assembly refusal |
| `src/dispatch.rs` | Codec-aware operation erasure and dispatch table | A route cannot decode or invoke |
| `src/gate.rs`, `src/gate_ceilings.rs` | Authentication proof, sealed body, the ceilings' and two deadlines' values (`gate_ceilings.rs`: the per-operation cap table, the upload-object ceiling and its refusal, `max_framed_upload_bytes`), and the refusals they produce | Moving work around the body read, or changing a body ceiling |
| `src/gate_tests.rs` | The body read's own unit suite, split out at the 800-line limit | Changing a ceiling, a deadline or a framed refusal code |
| `src/wire_read.rs` | The one bounded, deadlined source of a body's wire frames, and the pull-model view the chunk pipeline reads through | A limit stops being applied per frame, or the framed path holds the wire body |
| `src/probe.rs` | Observable request-body progress | Testing whether a refusal read bytes |
| `src/chunked.rs`, `src/chunked_trailer_tests.rs` | `aws-chunked` ingest execution and trailer commit tests | A framed upload stores wrong bytes |
| `src/integrity.rs` | What an `x-amz-checksum-*` header is the digest *of*, per operation, and how an integrity verdict renders | A body digest is compared against the wrong bytes, or not at all |
| `src/payload_header.rs`, `src/builder/bodyless_digest.rs`, `src/builder/bodyless_bodies.rs` | Signed payload and trailer declaration parsing, the RustFS-profile switch that leaves a bodyless request's signed digest uncompared (#1099), and the one that leaves the body of an operation that takes none unread (#1173) | A request head selects the wrong payload mode, a bodyless request is held to a digest, or a bodyless operation reads its body |
| `src/render.rs`, `src/response.rs`, `src/select_frames.rs`, `src/builder/legacy_sentences.rs`, `src/builder/legacy_heads.rs` | S3 error rendering, encoded-success-to-HTTP conversion, `frame_records`, the lazy one-frame-per-read select event-stream body, the RustFS-profile switch that answers body refusals with legacy RustFS sentences (#1099), and the one that writes a successful answer's status and headers as legacy RustFS does (#1148) | Changing final response bytes or headers, select framing memory, a RustFS-profile refusal sentence, or a RustFS-profile answer head |
| `src/commit.rs` | 200-then-answer/error response shape | Work continues after the head commits |
| `src/commit_task.rs` | Detached committed-work task ownership, its span, and the host's `DetachedWork` count | Work stops after its response body is dropped, or a host's shutdown cuts it off |
| `src/invariants.rs` | HEAD/bodyless and SSE-C response rules | A forbidden body or key reaches the wire |
| `src/monomorphic.rs` | Concrete-backend service and type-level operation set | Building or auditing static dispatch |
| `src/operation_mode.rs` | Dynamic/static adapters for the common pipeline | Auditing how a routed operation reaches its codec and handler |
| `src/panic_boundary.rs` | Panic isolation for deployment-provided futures and report callbacks | An extension panic escapes the request boundary |
| `src/logging.rs` | The `tracing` vocabulary every event shares (target, component, subsystems, event names), the dangerous-assembly event, the refusal and panic reporters (`request_refused`, `extension_panicked`) and the `Throttle` bounding per-request `error` events; catalogue in `docs/observability.md`, cases in `tests/tracing_events.rs` | An event is added, renamed or leveled, or a refusal is reported at the wrong stage |
| `src/posture.rs`, `src/dialect_posture.rs`, `src/presigned_expiry_posture.rs`, `src/naming_posture.rs` | Startup-only security posture rendering and the public assembly snapshot; `dialect_posture.rs` renders the `DIALECT_POSTURE` line (claimed prefixes, caller-secret operations); `presigned_expiry_posture.rs` renders `PRESIGNED_EXPIRY_POSTURE` when a non-default presigned-lifetime rule is on; `naming_posture.rs` renders the `NAMING_POSTURE` line (slash rule, key floor) | Auditing deployment security visibility |
| `src/request_deadline.rs` | Runtime-independent policy and failure-floor deadlines | Editing timeout mechanics used by the request pipeline |
| `src/request_body.rs`, `src/post_object.rs`, `src/post_object/legacy.rs`, `src/builder/post_forms.rs` | Live verified body producer, terminal verdict, bounded POST Object adapter, what a RustFS-profile form stores (or refuses), and `legacy_rustfs_post_forms`, the switch that selects it (held in `ViewPolicy`, rustfs/backlog#1677 R8) | A streaming upload crosses the codec or handler boundary, or a RustFS-profile form stores differently from legacy RustFS |
| `src/stamp.rs` | Framework-owned response headers | A response lacks IDs, `Server`, or `Date` |
| `src/trace.rs` | Request IDs and trace sources | Joining an answer to an audit record |
| `src/clock.rs` | Wall and monotonic clock sources | A request reads time twice |
| `src/close.rs` | Connection intent table | A refusal changes reuse behavior |
| `src/wire.rs` | Drained response preserving header order | Asserting exact response shape |
| `src/transport.rs` | Assembly-path vocabulary | A runner names its transport |
## Extension points

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/ext/mod.rs` | Extension roster and safe defaults | Choosing or adding an extension |
| `src/ext/authenticator.rs`, `src/ext/authenticator_presented.rs`, `src/ext/authenticator_switches.rs`, `src/ext/legacy_refusal.rs`, `src/ext/legacy_credential.rs` | `Authenticator`, SigV4 implementation; the signature material each surface presented; its opt-in switches (ADR-0022 secret hand-off, ADR-0023 any signing region, the empty signing region of rustfs/backlog#1677, the legacy RustFS signing services and scope refusals of rustfs/gateway#1130); a refusal worded as legacy RustFS words it; a credential read as legacy RustFS reads one | Replacing authentication, enabling a switch, or a RustFS-profile refusal sentence |
| `src/ext/authenticator_tests.rs` | The authenticator's own unit suite, split out at the 800-line limit | Changing an authenticator contract |
| `src/ext/sigv2.rs` | `SigV2Authentication` and the SigV2 half of the built-in authenticator | A SigV2 client fails to authenticate |
| `src/ext/authorizer.rs` | Two-stage authorization contract | Writing policy decisions |
| `src/ext/authz_audit.rs` | Read-only decision audit sink, and the `warn` event for a decision that refused | Recording authorization outcomes |
| `src/ext/bucket_owner.rs` | Fail-closed bucket-owner lookup for expected-owner assertions | Wiring bucket metadata ownership into request admission |
| `src/ext/policy.rs` | One policy snapshot per request | Two stages disagree on policy |
| `src/ext/credentials.rs` | Credential provider and secret-safe values | Wiring IAM or STS credentials |
| `src/ext/credential_guard.rs` | Provider timeout, panic isolation, negative cache | Bounding credential lookup work |
| `src/ext/host.rs` | Host resolution, the path-style default, and `HostResolver::refusal` | Locating the bucket source |
| `src/ext/vhost.rs`, `src/ext/legacy_vhost.rs` | Virtual-host label-boundary matching; the RustFS profile's legacy RustFS reading of its server domains, with the one host refusal (#1136) | Configuring served domains |
| `src/ext/governor.rs` | Governor contract and request dimensions | Adding deployment quotas |
| `src/ext/governor/default.rs`, `src/ext/governor/allocation_tests.rs`, `src/ext/governor/refund_tests.rs` | Mandatory layered token buckets, the charge a verified request returns, and their isolated allocator/RSS probes | Tuning shipped limits, the address table's storage, or what stays counted |
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
| `tests/pipeline.rs`, `tests/post_object_runtime.rs`, `tests/post_object_streaming.rs`, `tests/post_object_legacy_form.rs`, `tests/post_object_legacy_fields.rs` | End-to-end ordering, response shapes, POST byte ownership and allocation bounds, the object a RustFS-profile form stores, and the `PutObject` members it hands its handler |
| `tests/authz_contract.rs`, `tests/authz_contract/headers.rs` | Two authorization stages, audit, failure floor, and borrowed headers without Debug disclosure |
| `tests/governor_runtime.rs` | Limits run before expensive work and recover |
| `tests/cors_runtime.rs`, `tests/cors_runtime/headerless.rs` | Headerless OPTIONS rejection, preflight and actual-response CORS behavior |
| `tests/middleware.rs`, `tests/extra_response_headers.rs`, `tests/response_invariants.rs`, `tests/response_stream_termination.rs`, `tests/select_frame_records.rs` | Filter seams, handler extra response headers on both dispatch paths, runtime correction metrics, malformed response refusal, how a filter-installed stream ends on a real socket, and `frame_records` with its c-sel-0012 peak-RSS bound |
| `tests/sse_runtime.rs`, `tests/sse_runtime/context.rs` | TLS gate, key hygiene, multipart consistency and JSON context admission |
| `tests/vhost_resolution.rs`, `tests/host_resolve_replay.rs` | Host boundary and fallback behavior; the `host_resolve` fuzz property over its committed seeds and 100,000 fixed-seed samples |
| `tests/connection_teardown.rs`, `tests/self_held_http1.rs`, `tests/host_deadlines.rs` | Connection intent and production self-held HTTP/1.1 wire controls; `Duration::MAX` as the no-framework-deadline spelling, proved against a bounded deadline on the same staged write |
| `tests/payload_transport.rs`, `tests/unread_body_refusal.rs`, `tests/file_responses.rs`, `tests/empty_upload_without_length.rs` | Payload framing and cancellation observed through real HTTP/1 sockets; a handler refusal before the body is read is the answer on every entry; the RustFS-profile empty upload without `Content-Length` and the neighbours that keep their `411` |
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
