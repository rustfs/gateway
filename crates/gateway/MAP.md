# rustfs-gateway facade crate map

The public facade. It assembles the protocol kernel into one non-generic `S3Service` and re-exports
the consumer surface. Ring 1: no rustfs crate dependency. Start at `src/lib.rs`; read
`src/service.rs` for request order and `docs/assembly-order.md` for extension call counts.

## Runtime and assembly

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/lib.rs` | Modules and public re-exports | A downstream caller cannot name a type |
| `src/builder.rs` | Registration, extension setters, assembly checks | Adding a knob or diagnosing `build()` |
| `src/config.rs` | Hot config, update handle, immutable request snapshot | Adding a runtime setting or checking one-load-per-request |
| `src/service.rs` | Ordered pipeline and `S3Service` | Moving a stage or tracing a response |
| `src/service_tests.rs` | The pipeline's own unit suite, split out at the 800-line limit | Changing what is decidable without a request |
| `src/adapt.rs` | tower and hyper adapters | Wiring a server or checking `Infallible` |
| `src/assembly.rs` | `AssemblyError` and `asm-*` rule refs | Adding an assembly refusal |
| `src/dispatch.rs` | Codec-aware operation erasure and dispatch table | A route cannot decode or invoke |
| `src/gate.rs` | Authentication proof, sealed body, the two ceilings' and two deadlines' values, and the four refusals they produce | Moving work around the body read |
| `src/gate_tests.rs` | The body read's own unit suite, split out at the 800-line limit | Changing a ceiling, a deadline or a framed refusal code |
| `src/wire_read.rs` | The one bounded, deadlined source of a body's wire frames, and the pull-model view the chunk pipeline reads through | A limit stops being applied per frame, or the framed path holds the wire body |
| `src/probe.rs` | Observable request-body progress | Testing whether a refusal read bytes |
| `src/chunked.rs` | `aws-chunked` ingest selection and execution | A framed upload stores wrong bytes |
| `src/integrity.rs` | What an `x-amz-checksum-*` header is the digest *of*, per operation, and how an integrity verdict renders | A body digest is compared against the wrong bytes, or not at all |
| `src/payload_header.rs` | Signed payload and trailer declaration parsing | A request head selects the wrong payload mode |
| `src/render.rs` | One S3 error renderer | Changing refusal bytes or headers |
| `src/commit.rs` | 200-then-answer/error response shape | Work continues after the head commits |
| `src/invariants.rs` | HEAD/bodyless and SSE-C response rules | A forbidden body or key reaches the wire |
| `src/monomorphic.rs` | Concrete-backend service and type-level operation set | Building or auditing static dispatch |
| `src/operation_mode.rs` | Dynamic/static adapters for the common pipeline | Auditing how a routed operation reaches its codec and handler |
| `src/posture.rs` | Startup-only security posture rendering and the public assembly snapshot | Auditing deployment security visibility |
| `src/request_deadline.rs` | Runtime-independent policy and failure-floor deadlines | Editing timeout mechanics used by the request pipeline |
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
| `src/ext/authenticator.rs` | `Authenticator`, SigV4 implementation | Replacing authentication |
| `src/ext/authenticator_tests.rs` | The authenticator's own unit suite, split out at the 800-line limit | Changing an authenticator contract |
| `src/ext/sigv2.rs` | `SigV2Authentication` and the SigV2 half of the built-in authenticator | A SigV2 client fails to authenticate |
| `src/ext/authorizer.rs` | Two-stage authorization contract | Writing policy decisions |
| `src/ext/authz_audit.rs` | Read-only decision audit sink | Recording authorization outcomes |
| `src/ext/policy.rs` | One policy snapshot per request | Two stages disagree on policy |
| `src/ext/credentials.rs` | Credential provider and secret-safe values | Wiring IAM or STS credentials |
| `src/ext/credential_guard.rs` | Provider timeout, panic isolation, negative cache | Bounding credential lookup work |
| `src/ext/host.rs` | Host resolution and path-style default | Locating the bucket source |
| `src/ext/vhost.rs` | Virtual-host label-boundary matching | Configuring served domains |
| `src/ext/governor.rs` | Governor contract and request dimensions | Adding deployment quotas |
| `src/ext/governor/default.rs` | Mandatory layered token buckets | Tuning shipped limits |
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
| `tests/service_config.rs` | Mid-request updates cannot tear a snapshot |
| `tests/handler_panic.rs` | Handler panic becomes 500; next request still runs |
| `tests/pipeline.rs` | End-to-end ordering, response shapes, body progress |
| `tests/authz_contract.rs` | Two authorization stages, audit, failure floor |
| `tests/governor_runtime.rs` | Limits run before expensive work and recover |
| `tests/cors_runtime.rs` | Preflight and actual-response CORS behavior |
| `tests/middleware.rs` | Filter and operation-layer seams |
| `tests/sse_runtime.rs` | TLS gate, key hygiene, multipart consistency |
| `tests/vhost_resolution.rs` | Host boundary and fallback behavior |
| `tests/connection_teardown.rs` | Connection intent propagation |
| `tests/payload_transport.rs` | Payload framing and cancellation observed through real HTTP/1 sockets |
| `tests/compat_aliases.rs` | Input-parameterized compatibility aliases remain identical to operation requests |
| `tests/refusal_order_guards.rs` | Body-proof source guards |
| `tests/precondition_contract.rs` | Real adapter controls for conditional-race and completed-part contract inputs |
| `tests/custom_signature_verifier.rs` | Custom verifier wiring and AWS sealed-path isolation |
| `tests/support/mod.rs` | Shared operations, backends, signing, probes |
| `examples/minimal.rs` | Minimal complete assembly and two requests |

## Known gaps

- Request bodies are buffered, bounded by `ServiceConfig::max_buffered_body_bytes` and operation caps.
- `SseEnforced` is positional rather than carried on `Req<O>`; changing that needs a core API ADR.
- Trailered `aws-chunked` modes remain unimplemented until trailer verification can commit safely.
- This crate declares connection intent; only a transport can observe a socket close.
- The header map is cloned once because `WireRequest` does not expose the accepted signing view.
- `x-amz-id-2` is a fixed uppercase-hex token, intentionally not AWS-shaped.
