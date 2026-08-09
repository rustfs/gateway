# rustfs-gateway facade crate map

Agent entry point for service assembly and the end-to-end request pipeline.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Public facade and re-exports. | Start a facade task or change a public export. |
| `src/builder.rs` | `ServiceBuilder` configuration and assembly inputs. | Add or validate a builder option. |
| `src/assembly.rs` | Closed `asm-*` startup rules and errors. | A service refuses to start or `xtask why asm-*` changes. |
| `src/service.rs` | Ordered request pipeline. | A request stage runs in the wrong order. |
| `src/dispatch.rs` | Typed dispatch into registered codecs and handlers. | A routed request does not reach its handler. |
| `src/gate.rs` | Body-read proof and request-size ceilings. | A request body is read too early or exceeds a limit. |
| `src/probe.rs` | Observable request-body progress. | A test must prove whether a body was read. |
| `src/render.rs` | S3 error response rendering. | Status, headers, or XML error bytes are wrong. |
| `src/invariants.rs` | HTTP and secret-header response invariants. | A response carries forbidden content or headers. |
| `src/commit.rs` | Responses whose head is committed before their outcome. | Change the post-commit error path. |
| `src/stamp.rs` | Framework-owned response headers. | A response lacks request IDs, server, or date. |
| `src/close.rs` | Connection intent after each refusal. | A refusal keeps or closes the connection incorrectly. |
| `src/chunked.rs` | Signed `aws-chunked` ingestion handoff. | Framed uploads are decoded or rejected incorrectly. |
| `src/wire.rs` | Drained response shape with header order. | Assert on a response at the conformance boundary. |
| `src/trace.rs` | Request and host identifier sources. | IDs are missing, repeated, or need pinning in a test. |
| `src/ext/mod.rs` | Extension-point roster and defaults. | Choose or add an extension seam. |
| `src/ext/authenticator.rs` | Request authentication adapter. | Authentication accepts, refuses, or reports the wrong outcome. |
| `src/ext/credentials.rs` | Secret-bearing credential types and provider contract. | Wire IAM/STS credentials or review secret exposure. |
| `src/ext/credential_guard.rs` | Provider timeout, cache, panic isolation, and metrics. | Credential lookup cost or availability is wrong. |
| `src/ext/authorizer.rs` | Authorization request and decision contract. | Change fail-closed authorization. |
| `src/ext/policy.rs` | Per-request policy snapshots. | Authorization stages disagree about policy state. |
| `src/ext/authz_audit.rs` | Authorization audit events. | A decision is missing from audit output. |
| `src/ext/host.rs` | Addressing classification and host resolution seam. | A bucket or object target resolves incorrectly. |
| `src/ext/vhost.rs` | Virtual-hosted addressing implementation. | Host suffix or region parsing is wrong. |
| `src/ext/governor.rs` | Request-governor contract. | Add or tune a quota seam. |
| `src/ext/filter.rs` | Wire, routed, and response filters. | A deployment-level filter runs at the wrong stage. |
| `src/ext/oplayer.rs` | Per-operation typed middleware. | Middleware needs decoded input or typed output. |
| `tests/support/` | Shared integration backends and builders. | Add a facade integration scenario. |
| `tests/pipeline.rs` | End-to-end stage ordering. | Change the service pipeline. |
| `tests/authz_contract.rs` | Fail-closed authorization matrix. | Change authorization consumption. |
| `tests/credential_runtime.rs` | Credential lookup runtime guarantees. | Change credential-provider behavior. |
| `tests/trybuild_credential.rs` | Credential compile-fail surface. | Change what credential APIs expose. |
| `tests/middleware.rs` | Filter and operation-layer matrix. | Change middleware or its assembly rules. |
