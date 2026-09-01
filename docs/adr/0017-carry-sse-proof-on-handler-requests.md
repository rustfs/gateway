# ADR-0017: Carry the SSE enforcement proof on handler requests

- Status: Accepted
- Date: 2026-09-01
- Trigger: SSE transport enforcement must remain true across the erased handler boundary
- Supersedes / Superseded by: none

## Context

The facade validates SSE headers and transport security before reading the body, but the resulting
`SseEnforced` value was discarded. A handler that needed a customer-key fingerprint had to parse
the request metadata again inside its codec. That reused the same parser, but it did not prove that
the handler received the result produced by the production pipeline's earlier gate. `Req<O>` is the
owned, typed boundary every dynamic and monomorphic handler already receives.

## Decision

Store `SseEnforced` in `Req<O>`, expose it through a read-only `Req::sse` accessor, and require the
proof at every constructor and erased/static invocation transition. The facade stores the exact
proof produced above the body read in its private request-state carrier and supplies it when the
authorized input becomes `Req<O>`. Do not expose a default or empty proof constructor, and do not
reparse SSE headers in an operation codec to recreate the value.

## Evidence

On Rust 1.97.1, `cargo test -p rustfs-gateway-core --test integration
compile_time_contracts_are_not_openable -- --nocapture` rejects a real `PutObjectInput` wrapped in
`Req<PutObject>` without an `SseEnforced` argument with E0061. The 64-bit request snapshot grows
from 32 to 96 bytes and remains below the existing 136-byte ceiling. The gateway SSE runtime test
uses an intentionally empty codec field while its handler observes the customer-key fingerprint
through `Req::sse`; substituting the empty codec field makes the assertion fail.

## Rejected alternatives

- Keeping the proof only in the facade's request configuration leaves downstream handlers unable
  to observe it and preserves the second-parse escape hatch.
- Putting an extensible type map on `Req<O>` makes the security proof optional at run time and
  turns missing enforcement into a lookup branch.
- Reconstructing the proof from decoded operation input does not prove the transport gate ran and
  creates a second place whose parsing can drift.

## Consequences

Direct handler tests and typed registry callers must first obtain `SseEnforced` from `sse::enforce`
and pass it to `Req::new` or the invocation helper. This is a breaking core API change, so the core
and facade minor versions advance. The trybuild fixture guards the missing-proof boundary, the
request-size snapshot guards layout drift, and the production SSE runtime test guards against
substituting a codec reconstruction for the pipeline-produced proof.
