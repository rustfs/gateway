# ADR-0043: Owned external object-data ports

- Status: Accepted
- Date: 2026-10-16
- Trigger: Additive typed handler and facade interfaces for an explicitly enabled external data path.
- Supersedes / Superseded by: none

## Context

An object-data transport may carry upload bytes outside the HTTP request body while retaining
S3 request signing, authorization, conditions, checksums and business results. Empty HTTP body
verification cannot prove that the object bytes are complete. A handler must verify the external
input before publishing an object or multipart part. Device and peer implementation details belong
in the host integration; the protocol kernel must keep its dependency direction.

## Decision

Keep `Req<O>` and `HandlerContext` unchanged. Add the default-disabled `external-payload` feature
to core and the facade. Core exposes transport-neutral `ExternalPayloadControl`,
`LogicalPayloadCompletion`, `ExternalPayloadExecution`, the opaque `ExternalPayloadContext` and
explicit `ExternalPayloadHandler<O>`. Its context delegates directly to the execution capability;
core owns no execution state, data polling, scheduling, future allocation or native dependency.
No ordinary handler acquires external-data support through a default method.

The facade's `external_payload_context(length, control, logical)` factory creates one execution
owner and exposes it through the core context. The facade owns dormant input, actual delivered-byte
accounting, shared admission and verification, cancellation, and the explicit handler dispatch.
`bind_input` checks the declared exact length and binds one body. `verify_before_publish` rejects
unread input and requires both the original logical S3 integrity monitor and actual transport
terminal verification. An empty object requires the same admission and verification. Context clones
share one execution, admission and verification; all observers retain the first terminal cause.
Cancellation wakes dormant input while the transport owner retains progress, access-end evidence
and resource reclamation.

The facade's `dispatch_external_payload` accepts the `Req<O>` already produced by the ordinary
pipeline and invokes an explicitly capable handler. It neither decodes nor authorizes a request.
Its response guard rejects success without completed verification; it cannot undo a backend's
early publication. Storage integrations must verify before their existing publication boundary.

Every ordinary service entry rejects the reserved `x-rustfs-rdma-` namespace before invoking a
handler, regardless of feature selection. This also checks headers before and after wire filters.
A signed request's empty wire body therefore cannot be committed by an ordinary upload handler.

### Current executable boundary

This change implements the typed ports, dormant input, cancellation and publication guards. It
does not connect the signature-bound extension codec, the logical S3 checksum monitor, external
operation registration or response-envelope encoding. Both dynamic and monomorphic
`call_with_external_payload` methods explicitly refuse with `501 NotImplemented` after ordinary
wire acceptance, without preparing an exchange. They do not advertise a successful data path.

Completing that service path must preserve the existing signature, route authorization, input
authorization, SSE and layer stages. Providers receive a facade-created `ExternalRequest`; it has
no public constructor. The selected response consumer receives the final encoded response, its
exact logical length and unmodified duplicate-preserving header values. It must not repeat the
business operation or select a different version.

Native implementation dependencies belong in an independently selected host package. Normal
workspace builds have no dependency on a private source checkout. The build and repository-access
workflow is documented in [RDMA builds](../rdma-build.md).

## Evidence

The [service marker tests](../../crates/gateway/tests/external_payload_marker.rs) exercise ordinary
empty uploads alongside required, orphan and false-valued extension markers. The
[facade execution tests](../../crates/gateway/src/external_payload_execution/tests.rs) cover
single-use binding, lengths, dormant polling, cancellation, shared admission, both verification
sources, unread suffix rejection and empty-object completion. An unavailable transport produces
an explicit error and never a successful EOF.

## Rejected alternatives

An implicit extension on `Handler<O>` would let a storage integration publish without declaring
external verification support. Execution inside core would introduce scheduling and resource
ownership into its pure interface boundary. A private dependency in the normal workspace would
require repository access even when external-data support is disabled.

## Consequences

Default S3 routes and handler APIs retain their signatures and behavior. Storage integrations must
declare the explicit handler capability and complete verification before publication. The enabled
feature provides preparation interfaces while the service refuses unconnected external requests.
