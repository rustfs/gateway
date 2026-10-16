# ADR-0044: Bound external data execution through explicit storage registration

- Status: Accepted
- Date: 2026-10-16
- Trigger: Crate boundary: connect facade-owned execution with explicitly capable reference-storage handlers.
- Supersedes / Superseded by: none

## Context

ADR-0043 defines owned external-data ports. Executing these ports requires the facade to retain
ordinary signature verification, both authorization stages, logical integrity and the storage
publication boundary. A physical empty HTTPS body and a logical object have different lengths.
An external download must retain the selected status, headers, body and actual EOF trailers.

## Decision

Keep control-envelope codecs and device dependencies in the independently selected host package.
Expose `call_with_external_payload_bound` and `ExternalPayloadBinding` in the facade. Require an
exactly empty physical body, trusted HTTPS and a normal SigV4 signature covering the exact bound
extension values. Authenticate the physical caller head and process logical bytes through the
existing S3 pipeline. Register upload handlers through `register_external_payload`, whose private
dispatch capability cannot be inferred from an ordinary `Handler` implementation. Adapt the
filesystem reference backend through its `external-payload` feature and shared operation helpers,
verifying external completion before the existing object or multipart publication. Return a
logical response plus independently observed output completion to the selected host for finite
response-envelope encoding.

## Evidence

Measured with Rust 1.97.1:

- `cargo test -p rustfs-gateway --test integration --features external-payload
  external_payload_marker::execution` passed five cases: successful signed logical upload,
  ordinary-handler refusal, signature refusal before preparation, and checksum refusal before
  publication, and producer failure classification through the complete S3 body pipeline.
- `cargo test -p rustfs-gateway-fs --test crud --features external-payload external_payload::`
  passed nine cases covering persisted and empty PUT, multipart completion, selected GET bytes, missing
  business resources, integrity failures and an output consumer that claims unread EOF.
- `cargo test -p rustfs-gateway --lib --features external-payload external_payload::entry::tests`
  observed a closed cancellation observer incorrectly aborting output, then passed both closed
  observer and explicit-abort cases after matching the ordinary request cancellation semantics.

## Rejected alternatives

Inferring capability from ordinary registration permits a backend to publish without explicit
external verification support. Authenticating the substituted logical head rejects valid
signatures of the physical request. Returning the logical object length with an empty HTTP body
produces an incomplete HTTP response. Repeating `GetObject` after selection can choose a different
version or invalidate the original range and conditions.

## Consequences

Default builds and ordinary handler calls retain their existing behavior and private dependencies
remain outside the workspace. An enabled storage backend must declare its external capability and
verify before publication. The facade tests enforce signature and consumption boundaries; the
reference-backend cases enforce object and multipart publication. A host must encode actual
logical headers and EOF trailers and set the physical response length to its control-envelope size.
