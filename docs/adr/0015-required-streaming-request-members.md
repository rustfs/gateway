# ADR-0015: Required streaming request members use controlled construction

- Status: Accepted
- Date: 2026-09-01
- Trigger: rustfs/backlog#2124 and rustfs/gateway#16
- Supersedes / Superseded by: none

## Context

ADR-0004 requires every generated Input and Output to implement `Default`, while keeping required
members bare. That combination fails closed when a required member has no truthful default. The
pinned S3 model now contains `PutObjectAnnotation.AnnotationPayload`: a required streaming blob
whose value is the live request-body producer. Wrapping it in `Option` would weaken the model;
inventing an empty stream would claim that a body arrived when it did not; leaving the operation
excluded lets its `PUT` route fall through to `PutObject` and replace the parent object's bytes.

The runtime already hands a streaming operation to its codec as an owned `RequestBody`, and
ADR-0012 requires that stream to cross into the handler without aggregation. The missing rule is
how a generated DTO obtains that owned stream without first constructing a placeholder DTO.

## Decision

Exactly one operation Input member may bypass ADR-0004's `Default` requirement when all of these
facts come from the lowered IR:

- it is required;
- it is the operation's only request-body binding;
- its binding is `Payload`; and
- its type is a streaming blob.

Such an Input keeps the member bare and public, does not implement `Default`, and exposes
`from_required_body(ByteStream)`. Its builder also requires that `ByteStream` at construction.
The generated decoder consumes the real `RequestBody` once, creates the Input through that
constructor, then fills the remaining bindings and runs the ordinary required-member exit check.
The streaming member needs no placeholder check because safe construction cannot omit it.

This is not an operation-name exception. Optional streams, multiple body bindings, response
streams, body XML, form fields, nested streams and structural unions remain behind ADR-0004 P2's
hard generation failure. Every other generated Input and every Output keeps `Default`.

## Evidence

- Before this decision, admitting `PutObjectAnnotation` stopped generation at
  `PutObjectAnnotation.input.AnnotationPayload` because `ByteStream` has no `Default`.
- The focused DTO test proves the field stays bare, the Input and builder have no zero-argument
  default path, and the only constructor argument is the real `ByteStream`.
- The focused codec test proves `body.into_stream()` occurs once, before ordinary binding
  assignments, with no later payload reassignment.
- A corpus-wide negative test proves every other generated Input still implements `Default`.
- Mutating the policy to accept an optional streaming payload makes `PutObjectInput` incorrectly
  lose `Default` and turns that negative test red. Mutating the decoder to fabricate the body
  turns the body-injection test red.

## Rejected alternatives

- Make `AnnotationPayload` optional: the public type would deny a required model fact and every
  handler would need to recover it dynamically.
- Implement `Default` for `ByteStream`: an empty producer is an observable body value, not the
  absence of construction, so this invents a wire fact.
- Give only `PutObjectAnnotation` a hand-written DTO or codec: it would split generated protocol
  authority and make the next required streaming member a second special case.
- Reserve only the route: returning a refusal would avoid the destructive fallback but would not
  deliver the operation's real DTO, codec and dispatch capability.
- Store an `Option<ByteStream>` privately in the public Input: private fields would make the DTO
  builder-only and break the public-field contract more broadly than the required member does.

## Consequences

- `PutObjectAnnotationInput` becomes public and must be constructed with
  `PutObjectAnnotationInput::from_required_body(stream)` or
  `PutObjectAnnotationInput::builder(stream)`. There was no prior generated type to migrate.
- Future code that handles a generated required streaming Input must not assume `Input: Default`.
  It should use the operation's required-body constructor. Existing Inputs and Outputs are
  unchanged.
- Adding an optional field to this narrow Input can break exhaustive struct literals because
  functional update syntax is unavailable. Callers should use the builder or constructor; this
  workspace is still pre-1.0, and the affected crate versions advance with this change.
- Generated DTO, codec, route and error-status artifacts change together. The PR description must
  contain `BREAKING` and repeat the constructor migration above because those artifacts are
  protected contracts.
