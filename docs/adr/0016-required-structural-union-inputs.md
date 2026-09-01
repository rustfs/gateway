# ADR-0016: Explicit construction for required structural-union inputs

- Status: Accepted
- Date: 2026-09-01
- Trigger: rustfs/backlog#2123 and rustfs/gateway#16
- Supersedes / Superseded by: none

## Context

ADR-0004 requires every operation Input and Output to implement `Default`, while a required member
stays bare. It also requires code generation to fail when a required type has no honest default and
names structural unions and streaming bodies as the two known cases.

`UpdateObjectEncryption` reaches the first real required structural-union input. Its required
`ObjectEncryption` member selects one modeled XML child. Giving that enum a default would claim the
client selected a variant it did not send. Wrapping the public field in `Option` would make the Rust
type deny the wire requirement. Leaving the operation deferred instead lets its PUT request fall
through to `PutObject`, which can replace the object with the XML document.

## Decision

A top-level operation Input may carry a required structural union without `Default`, under these
rules:

1. The public field remains the bare union type. It is never `Option<T>` and the union receives no
   sentinel or default variant.
2. That Input alone does not implement `Default`. Its builder requires every such union as an
   argument to `Input::builder`, then initializes only the remaining defaultable fields.
3. The request decoder holds fields as local state and constructs the Input only after the union
   reader selects exactly one modeled child. Zero children, multiple children and an unknown child
   are malformed XML.
4. The exception is limited to top-level request structural unions. Required unions inside nested
   structures, required output unions and required streaming bodies continue to fail code
   generation under ADR-0004 P2.
5. Adding the first such operation is a breaking public API event with affected crate version bumps
   and a migration note. Later optional fields remain source-compatible for builder callers, while
   complete struct literals must name the new fields.

## Evidence

- The focused DTO test proves `ObjectEncryption` stays bare, the Input has no `Default`, and its
  builder requires the union value at construction.
- The focused codec tests prove the reader accepts exactly one modeled child and rejects absent,
  unknown, duplicate, mixed-known/unknown, and incomplete nested payloads.
- The route and dispatch controls prove `?encryption` selects `UpdateObjectEncryption` without
  falling through to `PutObject` or colliding with bucket encryption.
- Mutating the explicit-input construction predicate, duplicate-child rejection, or IAM action
  turns the corresponding assertion red.

## Rejected alternatives

| Alternative | Why it was rejected |
|---|---|
| Give the union a default variant | It invents which XML child the client selected. |
| Store the required member as `Option<T>` | It makes the public type permit a state the wire forbids. |
| Register only a route-only refusal | It leaves a modeled, bounded XML operation permanently unavailable after the codec can represent it. |
| Generalize the exception to streaming bodies | A stream has different ownership and framing constraints and is outside this decision. |

## Consequences

- Code generation preserves requiredness and can represent `UpdateObjectEncryption` without a
  fabricated wire value.
- The generated decoder is fail-closed across absent, ambiguous and future union variants.
- Callers construct this exceptional Input with its builder or a complete literal; functional
  update syntax is unavailable because the Input has no `Default`.
- ADR-0004 remains unchanged for every existing DTO and for required streaming members.
