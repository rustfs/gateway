# ADR-0019: Bounded JSON validation for the KMS encryption context

- Status: Accepted
- Date: 2026-09-12
- Trigger: dependency policy; permit a JSON parser in the protocol runtime
- Supersedes / Superseded by: none

## Context

The SSE gate currently validates the encryption context's canonical base64, decoded byte ceiling
and UTF-8. It accepts plain text, truncated JSON and arrays after those checks. Such a request can
reach a handler even though the header is supposed to describe a KMS context. This is the remaining
structural validation gap tracked by rustfs/backlog#2140.

`serde` and `serde_json` are already workspace dependencies, but neither is in the core runtime
closure. Adding a normal dependency is a dependency-policy decision, not permission to write a
partial JSON parser or to introduce a RustFS dependency into the protocol rings.

## Decision

Allow the existing workspace `serde` and `serde_json` packages as normal dependencies of
`rustfs-gateway-core` for this validation. Keep the existing 2,048-byte decoded context ceiling and
canonical base64/UTF-8 checks ahead of JSON parsing. Do not add a configurable limit or enable
`serde_json`'s `unbounded_depth` feature.

Accept one complete JSON object whose keys and values are strings. Empty objects and empty strings
remain structurally valid; key-policy meaning belongs to the KMS adapter. Require unique keys after
JSON escape decoding, including when two different escaped spellings name the same key. Preserve
the caller's original encoded header after validation; do not normalize, coerce or reserialize it.

Use a small Serde map visitor rather than deserializing into `Value` or a map that overwrites
repeated keys. A set of decoded keys detects duplicates. Values must deserialize directly as
strings, so a nested object or array fails at its opening token without recursive construction.
The accepted container depth is therefore one; deeply nested input is a refusal, not a traversal.
Require end of input after the object, allowing only JSON whitespace.

Reject malformed syntax, non-object roots, non-string values, duplicate keys and trailing content
with `InvalidArgument` before request-body consumption or handler dispatch. Translate parser errors
to a fixed refusal without exposing the context, decoded strings, or parser diagnostics. Retain the
existing SSE proof and redaction boundaries. This changes validation, not KMS calls, encryption or
stored metadata readers.

## Evidence

- Measured at gateway `52fb4913` with Rust 1.97.1: `cargo tree -p rustfs-gateway-core -e normal
  --prefix none` contains neither `serde` nor `serde_json`; both are already declared in the
  workspace manifest.
- Measured against the unchanged core SSE implementation: `ManagedChannel::validate` accepts all
  four base64 inputs below with `algorithm = Some("aws:kms".into())`, no key id, and no bucket-key
  switch. Calling it with `context = Some(input.into())` reproduces the missing structural check.

  | Decoded fixture | Base64 input | Current result |
  | --- | --- | --- |
  | `{}` | `e30=` | accepted |
  | `[]` | `W10=` | accepted |
  | `x` | `eA==` | accepted |
  | `{` | `ew==` | accepted |

- [Inferred from the published contracts] [S3 PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html)
  carries context pairs inside base64-encoded UTF-8 JSON; [KMS encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html)
  defines the context as string pairs. This boundary validates that representation and performs no
  KMS-specific value coercion.
- [Inferred] [RFC 8259 section 4](https://www.rfc-editor.org/rfc/rfc8259#section-4) explains that
  repeated names can be interpreted differently by readers. Refusing them is an explicit gateway
  interoperability rule, not a claim that the JSON grammar itself forbids them. The 2,048-byte
  ceiling is also gateway policy, retained from the existing implementation rather than attributed
  to an AWS limit.

## Rejected alternatives

- A hand-written parser would have to reproduce JSON escape, Unicode, token and trailing-input
  rules. The workspace already uses a maintained parser that can enforce them.
- `serde_json::Value` followed by a root-object check loses duplicate-key evidence during parsing
  and admits values that are not context strings.
- A new JSON crate or configurable depth adds another policy and dependency surface for a single
  bounded header. Rejecting nested containers at the string-value boundary needs neither.
- Deferring every check to a handler keeps malformed contexts behind backend-specific behavior and
  fails the existing requirement that the SSE proof be established before dispatch.

## Consequences

The implementation belongs in the shared core SSE gate so all operations receive the same proof.
It needs no new crate or dependency direction between workspace crates. This record authorizes the
external parser dependency; it does not mark #2140 complete.

The follow-up must demonstrate valid contexts reaching a handler, malformed contexts reaching
neither the body reader nor the handler, exact 2,048/2,049-byte behavior, Unicode and escaped-key
handling, and fixed error responses without context leakage. Negative cases must outnumber
positive controls, and every new assertion must be killed by a corresponding implementation
mutation. Public rejection variants or protected protocol records follow the usual version and
migration process.
