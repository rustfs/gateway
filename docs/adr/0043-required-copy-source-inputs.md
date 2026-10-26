# ADR-0043: Explicit construction for required copy-source inputs

- Status: Accepted
- Date: 2026-10-26
- Trigger: licensing/dependency policy (ADR-0004 public API construction contract), rustfs/gateway#1470
- Supersedes / Superseded by: none

## Context

The canonical `CopyObjectInput` and `UploadPartCopyInput` currently store the required
`x-amz-copy-source` header as a `String`. RustFS migration needs its decoded bucket or ARN
components and version presence in those same operation inputs. The owned `CopySourceValue`
carrier preserves those fields, including `None` versus `Some("")`, without validating names
or granting access. It has no truthful `Default`.

ADR-0004 keeps required fields bare and requires a separate decision when their type cannot
implement `Default`. ADR-0015 permits a required streaming payload; ADR-0016 permits a modeled
structural union. Neither exception covers this required header. Adding an unrelated RustFS
wrapper would not meet the canonical DTO boundary required by
[backlog#2749](https://github.com/rustfs/backlog/issues/2749).

Today the complete request decoder runs before copy-resource derivation. Core then derives the
source under the request's name policy, erases the raw source from the input, and authorizes the
derived resource. Moving source parsing to the ordinary header's position in the decoder can
change which error wins when another binding is invalid.

## Decision

Store a required, string-modeled `x-amz-copy-source` request header as the bare
`CopySourceValue` in its canonical operation Input. Select this representation through one
shared header-binding predicate used by DTO, codec and compatibility generation. The affected
Input and its builder have no `Default`; `Input::builder(copy_source)` requires the real
carrier, and complete public struct literals remain supported. This exception covers only
that required request header, currently CopyObject and UploadPartCopy. Other fields retain
their existing construction policy and unsupported required types still fail generation.

Decode into request-local state and preserve the current order of ordinary binding reads and
required-member refusals. Parse the source into the carrier only at the end of that existing
decode phase. Preserve the default and opt-in RustFS grammars, percent-decoding count, error
code and message precedence. Do not create a placeholder carrier to run the earlier checks.
Direct compatibility conversion copies already-decoded fields without re-parsing or validating
them; it preserves every ARN component and the distinction between absent and empty versions.

Keep deployment validation and proof derivation in core, under the request's existing name
policy. Before input authorization or dispatch, erase all source identity strings and version
presence from the DTO in place, retaining only its variant. This erasure is a pipeline action,
not a default value or an additional enum variant. The existing derived resource and
`AuthorizedRead` proof remain the only execution authority. Forward handler compatibility
continues to obtain its source from that proof-gated resource, never from the erased DTO.

## Evidence

Measured with `rustc 1.97.1 (8bab26f4f 2026-07-14)` against the carrier introduced by
[#1495](https://github.com/rustfs/gateway/pull/1495): compiling the following probe with
`rustc --edition=2024 --error-format=json probe.rs` fails with `E0277`,
`CopySourceValue: Default` is not satisfied. Replace the path with the checkout's absolute
path to the unchanged carrier file.

```rust
#[path = "/absolute/checkout/crates/types/src/copy_source.rs"]
mod copy_source;

#[derive(Default)]
struct CopyInput {
    copy_source: copy_source::CopySourceValue,
}

fn main() {}
```

Measured positive control: removing the derive, adding a constructor that takes
`CopySourceValue`, and constructing its Bucket variant with `version_id: Some(String::new())`
compiles with the same command. Running that probe verifies that the empty version remains
present. These are construction measurements, not evidence that the operation binding has
already been implemented.

Measured public-service ordering evidence is recorded in
[#1470](https://github.com/rustfs/gateway/issues/1470#issuecomment-6405119839): 144 cases compare
three legacy services with the owned RustFS profile, using fixture authorizers and handlers.
It does not execute native RustFS storage. The empty-version regression in #1498 demonstrates
why version presence must reach source authorization before backend validation.

[inferred] The required bare carrier cannot retain ADR-0004's zero-argument construction without
inventing a source variant. Preserving the existing decode/derive boundary avoids moving source
failures ahead of later header failures; implementation still needs executable precedence tests.

## Rejected alternatives

- Give `CopySourceValue` a default or a sentinel variant: it invents a source form and a new
  state that every consumer must distinguish from decoded data.
- Change the public member to `Option<CopySourceValue>`: it makes a required wire member optional.
- Retain the String and carry a second source in extensions or a RustFS-only wrapper: it creates
  competing source representations and leaves the canonical DTO migration incomplete.
- Parse at the ordinary header assignment: later invalid bindings can lose their existing
  error precedence.
- Leave decoded source components available after authorization: handlers could bypass the
  proof-gated execution resource.

## Consequences

The implementation is a breaking change for both Copy inputs. It must bump affected crate
versions, include `BREAKING` and a migration note, and update all three supported compatibility
seams. Callers replace String assignment and `..Default::default()` with an explicit carrier
and `Input::builder(copy_source)`, or a complete literal. Existing ADRs and other DTO defaults
remain unchanged. This decision alone changes no generated artifact or public signature.

Implementation tests must enforce the narrow storage predicate, the absence of default and
zero-argument builder paths, complete-decode error precedence, both grammars, lossless direct
conversions, all source-component erasure, exact version-bound proofs, and denial before backend
validation. Each new assertion needs a mutation. The existing required-field and authorization
guards must retain their refusals; unsupported inputs cannot gain a new default escape hatch.
Native assembly, legacy-name and ARN compatibility remain separate acceptance work under #1470.
