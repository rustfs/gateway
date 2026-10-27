# ADR-0045: Copy source capability before resource authorization

- Status: Accepted
- Date: 2026-10-27
- Trigger: crate boundary and RustFS Copy authorization ordering, rustfs/gateway#1470
- Supersedes / Superseded by: none

## Context

Both Copy operations carry a required `CopySourceValue` (ADR-0043). The current dispatcher decodes
all ordinary fields, derives and validates the source resource, erases the input source and asks
for input authorization. The authorizer can return Allow, Deny or Indeterminate; a denial is
always rendered as an authorization refusal.

RustFS's [CopyObject access method](https://github.com/rustfs/rustfs/blob/1000860cb84492cb318867182d4b947325954827/rustfs/src/storage/access.rs#L2412-L2422)
and [UploadPartCopy access method](https://github.com/rustfs/rustfs/blob/1000860cb84492cb318867182d4b947325954827/rustfs/src/storage/access.rs#L3570-L3580)
return `NotImplemented` for either ARN variant before source policy authorization. Legacy s3s
also parses an Outposts access-point component that the current Gateway Copy codec rejects.
RustFS-specific behavior belongs to its adapter, not to name validation in core.

## Decision

Add an explicit, per-assembly Copy ARN capability with two states: supported and unsupported.
The RustFS adapter selects unsupported; the generic assembly keeps its current supported behavior.
After ordinary decoding and authentication, but before source-resource derivation, the dispatcher
classifies only whether a Copy source is a bucket or an ARN. An unsupported ARN returns the fixed
`NotImplemented` refusal. This check is not an authorization decision and cannot create an
`AuthorizedRead` proof. It receives no bucket, key, account, access-point or version value.

The codec must preserve the legacy Outposts access-point spelling in the typed carrier before this
check, and must reject syntax that the legacy parser rejects before invoking it. In particular,
the observed invalid-account and empty-object-key cases remain `InvalidArgument`; deployment name
policy is still applied at resource derivation. Without the unsupported capability selected,
existing resource validation continues to reject the access-point spelling until an
identity-preserving resource representation is implemented. Do not treat an outpost and its access
points as the same policy resource.

For these two bodyless operations the RustFS adapter defers destination policy evaluation from
route authorization to the existing input stage. It evaluates source policy exactly once and
evaluates destination policy only after the source permits it, matching the RustFS access methods.
A source refusal must not invoke destination policy. The input stage still returns a complete fail-closed
decision batch, and both permissions are required before a handler receives the proof.
Authentication and the framework security floor remain before the capability check. No other
operation or assembly changes its authorization order.

## Evidence

At Gateway b96fbba3 and RustFS integration 1000860c, a 54-case service fixture shaped to the
RustFS access methods compared both Copy operations across three legacy s3s revisions and the
owned RustFS profile. The fixture returns `NotImplemented` for either ARN variant. The current
Gateway fixture reaches input authorization for an S3 access point and rejects an Outposts
access-point spelling during decoding. Route-denial and ordinary-binding controls are included.
The fixture is not native RustFS runtime evidence; its log SHA-256 is
`07d24dd6d39f8de478586326551e84d0fbdf500026fb1b2110f2727be6d30143`.

A separate 162-case fixture probe found that the legacy parser retains empty outpost and access
point components in that spelling but rejects an invalid account or empty object key. Its log
SHA-256 is `e615a67993ba87cdbc862a038d55d591477c1217e1a969f79afd424ff2088b75`.
[inferred] The capability check must precede resource validation to keep these errors in the
RustFS order; both operations require native runtime verification when the adapter exists.

AWS documents the [Outposts access-point object ARN](https://docs.aws.amazon.com/AmazonS3/latest/s3-outposts/S3OutpostsIAM.html)
as a policy resource. The [CopyObject API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html)
describes an Outposts object source form separately; this decision does not claim AWS accepts the
legacy access-point spelling as a Copy header.

## Rejected alternatives

- Return `NotImplemented` from name-policy validation. Name policy is independently composable and
  is not an authorization or RustFS adapter identity.
- Extend an authorization denial with arbitrary error codes. Denials must remain fail-closed and
  indistinguishable; a capability refusal is a separate, bounded result and grants no access.
- Drop the Outposts access-point component or authorize only its outpost. Distinct resources would
  become the same policy identity.
- Reject in the handler. A denied input would return before the handler, changing RustFS's order.
- Parse the header a second time in the adapter. The source used by policy and the source used by
  execution could disagree.

## Consequences

The implementation crosses core and facade boundaries and changes public assembly contracts; it
must bump affected crate versions and document migration. The default capability preserves existing
behavior. Tests must cover both operations, malformed and empty components, ordinary-field error
precedence, signed and anonymous requests, source-before-destination policy calls and denials, all source
forms, version presence and source erasure. A refused ARN must never reach the authorizer's input
stage or the backend; an allowed request must still require every resource decision and the
proof-gated source. Mutation controls must break each new boundary. A posture test and a guard for
both Copy operation classifiers must prevent the RustFS adapter from silently omitting the setting.
Native RustFS comparisons must also cover bucket-generation lookups, versioned actions, policy and
audit effects, and error precedence; the seven-night dual-stack acceptance remains open under #1470.
