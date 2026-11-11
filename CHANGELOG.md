# Changelog

## Host-verified header token claim (sig 0.15.0, core 0.60.0, gateway 0.62.0)

BREAKING: `AuthSchemeRef` gains `HeaderToken`, the scheme of a request admitted by the service's
header token claim, whose principal the host's verifier reported (ADR-0054, rustfs/gateway#1586).
Migration: a `match` on `AuthSchemeRef` adds an explicit `HeaderToken` arm; do not fold it into a
signed arm or into `Bearer`. A handler that serves such requests reads the principal through
`RequestContextView::header_token_principal()`; `principal()` stays the signed principal and is
`None` for them.

Additive: `ServiceBuilder::host_verified_header_token(claim, verifier)`, `HeaderTokenClaim` with
`refusing_aliases`, `InvalidHeaderTokenClaim`, the `HeaderTokenVerifier` host trait with its
`Established` slot type and `HeaderTokenRefused`, `HeaderTokenAdmission`, `HeaderTokenReceipt`,
`Identity::origin` and `IdentityOrigin` (part of `Identity`'s equality; every identity built before
this change is `AccessKey`), `AssemblyError::HeaderTokenClaimWithoutVerifier`,
`Admission::HeaderToken`,
`Verdict::HeaderToken` with `Verdict::header_token_receipt()`,
`SecurityFloor::with_header_token_claim`, `header_token_claim` and `admits_header_token`, and the
`HEADER_TOKEN_POSTURE` start-up line with its `gateway_header_token_posture` event. Nothing is
installed by default, and without the opt-in a request carrying the header is served exactly as
before.

With the opt-in: a request whose only credential is the claimed header is served as the identity
the verifier reports, on every standard S3 operation. A privileged operation, one of the STS
service, one that takes a browser form, one that declares a query bearer claim and one that
requires SigV4 under every policy refuse it. A claim names an `x-` extension header outside
`x-amz-`. The header beside any other credential surface is
refused `403` before any verifier runs. A refusal, a panic or a missing verifier is `403`, never an
anonymous request. The verifier is not given the token, and the claimed header is removed from the
request before acceptance, so no authorization or handler context holds it. The request is
unsigned and its body is held to what an anonymous body is. The recorded-request corpus redacts
`x-auth-token` and `x-storage-token`.

## Zip-download bearer claim (sig 0.14.0, core 0.59.0, gateway 0.61.0, dialect-rustfs-admin 0.13.0)

BREAKING: `AuthSchemeRef` gains `Bearer`, the scheme of a request admitted by an operation's query
bearer claim and verified by the host (ADR-0042, rustfs/gateway#1400). Migration: a `match` on
`AuthSchemeRef` adds an explicit `Bearer` arm; do not fold it into a signed arm. Additive:
`OperationFloor::with_query_bearer_claim`, `QueryBearerClaim`, `Admission::Bearer`,
`Verdict::Bearer`, the `BearerTokenVerifier` host trait with `BearerTokenRequest`, `BearerGrant`
and `BearerRefused`, `ServiceBuilder::bearer_token_verifier`, and
`RequestContextView::bearer()` returning a `BearerContext`. The RustFS admin dialect's zip
download now declares the `token` claim. Without an installed verifier its token-only URL stays
`403`, and a header-signed download is unchanged. With a verifier, the token is verified on the
signed path too and must name the signed principal; a handler reads the host's verified state
through `RequestContextView::bearer()`, and no authorization or handler context holds the token.

`BearerGrant::new(identity, resource, expires_at_unix_seconds, state)` carries the resource and
expiry the token itself names, and the kernel compares both with the request (`expires_at <= now`
refuses), so a verifier that only decrypts cannot admit a token for another download or a lapsed
one. `BearerAdmission::verify` returns the `Verdict`; `Verdict::Bearer` is matched as
`Verdict::Bearer { .. }` and cannot be constructed outside `rustfs-gateway-sig`. A token beside any
AWS credential surface — including one the RustFS profile's legacy recognition would read as
anonymous — is refused. A panicking verifier refuses the request with `403`. The recorded-request
corpus redacts a `token` query parameter.

## Required Copy inputs (types 0.40.0, core 0.56.0, gateway 0.59.0, codegen 0.20.0)

BREAKING: `CopyObjectInput.copy_source` and `UploadPartCopyInput.copy_source` now hold
`CopySourceValue`. Both inputs and their builders no longer implement `Default`.
Migration: construct a decoded Bucket, AccessPoint or Outpost variant and pass it to
`Input::builder(source)`, then set the remaining fields and call `build()`. Complete
struct literals remain supported. Existing decoded legacy inputs cross through
`input_from_s3s` without parsing or validating their source fields. Handlers continue
to resolve the source with `request.read_proof()`; the pipeline erases every source
component from the input before input authorization and dispatch. See ADR-0043.

## rustfs-gateway-types 0.32.0+aws.2026-10-02

BREAKING: `PostObjectFields` gains `object_lock_legal_hold_status`, `object_lock_mode`,
`object_lock_retain_until_date`, `sse_customer_algorithm`, `sse_customer_key` and
`sse_customer_key_md5`, and no longer implements `Clone` (an `SseCustomerKey` cannot be copied);
`PostObjectInput` gains `content_length`. Migration: a struct literal adds the new members or ends
in `..Default::default()`; code that cloned `PostObjectFields` reads the members it needs instead.
A `PostObject` handler applies the six new members or refuses the upload, as for every other
member it is handed. The model snapshot and storage formats are unchanged.

## rustfs-gateway-types 0.31.0+aws.2026-10-02

The model snapshot moves to AWS api-models-aws commit `7eb6ab98cd5f1e5dc6dd90ea1bdc625f9ae308ba`.
It adds `IntelligentTieringReferenceDate` to the inventory optional-field model; STS is unchanged.
The public `OptionalFields` open string type recognizes the new value. No operation is enabled
by this update, and storage formats are unchanged.
