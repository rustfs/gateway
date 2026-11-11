# ADR-0046: Zip bearer grants are bound to download and expiry by the gateway

- Status: Accepted
- Date: 2026-11-11
- Trigger: independent security review of the ADR-0042 implementation (rustfs/gateway#1568), amending ADR-0042 on where the download and expiry checks run
- Supersedes / Superseded by: none

## Context

ADR-0042 makes the host's bearer verifier responsible for three checks: authenticating the token,
binding the decrypted download ID to the requested download, and refusing `expires_at <= now`
against the request's single clock reading. The kernel only stamps the receipt with the request's
own resource.

The security review of rustfs/gateway#1568 found that this contract cannot be enforced. The host's
answer carried only a principal and opaque state. A verifier that only decrypts compiles, passes
every fixture test, and would admit `B.zip?token=<token minted for A>` or a lapsed token. Nothing in
the types records what the host checked, so a check the host forgets fails open.

## Decision

The host's grant states what the token says. `BearerGrant::new` takes the principal, the raw
resource the token was minted for, the token's expiry in Unix seconds, and the host state. There
is no constructor that omits the resource or the expiry.

The gateway then makes both comparisons itself, in `BearerAdmission::verify`, after the verifier
accepts the token and before any verdict exists:

- the grant's resource must equal the request's raw bound resource byte for byte, with no decoding
  or case folding;
- `expires_at <= now` refuses, using the admission's single clock reading.

Both refusals are `403 AccessDenied`, through the existing refusal path. The host may still refuse
earlier.

Everything else in ADR-0042 is unchanged, including the parsing and credential rulings recorded on
rustfs/gateway#1400. This record changes only which side performs the two comparisons. ADR-0042's
text is not edited.

## Evidence

- Measured on rustfs/gateway#1568: with the comparisons removed and a decrypt-only fixture host,
  `xyz.zip?token=<abc token>` and an expired grant were admitted, and the new kernel tests went red.
  With the comparisons in place, those tests pass under both the default floor and the RustFS
  profile floor.
- Measured: changing the expiry comparison from `<=` to `<` turned the exact-boundary tests red in
  `rustfs-gateway-sig` and `rustfs-gateway-goldens`.
- Measured: a two-argument `BearerGrant::new` call fails to compile (`compile_fail,E0061` probe in
  `crates/sig/src/bearer.rs`).

## Rejected alternatives

| Alternative | Reason |
| --- | --- |
| Keep both checks in the host and document them | A forgotten check fails open, and no test of the gateway can detect it. |
| Return a boolean "checked" flag from the host | A flag records an intention, not the value that was compared. |
| Have the gateway decode the token to read its resource and expiry | The token's cryptography and format belong to the host. ADR-0042 forbids a second decode. |

## Consequences

A host verifier must report the resource and expiry the token itself carries, never values copied
from the request. Copying them would turn the gateway's comparison into a tautology. The verifier
trait documentation states this as a requirement.

The host still owns the following. The gateway does not and cannot check them:

- Token authentication: refuse ciphertext the host did not mint.
- The operation check: refuse a token used for an operation it was not minted for
  (`BearerTokenRequest::operation`).
- Replay policy: the gateway keeps no token cache, so single use is the host's to enforce.
- Principal liveness and session binding: refuse a token whose principal was disabled, deleted or
  rotated since minting.

Residual. Host code can still construct a bearer verdict or receipt through these public items:

- `BearerAdmission::verify` and `BearerAdmission::verify_alongside`, on an admission from
  `SecurityFloor::admit`;
- `SecurityFloor::bearer_alongside_signature`, which skips the AWS-surface gate.

Related public items: `OperationFloor::with_query_bearer_claim`, and
`RequestContextView::with_bearer_receipt` and `without_bearer_token`. They stay public because the
signature, core, facade and dialect crates call them across crate boundaries.

The service-level check in `crates/gateway/src/service.rs` is the only thing that keeps such a
verdict out of the pipeline: a bearer verdict is accepted only from the request's own bearer
admission. Host code can mint a verdict, but cannot use one to widen access. Sealing these items
behind a crate-private constructor is tracked in rustfs/gateway#1574.

The signature of `BearerGrant::new` changes before its first release. That change is recorded in the
CHANGELOG entry for sig 0.14.0.
