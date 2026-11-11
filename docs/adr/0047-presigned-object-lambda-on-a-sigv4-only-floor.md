# ADR-0047: A presigned object lambda on a SigV4-only floor

- Status: Accepted
- Date: 2026-11-11
- Trigger: a RustFS-profile behaviour difference (rustfs/gateway#1576), overturning for one claimed operation the presigned rulings of ADR-0024 (f), ADR-0035 and ADR-0021
- Supersedes / Superseded by: none

## Context

The RustFS dialect serves RustFS's object lambda extension route, `GET /{bucket}/{key}?lambdaArn=…`,
as the claimed operation `rustfs:InvokeObjectLambda`. Like every dialect operation, it used the
privileged, header-only floor (`OperationFloor::custom`). Three accepted records rest on that:

- ADR-0024 (f) refuses presigned requests to claimed operations. It lets an operation opt in through
  `OperationFloor::allow_presigned` only "until a RustFS admin client is shown to presign that
  route", and its rejected-alternatives table says no such client was found.
- ADR-0035 widens presigned admission to standard operations only. It states that every
  third-party operation refuses every presigned URL.
- ADR-0021 keeps a privileged operation out of anonymous delegation.

For this route the premise was false when it was written. RustFS's own end-to-end suite presigns
the route with `lambdaArn` inside the signed query and expects `200`. Legacy RustFS admits header
or query SigV4 on every extension route. It refuses SigV2 (header or presigned), POST policies and
unsigned requests there. Its object lambda handler then authorises through its `GetObject` check:
`s3:GetObject`, or `s3:GetObjectVersion` when `versionId` is present (the GHSA-3ppv fix).

The gateway answered that request `403` before the authorizer was asked. That is a release-blocking
difference under the RustFS profile.

ADR-0024 (f)'s opt-in path cannot be used as written. `allow_presigned` returns
`PresignedOnPrivilegedOperation` for a privileged floor. Simply dropping the privilege would have
made the route anonymous-reachable under the RustFS profile, which delegates anonymous requests to
the authorizer. It would also have made the route SigV2-reachable, because the profile enables SigV2
presigned compatibility. Legacy refuses both.

## Decision

`rustfs:InvokeObjectLambda`, and no other operation, admits a presigned SigV4 URL. Its floor is
`admin::presigned_floor`:

```rust
OperationFloor::builtin_presigned(name, SigService::S3).require_sigv4_under_every_policy()
```

The floor is not privileged and carries no bearer claim.

`OperationFloor::require_sigv4_under_every_policy` admits SigV4 only, header or presigned, as the
allow-list says. Under every anonymous policy, every SigV2 policy and every custom-scheme registry,
it refuses:

- a request that presented no credentials;
- a SigV2 request, header or presigned;
- a request matched by a registered custom scheme;
- a query bearer token.

The registry refuses to register a floor that combines the requirement with a bearer claim.

The operation's authorisation is `s3:GetObject` on the object, or `s3:GetObjectVersion` instead when
the request names `versionId`. The authorizer still decides every request.

Every rule of the presigned path still runs:

- the duplicate-parameter check;
- the clock;
- the lifetime ceiling;
- the scope cross-check;
- the signature over a canonical query that includes `lambdaArn`.

The posture line `SECURITY_POSTURE presigned_allowed_ops=[…]` names the operation.

These stay refused exactly as before:

- the other seven extension routes and every other claimed admin operation, which keep the
  privileged, header-only floor;
- both zip-download operations, which keep the privileged floor and ADR-0042's bearer claim.

A further claimed operation may take this floor only through a new generator ruling
(`rulings::PRESIGNED_EXTENSIONS`) that cites a RustFS client presigning that route. ADR-0024,
ADR-0035 and ADR-0021 are not edited. This record narrows their statements for one operation.

## Evidence

- RustFS's end-to-end test presigns the route and asserts `200`: https://github.com/rustfs/rustfs/blob/443e8afee194fe38b32d62a9289a99c1f703715c/crates/e2e_test/src/object_lambda_test.rs#L608-L636. Read from source.
- RustFS's signer keeps the request's own query pairs before appending the `X-Amz-*` pairs, so
  `lambdaArn` is signed: `crates/signer/src/request_signature_v4.rs` at the same commit. Read from
  source.
- RustFS's router admits header or query SigV4 on extension routes and refuses SigV2, POST policy
  and missing credentials: `check_access` and `reject_unbound_custom_route_auth` in
  `rustfs/src/admin/router.rs` at the same commit. Read from source.
- RustFS's handler authorises through the `GetObject` hook, `authorized_object_lambda_get_request`
  in the same file. Read from source.
- Measured in CI on rustfs/gateway#1577:
  - the presigned request was `403` before the change and `200` after it;
  - each new refusal went red when the property it pins was removed in a labelled mutation commit,
    covering anonymous, SigV2, the custom scheme, the bearer token, the version action, the
    registry refusal and the generator ruling.

## Rejected alternatives

| Alternative | Reason |
| --- | --- |
| Keep refusing (ADR-0024 (f) as written) | Its premise is false for this route, and RustFS's own client depends on it. |
| `OperationFloor::allow_presigned` on the privileged floor | Refused by construction (`PresignedOnPrivilegedOperation`), and relaxing that check would let any privileged operation be widened. |
| Drop the privilege alone (`builtin_presigned`) | Anonymous-reachable under delegation and SigV2-reachable under SigV2 compatibility, both refused by legacy. |
| Admit presigned SigV4 on every extension route, as legacy does | No RustFS client is shown to presign the others. A presigned URL is a bearer credential in a log line. |

## Consequences

`require_sigv4_under_every_policy` is part of `rustfs-gateway-sig`'s public surface. Its rustdoc
lists every admission it refuses. The registry refuses the bearer combination at build time, and the
floor refuses a custom scheme at request time. A deployment's custom schemes never reach this
operation.

The generator owns the ruling: `PRESIGNED_EXTENSIONS` and `VERSIONED_EXTENSIONS` in
`xtask/src/rustfs_admin_dialect/rulings.rs`, and a stale or unevidenced entry is refused. The drift
test keeps the committed module equal to the renderer's output.

The following tests in `rustfs-gateway-goldens`, `rustfs-gateway-dialect-rustfs-admin`,
`rustfs-gateway-sig` and `rustfs-gateway-core` pin the decision:

- the facade tests under the default floor, the RustFS-profile floor and
  `ServiceBuilder::rustfs_profile()`;
- the dialect floor census;
- the sig floor tests;
- the registry refusal.
