# ADR-0021: Delegate anonymous admission to the Authorizer at service level

- Status: Accepted
- Date: 2026-09-14
- Trigger: axiom A4 (extension points are symmetric in granularity): anonymous admission gains a service-level grain beside the per-operation one
- Supersedes / Superseded by: none

## Context

The security floor admits a request that presented no credentials only when the routed
operation's `OperationFloor` opted in with `allow_anonymous_after_listing_in_the_posture_report`.
Every other operation refuses it with `403 AccessDenied` before authentication, and before the
`Authorizer` is consulted. That default is fail-closed and stays.

An `OperationFloor` is a `&'static` value returned by `Operation::floor()`. A deployment cannot
change the floor of a built-in operation without forking the operation. RustFS does not decide
anonymity per operation: every anonymous request reaches its own access check (bucket policy,
ACL), and that check decides. rustfs/backlog#1762 (second slice, rustfs/gateway#748) had to opt
each operation in by hand to get an anonymous request to the same point on both stacks.
rustfs/backlog#1752 lists this as the third gateway gap blocking the RustFS ring-2 adapter,
which must keep one authority for anonymous access.

The pipeline already sends an anonymous request through both `Authorizer` stages with
`AuthzRequest::identity == None`, and there is no default authorizer (`c-azc-0027`, `c-azc-0006`).
The missing piece is only the floor's admission.

## Decision

`rustfs-gateway-sig` adds `AnonymousPolicy { PerOperation, DelegateToAuthorizer }`. `PerOperation`
is the `Default` and is what `SecurityFloor::new()` holds. A deployment opts in with
`SecurityFloor::delegate_anonymous_to_authorizer_after_listing_in_the_posture_report()` and
installs the floor through the existing `ServiceBuilder::security_floor`. Under delegation,
every non-privileged operation admits a request that presented nothing. A privileged operation,
including every third-party operation, still has to opt in itself. Delegation widens the
anonymous slot only: header, presigned and POST-policy admission still follow each operation's
allow-list, and presented credentials are still verified or refused, never downgraded.

The one predicate is `SecurityFloor::admits_anonymous(&OperationFloor)`, built on
`OperationFloor::admits_anonymous_under(AnonymousPolicy)`. Both the floor's H3 check and the
startup posture report read it, so under delegation the report's `anonymous_reachable_ops`
lists every operation the floor now admits. The report's format is unchanged.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`.
- Measured, red before the change:
  - `cargo test -p rustfs-gateway-sig --test integration security_floor_schemes` failed with
    10 errors: `E0432` for `AnonymousPolicy`, and `E0599` for `admits_anonymous` (5),
    `anonymous_policy` (3) and the delegation method (1).
  - `cargo test -p rustfs-gateway --no-run` failed with 2 × `E0599` on the delegation method.
- Measured, at the gateway runtime (`anonymous_delegation_runtime`), with `ListBuckets`, a
  built-in header-only operation:
  - Under the default floor an anonymous request is `403` and the authorizer records 0 calls.
  - Under delegation, a `Deny` authorizer answers `403` after exactly 1 route-stage call with an
    anonymous caller.
  - Under delegation, an `Allow` authorizer answers `200` after both stages ran with an anonymous
    caller.
  - A malformed signature, a lone security token or a wrong signature is a 4xx with 0
    authorizer calls.
  - A correctly signed request reaches both stages as authenticated.
- Measured, at the floor (`security_floor_schemes`):
  - Delegation still refuses anonymous on `admin_op()`, on a `custom` operation, and on a
    `mark_privileged` built-in.
  - Presigned and POST-policy slots stay `AccessDenied` on a header-only operation.
- Mutation results for each guarantee are listed in the pull request that lands this ADR.

## Rejected alternatives

- **Opt every operation in from the adapter.** Built-in floors are `&'static`, so this means
  forking each operation. A new operation would silently stay closed, or be forgotten when it
  should not be, and the posture report would carry 72 hand-maintained opt-ins.
- **Make anonymous admission the default.** That turns the floor fail-open for every deployment
  without an authorizer that understands anonymity; the current default is the safer one.
- **Delegate privileged operations too.** A third-party operation is privileged by default
  precisely so that it cannot be reached by a request that declared nothing (attack scenario B,
  rustfs/rustfs#4845). A deployment that wants one reachable still opts it in by name.
- **A new `anonymous_policy=` field in the posture line.** The two posture format strings are
  pinned by `check_sig_case_coverage.sh` and its guard self-test. The reachable list already
  carries the security-relevant fact, per operation, and now tells the truth under delegation.
- **A second anonymous check in the gateway service.** It would be a second predicate that could
  drift from the floor's. The floor stays the one place anonymity is admitted.

## Consequences

This is additive: `rustfs-gateway-sig` 0.11.0 -> 0.11.1 and `rustfs-gateway` 0.38.0 -> 0.38.1.
Existing floors behave identically. A deployment that turns delegation on owns anonymous policy
completely in its `Authorizer`, which must answer `Deny` for every anonymous request it does not
mean to allow. The startup posture line then lists every reachable operation. The floor tests,
the gateway runtime tests and the posture unit test enforce the default, the privileged fence,
the no-downgrade rule and the authorizer's sole authority. The goldens request-context harness
now reaches anonymous parity with RustFS by delegation instead of per-operation opt-ins.
