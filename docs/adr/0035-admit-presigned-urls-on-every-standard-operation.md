# ADR-0035: Admit presigned URLs on every standard operation at service level

- Status: Accepted
- Date: 2026-09-30
- Trigger: axiom A4 (extension points are symmetric in granularity): presigned admission gains a service-level grain beside the per-operation one, as anonymous admission did in ADR-0021
- Supersedes / Superseded by: none

## Context

The security floor admits a presigned URL only when the routed operation's `OperationFloor`
opted in with `allow_presigned` (`builtin_presigned`). Among the built-in operations only
GetObject and PutObject do, so every other operation answers a presigned URL with
`403 AccessDenied` before authentication. That default is fail-closed and stays.

Legacy RustFS verifies a presigned URL on every request before it routes it, and then authorizes
the verified credential exactly as it authorizes a header signature. A legacy RustFS build was
observed serving a botocore-generated presigned URL on GetObject, HeadObject, ListObjectsV2,
ListObjects, ListBuckets, HeadBucket, GetBucketLocation, GetBucketVersioning, GetObjectTagging,
PutObject, UploadPart, ListParts, CreateMultipartUpload, DeleteObject, PutBucketTagging and
DeleteBucketTagging. The RustFS staging differential measured the gap as rustfs/gateway#1052
(presigned DeleteObject: legacy `204`, gateway `403`), and the migration's ruling R7
(rustfs/backlog#1677) is to accept presigned URLs on every operation legacy RustFS accepts them
on. As with anonymity (ADR-0021), a deployment cannot change the `&'static` floor of a built-in
operation without forking it.

## Decision

`rustfs-gateway-sig` adds `PresignedPolicy { PerOperation, EveryStandardOperation }`.
`PerOperation` is the `Default` and is what `SecurityFloor::new()` holds. A deployment opts in
with `SecurityFloor::admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report()`.
Under it every non-privileged operation admits a presigned URL. A privileged operation, including
every third-party operation, refuses every presigned URL under either policy and cannot be made
to accept one (`FloorConfigError::PresignedOnPrivilegedOperation` stands). The widening covers the
presigned slot only: a SigV2 presigned URL still needs the SigV2 policy to admit it, anonymous and
POST-policy admission keep their own rules, and every rule of the presigned path — duplicate
parameters, clock, the seven-day lifetime, scope and signature — still runs.

The one predicate is `SecurityFloor::admits_presigned(&OperationFloor)`, built on
`OperationFloor::admits_presigned_under(PresignedPolicy)`. The floor's H3 check and the startup
posture report both read it, so under the widening the report's `presigned_allowed_ops` lists
every operation the floor admits. The report's format is unchanged.

## Evidence

- Legacy RustFS (rustfs/rustfs `origin/main` e870a6d25b), observed with a legacy build: the
  operations above serve a presigned URL (`200`/`204`); an altered signature, an added query
  parameter or another method is `403 SignatureDoesNotMatch`; a missing `X-Amz-Expires` or
  `X-Amz-Date`, or an expiry above seven days, is `400 AuthorizationQueryParametersError`; an
  unsigned `x-amz-*` header is `403 AccessDenied`.
- Measured at the floor (`crates/sig/tests/security_floor_presigned.rs`): the default refuses a
  presigned URL on a header-only standard operation; the widening admits it as a sealed AWS
  admission with its expiry; `admin_op()`, a `custom` operation and a `mark_privileged` built-in
  are refused under it; SigV2 presigned stays refused until the SigV2 policy admits it; the
  anonymous and POST-policy slots are unchanged; expiry, a missing expiry, an eight-day lifetime
  and a repeated signature parameter are refused as on an opted-in operation.
- Measured through the RustFS-profile launcher (`compat/sut`, `presigned_operation_tests.rs`):
  each operation above served, the writes and deletes performed; each tampered form refused with
  legacy RustFS's code and nothing deleted; a presigned URL on another identity's bucket refused
  by the authorizer.
- Mutation results for each guarantee are listed in the pull request that lands this ADR.

## Rejected alternatives

- **Opt every built-in operation in.** That changes the default for every deployment, including
  those whose authorizer was written for header signatures only; the AWS answer stays the default.
- **Admit presigned URLs on privileged operations too.** Legacy RustFS also verifies a presigned
  URL on its admin routes, but rewriting a presigned URL onto an admin operation is MinIO #5411,
  and the fence exists so that no registration can lift it. That difference is recorded for a
  maintainer ruling rather than reproduced here.
- **A new `presigned_policy=` field in the posture line.** The posture format strings are pinned
  by `check_sig_case_coverage.sh` and its guard self-test; the listed operations already carry the
  security-relevant fact and now tell the truth under the widening.

## Consequences

Additive: existing floors behave identically. A deployment that turns the widening on must make
its `Authorizer` decide a presigned request as strictly as a header-signed one; the startup
posture line lists every presigned-reachable operation.
