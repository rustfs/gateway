# ADR-0044: STS action credentials and claimed-route signing

- Status: Accepted
- Date: 2026-10-26
- Trigger: axiom A4, refining the authentication contract of the form extension point established by ADR-0041; crate boundary, adding the direct admin-dialect dependency on the shared error types.
- Supersedes / Superseded by: none

## Context

The STS form endpoint has two different authentication contracts. Ordinary `AssumeRole`
uses an AWS request credential, while `AssumeRoleWithWebIdentity` delegates token verification
to its registered handler. The [scope decision](https://github.com/rustfs/backlog/issues/2790#issuecomment-6414067529)
requires the ordinary action to use header authentication without changing Web Identity's
independent contract. This refines the compatibility decisions in ADR-0041 (c) and (d) for these two contracts;
the other form-claim decisions and the original historical record remain unchanged.

Source inspection found that the RustFS console's ordinary login sends `AssumeRole` through
its AWS SDK client, and that the mc credential chain can separately use unsigned Web Identity.
The [console caller](https://github.com/rustfs/console/blob/ec3ddbe8121bfa8376bcb35781a6d4e703bca607/lib/sts.ts)
and [Web Identity client](https://github.com/minio/minio-go/blob/68fb5ee339f2e3a798c14d12ca0e04c51f304d58/pkg/credentials/sts_web_identity.go)
therefore require action-specific treatment. These are source observations, not a claim about
all deployed clients.

## Decision

Keep one bounded STS form operation and authenticate any presented request credential before
its codec reads the body. Decode the body form's `Action` exactly once for admission, refuse
repeated decoded `Action` fields as `InvalidRequest`, and require the ordinary `AssumeRole`
action to carry its verified credential in the `Authorization` header. Refuse its anonymous
and query-credential requests as `AccessDenied`. Leave Web Identity token verification and
other downstream action handling with the registered handler, and preserve the original form
bytes. Ignore query parameters when selecting the action contract. After routing identifies a
claimed request, sign its declared service-level path without a host-derived S3 bucket. Ordinary
S3 requests retain their host-derived signing bucket.

The codec reads `MetaView::authenticated_aws_location`, which defaults to no fact. The facade
populates this private fact only after its verdict rejection check, using the settled verdict
and the AWS marker captured from the original pre-filter credential view. Both family and
location must agree. Anonymous or rejected verdicts, absent markers and mismatches publish no
location; valid query markers remain query locations. The manually reconstructed framed view
preserves the fact. A filter's insertion or removal of a displayed header cannot supply or erase
it. This is a narrow core metadata API; it introduces no route selector or verifier logic.

The shared form envelope remains anonymous-capable for Web Identity; making that envelope
privileged would change the independent action contract. The admin dialect depends directly
on `rustfs-gateway-types` for `ErrorCode`, matching the existing MinIO dialect pattern. The
deterministic dependency guard admits only that additional downward edge; types cannot depend
on either dialect.

## Evidence

- Measured toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`.
- Measured before implementation: `cargo test -p rustfs-gateway-dialect-rustfs-admin --test integration sts_form::sec1_`
  executed eight tests, with six expected semantic failures and two positive controls passing.
  The failing cases cover query/anonymous ordinary actions, decoded action spellings,
  query/body disagreement and repeated action fields.
- Measured before implementation: `cargo test -p rustfs-gateway-goldens --lib sts_parity::sec1::`
  executed fourteen tests, with eight expected semantic failures and six controls passing.
  The failures cover action-specific admission and both directions of claimed SigV2 resource
  selection. Controls include ordinary S3 virtual-host signing, independent Web Identity
  admission, downstream token refusal and invalid presented credentials.
- Measured before implementation: `cargo test -p rustfs-gateway-goldens --lib sts_parity::sec1::sec1_23`
  passed the ordinary-action malformed-header control, including an empty header, an unknown
  scheme and an incomplete AWS header. No request reached its handler.
- Measured against the first generated mutable-header candidate: the three separate
  `sec1_24` filter-insertion controls returned 200 where 403 was required, and both separate
  `sec1_25` header-removal controls returned 403 where 200 was required. They establish both
  directions of the immutable-fact requirement before its implementation.
- Measured dependency guard controls: the unmodified matrix rejected the new admin-to-types
  dependency; admitting only that edge passes. Removing that allowance fails, and adding the
  reverse types-to-admin dependency fails with its forbidden-edge diagnostic. The two mutations
  are retained in `scripts/test_guard_scripts.sh`.
- Measured on the immutable-fact candidate: nine core metadata controls, twelve STS codec
  tests and thirty legacy/gateway STS parity tests pass. The parity set retains all five
  filter insertion/removal controls and the ordinary S3 signing controls.
- Measured mutation audit: all 67 new or changed behavioral assertion sites produced direct
  semantic failures under temporary implementation mutations: nine metadata sites, ten codec
  sites, 31 assembled-service sites, sixteen revised compatibility sites and one emitter-document
  contract. The mutations cover metadata defaults, marker agreement, stale facts, framed-view
  propagation, action admission, duplicate handling, error status and code, body preservation,
  mutable headers, signing context, handler exclusion, principal propagation and route authorization.
  Every temporary source change was restored exactly; the tests and fixtures were unchanged.
- Mutation coverage is per assertion site, not independently per input of a loop. Family/location
  matrices, form variants, signing modes and malformed-header variants still run in the restored
  test suites. Late-refusal mutations separately reached handler-exclusion assertions after the
  status and error-code assertions passed. These calibrate the observers; they do not constitute
  an independent cryptographic or credential-parser audit.
- [inferred] The inspected console and SDK call paths need no ordinary-login change because
  they use header signing. This does not establish compatibility for unexamined deployments;
  the migration rule below applies to every ordinary-action client.

## Rejected alternatives

| Alternative | Concrete reason it was rejected |
|---|---|
| Make the whole form operation privileged | Web Identity authenticates its token downstream and must retain unsigned admission. |
| Select the action from the URL query | The registered handler selects the action from the form body; two selectors could disagree. |
| Route each action before authentication | Routing would need a new unauthenticated body read and additional cross-crate state for one consumer. |
| Replace the request body with a re-encoded form | The handler must receive the original bytes, including token encoding. |
| Infer authentication from codec-visible headers | Stage filters may rewrite those headers after the verifier snapshot; insertion and removal controls both fail on that candidate. |
| Add a new verifier or routing trait | The existing accepted verdict and original AWS marker already contain the required fact; a narrow metadata method carries it. |
| Remove host-derived signing buckets globally | Ordinary S3 virtual-host signatures still require their bucket; only a routed claim changes the canonical resource. |

## Consequences

- **BREAKING**: `rustfs-gateway-dialect-rustfs-admin` advances from 0.11.0 to 0.12.0,
  `rustfs-gateway` advances from 0.57.0 to 0.58.0, and `rustfs-gateway-core` advances from
  0.54.0 to 0.55.0 for the new codec metadata contract. Custom assemblies calling the STS codec
  directly must populate the accepted same-request AWS fact through
  `MetaView::with_authenticated_aws_marker`; raw Authorization presence is insufficient.
- Ordinary `AssumeRole` clients must sign with the `Authorization` header. Clients using
  query credentials must switch to the SDK's normal header-signed request path. Web Identity
  clients keep their token flow and their registered handler remains responsible for validation.
- SigV2 clients of claimed routes must canonicalize the declared service-level path without a
  bucket inferred from the host. Ordinary S3 canonical resources are unchanged.
- Enforcement is the generated form codec, the facade's post-dispatch bucket selection, the
  action and signature control matrices, and deterministic regeneration checks. The existing
  legacy observations remain in the parity tests alongside explicit gateway expectations.
