# ADR-0038: All-method claimed rows

- Status: Accepted
- Date: 2026-10-06
- Trigger: axiom A4, because a claimed operation must express its method coverage at the same granularity as the selector used by the routing lattice.
- Supersedes / Superseded by: none

## Context

This ADR extends ADR-0024 (b); its other decisions are unchanged.

RustFS answers an unmatched admin v4 request with an empty 426 after authentication. This includes
extension methods: a finite list of GET, POST and other familiar methods cannot represent its
fallback. [Gateway #1189](https://github.com/rustfs/gateway/issues/1189) needs explicit operations
for these answers, and [#1307](https://github.com/rustfs/gateway/issues/1307) records the method
coverage prerequisite.

A `RouteSelector` is already a conjunction: an omitted dimension is unconstrained. Its matcher,
constraint meet and refinement rules already handle an omitted method. ADR-0024 (b) nevertheless
requires a claimed row to name exactly one method, and claimed-row validation rejects an empty
selector or one containing only query/header predicates. That restriction prevents an operation
from expressing the native fallback's method coverage.

## Decision

Allow a claimed row to name zero or one `Method` predicate. Zero means any method represented by
`http::Method`, including extension tokens. One retains exact, case-sensitive matching. Two or
more remain invalid, even if both name the same method. There is no special wildcard method
string and no new predicate or callback.

Keep the rest of the claimed-row contract:

- The existing claim and path template still limit where a row can match. Method omission does
  not admit another prefix, a virtual-hosted request, a nonstandard endpoint or an ARN.
- Query and header predicates remain a conjunction. Omitting the method does not bypass them.
- Target, path-literal, host-class and ARN predicates remain forbidden inside a claimed row.
- Every overlap at the same precedence conflicts. Across precedences, the configured shadowing
  policy and sourced declarations still apply. Under `EveryOverlap`, an exact-method row and an
  all-method row owe a declaration in either precedence order.
- An exact-method selector refines the otherwise identical all-method selector; the reverse is
  false. An earlier all-method row therefore hides that exact-method row completely, while an
  earlier exact-method row leaves other methods reachable. The overlap report must retain this
  distinction.
- Existing authentication floors, authorisation requirements, body rules, handlers and startup
  posture reporting are unchanged. This is a route declaration, not permission to skip a stage.

A deployment may use this capability to declare an explicit fallback operation after its concrete
operations. This ADR does not install a fallback, invent an IAM action, change parameter decoding,
or introduce a claim-level response hook. In a RustFS-profile assembly, the existing outer CORS
layer continues to answer OPTIONS before these routes.

## Evidence

- Measured with `rustc 1.97.1 (8bab26f4f 2026-07-14)`:
  `cargo test -p rustfs-gateway-core --test integration dialect_claims` passes all 40 cases.
  The eight new cases first produced seven failures at the old method-count check and one pass.
  They cover standard and extension methods, a case-distinct method, aliases, query/header
  restrictions, claim boundaries, duplicate methods and overlaps in both precedence orders.
  The shadowing error's `total` field independently exposes the two refinement directions.
- Measured over HTTP against clean frozen RustFS
  `5e1bd498ce1ca33bcb0ca50aeee861e69e6c8744`: the 360-request matrix in #1307 covers two aliases,
  six path forms, GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE, CONNECT and FROB, each with
  valid, forged and absent credentials. Except for OPTIONS, authenticated v4 requests return
  empty 426; authenticated non-v4 forms return 501; forged and absent credentials return 403.
  HEAD carries no body. OPTIONS returns empty 200 through the outer CORS layer. These are native
  observations, not gateway fallback acceptance.
- [Frozen native router](https://github.com/rustfs/rustfs/blob/5e1bd498ce1ca33bcb0ca50aeee861e69e6c8744/rustfs/src/admin/router.rs#L3372):
  its unmatched v4 answer depends on the path after the registered operation lookup has failed.
- [Inferred] A finite enumeration of methods cannot represent this fallback for every valid
  extension token; an unconstrained method dimension can.

## Rejected alternatives

| Alternative | Reason rejected |
| --- | --- |
| Register one fallback per familiar method | The measured FROB request already falls outside that list; more tokens do not close an unbounded vocabulary. |
| Add `AnyMethod` or treat `Method("*")` specially | Absence already represents an unconstrained dimension; a second spelling adds matcher and lattice rules without adding meaning. |
| Return a status directly from a claim | That bypasses the normal operation stages and does not solve authenticated fallback dispatch. |
| Ignore overlapping rows when either omits a method | Such rows overlap more requests, so skipping their declarations hides precisely the dangerous case. |
| Change all unmatched requests to the admin answer | Other claims and the ordinary S3 table have separate contracts. |

## Consequences

Previously accepted claimed rows retain their meaning. A previously rejected declaration with no
Method predicate can now be installed, subject to the same remaining validation and overlap
checks. No Rust type, dependency, generated model or standard route-table snapshot changes.

The two old method-omission rejection inputs become acceptance tests with absence-of-query
controls; their target/path/host/ARN and repeated-method rejection companions remain in place.
Both readable and compiled routing are checked, and mutation probes must demonstrate that the
new assertions fail when method coverage, containment, filtering, overlap or refinement breaks.

This only removes one prerequisite for #1189. Authentication-only dispatch, explicit admin
fallback registration, unmatched-path handling and assembled-service HTTP parity still need their
own implementation and evidence. An all-method row passing its routing tests does not prove any
of those behaviours.
