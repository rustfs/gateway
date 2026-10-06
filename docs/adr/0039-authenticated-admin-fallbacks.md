# ADR-0039: Authenticated admin fallbacks

- Status: Accepted
- Date: 2026-10-06
- Trigger: axiom A4, because the admin router's fallback must be an operation with the same authentication and authorisation stages as a registered route.
- Supersedes / Superseded by: none

## Context

This ADR extends ADR-0024 (a) for the RustFS admin dialect. The generic claim contract stays:
a request inside a claim never falls through to S3, and an unmatched claim returns 501 before
authentication. The dialect instead needs explicit operations that cover its unmatched admin
paths. [Gateway #1189](https://github.com/rustfs/gateway/issues/1189) records the native contract
and the decision to preserve it.

Within the request-head limits, RustFS authenticates an unmatched admin request before answering
it. A valid request at either admin alias's exact `/v4` prefix or beneath it receives an empty
426, which allows an admin client to retry its v3 form. Other unmatched admin paths receive 501. An unsigned or forged request
receives 403 first. OPTIONS is handled separately by the outer legacy CORS layer.

ADR-0038 supplies an all-method claimed selector. ADR-0036 supplies a trailing catch-all, and
ADR-0025 (d) supplies the authenticated caller-only vendor label. None alone installs an answer:
the fallback still needs declared operations, codecs, handlers and reviewed overlaps.

## Decision

Declare two explicit operations in the RustFS admin dialect, after all registered admin routes:

| Operation purpose | Templates under each of `/rustfs/admin` and `/minio/admin` | Answer |
| --- | --- | --- |
| v4 downgrade | `/v4`, `/v4/`, `/v4/{*remainder}` | 426, no body, content type or Upgrade header |
| other unmatched admin request | the claim itself, `/`, `/{*remainder}` | 501 NotImplemented |

Every row omits the Method predicate, so extension methods have the same coverage as familiar
methods. Templates are literal prefixes with separate exact and trailing-slash rows: a catch-all
requires at least one remaining byte and cannot cover either empty form by itself. `/v40` and
`/v4-extra` belong to the general fallback, not the downgrade response. Match that prefix in the
raw path: `/%764`, `/v%34` and `/v4%2F...` are not the native downgrade prefix, even when the
signature's canonical path represents their decoded spelling.

Use increasing precedence numbers in this order: existing routes, v4 fallback, general fallback.
Every overlapping pair owes the normal sourced `ShadowingDecl`, including each real admin
operation over the applicable fallbacks and the v4 fallback over the general fallback. Generate
these declarations from the existing route inventory and the two explicit fallback definitions;
do not maintain a second hand-written list of registered routes. The fallback definitions are
synthetic operations, not invented native route-inventory entries. Inventory census and handler
provenance must continue to describe actual registered native routes.

Existing routes keep their selectors, action rules, subjects, bucket bindings, anonymous opt-ins,
secret opt-ins, body modes and handlers. A matched operation that refuses a request stays that
operation's refusal; neither a failed signature, an authorizer denial nor a missing handler
causes another routing attempt. Unmatched query forms still have their separately recorded
compatibility gaps; this ADR does not make the native unknown `service?action` answer equivalent.

Both fallback operations are privileged, header-signed, service-level and caller-only. Use an
operation label in the `rustfs:` namespace with `SubjectRule::Caller`, following ADR-0025 (d).
The label is not an IAM permission. The request cannot select another subject, bucket or key,
and no caller secret is handed to the handler. Anonymous and forged requests fail before the
fallback answer. Both Authorizer stages still run for an authenticated request; either may deny.
Do not add an authentication-only bypass or weaken `MissingAuthRequirement` registration checks.

Each fallback codec declares `RequestBodyMode::None`. In the RustFS profile, use the existing
bodyless-request policy that releases the body unpolled: a final answer must not wait for bytes
the client has not sent, even when its signed headers declare a nonempty payload. This does not
waive signature verification or the existing request-head, admission and framing checks.
Other profiles retain their own bodyless-request rules.

Keep the RustFS profile's 1 MiB declared-length ceiling. Native requests declaring more than
that return 400 EntityTooLarge with valid or absent credentials, but a forged signature still
returns 403 first. Thus "anonymous returns 403" describes requests within the ceiling, not every
possible head. The gateway's privileged operation floor currently precedes that ceiling;
matching the oversized-anonymous ordering belongs to [#1173](https://github.com/rustfs/gateway/issues/1173).
Do not weaken that floor or move a size refusal ahead of signature verification as part of
installing the fallbacks. Record the remaining ordering difference in compatibility evidence.

Supply fixed fallback handlers through the existing typed `Handler` registration surface. As
with other dialect operations, installing a dialect and registering handlers remain explicit
deployment actions. The downgrade handler and codec produce an empty 426; the general handler
produces the ordinary NotImplemented error. A generic backend for inventory-derived admin
operations must not accidentally substitute its JSON response for either fallback. No new
claim callback, facade dispatch branch or dependency from the dialect back to the facade is
needed. A deployment claiming this compatibility must register both fallback handlers.

The scope is exactly the two admin claims. Do not add fallbacks to Iceberg, profiling or S3.
Keep the existing profile's addressing and UTF-8 validation order. Under the RustFS profile,
an undecodable path is InvalidURI before authentication; a decoded catch-all suffix is data,
not an S3 key or another route to try. The existing outer legacy CORS handler still answers
OPTIONS first, including an OPTIONS request with invalid credentials.

## Evidence

- Measured on frozen RustFS `5e1bd498ce1ca33bcb0ca50aeee861e69e6c8744`, binary SHA-256
  `f366d331f444e077a1fd6b9ae83954f1313c82de0729feae567cfaffcc662f94`:
  [360 HTTP responses](https://github.com/rustfs/gateway/issues/1189#issuecomment-6002672342)
  cover two aliases, six path forms, ten methods and valid, forged and absent credentials.
  FROB and origin-form CONNECT have the same fallback contract as GET. OPTIONS returns empty
  200 through CORS; every other method follows the authenticated 426/501 or unauthenticated 403
  split. HEAD carries no response body.
- Measured on the same binary:
  [98 raw-path responses](https://github.com/rustfs/gateway/issues/1189#issuecomment-6002982594),
  with 62 independent expectations, separate signing canonicalization from path handling.
  Eighteen once-decoded/re-encoded signing controls return empty 426 for malformed percent
  escapes, repeated separators, dot segments, encoded separators and control bytes. Their
  forged and unsigned companions return 403. Eight non-UTF-8 requests return InvalidURI; two
  impossible decoded-path signing candidates are explicitly skipped. The other 36 generic
  signer observations are not relabelled as path acceptance or refusal.
- Measured on the same binary:
  [12 POST responses](https://github.com/rustfs/gateway/issues/1189#issuecomment-6003199183)
  arrive before any of their 208 declared body bytes are sent. A normal signed PUT control
  produces no final response headers during a two-second body hold, then succeeds after the
  bytes are sent; GET returns all 208 bytes unchanged. This observes final response headers,
  not socket closure or a server-reported intent. The initial control signed the wrong body
  and failed; the corrected probe verifies its signed hash before withholding the payload.
- [Frozen router](https://github.com/rustfs/rustfs/blob/5e1bd498ce1ca33bcb0ca50aeee861e69e6c8744/rustfs/src/admin/router.rs#L3372):
  the fallback follows authentication and the registered-route lookup.
- Measured on the same binary: [36 header-only POST requests](https://github.com/rustfs/gateway/issues/1189#issuecomment-6003399757) cover both aliases, v4 and v3,
  lengths 1 MiB minus one, exactly 1 MiB and 1 MiB plus one, and all three credential states.
  At or below the limit they preserve the 426/501/403 split. Above it, valid and anonymous
  requests return 400 EntityTooLarge; forged requests remain 403 SignatureDoesNotMatch.
  No request-body byte was sent. This is native evidence; the gateway ordering difference
  follows from the existing floor preceding its declared-length check and still needs an
  assembled-service regression in #1173.
- Measured on the same binary: [48 further prefix/auth controls](https://github.com/rustfs/gateway/issues/1189#issuecomment-6003422815) distinguish literal `/v4/`
  from encoded and double-encoded spellings, `/v4-extra/` and the bare admin trailing slash.
  Authenticated literal v4 forms return empty 426; the other forms return 501 NotImplemented.
  Their forged and anonymous companions return 403. Matching the decoded v4 prefix would
  therefore disagree with the native fallback.
- [Inferred] The existing operation, caller-subject, codec and handler contracts can express
  these answers without bypassing a pipeline stage. This is a design decision, not measured
  gateway acceptance; the implementation must supply the controls below.

## Rejected alternatives

| Alternative | Reason rejected |
| --- | --- |
| Return 426 from an unmatched-claim callback | A claim answers before authentication, exposing the downgrade signal to forged and unsigned requests. |
| Enumerate familiar HTTP methods | The measured FROB request already falls outside such a list. |
| Add an authentication-only dispatch mode | ADR-0025 already supports a caller-only vendor label while allowing the deployment to deny. |
| Apply the response to all v4 requests before routing | Registered v4 operations must retain their own handlers and policy checks. |
| Buffer or verify the whole payload before answering | The native final response arrives before the client sends its declared body. |
| Hide synthetic fallbacks in the native inventory | That would claim native registered handlers and routes that do not exist. |
| Treat any path beginning with `/v4` as a downgrade | `/v40` is a measured non-v4 control; the separator boundary matters. |

## Consequences

The implementation must first fail assembled-service tests at the old 501 answer, then prove
both aliases and empty suffix forms, arbitrary methods, non-v4 near misses, unsigned/forged
refusals, both authorization denials, caller-only scope and no secret exposure. Every existing
registered route must still select the same operation and retain its input and output behavior.
Missing handlers and denied real routes must never turn into a fallback answer.

Real HTTP controls must send only the signed headers, observe a fallback's final response,
and pair it with a body-consuming operation that waits and then stores the sent bytes. Raw-path
and OPTIONS controls must run with the actual RustFS profile switches. Break each new guarantee
deliberately and record the failed assertion; a status-only stub is not acceptance evidence.

This ADR adds no runtime behavior. #1189 remains open until the fallback implementation and
assembled-service evidence land. Broader RustFS adapter installation and native integration
acceptance remain separate migration work.
