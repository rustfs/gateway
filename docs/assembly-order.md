# Assembly call order

This table is the call-count oracle for one ordinary request that reaches its
handler. A count is per installed implementation; multiple stage filters or
operation layers each receive the stated calls. Early refusals stop the rows
that follow them.

| Order | Extension point | Calls | Condition |
| ---: | --- | ---: | --- |
| 1 | `StageFilter::on_wire` | 1 | Always, when a filter is installed |
| 2 | `HostResolver::resolve` | 1 | After wire acceptance |
| 3 | `StageFilter::on_routed` | 1 | After a route and normalized target are known |
| 4 | `Governor::try_acquire` | 1 | Before credential lookup and before any body read |
| 5 | `Authenticator::authenticate` | 0 or 1 | Once for a sealed signed request; zero for anonymous admission |
| 6 | `PolicySource::snapshot` | 1 | After authentication and before authorization |
| 7 | `Authorizer::authorize_route` | 1 | Before CORS lookup, body read, and decoding |
| 8 | `AuthzAuditSink::on_decision` | 1 | Records the route decision without changing it |
| 9 | `CorsSource::load` | 0 or 1 | Once on a cache miss when an authorized request has one usable `Origin` and bucket |
| 10 | `Authorizer::authorize_input` | 1 | After decoding and resource derivation |
| 11 | `AuthzAuditSink::on_decision` | 1 | Records the input decision without changing it |
| 12 | `OpLayer::wrap` | 1 | After both authorization stages, outside the handler |
| 13 | `Handler::call` | 1 | Innermost dispatch |
| 14 | `StageFilter::on_response` | 1 | For every response, including an early refusal |
| 15 | `Observer::on_response` | 1 | Last, after invariants and framework headers |

An accepted CORS preflight is a separate path: it calls the wire filter, host
resolver, governor, CORS source, response filter, and observer once each. It
does not route, authenticate, authorize, read a body, invoke an operation
layer, or dispatch a handler.

The ordering constraints are structural. The governor needs the routed bucket
but must run before credential and body work. Route authorization needs only
the normalized target, while input authorization must wait for decoded derived
resources. Response filters run before response invariants and framework
headers so they cannot remove either guarantee.

The integration tests that pin these positions are `governor_runtime`,
`authz_contract`, `middleware`, `cors_runtime`, and `pipeline`. The assembly
test for this document should count calls, not infer them from a successful
status.
