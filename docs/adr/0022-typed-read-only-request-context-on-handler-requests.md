# ADR-0022: A typed, read-only request context on handler requests

- Status: Accepted
- Date: 2026-09-14
- Trigger: crate boundary — what the sig, http and facade stages hand across into the `rustfs-gateway-core` handler request; and axiom A2, because a verified fact must reach a handler as the value that was verified, not as client text to parse again
- Supersedes / Superseded by: none

## Context

`Req<O>` carried the decoded input, the derived resources, the `AuthorizedRead` proof and the
`SseEnforced` proof (ADR-0017), and nothing about the caller. A handler could not learn who
signed the request, which scope the signature was verified under, which host and addressing
style routed it, or what the raw request target and header lines were.

The RustFS ring-2 adapter needs exactly those facts. It wraps every RustFS handler, and those
handlers read an `s3s::S3Request` whose context members are `method`, `uri`, `headers`,
`extensions`, `credentials`, `region`, `service` and `trailing_headers`. rustfs/backlog#1762
(rustfs/gateway#748) could only build that context outside the pipeline. It re-ran the floor and
the authenticator, rebuilt headers from `HeaderView::iter_text` and so dropped unreadable
unrelated lines (divergence `rd-ctx-0002`), and looked the secret up a second time in its own
store. ADR-0020 put the verified scope on the verdict, rustfs/gateway#762 added
`HeaderView::iter_raw`, and ADR-0021 delegated anonymous admission to the authorizer. None of
the three reaches a handler. The rustfs/backlog#1752 ruling forbids putting a raw `HeaderMap` or
`Extensions` back on `Req`, and it forbids a global table or side map as a fallback.

s3s's `Credentials { access_key, secret_key }` has no optional secret. So an adapter that must
fill `S3Request.credentials` must hold a secret, or invent one. In RustFS (`62cc19e93`), the S3
app bodies under `rustfs/src/app` never read the request credential's secret:

- `metadata_route.rs:114` resolves the principal from IAM by access key alone.
- `bucket_usecase.rs:1365` treats present credentials as "authenticated".

Admin handlers do read the secret. For example, `admin/handlers/service_account.rs:595`
decrypts the request body with `input_cred.secret_key`.

## Decision

`Req<O>` gains `Req::context() -> &RequestContextView`, boxed and owned. There is no mutable
accessor and no setter.

The facade builds the context once per request, inside the input-authorization stage, after both
authorizer stages allowed the request. It calls `RequestContextView::from_pipeline(operation,
&wire, addressed, &verdict, caller_secret)`:

- **From the accepted `WireRequest`:** the method, the raw path, the raw query, the effective
  host, and every accepted header line, copied through `iter_raw`.
- **`Addressed`:** the addressing style and host region, plus the bucket and key both authorizer
  stages were asked about.
- **From the verdict:** the principal. `Authenticated` becomes a `RequestPrincipal` with its
  `Identity`, an `AuthenticatedScheme` (family, location, service, temporary; never the token)
  and its `Option<VerifiedScope>`. `Anonymous` becomes no principal, and therefore no scope. A
  rejected verdict, or any variant added later, builds no context.

Header lines are published only as the borrowed `HeaderView`, so a value cannot be assigned
through them.

`Req::new` and the registry's direct-call helper carry `RequestContextView::detached(operation)`,
which is anonymous and has no lines.

The context travels beside the SSE proof through every transition:

- `Authorized::into_request(sse, context)`;
- `ErasedHandler` and `erase_authorized_handler_with_context`;
- `HandlerTable::invoke_erased`;
- the static-dispatch input tuple.

The caller's secret reaches a context only on explicit request:

- **Who can attach it:** only the authenticator that looked it up.
  `SigV4Authenticator::hand_caller_secret_to_handlers()` does this for its SigV4 and SigV2
  halves. A custom authenticator uses `AuthenticationOutcome::with_caller_secret`.
- **When:** it is off by default, and only after the signature matched and the credential was
  admitted.
- **Where:** it is attached only to an authenticated principal, and read only through
  `RequestPrincipal::secret_key_from_authenticator_lookup()`.
- **In what form:** a `CallerSecretKey`, which is zeroized on drop, has no `Clone` and no
  `PartialEq`, prints `<redacted>`, and yields bytes only through `expose_secret()`.

Nothing performs a second lookup. The context's `Debug` prints header names and the query's
length, never a header value or the query.

On the s3s side, `compat::request_context` gains `Principal::from_handler`, which refuses a
missing or non-UTF-8 secret by the member name `credentials`. It also gains
`GatewayRequestContext::raw_headers(iter_raw)`. With these, an adapter builds the s3s context from
the handler context alone. The goldens context diff now drives a real assembled service and
converts inside the handler.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`.
- Measured, red before the change:
  - `cargo test -p rustfs-gateway --test integration --no-run` failed with `E0599` on
    `Req::context`, `E0599` on `hand_caller_secret_to_handlers` and `E0432` on
    `rustfs_gateway::AddressingStyle`. A fourth error, `E0433`, came from a test-side import the
    final test no longer uses.
  - `cargo test -p rustfs-gateway-goldens --lib --no-run` failed with 2 × `E0599` on
    `Principal::from_handler` and `E0599` on the harness's secret-hand-off switch.
- Measured, at the gateway runtime (`request_context_runtime`, a signed `HeadObject` through the
  assembled service):
  - The handler sees `HeadObject`, `HEAD`, `/photos/2026/a.jpg`, `versionId=v1`,
    `s3.example.com`, path style, bucket `photos` and key `2026/a.jpg`.
  - It sees the access key, a V4/header/S3 long-term scheme, and scope
    `("20260102", "us-east-1", "s3")`. The served regions sort to `eu-west-1` first.
  - It sees the signed lines and an extra line.
  - An unrelated `caf\xe9` value arrives byte for byte.
  - An anonymous request has no principal, scope or secret, even with the hand-off on.
  - By default no secret arrives. With the hand-off, the secret equals the stored one (a
    non-short-circuit comparison).
  - With a session credential and the hand-off on, neither the context's nor the request's
    `Debug` contains the secret, the session token, the signature or the `Authorization` value.
  - A wrong signature never reaches the handler.
- Measured, at compile time, as `compile_fail` doctests on the new types:
  - `E0594`: assigning through `context.headers().iter_raw()`.
  - `E0599`: `Req::context_mut`.
  - `E0451`: a `RequestPrincipal` struct literal.
  - `E0599`: `CallerSecretKey::clone`.
- Measured: `size_of::<Req<PutObject>>()` and `size_of::<Req<GetObject>>()` grow from 96 to 104
  bytes on 64-bit, one pointer, under the unchanged 136-byte ceiling (`dto_cold_split`).
- Measured, in the goldens context diff:
  - `rd-ctx-0002`, a non-UTF-8 header value, is now a zero diff.
  - A signed request whose authenticator keeps the secret is refused by name, `credentials`, at
    conversion rather than converted with an invented secret.
- Mutation results for each guarantee are listed in the pull request that lands this ADR.

## Rejected alternatives

- **A `HeaderMap` or `Extensions` member on `Req`.** The #1752 ruling forbids it. An owned map
  is also writable by any layer that holds the request, so the next layer could be told a header
  the client never sent.
- **Rebuild the context in the adapter.** This is the status quo this decision removes. It means
  a second authentication run, a second secret lookup, and headers from the text view that
  silently lose lines.
- **Do RustFS's access check in the `Authorizer` and keep its result in a ring-2 side table.**
  The #1752 ruling forbids a side map. The handlers would still need the URI and the header
  lines.
- **A public constructor from loose values.** Anyone could then name any principal.
  `from_pipeline` takes the `Verdict`, whose authenticated and anonymous variants need
  unforgeable receipts.
- **Carry the context in `HandlerContext` (ADR-0011).** That type holds execution signals, and
  only `call_with_context` receives it. The legacy `call` path and every `OpLayer` would not see
  the caller.
- **Always carry the secret, as s3s does.** Every handler would hold key material that almost
  none of them reads. A value that is merely present ends up in a log line.
- **Never carry the secret.** `S3Request.credentials` could then only be filled with an invented
  secret, and RustFS's admin body decryption would silently use it. The conversion refuses
  instead.
- **Borrow the wire request in the context.** `Req<O>` is owned `'static` stage state, and the
  facade still reads the accepted request after the handler returns.

## Consequences

This is a breaking change to `rustfs-gateway-core`, 0.33.0 -> 0.34.0. The following gain a
`RequestContextView` argument:

- `Authorized::into_request`;
- the `ErasedHandler` signature;
- `erase_authorized_handler_with_context`;
- `HandlerTable::invoke_erased`;
- `StaticOperation`'s input-callback tuple.

A caller outside the pipeline passes `RequestContextView::detached(operation)`. `rustfs-gateway`
goes 0.39.0 -> 0.40.0, because it re-exports the changed core items. The new facade API is
additive: `SigV4Authenticator::hand_caller_secret_to_handlers`,
`AuthenticationOutcome::with_caller_secret` and the re-exported context types.
`rustfs-gateway-types` goes 0.21.0 -> 0.21.1, which is additive.

Each request pays for one header-map copy, cloning each accepted line after both authorization
stages allowed it, plus one `Box`. A request refused earlier pays nothing.

The following enforce the decision, and each went red under its mutation:

- the runtime tests;
- the core unit tests in `request_context.rs`;
- the four `compile_fail` doctests;
- the goldens context diff and its divergence register;
- the size snapshot;
- `check_monomorphic_dispatch.sh`, which pins the static transition
  `authorized.into_request(sse, context)`.
