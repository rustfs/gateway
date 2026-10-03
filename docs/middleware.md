# Middleware

Three levels of extension, one decision tree, and the list this project will be judged against:
the nine tower patch layers RustFS carries around s3s today, and where each of them lands here.

[docs/security-model.md](security-model.md) covers the signature declarations this file leans on;
[docs/adr/0002-dyn-and-async-policy.md](adr/0002-dyn-and-async-policy.md) is why every signature
below is spelled the way it is.

## Why this file exists

A framework that only lets you *observe* sends you back to patching it from outside. That is the
state RustFS is in: nine `tower::Layer`s wrapped around s3s, and most of them **rewrite** a request
or a response rather than watch it. One of them parses the response XML of a single operation,
edits one element and serialises it back — for a value the server produced from a struct one stack
frame earlier — because there was no way to reach the struct.

So this framework has three levels of middleware, and the whole point of the table at the bottom is
that every one of the nine has a written destination with a test standing behind it.

## The decision tree

| The shape of the requirement | Use | Why that one |
| --- | --- | --- |
| Connection- or service-wide, no S3 semantics: panic capture, tracing, a global rate limit, compression, TLS termination | a **tower `Layer`** around the whole `S3Service` | it needs no S3 context, and the ecosystem already implements it. This framework does nothing for it and does not need to: `S3Service` is a `tower::Service` |
| See or rewrite the HTTP shape, or a finished response; no typed input needed | **`StageFilter`** | three synchronous seams inside the pipeline, with the head and the response mutable |
| One operation (or a few), and it needs the decoded `Input` or the typed `Output` | **`OpLayer<O>`** | it holds the DTO, so changing a field is three statements and cannot break the document's shape |
| Only watching — logs, metrics, an audit trail | **`Observer`** | read-only, and permanently so |

**If you need to rewrite something, do not reach for `Observer`.** It hands out shared references
to summaries, is called after the response has been decided, and no `&mut` method will ever be
added to it.

[docs/metrics-and-audit.md](metrics-and-audit.md) lists what RustFS records about each request and
which of it an `Observer` and an `AuthzAuditSink` carry.

## Level 2: `StageFilter`

```rust
pub trait StageFilter: Send + Sync + 'static {
    fn on_wire(&self, head: &mut WireHead<'_>) -> Result<(), S3Error> { Ok(()) }
    fn on_routed(&self, routed: &RoutedView<'_>) -> Result<(), S3Error> { Ok(()) }
    fn on_response(&self, view: &ResponseView<'_>, response: &mut Response<Body>) -> Result<(), S3Error> { Ok(()) }
}
```

Every method has a default, so an implementation states only the seam it cares about, and there are
closure adapters — `wire_filter`, `routed_filter`, `response_filter` — so that supplying one
function does not require declaring a struct.

### The three seams, and why there are three

```text
  freeze        the signing material, copied out before anything may touch the head
  → on_wire     the head, mutable
  accept        every wire-level ambiguity refused
  resolve host / route / address
  → on_routed   the operation, the bucket and the key, read-only
  govern / admit / authenticate / authorize / read body / decode
  → OP LAYERS   inside dispatch
  dispatch / encode
  → on_response the response, mutable
  invariants    the RFC 9110 body rules
  stamp         the four framework headers
```

The seams are the three the landing table needs and no more. A seam between every pair of stages
would be six more public positions to keep stable, and five of them would have nothing but the same
head to offer that `on_wire` already offers — the intermediate stages hold *type states*, consumed
by value, and publishing them as `&mut` is exactly the property `P4-04` exists to prevent.

Each position is load-bearing:

- **`on_wire` runs before acceptance.** Whatever a filter writes is then judged by every acceptance
  rule — the `Content-Length`/`Transfer-Encoding` conflict, the duplicate-header refusals, the
  limits — exactly as a client's own bytes are. A seam *after* acceptance would need a second
  acceptance pass over rewritten input, and "the front end and the back end parsed different bytes"
  is the whole of request smuggling.
- **The signing material is frozen before it.** The header snapshot the verifier reads is taken one
  line earlier, so nothing a filter does can reach a signature. See below.
- **`on_routed` runs after the single normalisation.** That is the earliest point at which the
  operation, the bucket and the key are all decided — and it is read-only *because* they are
  decided: the target has one producer, and a seam is not a second one.
- **`on_response` runs before the invariants and the stamp.** So the two things the framework
  guarantees about every response survive a deployment's rewrite.

### What a filter may do

Observe, rewrite, refuse. An `Err` goes through the one renderer every other refusal goes through,
and the pipeline stops.

### What a filter may not do

1. **It may not answer.** There is no `Ok(Response)` arm at any seam. A seam that could return a
   success would be able to serve object bytes from in front of the security floor — which is the
   structural shape of [rustfs#4845](https://github.com/rustfs/rustfs/issues/4845), where a custom
   route bypassed the access check entirely. A filter can *end* a request, and the only way it can
   end one is with an error, which is a refusal and never a payload.
2. **It may not affect a signature — in either direction.** The verifier reads a header snapshot
   taken before the first filter runs. A filter that writes an `Authorization` header does not make
   an anonymous request authenticated; a filter that deletes one does not make a signed request
   fail. Both halves are asserted, because only the pair distinguishes this design from one that
   reads the post-filter head.
   The single exception is the **`Host` header**, which is *frozen* (`FROZEN_WIRE_HEADERS`): the
   effective host is derived from the head *after* the seam and then feeds the canonical request, so
   it is the one field the snapshot does not cover. The method and the request target are not
   reachable from `WireHead` at all, so there is nothing to freeze there.
3. **It may not choose the target.** `RoutedView` publishes shared references and no mutable one.
4. **It may not defeat a response invariant.** A `304` cannot be given content, a `Content-Length`
   that disagrees with a body of known length is corrected, and the request identifier cannot be
   removed — all three run after `on_response`.
   A filter that installs a stream of *unknown* length keeps the `Content-Length` it declared,
   because nothing can check a length before the bytes exist. The transport holds it to that
   declaration instead: on both HTTP/1.1 drivers a stream that ends short of it, or fails part-way,
   ends the connection with only the bytes the stream produced, and an undeclared stream that fails
   never sends the last chunk, so a truncated body cannot pass for a complete one. That is c-mw-0024,
   asserted on a real socket in `crates/gateway/tests/response_stream_termination.rs`.

### Order

Registration order, at every seam, including the response seam. A later filter sees an earlier
one's rewrite, because all three seams operate on one value in sequence. Reversing the registrations
reverses the order, which is asserted rather than implied.

### Why every method is synchronous

`on_wire` and `on_routed` run **before authentication**. An asynchronous seam there is an invitation
to read a store, and an unauthenticated request that drives a storage read is an amplifier and a
private-bucket enumeration oracle at once. This is the same rule that makes `HostResolver`
synchronous, and `scripts/check_stage_filter_sync.sh` enforces it over the source.

`on_response` is synchronous for a different reason: the request is already finished, so awaiting
there buys latency and nothing else.

## Level 3: `OpLayer<O>`

```rust
pub trait OpLayer<O: Operation>: Send + Sync + 'static {
    fn wrap<'a>(&'a self, request: Req<O>, next: Next<'a, O>) -> BoxFuture<'a, HandlerResult<O>>;
}
```

Hand-written `BoxFuture`, because it is held as `Arc<dyn OpLayer<O>>` and RPITIT is measurably not
dyn compatible (ADR-0002). There is a closure adapter, `op_layer`.

**Storage and dispatch.** A per-operation, typed layer cannot live in a non-generic registry as
itself. `ServiceBuilder::op_layer::<O, _>` boxes each one as `OpLayerSlot<O>` — a concrete,
`O`-parameterised struct — and stores it as `Arc<dyn Any + Send + Sync>` keyed by `O::NAME`.
`register::<O, B>` does not erase on the spot: it stores a closure that still knows `O` and `B`, and
`build()` calls that closure with the slots collected for the same name, downcasting them back to
`Arc<dyn OpLayer<O>>` inside it. That is the same closure-erasure shape the core operation registry
uses for handlers, and the reason neither needs `inventory` (ADR-0003). Registering a layer for an
operation with no handler fails the build with `asm-op-layer-unattached`; it is never silently
ignored.

**Cost when nothing is registered.** The dispatch entry holds `Option<Arc<[Arc<dyn OpLayer<O>>]>>`,
and the `None` is the hot path: with no layer registered the invocation calls the backend directly,
so no continuation, no terminal and no second `Box::pin` exist. `GET /b/key` pays nothing for a
level it does not use. The property is asserted by a chain-entry counter in `crates/gateway/src/
dispatch.rs`, in both directions — an unlayered invocation must not move it and a layered one must.
It counts chain entries, not allocations: a counting global allocator needs `unsafe impl
GlobalAlloc` and the workspace forbids `unsafe`, so what is proven is that the branch holding the
allocations was not taken.

**Order.** Outer to inner, in registration order.

**`Next::run` takes `self`.** Calling the continuation twice is not a runtime error to report — it
is a moved value, and the second call does not compile.

**It cannot skip authorisation.** A layer runs *inside* dispatch, after the security floor, the
authenticator and both authorisation stages. Not calling `next` skips the *handler*, never the
authorisation: there is no constructor anywhere that turns a layer's own value into an authorised
request.

## Replacing middleware

`S3Service::replace_assembly(AssemblyUpdate)` validates and publishes a complete request assembly:
request settings, routes and handlers, operation layers, stage filters, authorizer, policy source
and timeout, audit sink, and observer. Each candidate supplies its complete registry and authorizer.
Omitted optional middleware uses the same defaults as initial assembly. An invalid candidate leaves
the installed generation intact.

Every request captures one immutable generation at entry and keeps it through both authorization
stages and response delivery. That includes a replacement published by the request's own
`on_wire` or `on_routed`: routing, the policy source, both authorization stages, the operation
layers, the response seam and the observer of that request all stay on the entry generation.
`crates/gateway/tests/assembly_snapshot.rs` publishes from inside those two seams to prove it. A committed response also retains that generation's observer until
its terminal document is ready. A successful update reaches every service clone together.

The existing narrower updates remain available: `ConfigHandle::store` changes only request
settings, and `S3Service::replace_registry` changes only routes, codecs, handlers, and operation
layers. Their atomic updates retain concurrent changes to the other fields. Handles obtained from
the original service builder keep updating the same service after a complete assembly replacement.

`AssemblyUpdate` exposes only replaceable fields. Authentication, security floors, governors, and
other fixed host settings belong to the initial `ServiceBuilder`; the update API cannot accept and
silently ignore a change to those settings.

## The nine RustFS tower patch layers, and where each one lands

Source: `rustfs/src/server/layer.rs`. This table is the acceptance list for `P10-06`, which deletes
those nine layers. Every row names a test in
`crates/gateway/tests/patch_layer_landings.rs`, and `scripts/check_patch_layer_map.sh` requires the
two sets to match in both directions — a row naming a test that does not exist fails, and a test
here with no row fails.

| # | Tower patch layer | What it patches | Lands on | Level | Test |
| --- | --- | --- | --- | --- | --- |
| 1 | `BodylessStatusFixLayer` | s3s serialises an XML body onto `304`/`204`/`205`/`1xx`, against RFC 9110 §15, costing an h2 `GOAWAY` | the response invariants, applied once to every response | built-in | `bodyless_status_fix_is_the_response_invariant` |
| 2 | `HeadRequestBodyFixLayer` | a refused `HEAD` carries an error document, which h2 clients read as a protocol error | the same invariants, on the refusal path too | built-in | `head_request_body_fix_is_the_response_invariant` |
| 3 | `DoubleSlashListBucketsCompatLayer` | `GET //` is read as an empty bucket name and refused | the route table: `//` and `/` both name `ListBuckets` | built-in | `double_slash_list_buckets_compat_is_the_route_table` |
| 4 | `VirtualHostStyleHintLayer` | with no domain configured, a virtual-hosted `PUT /` is an unreadable `501` | `HostResolver`'s diagnostic, which replaces the message and nothing else | configuration | `virtual_host_style_hint_is_the_host_resolver` |
| 5 | `EmptyBodyContentLengthCompatLayer` | some clients omit `Content-Length` and s3s wants one before it validates | `StageFilter::on_wire` | **level 2** | `empty_body_content_length_compat_is_a_stage_filter` |
| 6 | `S3ErrorMessageCompatLayer` | refusal wording differs from what MinIO and AWS clients expect | the dialect's error-render policy (`P6-08`) first; `StageFilter::on_response` as the per-message escape hatch | **level 2** | `s3_error_message_compat_is_a_stage_filter` |
| 7 | `ObjectAttributesEtagFixLayer` | `GetObjectAttributes` renders its entity tag differently from every other operation, and the layer parses the response XML to fix it | the quirk table (`q-mpu-attributes-etag-0036`) first; `OpLayer<GetObjectAttributes>` to override, in three statements | **level 3** | `object_attributes_etag_fix_is_the_quirk_table_and_an_op_layer` |
| 8 | `StsQueryApiCompatLayer` | the STS query shape has to be rewritten before s3s will look at it | registering STS calls as extension operations, selected by a `QueryPresent` route predicate | built-in mechanism | `sts_query_api_compat_is_an_extension_operation` |
| 9 | `ConditionalCorsLayer` | s3s has no bucket-level CORS, so the layer conditionally decorates S3 paths and the bucket rules are hand-rolled elsewhere | the built-in `CorsPolicy` and preflight, answered from the bucket's stored document | built-in | `conditional_cors_is_the_built_in_preflight` |

**Six of the nine disappear, two become a `StageFilter`, one becomes an `OpLayer`.** That is the
claim this project makes about its own value, and the six columns above are what makes it checkable
rather than asserted.

### Two rows where the record disagrees with itself

Row 4 was listed in the Epic's §5.4 as a `StageFilter`; the task issue's own landing table
(`rustfs/backlog#1731` §4.7) assigns it to the host resolver's diagnostic, which is what landed in
`P6-04` and what is in the tree. The issue is the later and more specific statement, so it is what
this table records.

Row 7's `q-etag-0003` is `q-mpu-attributes-etag-0036` in this repository's quirk registry; the
identifier in the issue predates the generated numbering.

## What this framework deliberately does not offer

**No escape hatch to the raw request.** There is no accessor that hands back an `http::Request`, an
`http::HeaderMap` or a `hyper` body from inside the pipeline, and there will not be one. That hatch
is how [rustfs#4845](https://github.com/rustfs/rustfs/issues/4845) happened: a custom route reached
the raw request and skipped the access check, so authentication had to be re-implemented by hand
inside it, and one of the re-implementations was wrong. Anything that needs to see the whole request
sees it at `on_wire`, before acceptance, where the framework still runs everything afterwards.
