# rustfs-gateway-core — crate map

Which S3 operation a request names, what that operation requires of it, whether this backend
handles it, and how it is called. P4-01 landed the ordered route table and its build-time overlap
decision, P4-02 split parameter validation from routing, P4-03 added the compiled lookup form, and
P4-06 added the operation trait, the per-operation handler, and the registry that erases the backend
type. Nothing on the routing path is `async`, nothing there holds a store, and nothing there can say
a word about a request that is not a compile-time constant — routing runs before the signature is
verified. `src/registry/handlers.rs` is the one file that awaits, and it runs after the floor has
admitted the request.

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring, re-exports, the three properties in full | First stop; you can often stop here |
| `src/route/mod.rs` | The map of the routing module and the pre-auth invariant | Before touching anything under `route/` |
| `src/route/selector.rs` | `Predicate` (ten variants), `TargetKind`/`HostClass`/`ArnForm`, `RouteSelector`, `RouteEntry`, and evaluation | You are adding a predicate or asking what one means |
| `src/route/lattice.rs` | Normalisation into constraints, the meet, refinement, the witness | You are touching the conflict decision |
| `src/route/shape.rs` | `RequestShape`: the concrete request a conflict is reported with | Rarely |
| `src/route/table.rs` | `RouteTable::build` and its refusals, first-match `resolve`, the golden rendering | You changed a table or hit a build error |
| `src/route/shadowing.rs` | `ShadowingDecl`, `ShadowingPolicy`, `PROVISIONAL_SHADOWING` | The build asks you for a declaration |
| `src/route/mask.rs` | Routing query keys → one bit each, derived from the table itself | You hit the 64-key ceiling |
| `src/route/compiled.rs` | `CompiledRouter`: `method × target` buckets, mask rules, the empty-mask shortcut | You are changing lookup performance |
| `src/route/explain.rs` | `Explanation`: what won, what it hid, and why | You are building `route explain` |
| `src/route/generated.rs` | `RouteRow`/`RoutePredicate` and the parse of `generated/routes.rs` | Codegen changed the emitter |
| `src/op.rs` | `Operation`, `OperationOrigin` and its sealed token, `AuthRequirement`, `HasOperation`, the standard-name set | You are adding an operation, or asking what makes one standard |
| `src/codec/mod.rs` | `OperationCodec`, and the orphan-rule reason the generated codecs are mounted here rather than in `rustfs-gateway-types` | You are adding an operation family, or asking where a wire binding lives |
| `src/codec/view.rs` | `MetaView` — the request head a decoder reads, with the URI labels split and percent-decoded **exactly once** — and `RequestBody`'s three shapes | You are decoding a path label, or asking why a decoder cannot aggregate a streaming body |
| `src/codec/response.rs` | `EncodedResponse`, `ResponseBody`, the `response-*` override table, and the one copy of the RFC 9110 body invariants | A response carries a body it should not, or an override did not apply |
| `src/codec/value.rs` | One function per IR scalar, in each direction, plus the one-checksum-header rule and the decode-path placeholder exit | A wire value is parsed or rendered wrongly |
| `src/codec/tests.rs` | 27 tests over the object family: what the generated codecs do to bytes | You changed an emitter or a conversion |
| `src/ops/*.rs` | One AWS operation per file: spec, floor, `impl Operation`, `impl HasOperation` | You are adding an operation — copy the nearest one |
| `src/handler.rs` | `Handler<O>`, `Req`, `Resp`, `HandlerError`, `BoxFuture` | You are implementing a backend |
| `src/registry/mod.rs` | `OperationSpec`, `RequiredParam`, `check_required`, `Registry` | You are adding a required parameter |
| `src/registry/reject.rs` | `RegistryError` and the seven rules an operation passes before it registers | A registration was refused |
| `src/registry/handlers.rs` | The erasure closure, `HandlerTable`, `Invocation` — the only file here that awaits | You are wiring the pipeline to the handlers |
| `src/registry/opset.rs` | `OperationSet`, `MissingHandlers` and its one-line message | You are asserting completeness |
| `src/registry/builder.rs` | `RouterBuilder`: `handle`, `route`, `require`, `build`, and `BuildError` | You are assembling a service |
| `src/error.rs` | `PreAuthError` and the closed pre-authentication status set | You are raising an error before authn |
| `src/dispatch.rs` | `Router`: route, then registration, then parameters — three failures, not one | You are wiring the pipeline |
| `tests/route_table.rs` | 9 positive / 25 negative — every routing and build-refusal case | You changed `table.rs` or `lattice.rs` |
| `tests/params_and_dispatch.rs` | 4 positive / 14 negative — the 400-not-501 rule and the error properties | You changed `registry.rs` or `error.rs` |
| `tests/hot_path.rs` | 7 positive / 10 negative — cost, the key ceiling, and the differential generator | You changed `compiled.rs` or `mask.rs` |
| `tests/golden.rs` + `tests/golden/route-table.txt` | The whole table as text, so a routing change shows up in a diff | Codegen changed |
| `tests/registration.rs` | 7 positive / 17 negative — the registration rules, erasure, `require`, the 501 | You changed anything under `registry/` |
| `tests/purity_guard.rs` | 12 source guards: no `async` off the allowance list, no store, no leaked message, one `Box::pin`, file shape | You added a file or a public method |

## Shape decisions worth not re-litigating

- **Ordered, not disjoint.** `GET /b?acl&tagging` is a request AWS answers. A disjoint table needs
  quadratically many `Absent` predicates that every new subresource invalidates, and the SDKs'
  `?x-id=` would make any "unknown key is ambiguous" rule reject ordinary traffic. Overlap *within*
  one precedence stays fatal: there the winner is sort order.
- **Overlap is a decision, not a comparison.** `GET /b?acl` and `GET /b` are unequal, share no key,
  and one is dead. Selectors normalise into constraints over independent dimensions; two overlap
  exactly when their meet is non-empty. The meet is then materialised into a request and run back
  through the ordinary matcher — a lattice bug cannot report "no conflict", it reports an
  inconsistency.
- **Requiredness is not a routing predicate.** `?analytics` without `id` is a `400` from an
  operation already chosen. As a predicate it would be a `501`, and clients disable features on a
  `501`.
- **Two `501`s, two messages.** "No route" means the vhost domain is probably unconfigured; "not
  registered" means write a handler. One string for both hides which happened.
- **Pre-auth messages are `&'static str`.** Not a review rule — a type. `format!` does not
  typecheck, and `tests/purity_guard.rs` refuses `Box::leak`, which is the only laundering route.
- **The bit table has no second source.** Keys are derived from the route table's own selectors, so
  the classic "hand-written keyword list drifts from the table" failure has nowhere to happen. Over
  64 keys is a hard compile error naming the key that did not fit, never a truncation.
- **The shortcut answers one context.** Zero mask, standard endpoint, no ARN. Rules that need an
  ARN or a different endpoint are skipped at compile time (so one access-point entry does not cost
  every object read its fast path); a rule with any residual predicate disables the shortcut for
  that bucket entirely (so `POST /bucket` is never answered without looking at `content-type`).
- **The backend type is erased at registration, and the operation type is not.** A registry entry
  has to call `B::call`, so it has to know `B` — which is why link-time collection cannot work
  (measured `error[E0117]`, ADR-0003). Erasing `B` in a closure keeps `Router` non-generic, which is
  what lets one process hold two routers over two backends.
- **Completeness is a run-time assertion, not a bundle trait.** A bundle supertrait produced 73
  `E0277` errors for one missing implementation and was not dyn compatible.
  `require(&OperationSet)` produces one sentence: `backend is missing handlers for: A, B (2 of 73)`.
- **An operation with no authorisation action cannot be registered.** That is the structural form of
  rustfs/rustfs#4845 — there is no registration path on which the question can be skipped.
- **A third party cannot claim to be an AWS operation.** `OperationOrigin::Standard` carries a token
  whose field is private to this crate, so the namespaced-name rule cannot be opted out of.
- **The readable table is not deleted.** A fast implementation of a pre-auth security decision is
  only allowed to exist while something proves it agrees with the one a person can read.
- **Binary search, not `phf`.** `phf` is not a workspace dependency and this task may not add one.
  Sixty-four short sorted keys is six comparisons and no build script.

## Open for maintainer review

- **P4-05 will add `Operation::DerivedResources`, and that breaks every `impl Operation`.**
  Associated types cannot have defaults, so adding one is a breaking change for every operation
  module. If P5 is to run in parallel, P4-05 should land its associated type first, or accept a
  mechanical edit across every operation file.
- **The codecs exist; the erasure closure has not been rewired to them yet.** `OperationCodec` is a
  separate trait from `Operation` rather than two more methods on it, so a third party can still
  name an operation without writing a codec. The erased payload is still `Box<dyn Any + Send>`:
  changing it to "wire request in, wire response out" is the next step and touches
  `registry/handlers.rs` alone.
- **`OperationCodec` decides the status from the handler's `Resp`, and applies the RFC 9110 body
  invariants last.** A `HEAD` response and a `1xx`/`204`/`205`/`304` lose their body in
  `EncodedResponse::enforce_http_invariants`, once, for every operation — never per operation.
- **`OperationSet` is a name set, not a bit set, and there is no `AWS_CORE`.** An index-based set
  needs a generator to assign the indices, and a curated `AWS_CORE` would be a second source of
  truth about which operations exist. Both belong in codegen; `OperationSet::aws_full()` reads the
  route table.
- **`AuthRequirement` lives in `op.rs` and is deliberately minimal.** P4-05 owns the full
  authorisation shape; this is the least that lets registration refuse an operation nobody can
  authorise, and the two should be merged when P4-05 lands.
- **`tests/purity_guard.rs` gained a file-level allowance list.** `registry/handlers.rs` awaits,
  because calling a handler is what it does. The store-word detector now matches whole identifier
  segments instead of substrings, so `Handler` is no longer read as `Handle`; every catch the
  substring version had is still asserted, including `ObjectStore` and `ConnectionPool`.

- **`ShadowingPolicy` defaults to `EveryOverlap`, as the design asks, and it is quadratic.** Once
  thirty bucket subresources are in the table, every `?acl`/`?tagging` pair overlaps and the strict
  policy asks for several hundred declarations that all say the same thing. `TotalOnly` keeps the
  guarantee that matters — no route is silently unreachable — without the paperwork. Switching the
  default is a decision, not a cleanup; both are implemented and tested.
- **`PROVISIONAL_SHADOWING` belongs in `model/overlays/route.toml`.** That path is outside this
  task's file scope, so the one declaration the generated table needs lives here in the same four
  fields the overlay will use. P4-06 should move it and delete this static.
- **`tests/golden/route-table.txt` should join the protected-files list** — it is the artefact that
  makes a model upgrade's routing change visible.
- **`RoutePredicate` has eight variants, `Predicate` has ten.** `HostClass` and `ArnForm` are in the
  frozen IR schema and here, but `rustfs-gateway-model`'s `Predicate` does not carry them, so
  codegen cannot emit them and no generated row can use them yet.
- **`QueryEquals` compares the still-encoded value.** Every routing value in the model is an ASCII
  token, so it does not matter today; `list-type=%32` would not route. Decoding on the pre-auth path
  is the alternative.
- **`MissingContentLength` (411) cannot be a `RequiredParam` code**, because the pre-auth set is
  `{400, 403, 501}`. That looks right — a missing `Content-Length` is a framing fact acceptance
  already refuses — but it is a real constraint on how P5 writes specs.
- **P4-03's canonical-header half is already upstream.** `rustfs-gateway-sig` /
  `rustfs-gateway-http` verify `SignedHeaders` is ascending and look up by name without sorting.
  Nothing was needed here, and nothing here duplicates it.

## Verify

```bash
cargo test -p rustfs-gateway-core                                  # 80 tests, 59 negative / 21 positive
cargo clippy -p rustfs-gateway-core --all-targets -- -D warnings
cargo fmt --all --check
bash scripts/check_license_headers.sh
bash scripts/check_layer_dependencies.sh
bash scripts/check_ring_boundaries.sh
bash scripts/check_no_planning_docs.sh
UPDATE_GOLDEN=1 cargo test -p rustfs-gateway-core --test golden    # only when the change is intended
```
