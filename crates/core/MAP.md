# rustfs-gateway-core — crate map

Which S3 operation a request names, what that operation requires of it, and whether this backend
handles it. P4-01 landed the ordered route table and its build-time overlap decision, P4-02 split
parameter validation from routing, P4-03 added the compiled lookup form. Nothing here is `async`,
nothing here holds a store, and nothing here can say a word about a request that is not a
compile-time constant — routing runs before the signature is verified.

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
| `src/registry.rs` | `OperationSpec`, `RequiredParam`, `check_required`, `Registry` | You are adding a required parameter |
| `src/error.rs` | `PreAuthError` and the closed pre-authentication status set | You are raising an error before authn |
| `src/dispatch.rs` | `Router`: route, then registration, then parameters — three failures, not one | You are wiring the pipeline |
| `tests/route_table.rs` | 9 positive / 25 negative — every routing and build-refusal case | You changed `table.rs` or `lattice.rs` |
| `tests/params_and_dispatch.rs` | 4 positive / 14 negative — the 400-not-501 rule and the error properties | You changed `registry.rs` or `error.rs` |
| `tests/hot_path.rs` | 7 positive / 10 negative — cost, the key ceiling, and the differential generator | You changed `compiled.rs` or `mask.rs` |
| `tests/golden.rs` + `tests/golden/route-table.txt` | The whole table as text, so a routing change shows up in a diff | Codegen changed |
| `tests/purity_guard.rs` | 8 source guards: no `async`, no store, no leaked message, file shape | You added a file or a public method |

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
- **The readable table is not deleted.** A fast implementation of a pre-auth security decision is
  only allowed to exist while something proves it agrees with the one a person can read.
- **Binary search, not `phf`.** `phf` is not a workspace dependency and this task may not add one.
  Sixty-four short sorted keys is six comparisons and no build script.

## Open for maintainer review

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
