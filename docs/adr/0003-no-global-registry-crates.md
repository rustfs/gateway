# ADR-0003: No global-registry crates (inventory / linkme / ctor)

- Status: Accepted
- Date: 2026-08-05
- Trigger: RustFS Gateway axiom A4 (extension points are symmetric in granularity) and dependency policy
- Supersedes / Superseded by: none

## Context

RustFS Gateway dispatches per operation: one `Handler<O>` implementation per S3
operation, collected into an explicit registry that a `RouterBuilder` turns into
a router. Seventy-three operations means seventy-three registrations, and the
obvious "improvement" is to make them automatic — annotate the implementations
and let [`inventory`](https://docs.rs/inventory) or
[`linkme`](https://docs.rs/linkme) collect them through linker sections, so
nobody has to write `register()` at all.

That idea has to be refused *before* the first line of registry code, for four
reasons: it does not compile (the orphan rule blocks it); the only way to make
it compile breaks a deployment shape RustFS depends on today; the mechanism is
unreliable on `wasm32-*`, which is a real target because upstream s3s ships
`s3s-wasm`; and the idea is attractive enough that it will be proposed again
every few months. Rust has no reflection, no specialisation and no negative
trait bounds — automatic collection of an open set of implementations is not
something the language supports, and each rediscovery of that fact costs a day.

## Decision

**RustFS Gateway must not depend on `inventory`, `linkme`, `ctor`, or any equivalent
crate that performs global collection via linker sections or start-up side
effects.** This applies to every `Cargo.toml` in the repository, including
`xtask`, examples, fuzz targets and dev-dependencies.

**The registry is built from macro-generated explicit `register()` calls.** The
attribute macro performs declarative registration only — it generates a
composable `register_*` function and never rewrites a function body. The
registration happens in the caller's own assembly code, and the resulting
registry belongs to a `ServiceBuilder` instance. **It is not a process-global
singleton.**

```rust
// What the user writes:
#[rustfs-gateway::handlers]
impl Fs {
    async fn get_object(&self, req: Req<GetObject>) -> Result<Resp<GetObject>> { /* … */ }
}

// What the macro generates — declarative registration, body untouched:
impl Fs {
    pub fn register_s3gate_handlers(router: &mut RouterBuilder<Self>) {
        router.register::<GetObject>(/* … */);
    }
}

// What the assembly code writes — explicit, per instance, never global:
let router = RouterBuilder::new().with(Fs::register_s3gate_handlers).build()?;
```

## Evidence

All compiler results below were measured with **rustc 1.97.1 (8bab26f4f
2026-07-14)**.

**Measured (probe4): `inventory::collect!` cannot be applied to a registry entry
that carries a backend type parameter.** `inventory::collect!(T)` expands to
`impl inventory::Collect for T`, so a downstream crate registering handlers for
its own backend has to write `inventory::collect!(HandlerEntry<Fs>)`, which
yields:

```
error[E0117]: only traits defined in the current crate can be implemented
              for arbitrary types
```

`Collect` is `inventory`'s trait and `HandlerEntry` is RustFS Gateway's type. `Fs` being
local does not help: under the coherence rules, `ForeignType<LocalType>` is not
a local type. This is not a spelling that can be adjusted — it is the orphan
rule itself.

**Measured consequence: the only way through the orphan rule breaks an existing
deployment shape.** Making `HandlerEntry` non-generic satisfies coherence, but
it degrades the registry into a process-global singleton, which:

- **Breaks RustFS's two-backends-in-one-process arrangement.** RustFS end-to-end
  tests run `fake_s3_target` and the production `FS` backend inside the same
  process. Under a global singleton their registrations overwrite each other.
- **Breaks test isolation.** A unit test that registers a mock handler pollutes
  every other test in the same binary.
- **Breaks the wasm target.** wasm builds have no dependable multi-instance
  isolation story here, and see the platform note below.

**`[inferred]` — platform cost of the linker-section mechanism.** `inventory`
and `linkme` both work by placing statics into a named section and walking that
section at run time. That makes them sensitive to the linker and target
platform; behaviour is known to be unreliable on `wasm32-*` targets and under
build configurations that enable `--gc-sections` or use a non-default linker.
This paragraph is **inferred from the crates' documented mechanism, not measured
on our targets**, and must not be cited as a measured result.

**Measured, from the alternative that was already rejected for dispatch:** using
a bundle supertrait to get compile-time completeness instead of a registry
produces **73 `E0277` errors** when a single implementation is missing, and the
bundle trait is itself unusable as a trait object —
`error[E0038]: the trait FullS3 is not dyn compatible`. Compile-time
completeness checking is therefore not an escape from explicit registration.

## Rejected alternatives

| Alternative | Why it was rejected |
|---|---|
| `inventory` for automatic collection | Measured `error[E0117]` from the orphan rule; the only workaround requires a process-global singleton, which breaks the same-process dual-backend arrangement RustFS relies on |
| `linkme` | Same mechanism, same outcome; distributed slices are assembled by the linker in exactly the way the orphan-rule workaround requires |
| `ctor` for start-up-time registration | Same family of linker and start-up side effects, and it adds non-deterministic initialisation ordering on top |
| A `build.rs` that scans sources to emit the registry | Would require parsing Rust source, and downstream handlers live in downstream crates that our `build.rs` never sees |
| A bundle supertrait for compile-time completeness | Measured: 73 `E0277` errors for one missing implementation, plus `error[E0038]` — not dyn compatible. Run-time `RouterBuilder::require(OperationSet)` yields one sentence a human can act on |
| Write the ADR but skip the guard script | Documentation blocks nothing. This policy reduces to grepping dependency names, so it must be a script; a rule that can be mechanised and is not will be broken |
| One CI job per guard script | Blows out the 10-minute PR gate budget and turns the checks list into noise. All guard scripts share a single `arch-checks` job |

## Consequences

- **Registration is explicit and appears in the caller's assembly code.** That
  is the visible cost: a user who adds a handler must also make sure its
  `register_*` function is called. It is also the benefit — the set of
  registered operations is readable at the call site rather than assembled
  invisibly by the linker.
- **The macro must support multiple `impl` blocks across multiple files** and
  generate composable `register_*` functions. It must never rely on any form of
  global collection to stitch them together.
- **Completeness is a run-time assertion.** `RouterBuilder::require(OperationSet)`
  checks for missing operations during `build()` and reports them in one plain
  sentence naming the missing operations. There is no compile-time completeness
  guarantee, and this ADR accepts that.
- **Macro governance applies** (see `AGENTS.md`, "Macro Governance"): declarative
  registration only, no rewriting of function bodies, a `cargo expand` golden
  file in the repository, and an equivalent macro-free spelling that always
  works.
- **A deterministic guard script enforces the ban.**
  `scripts/check_no_global_registry_deps.sh` scans every tracked `Cargo.toml`
  for the banned names in dependency position only — it must not fire on
  `description = "an inventory of things"` or on a commented-out line — and its
  diagnostics carry the full triple: what failed, file and line, and the rule
  reference pointing at this document. The script has its own test
  (`scripts/test_check_no_global_registry_deps.sh`); an unguarded guard script's
  false positives cost more than the problem it prevents. The script runs in the
  shared `arch-checks` CI job. (`P0-09` tracks the same guard under the working
  name `check_no_inventory.sh`; the two must not both exist — see the note in
  that task.)
- **Registry instances are per `ServiceBuilder`.** Any future proposal to make
  the registry global — for convenience, for speed, or for macro simplicity —
  reopens every failure listed under Evidence and requires a superseding ADR.
