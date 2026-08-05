# ADR-0005: The generated dto crosses the package boundary by symlink

- Status: Accepted
- Date: 2026-08-05
- Trigger: licensing/dependency policy
- Supersedes / Superseded by: none

## Context

`rustfs-gateway-types` does not declare its own dto. The tree is emitted by
`cargo xtask codegen` into the top-level `generated/` directory and mounted into
the crate with two `#[path]` module declarations. ADR-0004 (`P1`, `P8`) and issue
`P1-06` fix that arrangement deliberately: generated output lives in exactly one
place, `cargo xtask spec verify` is a zero-diff gate over `generated/**`, and the
whole tree is on the `AGENTS.md` do-not-read list so that no agent burns its
context window on 73k lines of emitted code. Emitting into
`crates/types/src/` was considered and rejected there, and this ADR does not
reopen that.

What that arrangement did not account for is that **Cargo's file walk never
leaves the package directory**. `cargo package` and `cargo vendor` share the same
listing logic, and both build the file list by walking the package root. A
`#[path]` spelled `../../../generated/dto/ops/mod.rs` reaches the tree fine in a
workspace checkout — where the parent directories exist — and reaches nothing at
all in a package tarball or a vendor directory, where they do not.

Publishing to crates.io is **not** the trigger. Every crate in this workspace
carries `publish = false`, with the recorded reason that rustfs consumes this
repository as a git dependency exactly as it consumed s3s. That decision stands
and this ADR does not revisit it. The live failure mode is `cargo vendor`, which
is part of the git-dependency consumption path: a downstream vendoring
`rustfs-gateway-types` gets a crate directory with `src/` and no dto, and the
build fails in the consumer's tree rather than in ours.

## Decision

`crates/types/generated` is a **symlink to the top-level `generated/dto`**, and
every `#[path]` in `rustfs-gateway-types` is written relative to it
(`../generated/ops/mod.rs`), never relative to the repository root. Generated
output continues to live in exactly one place: the symlink is a second *name*
for the tree, never a second *copy* of it. We will not copy generated files into
any crate directory, at build time or at release time, and we will not emit them
under `crates/types/src/`. `publish = false` is unchanged.

## Evidence

Measured with **cargo 1.97.1 (c980f4866 2026-06-30)** and **rustc 1.97.1
(8bab26f4f 2026-07-14)** on `darwin/arm64`, against the working tree of this
repository.

**Measured 1: the package boundary silently drops the dto.** Before the symlink,
with `#[path = "../../../generated/dto/ops/mod.rs"]`:

```
$ cargo package -p rustfs-gateway-types --list --allow-dirty
```

listed **27 entries** — `Cargo.toml`, `MAP.md`, the cargo-injected metadata files
and 22 files under `src/`. Not one file from `generated/dto/**`, of which
**23 are tracked**. After the symlink, the same command lists **50 entries**,
**23 of them under `generated/`** — exactly the tracked dto tree, and nothing
else from `generated/` (`ir/`, `routes.rs` and `error_codes.rs` belong to other
consumers and stay out, because the link targets `generated/dto` rather than
`generated`).

**Measured 2: a vendored consumer fails to compile without the symlink.** A
throwaway consumer crate depending on `rustfs-gateway-types` as a git
dependency, then `cargo vendor` followed by `cargo build --offline`:

| Arrangement | `vendor/rustfs-gateway-types/generated` | `cargo build` |
|---|---|---|
| `#[path = "../../../generated/dto/..."]`, no symlink | absent | **fails** |
| `#[path = "../generated/..."]` through the symlink | present, 23 files | succeeds |

The failure is not a warning, it is a hard error naming the escaped path:

```
error: couldn't read `.../vendor/rustfs-gateway-types/src/../../../generated/dto/ops/mod.rs`:
       No such file or directory (os error 2)
  --> .../vendor/rustfs-gateway-types/src/lib.rs:48:1
   |
48 | pub mod ops;
   | ^^^^^^^^^^^^
```

**Measured 3: the constraints ADR-0004 and `P1-06` impose are preserved.**

| Property | Command | Result |
|---|---|---|
| Zero-diff codegen gate | `cargo xtask spec verify` | `clean (32 files, 0 differ)` |
| Generated tree stays rustfmt-normal | `cargo fmt --all -- --check` | clean; a deliberately misformatted line in `generated/dto/flat.rs` was reported as `crates/types/src/../generated/flat.rs`, proving rustfmt still follows `#[path]` **through** the link to the one real file |
| Workspace build | `cargo check -p rustfs-gateway-types` | succeeds |
| Git records a link, not a copy | `git ls-files -s crates/types/generated` | mode `120000` |

**Measured 4: the guard costs nothing.** `cargo package --list` completes in
**0.05s**, so the packaged-file-list assertion was affordable as a guard rather
than a slow release-time job. It was subsequently dropped from
`check_generated_dto_packaged.sh` on the grounds that with `publish = false`
nothing in CI invokes `cargo package`; the two structural checks that remain are
sufficient, because the escaping `#[path]` is the defect and the symlink is its
only fix. `[inferred]` — if `cargo package`/`cargo vendor` ever re-enters CI,
restoring the third check is the cheapest way to assert the property end to end.

## Rejected alternatives

| Alternative | Why it was rejected |
|---|---|
| A build script copying `generated/dto/**` into `OUT_DIR` and `include!`ing from there | **Does not solve the problem.** Build scripts run at *build* time, and in an extracted tarball or vendor directory there is no `../../generated` left to copy *from* — the files must already be inside the package, which is the very thing being fixed. It would also add a build script to a ring-0 crate that every consumer pays for, and `include!` resolves nested `mod` declarations relative to the *including* file, so the multi-file `ops/` tree would need `#[path]` into `OUT_DIR` anyway |
| A pre-publish / pre-vendor vendoring step in release tooling | Puts the correctness of the crate in a script that only runs at release time, so `cargo package --list` and `cargo vendor` stay wrong in every ordinary checkout — the failure is still discovered downstream, just later. It also creates a second copy of generated output that `cargo xtask spec verify` does not police, since that gate covers `generated/**` only |
| Committing a real `crates/types/generated/` directory | The same unpoliced second copy, now permanently in the tree and diffed twice in every codegen PR. Drift between the two copies would be invisible until a build broke |
| Generating the dto into `crates/types/src/` | Already rejected by ADR-0004 and `P1-06`: generated output must live under the single top-level `generated/` tree, which is also what keeps it on the do-not-read list and out of `grep` results for hand-written code |
| Doing nothing, because `publish = false` | Confuses publishing with packaging. `cargo vendor` uses the same file walk and is part of the git-dependency path this project *does* support — Measured 2 is a failing build with no crates.io involved |

## Consequences

- **`crates/types/generated` is load-bearing infrastructure, not a convenience.**
  Deleting it, or replacing it with a real directory, breaks the crate for every
  consumer that vendors. `scripts/check_generated_dto_packaged.sh` enforces this
  and runs in the `static` CI job, which executes every `scripts/check_*.sh`.
  It checks that no `#[path]` under `crates/*/src/**` resolves outside its own
  crate directory, and that the mount point is a symlink onto `generated/dto`.
  Three negative cases in `scripts/test_guard_scripts.sh` prove it can fail.
- **Windows is now a tripwire.** Git materialises a symlink as a small text file
  unless `core.symlinks` is true, which needs Developer Mode or elevation. CI is
  `ubuntu-latest` only today and the 3-OS matrix is explicitly deferred until
  platform-specific code exists; when that matrix lands, the Windows job will
  fail on this unless the checkout enables symlinks. The guard reports that case
  by name rather than letting rustc emit a bare `file not found for module`.
- **Contributors gain one rule**: a `#[path]` in this workspace is relative to
  its own crate directory. Reaching up past the crate root is now a guard
  failure, not a style preference.
- **The do-not-read list is unaffected in practice.** `crates/types/generated` is
  a second name for a tree that is already excluded, and neither `grep -r` nor
  ripgrep follows directory symlinks by default, so the link does not pull
  generated code into ordinary searches of `crates/`.
- **`cargo fmt`, `cargo xtask spec verify` and the emitter are untouched.**
  Codegen still writes only to `generated/`, the zero-diff gate still covers
  `generated/**`, and rustfmt still normalises the one real copy — reached
  through the link, as Measured 3 shows.
