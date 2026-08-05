# Architecture guard scripts

Every file here named `check_<topic>.sh` is a deterministic guard: it takes no
arguments, prints a diagnostic to stderr when something is wrong, and **its
exit code is the verdict**. Each one can be run on its own:

```bash
scripts/check_layer_dependencies.sh
scripts/test_guard_scripts.sh          # runs every guard, plus its negative cases
```

## Conventions

These are binding for every script added here (rustfs/backlog#1723).

1. **Location and name.** `scripts/check_<topic>.sh`, executable, `#!/usr/bin/env bash`
   plus `set -euo pipefail`.
2. **Exit code is the verdict.** `0` = clean, non-zero = violation. No script
   may require a wrapper to interpret its output.
3. **Header comment is mandatory** and states three things:
   *what* it checks, *why* (with the issue or ADR that decided it), and
   *how to exempt* a case.
4. **Exemptions use the allowance-list pattern** borrowed from the rustfs/rustfs
   main repository (`check_unsafe_code_allowances.sh`): a plain-text file under
   `scripts/allowances/`, one entry per line, `#` for comments, each entry
   carrying a reason. Allowance files are hand-maintained and reviewed — there is
   deliberately no `--update-baseline` style regeneration flag, because a
   violation should cost a review, not one command. A guard treats a missing
   allowance file as an empty one, so none of them exist until they are needed.
5. **Root override.** Every guard honours `GATEWAY_CHECK_ROOT` so it can be run
   against a sandbox copy; this is what `test_guard_scripts.sh` uses.
6. **Only deterministic scripts may block CI.** LLM judgement (the expert roles
   in `.claude/skills/gateway-adversarial/`) produces verdicts, never a red
   build. See rustfs/backlog#1724.

`lib/cargo_deps.awk` is a shared helper, not a guard: it extracts declared
dependency names from a `Cargo.toml` so the three manifest-scanning guards agree
on what a "dependency" is.

## Registry

The full set of guards planned for this repository, with the phase each one
lands in. **Registration is not implementation** — names, scope and location are
fixed now so that the same check does not get written twice under two names.

### Implemented

| Script | Checks | Phase |
|---|---|---|
| `check_layer_dependencies.sh` | Internal crate dependency direction is one-way; the allow matrix is a DAG; `rustfs-gateway-conformance` may only use the `rustfs-gateway` facade | P0 (Week-1, before P1) |
| `check_ring_boundaries.sh` | Ring 0/1 (`rustfs-gateway*`) depends on no `rustfs-*` crate and no ring-2 `rustfs-gateway-*` crate; `s3s` only via `rustfs-gateway-types`' `compat-s3s` feature, which must keep its `# DELETE BY` marker | P0 (Week-1) |
| `check_no_planning_docs.sh` | Agent notes and planning documents are not tracked by git (closes the `git add -f` hole that `.gitignore` leaves open) | P0 |
| `check_no_global_registry_deps.sh` | No `inventory` / `linkme` / `ctor` dependency in any `Cargo.toml` (ADR-0003) | P0-07 |
| `check_ct_eq.sh` | Secret-bearing types (`Signature`, `Secret`, `SigningKey`, …) derive no `PartialEq` / `Eq` / `Debug`; comparison must go through `ct_eq`. No-ops with an explanation until `crates/sig` lands | P0 (before P2) |
| `check_license_headers.sh` | Every tracked `.rs` file opens with the Apache-2.0 licence header (ADR-0001 provenance boundary) | P0 |
| `check_generated_dto_packaged.sh` | Every `#[path]` under `crates/*/src` stays inside its crate, reaching the generated dto through the `crates/types/generated` symlink | P1-06 |
| `check_no_dto_non_exhaustive.sh` | No generated dto struct carries `#[non_exhaustive]`; it forbids `..Default::default()` (E0639), which is the very syntax that keeps a new field minor (ADR-0004 P1) | P1-06 |
| `check_no_exhaustive_destructuring.sh` | No hand-written code destructures a dto without a trailing `..`; that is the one pattern a new field breaks (ADR-0004 P3) | P1-06 |
| `test_guard_scripts.sh` | Not a guard: runs every guard on the tree and asserts each one fails on an injected violation | P0 |

### Registered, not yet implemented (TODO)

| Script | Checks | Phase |
|---|---|---|
| `check_dto_fields.sh` | DTO public field count only grows (the `non_exhaustive` and destructuring halves are now implemented separately, see above) | P0-08 |
| `check_ci_time_gate.sh` | Total PR gate wall time stays inside the 10-minute budget | P0-04 |
| `check_role_verdicts.sh` | High-risk PR descriptions carry the required expert-role verdicts (PR-only job; needs the `## Role Verdicts` anchor from the PR template) | P0-10 |
| `check_op_file_shape.sh` | One operation per file; `//! Shares:` declaration agrees with the actual `use` graph; 800-line ceiling | P1 |
| `check_quirks_evidence.sh` | Every quirk has ≥1 evidence and ≥1 case referencing it, consistent in both directions | P1 |
| `check_error_has_rule_ref.sh` | Diagnostic errors carry a rule reference (quirk id / RFC section / spec field path) | P2 |
| `check_wire_boundary.sh` | Wire-layer boundary constraints | P3 |
| `check_no_as_any.sh` | No `as_any()`-style runtime downcast escape hatch | P3 |
| `check_no_trailer_mutex.sh` | No `Arc<Mutex<Option<_>>>` trailer timing contract — the ordering must be encoded in the type | P3 |
| `check_multer_constraints.sh` | multipart parsing sets explicit limits (multer defaults to `u64::MAX`) | P3 |
| `check_governor_position.sh` | `Governor::try_acquire` is called after routing and before the body is read | P3 |
| `check_config_load_once.sh` | The policy/config snapshot is taken exactly once per request | P3 |
| `check_no_header_unwrap.sh` | Header parsing never `unwrap`s | P3 |
| `check_no_minio_source.sh` | Clean-room: no reference to MinIO server sources (AGPL-3.0 and archived) | P6-08 |
| `check_no_duplicate_fuzz_targets.sh` | Fuzz targets are not duplicated between P2-07 and P8-07 | P8-07 |
| `check_agents_no_dup.sh` | Scoped `AGENTS.md` files do not restate root rules | Deferred until layered `AGENTS.md` files exist |
