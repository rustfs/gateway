# xtask

Repository automation for bounded verification, generation, route explanation, scaffolding,
bootstrap and reverse tracing.

## Verification timing

`cargo xtask verify --crate <name>` prepares the selected test and lint artifacts before running
its 30-second verification loop. A workspace build may not prepare the same Cargo feature selection.
This prebuild exclusion was accepted in [#642](https://github.com/rustfs/gateway/issues/642) and
implemented in [#690](https://github.com/rustfs/gateway/pull/690).

Read the existing output as two measurements. For example, the recorded #690 run printed:

```text
verify: crate xtask build compiled 8 crate(s) in 8.08s outside the budget
verify: crate xtask passed in 16.72s
```

- `build ... outside the budget` reports the prebuild duration and compilation count. A prebuild
  failure still fails the command; the exclusion does not skip preparation.
- `passed in ...` reports the prepared loop, including launcher time and excluding only the
  measured prebuild duration. It does not report the complete invocation.
- Measure the complete invocation separately, for example with
  `/usr/bin/time -p cargo xtask verify --crate rustfs-gateway-sig`. Keep that `real` duration alongside
  both verifier measurements; do not label their rounded sum as an independently measured total.

The prebuild runs the loop's own commands minus the run: each `test` selection with `--no-run` and
without its filter tail, and each `clippy` step as itself, `-- -D warnings` included. It used to
run a `cargo check` of the Clippy targets instead, which prepares nothing Clippy reuses for a
workspace crate: Cargo fingerprints a workspace member's lint pass against the Clippy driver and
the lint arguments, so every workspace crate with a stale lint pass was relinted inside the
budget. That was the build behind the killed loops in
[#1264](https://github.com/rustfs/gateway/issues/1264),
[#1336](https://github.com/rustfs/gateway/issues/1336) and
[#1367](https://github.com/rustfs/gateway/issues/1367). A lint failure now fails the prebuild,
before the loop starts, and names the command that failed.

On a prepared tree the loop compiles nothing. A loop step that does compile is reported whether
the loop then passes or is killed. With the old `check` mapping restored, the first goldens run
after `crates/types/src/lib.rs` was touched passed and printed:

```text
verify: crate rustfs-gateway-goldens step 2 compiled 8 crates inside the budget; the deadline covered a build, not just the work
verify: crate rustfs-gateway-goldens step 2 built what the prebuild did not cover; that is an xtask defect, not this crate's cost: file an xtask issue naming `cargo clippy -p rustfs-gateway-goldens --all-targets -- -D warnings`
```

That pair of lines is a prebuild defect, not a cost of the crate: file it against xtask with the
command it names.

A complete invocation over 30 seconds can still have a passing prepared loop. A loop killed at
its deadline is a failure whose unfinished work has not been timed to completion; retain the
diagnostic and the step it names. Investigate that failure without increasing the budget or
dropping checks. This clarification changes no clock, check or shared-runner CI timing rule, and
does not extend the crate prebuild exclusion to `verify --op` or `verify --all`.

### Full gate

`cargo xtask verify --all` runs three stages in order — `workspace test build`, `workspace tests`,
`guard self-test` — and each stage runs under a deadline, not a share of one. The build opens a
480-second deadline and the tests inherit it, because CI's `cargo test` compiles inside its own
480 seconds; the guard self-test opens a fresh 480 seconds, the budget the suite declares for
itself. A stage over its budget fails the gate however much time an earlier stage left, and a
later stage never starts after one that failed, was killed or finished late. Until
[#1247](https://github.com/rustfs/gateway/issues/1247) every stage shared one 600-second deadline,
which two suites costing 227-461 and 265-453 seconds on a loaded host could not fit by construction.

Every started stage gets a line against its budget. The first run of this contract, on a host
other builds were loading, printed:

```text
verify: workspace test build finished in 0.89s, 0.89s into its 480s budget
verify: workspace tests finished in 249.24s, 250.13s into the 480s budget it shares with workspace test build
verify: guard self-test finished in 341.35s, 341.35s into its 480s budget
verify: workspace tests and build guards passed in 591.48s
```

A killed stage reads `the deadline ran out during <stage>, <n>s into <budget>; the gate was
stopped <m>s after it started`, and its `rule:` line quotes that stage's budget. A standalone
`bash scripts/test_guard_scripts.sh` pass is a diagnostic, not a full-gate pass.
