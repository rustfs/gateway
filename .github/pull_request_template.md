## Summary

<!-- One paragraph. What changed and why. -->

Closes #

## Verification

<!-- Paste REAL output, not "I ran it". If a command was not run, say so and
     say why — an empty block is treated as "not verified". -->

```console
$ cargo fmt --all --check
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo test --workspace
$ cargo xtask verify --crate <the crate you changed>
```

<!-- PRs that add a CI job MUST also report the measured impact on total PR
     gate wall-clock time here. The budget is 10 minutes; see
     .github/workflows/ci.yml. -->

## Role Verdicts

<!-- One line per required role (see the trigger table in AGENTS.md), format:
     - <role>: <verdict>
     A bare "pass" is not a result. State what you attacked and what held —
     a non-blocking role still owes a null report, e.g.
     "attacked X, Y, Z — no break found". -->

- simplicity-adversary:

## Breaking Change

- [ ] BREAKING — this PR touches a protected file or changes a public contract.

<!-- If checked, describe the migration path here: what breaks, what callers
     must do, and in which release it lands. -->

## Checklist

<!-- Must match the "PR Checklist" section of AGENTS.md verbatim.
     AGENTS.md is the source of truth; if an item is wrong, fix it there
     first and mirror the change here in the same PR. -->

- [ ] The four-command gate passed (fmt, clippy, test, `cargo xtask verify`)
- [ ] New or changed public API has rustdoc
- [ ] Negative test cases outnumber positive ones
- [ ] Every new assertion was mutated — the implementation was broken on purpose and the assertion
      went red. The PR description names which ones
- [ ] No Protected File touched; if one was, the PR description contains `BREAKING` and a migration path
- [ ] No `unsafe` introduced
- [ ] No `inventory` / `linkme` introduced
- [ ] No `#[non_exhaustive]` added to a DTO
- [ ] No s3s code copied; behavioural evidence is URL + self-written summary
- [ ] No credentials, signatures, or expected-signature values reachable from logs or error bodies
- [ ] No plan document, analysis report, or working note committed
- [ ] Commits follow Conventional Commits; PR title ≤72 characters
- [ ] A Handoff comment has been appended to the issue
