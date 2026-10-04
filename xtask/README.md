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

A complete invocation over 30 seconds can still have a passing prepared loop. A loop killed at
its deadline is a failure whose unfinished work has not been timed to completion; retain the
diagnostic and the step it names. Investigate that failure without increasing the budget or
dropping checks. This clarification changes no clock, check or shared-runner CI timing rule, and
does not extend the crate prebuild exclusion to `verify --op` or `verify --all`.
