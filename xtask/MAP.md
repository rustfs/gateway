# xtask crate map

Agent entry point for repository automation commands.

| File | Responsibility | Read it when |
|---|---|---|
| `src/main.rs` | Stable CLI dispatch and help. | Add or rename a subcommand. |
| `src/bootstrap.rs` | Bounded fresh-checkout preparation. | Bootstrap is slow or misses a prerequisite. |
| `src/catalog.rs` | Operation-to-crate verification map. | `verify --op` selects the wrong work. |
| `src/codegen.rs` | Codegen/spec command process boundary. | Generated verification reports wrongly. |
| `src/new_op.rs` | Intentionally-red operation scaffold. | Scaffold contents or collision checks change. |
| `src/route.rs` | Route explanation CLI rendering. | `route explain` output changes. |
| `src/verify.rs` | Bounded verification command selection. | A crate/op/all verification command is wrong. |
| `src/why.rs` | Reverse trace and stable text/JSON rendering. | A `why` namespace or section changes. |
| `tests/cli_contract.rs` | Shared CLI output/exit contracts. | Change help or general process behavior. |
| `tests/why_contract.rs` | Six-namespace reverse-trace goldens. | Change `why` resolution or output. |
