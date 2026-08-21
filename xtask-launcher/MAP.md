# xtask-launcher crate map

Agent entry point for the budget-aware automation launcher.

| File | Responsibility | Read it when |
|---|---|---|
| `src/main.rs` | Selects the warmed full runner for crate verification, keeps other commands on the light runner, and records launcher time. | `cargo xtask` startup or feedback-budget accounting changes. |
