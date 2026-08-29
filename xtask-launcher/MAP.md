# xtask-launcher crate map

Agent entry point for the budget-aware automation launcher.

| File | Responsibility | Read it when |
|---|---|---|
| `src/main.rs` | Selects the smallest runner that can serve each request, including light facade and conformance crate verification, and records launcher time. | `cargo xtask` startup or feedback-budget accounting changes. |
