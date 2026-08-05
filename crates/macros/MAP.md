# rustfs-gateway-macros — crate map

`#[handlers]`: put it on an inherent `impl` block and each `async fn` named after an S3 operation
gets an `impl Handler<Operation>` that delegates to it, plus one `register[_<group>]` function that
calls `RouterBuilder::handle` once per method. It is optional sugar — the hand-written form is
documented beside every example and proved equivalent by a test.

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | The attribute entry point, the hand-written equivalent, the five governance rules | First stop; you can often stop here |
| `src/expand.rs` | Parsing the block, validating each method, emitting the three pieces | You are changing what the macro produces |
| `src/mapping.rs` | snake ↔ Pascal, the unknown-operation error, the signature cross-check | You are changing an error message or the mapping |
| `src/levenshtein.rs` | Edit distance and the two nearest suggestions | Rarely |
| `src/op_names.rs` | The operation-name mirror, and why it is a mirror | You added an operation and the macro does not know it |
| `src/tests/mod.rs` | 7 positive / 15 negative: goldens, error spans, both governance guards | You changed anything above |
| `tests/expand/*.rs` + `*.expanded.rs` | The expansion, checked in | You want to know what the macro does, without reading it |
| `tests/equivalence.rs` | 3 positive / 3 negative: macro form ≡ hand-written form | You changed `expand.rs` |
| `tests/op_names.rs` | 1 positive / 2 negative: the mirror against the route table | The operation whitelist grew |

## The five governance rules, and where each one is enforced

| # | Rule | Enforced by |
|---|---|---|
| 1 | Declarative registration only: no minted type names | `tests::the_expansion_mints_no_public_type_name` — parses the expansion and counts `struct`/`enum`/`type`/`union`/`trait`/`mod` items; the count must be zero |
| 2 | No rewritten function bodies | `tests::the_expansion_rewrites_no_function_body` — compares every method body token for token before and after, plus `the_generated_handler_only_delegates`, which asserts the body appears exactly once |
| 3 | Expansion goldens checked in | `tests/expand/*.expanded.rs`, asserted by `assert_golden`; refresh with `UPDATE_GOLDEN=1 cargo test -p rustfs-gateway-macros` |
| 4 | A macro-free equivalent exists and is documented | `tests/equivalence.rs::macro_and_manual_registration_are_equivalent` and `the_two_forms_answer_identically`; the hand-written spelling is in `src/lib.rs`'s module docs and in `rustfs-gateway-core`'s |
| 5 | Errors point at the method name, with suggestions | `tests::an_unknown_operation_is_reported_on_the_method_name` (line and column of the identifier), `the_error_is_not_reported_on_the_impl_block`, `a_signature_for_another_operation_is_reported_on_the_request_type` |

## Shape decisions worth not re-litigating

- **Goldens are rendered with `prettyplease`, not `cargo expand`.** The rule is that the expansion
  is readable in the repository; it says nothing about which tool produced the file.
  `cargo expand` needs a tool install and a full compilation, and it would put a manual step
  between a macro change and a refreshed golden.
- **Error spans are asserted directly, not through `trybuild` `.stderr` goldens.** The property is
  "the error points at the method name identifier". Asserting the `syn::Error`'s line and column
  checks exactly that; a `.stderr` golden also checks how one compiler version renders a
  diagnostic, which is the part that breaks on upgrade. AGENTS.md asks that anything blocking be
  deterministic, and a rustc-version-coupled golden is not.
- **The macro does not depend on `rustfs-gateway-core`.** It generates code against it, and its
  tests link it. A build-time dependency would pull the generated dto tree into the build graph of
  every crate that writes `#[handlers]`, to validate a list of strings.
- **`register` lands in a second `impl` block.** The block the user wrote is copied through
  untouched, so what the compiler sees for that block is what they can read in their own file.
- **An unrecognised method name is an error, never a silent skip.** A helper says `#[handlers(skip)]`.
  The failure mode being prevented is a handler that is never registered, never called, and never
  mentioned anywhere.
- **No summary function is generated.** Composing `register_objects` and `register_buckets` needs
  knowledge of every file that has a block, which this macro does not have. The assembly point
  writes the composition, and that line is greppable.
- **The generated `register` takes `this: &Arc<Self>`, not `self: &Arc<Self>`.** Arbitrary self
  types are not stable, so the receiver form the design sketch used does not compile. Call it as
  `Fs::register_objects(&fs, builder)`.

## Open for maintainer review

- **`crates/macros` is not in the layer allow matrix.** `scripts/check_layer_dependencies.sh`
  refuses a crate it has no row for, and both that script and `AGENTS.md`'s dependency graph are
  outside this task's file scope. The row to add, below the `rustfs-gateway-core` one, is
  `"rustfs-gateway-macros|rustfs-gateway-core rustfs-gateway-types"` — the two edges are
  dev-dependencies of the equivalence and mirror tests. Until it lands, that one guard is red and
  `scripts/test_guard_scripts.sh` reports one failure in its positive control.
- **`src/op_names.rs` should become a codegen artefact.** It is a mirror guarded by a test today
  because `xtask` is outside this task's scope. When codegen owns it, keep `tests/op_names.rs`:
  it is what proves the generator ran.
- **`syn` 3.0 is used, and `ReceiverKind` is 3.0-only.** If the workspace ever pins `syn` 2, the
  receiver check in `mapping.rs` is the one place that has to change.
- **The macro has no opinion about `OperationSpec`, floors or `derive_resources`.** Those stay
  hand-written or generated per operation, deliberately: a macro that wrote the authorisation
  action would make the "every operation declares one" rule vacuous.

## Verify

```bash
cargo test -p rustfs-gateway-macros                                 # 31 tests, 20 negative / 11 positive
UPDATE_GOLDEN=1 cargo test -p rustfs-gateway-macros                 # only when the expansion change is intended
cargo clippy -p rustfs-gateway-macros --all-targets -- -D warnings
cargo fmt --all --check
```
