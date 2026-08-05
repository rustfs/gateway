# MAP — rustfs-gateway-codegen

Agent entry point. File → responsibility → when you need to open it.

Build-time only. Turns the IR from `rustfs-gateway-model` into the checked-in artefacts, and answers the
zero-diff question.

```
rustfs-gateway-model::lower ──▶ generate() ──▶ Vec<(path, bytes)> ──┬─▶ write()   put them on disk
                                                            └─▶ verify()  compare with the tree
```

`generate` touches no file, so determinism is structural: the same IR renders to the same bytes,
and the zero-diff gate needs no temporary directory.

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | `CodegenInput` / `CodegenOutput`, `generate`, `write`, `verify`, the run report, stale-file removal. | You are adding an artefact, or `spec verify` fails and you want to know what it compared. |
| `src/emit/mod.rs` | Shared TOML value formatting. | Adding a value kind to a spec file. |
| `src/emit/spec_toml.rs` | `spec/operations/<Op>.toml` — the field-binding view, plus the one-line spellings of a type and a predicate that the other emitters reuse. | A field's rendering in a spec file is wrong. |
| `src/emit/operations_md.rs` | `OPERATIONS.md` — three reverse indexes (query key, header, error code), the forward table, the route order, and one section per operation. | You are changing what an agent can look up without reading the model. |
| `src/emit/rust_files.rs` | `generated/routes.rs` and `generated/error_codes.rs`, data only. | P4 wires the route table up, or a row shape changes. |
| `src/golden.rs` | The structural diff behind the sample comparison: objects as maps, arrays as sequences, records matched by `name` or `id`, string lists as sets plus an order note. | A golden difference report is noisy or misleading. |
| `src/semantic.rs` | The wire-dimension diff for a PR body: operations, route selectors, optionality, bindings, types, XML, error codes. | `generated/` moved by more than 200 lines and the PR needs a summary. |
| `src/why.rs` | Reverse tracing from a quirk id, operation, error code, header or query key to the evidence behind it — with nearest-candidate suggestions when nothing matches. | Someone asks "why is this behaviour like this?", or you are adding a lookup namespace. |
| `src/tests/` | End-to-end generation against the pinned model, determinism, both drift directions, and the golden diff's own failure modes. | Before changing any emitter. |

## Commands

```bash
cargo xtask codegen        # regenerate everything, print the run report and the golden comparison
cargo xtask codegen --diff # the semantic summary between the working tree and a fresh run
cargo xtask spec verify    # the zero-diff gate; also runs as a unit test
cargo xtask why <target>   # quirk id, operation, error code, header or query key
```

## Things that will bite you

- **A golden difference is not a build failure.** `spec/ir/samples/*.json` is hand-written and can
  be the stale side; the run reports differences and exits zero. The gate that must stay green is
  `spec verify`.
- **The error-code → HTTP status table is deliberately not generated.** It is owned by
  `rustfs-gateway-types::ErrorCode`. A generated second copy could disagree with it, which is the exact
  failure the spec pipeline exists to prevent. `generated/error_codes.rs` carries only what the IR
  knows and the status table cannot express: which operations produce a code.
- **`generated/*.rs` define no types.** They are `include!` fodder. A generated file that minted a
  public type name would put a name into the tree that `grep` cannot trace to a declaration.
- **Emitters must stay pure.** No clock, no host name, no `HashMap` iteration, no generator version
  string. `c_cg_0004_two_runs_produce_identical_bytes` is the guard, but the rule is the design.
- **`write` skips files whose bytes are unchanged**, so a no-op run does not churn mtimes.
