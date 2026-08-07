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
| `src/emit/dto/mod.rs` | `generated/dto/**` — one module per operation, plus flat aliases and the `field_counts.txt` ratchet. Owns the **ADR-0004 P2 gate**: a required member whose type has no `Default` fails the build rather than being quietly wrapped in an `Option`. | A dto's shape is wrong, or the P2 gate fires. |
| `src/emit/dto/naming.rs` | Operation and member names to Rust identifiers, keyword escaping included. | A generated name collides or reads badly. |
| `src/emit/dto/registry.rs` | Which shapes and enums each operation drags in, so a shape emitted once is shared rather than duplicated. | A type is emitted twice, or is missing. |
| `src/emit/dto/render.rs` | The struct, enum and builder text itself, formatted to rustfmt's normal form so `cargo fmt` is a no-op over generated code. | Output no longer survives `cargo fmt --check`. |
| `src/emit/dto/shared.rs` | Helpers common to the dto emitters. | — |
| `src/emit/codec/mod.rs` | `generated/codec/ops/**` — one `impl OperationCodec` per operation, the module facade, the `response-*` table, and which shapes need a reader or a writer. A binding the codec surface has no form for is a **hard failure**, never a skipped member. | You are adding an operation family, or codegen refuses a member. |
| `src/emit/codec/decode.rs` | The request half: URI labels, headers, query, prefix headers, payloads and XML bodies, plus the per-shape readers. The error code for a missing member comes from `missing_error` in the overlay. | A request value is read wrongly, or a family needs a new missing-member code. |
| `src/emit/codec/encode.rs` | The response half: headers with their `omit_when` suppression, the XML body in `element_order` with its `empty_value_policy`, and the per-shape writers. | A response byte is wrong. |
| `src/emit/codec/bounds.rs` | Which integer bindings carry an inclusive range, resolved from the `bounded_range` quirks a field references. The two numbers live here because the frozen IR has nowhere to put them; *which* members are bounded is overlay data. | A bounded member needs adding, or codegen refuses a `bounded_range` quirk. |
| `src/emit/codec/forms.rs` | Which string bindings carry a wire form stricter than the type they are stored in — an entity tag, a server-minted cursor — resolved from the `wire_form` quirks a field references. The twin of `bounds.rs`, and here for the same reason: the frozen IR has no `pattern`. *Which* members have a form is overlay data. | A member's wire spelling needs checking, or codegen refuses a `wire_form` quirk. |
| `src/emit/codec/tolerance.rs` | Which bindings are read **tolerantly** — a value the specification says to ignore rather than refuse — resolved from the `header_tolerance` quirks a field references. The third twin of `bounds.rs` and `forms.rs`, and the one whose absence is invisible: a tolerance that fails to resolve leaves the member strict, which looks exactly like a decoder doing its job. | A header must be ignored rather than refused, or codegen refuses a `header_tolerance` quirk. |
| `src/emit/codec/expr.rs` | One IR type to one Rust expression, in each direction. Every conversion is a call into `rustfs-gateway-core`'s `codec::value`, never inline logic. | You are adding a scalar to the IR. |
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
