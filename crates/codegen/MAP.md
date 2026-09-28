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
| `src/emit/operations_json.rs` | `generated/OPERATIONS.json` — seven wire fields per operation and one reverse index per field, for a consumer that has wire evidence rather than an operation name. | A tool must reach an operation from a query key, a header, an error code or a precedence. |
| `src/emit/rust_files.rs` | `generated/routes.rs`, `generated/error_codes.rs`, and the macros crate's operation-name table; data only. | P4 wires the route table up, a row shape changes, or the handler macro rejects a standard operation. |
| `src/emit/error_status.rs` | `generated/error_status.rs` — every `ErrorCode` constant and the status lookup, rendered from `model/overlays/error-status.toml`, plus the wire-code to constant index generated call sites resolve through. | A code needs a status, or a call site must name a code. |
| `src/emit/dto/mod.rs` | `generated/dto/**` — one module per operation, plus flat aliases and the `field_counts.txt` ratchet. Owns the **ADR-0004 P2 gate**: a required member whose type has no `Default` fails the build rather than being quietly wrapped in an `Option`. | A dto's shape is wrong, or the P2 gate fires. |
| `src/emit/dto/naming.rs` | Operation and member names to Rust identifiers, keyword escaping included. | A generated name collides or reads badly. |
| `src/emit/dto/registry.rs` | Which shapes and enums each operation drags in, so a shape emitted once is shared rather than duplicated. | A type is emitted twice, or is missing. |
| `src/emit/dto/render.rs` | The struct, enum and builder text itself, formatted to rustfmt's normal form so `cargo fmt` is a no-op over generated code. | Output no longer survives `cargo fmt --check`. |
| `src/emit/dto/shared.rs` | Helpers common to the dto emitters. | — |
| `src/emit/seam/mod.rs` | `generated/dto/seam/**` — the migration seam's s3s conversions for every RustFS operation (rustfs/gateway#967), mounted by `rustfs-gateway-types::compat::s3s_0_17_0::generated`. | A seam member fails generation, or an operation joins the seam. |
| `src/emit/seam/expr.rs` | The (gateway IR type, s3s type) pairing table, each direction, and which nested shapes it reaches. | A pair is missing, or a leaf function changes. |
| `src/emit/seam/render.rs` | Member matching (same name, keyword escaping, checksum fan-out, runtime members, overrides), `Option`/container wrapping, file layout. | A generated line is wrong. |
| `src/emit/seam/overrides.rs` | Covered operations, hand-written ones, and every reviewed member exception with its reason. | Generation names an undecided member. |
| `src/emit/seam/facts.rs` + `s3s_0_17_0.facts` | The s3s DTO fact table (`scripts/extract_s3s_shapes.py`) and its parser. | RustFS moves to another s3s release. |
| `src/emit/seam/tests.rs` | Matching and wrapping rules, and that undecided members fail generation. | Changing the seam generator. |
| `src/emit/codec/mod.rs` | `generated/codec/ops/**` — one `impl OperationCodec` per operation, the module facade, the `response-*` table, and which shapes need a reader or a writer. A binding the codec surface has no form for is a **hard failure**, never a skipped member. | You are adding an operation family, or codegen refuses a member. |
| `src/emit/codec/decode.rs` | The request half: URI labels, headers, query, prefix headers, payloads and XML bodies, plus the per-shape readers. The error code for a missing member comes from `missing_error` in the overlay and is emitted as the `ErrorCode` constant, so a code with no status row fails the build instead of the request. | A request value is read wrongly, or a family needs a new missing-member code. |
| `src/emit/codec/decode/layout.rs` | Rustfmt-equivalent wrapping primitives for generated request decoders. | Decoder output drifts after formatting or crosses a line/chain width boundary. |
| `src/emit/codec/encode.rs` | The response half: headers with their `omit_when` suppression, the XML body in `element_order` with its `empty_value_policy`, and the per-shape writers. | A response byte is wrong. |
| `src/emit/codec/bounds.rs` | Resolves inclusive integer ranges from typed codec rules; free-text quirk kinds are not codec inputs. | A bounded member's typed current value is wrong. |
| `src/emit/codec/all_unknown.rs` | Resolves and emits a field-level guard for non-empty structure members whose children are all unknown. | Tolerant XML decoding would erase a written nested scope. |
| `src/emit/codec/boolean.rs` | Resolves field-level boolean spelling from typed codec rules, failing ambiguous operation-level attachments. | A boolean header's accepted spelling is wrong. |
| `src/emit/codec/name_policy.rs` | Finds input XML shapes containing object keys and renders the policy-bearing reader call and signature. | A body-carried object key does not use the deployment name policy, or a generated reader has the wrong signature. |
| `src/emit/codec/forms.rs` | Resolves string wire grammars from typed codec rules; free-text quirk kinds are not codec inputs. | A member's wire spelling is wrong. |
| `src/emit/codec/tolerance.rs` | Resolves tolerant header readings from typed codec rules; free-text quirk kinds are not codec inputs. | A header must be ignored rather than refused. |
| `src/emit/quirk_toml.rs` | Disjoint `spec/quirks/<id>.toml` mutable rules and `spec/contracts/<id>.toml` typed runtime contracts; deferred overlay facts are not emitted. | A mutation input is missing or a deferred fact leaked into a protected table. |
| `src/emit/runtime_contracts.rs` | `generated/contracts.rs` and `generated/signature_contracts.rs` — typed data constants selected by runtime contract rules. | A non-codec protocol rule must become the unique input to a core or signature runtime consumer. |
| `src/emit/naming_contracts.rs` | `generated/naming_contracts.rs` — typed data constants consumed by the ring-0 naming pipeline. | A naming contract must become the unique input to key or bucket materialisation. |
| `src/emit/range_contracts.rs` | `generated/range_contracts.rs` — typed data constants consumed by ring-0 byte-range parsing and resolution. | A range grammar or boundary contract must become a types-crate input. |
| `src/emit/upload_id_contracts.rs` | `generated/upload_id_contracts.rs` — private ownership-scope input consumed by the types upload-id exchange. | Upload-id resolution scope or its mechanical mutant changes. |
| `src/emit/runtime_contracts/precondition.rs` | Conditional/range half of `generated/contracts.rs`. | A precondition policy needs a new core runtime constant. |
| `src/emit/runtime_contracts/cors.rs` | Bucket-CORS half of `generated/contracts.rs`. | A CORS policy needs a core runtime constant. |
| `src/emit/runtime_contracts/select_restore.rs` | Select/restore half of `generated/contracts.rs`. | A SelectObjectContent or RestoreObject policy needs a core runtime constant. |
| `src/emit/codec/expr.rs` | One IR type to one Rust expression, in each direction. Every conversion is a call into `rustfs-gateway-core`'s `codec::value`, never inline logic. | You are adding a scalar to the IR. |
| `src/mutate.rs` | The one alternative value each mutation dimension admits, plus the quirk id to overlay family index the kill matrix selects by. | A rule's planned flip is wrong, or a dimension needs a planned mutation. |
| `src/mutate/apply.rs` | The writer for the mutation-source path grammar `emit/quirk_toml.rs` reads, refusing to write over a value the plan did not record. | A mutation must reach an IR field the writer has no arm for. |
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
cargo xtask conformance mutate --family <name>   # flip each mutable rule and report what caught it
```

## Things that will bite you

- **A golden difference is not a build failure.** `spec/ir/samples/*.json` is hand-written and can
  be the stale side; the run reports differences and exits zero. The gate that must stay green is
  `spec verify`.
- **The error-code → HTTP status table is generated, and it is the only one.** Until
  rustfs/backlog#1694 it was hand-written in `rustfs-gateway-types::ErrorCode` and this note said
  the opposite — on the grounds that a generated second copy could disagree with it. That was the
  right worry and the wrong conclusion: what a hand-written table could disagree with was the code
  set the IR already knew, and it did, for six codes that took a silent 400. There is now one
  input, `model/overlays/error-status.toml`, and `src/emit/error_status.rs` renders both the
  constants and the lookup from it. `generated/error_codes.rs` still carries the separate fact the
  status table cannot express: which operations produce a code.
- **`generated/*.rs` define no types.** They are `include!` fodder. A generated file that minted a
  public type name would put a name into the tree that `grep` cannot trace to a declaration.
- **Emitters must stay pure.** No clock, no host name, no `HashMap` iteration, no generator version
  string. `c_cg_0004_two_runs_produce_identical_bytes` is the guard, but the rule is the design.
- **`write` skips files whose bytes are unchanged**, so a no-op run does not churn mtimes.
