# MAP — rustfs-gateway-model

Agent entry point. File → responsibility → when you need to open it.

Build-time only. Nothing here ever appears in a runtime dependency tree.

```
model/s3.json ──strip──▶ smithy::Model ──┐
                                         ├──▶ lower::lower ──▶ ir::OperationIr ──▶ rustfs-gateway-codegen
overlays/scalars.toml   ──┐
overlays/ops/*.toml     ──┼▶ overlay::Overlay ────┘
overlays/quirks/*.toml  ──┘
```

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Crate docs, module wiring, the re-export list. | You need to know what this crate exposes. |
| `src/error.rs` | The one error type. Every failure names a file, a line, or an operation. | A codegen failure message is unclear and you want to know who raised it. |
| `src/json.rs` | Hand-written JSON reader plus the canonical writer (two-space indent, flat when it fits in 120 columns, one trailing newline). | An IR document's layout changed, or you are adding a value kind. |
| `src/toml_lite.rs` | The overlay TOML subset: tables, arrays of tables, strings, integers, booleans, arrays. Everything else is a parse error on purpose. | An overlay entry is rejected and you want to know whether the grammar or the entry is wrong. |
| `src/smithy.rs` | Loads the pinned Smithy 2.0 AST and **deletes the documentation and client-endpoint traits before anything else sees a shape**. Shape, member, trait and enum lookups. | You need a model fact, or you are checking that a trait really cannot leak. |
| `src/overlay.rs` | The hand-written source, **merged from one file per operation family**: whitelist, deferred groups, scalar map, per-operation and per-shape overrides, quirk records. Self-consistency checks and every cross-file collision refusal live here. | Adding an overlay key, a quirk is rejected, or a load failed naming two family files. |
| `src/ir/mod.rs` | The IR document structure — one type per construct in `spec/ir.schema.json`. Also the quirk ordering rule and the query-key/header reverse lookups. | You are adding an IR construct, or you want to know what the IR can express. |
| `src/ir/types.rs` | The scalar and composite type vocabulary: `Type`, timestamp and entity-tag rendering, `OmitWhen`. Nothing here has a default rendering. | You are binding a field and need to know which types exist. |
| `src/ir/emit.rs` | IR → JSON value, in the schema's key order. | A generated IR document's key order looks wrong. |
| `src/lower/mod.rs` | The derivation rules that need the model, the overlay and the route at once: uri → route and target, member traits → binding and wire name, shape kinds → IR types, and the overlay-target checks. | Any question of the form "why did codegen decide *that*?" |
| `src/lower/support.rs` | The self-contained half: uri parsing, payload discipline, empty-value policy, XML root, checksum algorithms, error-code union, and the `validate` pass. | A derived default is wrong, or an IR rule rejected your operation. |
| `src/tests/` | Parser tests, and lowering tests against a miniature model rather than the 3 MB pinned one. | You changed a rule and want the fastest possible red. |

## The division of authority (the rule to keep)

**Structure comes from the model. Decisions come from the overlay.**

| From the pinned Smithy source | From `overlays/` |
|---|---|
| method, uri, labels, query literals | route `precedence`, extra predicates |
| member bindings, wire names, enum values | IAM action, presigned policy |
| list flattening, wrapper names, timestamp formats | hot/cold split, body caps |
| XML root names (`xmlName`), `s3UnwrappedXmlOutput` | element order, empty-value overrides, url-encoded members |
| declared error shapes | the full error-code set, `not_configured` |

Where the model has no opinion and the overlay is silent, lowering **stops**. Missing route
precedence and missing IAM action are hard failures, not defaults.

## The overlay is a directory, and a collision is fatal

One file per operation family — `ops/<family>.toml` and `quirks/<family>.toml` — because a family
file is the unit of parallel edit conflict. The cost is that two families can both claim one
operation, so the loader refuses every cross-file collision and names **both** files: an operation
included twice, deferred twice, included here and deferred there, an `[op.X]` or `[shape.X]`
declared twice, or one quirk id declared twice. `scalars.toml` is the single cross-family file and
may hold nothing but `[scalar]`.

## Things that will bite you

- **Header wire names are lowercased.** The model spells them `Content-Length`; the IR stores
  `content-length`, so the `OPERATIONS.md` header index is a set of names, not of spellings.
- **`x-id` is dropped from route predicates.** It is an AWS SDK cache-busting query key with no
  server-side meaning.
- **`empty_value_policy` defaults to "required emits, optional omits".** Every deviation is a
  quirk with evidence — that is what `q-empty-*` records exist for.
- **The IR's checksum algorithm set is closed and the model's is not.** The pinned model already
  carries SHA512, MD5 and three XXHASH variants; `ChecksumAlgo::parse` filters them out of
  `checksum.request_algorithms` and they survive only inside a `StringEnum`. Widening the IR is an
  IR-FREEZE decision.
- **Field order in `input`/`output` is model declaration order** and carries no wire meaning. The
  wire order is `xml.element_order`, which is a separate, overlay-owned list.
- **No serde.** The workspace dependency set is pinned and has none; `json.rs` and `toml_lite.rs`
  are why. Do not add a dependency to avoid writing five lines of parsing.
