# overlays — the one hand-written protocol source

Everything below this directory is generated. Everything above it is read-only. This is the only
place a human or an agent may change wire behaviour.

```
model/s3.json          pinned, read-only, never edited
overlays/*.toml        hand-written; you edit here
        ↓  cargo xtask codegen
generated/ir/*.json    IR documents (do-not-read list)
spec/operations/*.toml field bindings
OPERATIONS.md          wire reverse index
generated/*.rs         route table, error-code index
```

Editing a generated file is a CI failure (`cargo xtask spec verify`), not a style question.

## operations.toml

- `include` — the operations that are generated.
- `[[deferred]]` — every other operation in the model, grouped, each group with a `reason`.
  Codegen **fails** on an operation that is in neither list, so an upstream addition is a build
  failure that needs a decision instead of silence.
- `[scalar]` — Smithy shape name to IR scalar. This is how `ETag`, `ObjectKey` and the opaque
  pagination tokens escape the generic `String`, without a per-field override at every use site.
- `[op.<Operation>]` — the decisions the model cannot make: route `precedence`, `auth_action`,
  body caps, `element_order`, `error_codes`, the hot/cold split, `quirk_refs`.
- `[[op.<Operation>.field]]` — one field: a type or binding override, a wire default, an
  `omit_when` rule, `quirks`, or (with `synthesize = true`) a field that has no model member
  behind it at all.
- `[shape.<Shape>]` and `[[shape.<Shape>.field]]` — the same for a nested body shape.

An entry naming a member the model does not have is a hard failure. A silently ignored typo would
quietly disable the rule it was carrying, which is the worst outcome for a hand-written file.

The grammar is a deliberate TOML subset: tables, arrays of tables, strings, integers, booleans and
arrays. No inline tables, no floats, no dates. If the parser rejects your entry, rewrite it in the
subset rather than widening the reader.

## aws-quirks.toml

One `[[quirk]]` per behaviour the model does not state.

```toml
[[quirk]]
id      = "q-etag-0020"          # q-<slug>-NNNN, allocated in discovery order
kind    = "etag_render"          # free-form category; new behaviour must not need a schema bump
target  = "Object.ETag"          # Operation, Shape, Shape.Member or Operation.Field
summary = "…"                    # your own sentence, at least 16 characters
cases   = ["c-etag-0011"]        # conformance cases that would fail if the quirk were flipped

  [[quirk.evidence]]
  kind    = "s3s-issue"          # aws-doc | smithy-spec | rfc | s3s-issue | s3s-pr | capture | observed
  ref     = "https://github.com/s3s-project/s3s/issues/632"
  summary = "…"                  # what the source establishes, in your own words
```

Rules, all enforced by codegen:

- at least one `evidence` entry and at least one `cases` entry per quirk;
- a quirk that nothing references is dead weight, and a reference to an undeclared quirk fails
  the run.

**Never paste upstream prose.** Behavioural facts are not copyrightable; the sentences describing
them are. Evidence is a link plus a sentence you wrote. This is ADR-0001, and it is also why
`git blame` is not the answer: squash-merges erase the trail, so the reason lives beside the rule.

Read it back with `cargo xtask why <quirk-id | operation | error-code | header | query-key>`.
