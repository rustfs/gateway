# overlays — the one hand-written protocol source

Everything below this directory is generated. Everything above it is read-only. This is the only
place a human or an agent may change wire behaviour.

```
model/s3.json          pinned, read-only, never edited
overlays/**.toml       hand-written; you edit here
        ↓  cargo xtask codegen
generated/ir/*.json    IR documents (do-not-read list)
generated/codec/**     per-operation decode/encode (do-not-read list)
spec/operations/*.toml field bindings
OPERATIONS.md          wire reverse index
generated/*.rs         route table, error-code index
```

Editing a generated file is a CI failure (`cargo xtask spec verify`), not a style question.

## Layout: one file per operation family

```
overlays/
  scalars.toml          the cross-family scalar vocabulary — the ONLY shared file
  ops/<family>.toml     include, [[deferred]], [op.<Operation>], [shape.<Shape>]
  quirks/<family>.toml  [[quirk]]
```

**A family file is the unit of parallel edit conflict.** That is the whole reason for the layout,
and it is the same reason `rustfs-gateway-core` puts one operation in one file: sixteen agents
landing sixteen operation families into one `operations.toml` conflict on every merge, and landing
them into sixteen `ops/<family>.toml` files conflict on none. Nobody ever failed to *find*
`GetObject`; what a single file costs is throughput, every time two families move at once.

The family name is the file stem, and it is also the directory-free half of the P5 task id — the
object data-plane family is `ops/object.toml` and `quirks/object.toml`. Claiming a family means
touching those two files and nothing else under `overlays/`.

Today's families:

| File | Operations |
|---|---|
| `ops/object.toml` | GetObject, HeadObject, PutObject, DeleteObject, DeleteObjects |
| `ops/list.toml` | ListObjectsV2, and the listings that land beside it |
| `ops/bucket.toml` | GetBucketLocation, and bucket lifecycle |
| `ops/object-copy.toml` | CopyObject, RenameObject |
| `ops/object-advanced.toml` | attributes, torrent, restore, select, encryption update |
| `ops/object-acl.toml` | object tagging, ACL, object lock |
| `ops/multipart.toml` | the multipart upload family |
| `ops/bucket-config.toml` | every bucket subresource configuration triple |
| `ops/bucket-policy.toml` | bucket policy and public access |
| `ops/excluded.toml` | the operations this gateway does not serve at all |

Create a new file when you claim a family no existing file covers. Nothing registers it: the
loader merges every `.toml` in `ops/` and every `.toml` in `quirks/`, in file-name order.

### What the split costs, and what pays for it

A single file made a duplicate impossible. Ten files do not, and a last-write-wins merge would
silently disable whichever rule lost — the worst outcome a hand-written file can have. So the
loader refuses every cross-file collision and **names both files**:

```
`GetObject` is declared as `[op.<Operation>]` by both `ops/object.toml` and `ops/object-copy.toml`;
one family owns it, and merging the two would silently drop whichever rule lost
```

Refused: one operation `include`d twice, deferred twice, included here and deferred there, declared
as `[op.X]` twice, one `[shape.X]` twice, one quirk id twice. Also refused: a family file carrying
`[scalar]`, and `scalars.toml` carrying anything else.

`scalars.toml` is deliberately *not* sharded. A shape name means the same thing whichever family
reads it, so two families holding two answers for `ETag` is not a merge to resolve — it is a
contradiction, and one file makes it impossible.

## ops/&lt;family&gt;.toml

- `include` — the operations of this family that are generated.
- `[[deferred]]` — the family's operations that are not generated yet, grouped, each group with a
  `reason`. Codegen **fails** on an operation that is in neither list anywhere, so an upstream
  addition is a build failure that needs a decision instead of silence.
- `[op.<Operation>]` — the decisions the model cannot make: route `precedence`, `auth_action`,
  body caps, `element_order`, `error_codes`, the hot/cold split, `quirk_refs`.
- `[[op.<Operation>.field]]` — one field: a type or binding override, a wire default, an
  `omit_when` rule, `quirks`, or (with `synthesize = true`) a field that has no model member
  behind it at all.
- `[shape.<Shape>]` and `[[shape.<Shape>.field]]` — the same for a nested body shape. A shape used
  by two families is declared by the family that owns its wire contract, once.

An entry naming a member the model does not have is a hard failure. A silently ignored typo would
quietly disable the rule it was carrying, which is the worst outcome for a hand-written file.

The grammar is a deliberate TOML subset: tables, arrays of tables, strings, integers, booleans and
arrays. No inline tables, no floats, no dates. If the parser rejects your entry, rewrite it in the
subset rather than widening the reader.

## scalars.toml

`[scalar]` alone: Smithy shape name to IR scalar. This is how `ETag`, `ObjectKey` and the opaque
pagination tokens escape the generic `String`, without a per-field override at every use site.

## quirks/&lt;family&gt;.toml

One `[[quirk]]` per behaviour the model does not state, in the file named after the family whose
operations it applies to.

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
  the run;
- the number in a quirk id is allocated globally, in discovery order. It is not per family, so
  two families never mint the same id — and the loader refuses it if they do.

**Never paste upstream prose.** Behavioural facts are not copyrightable; the sentences describing
them are. Evidence is a link plus a sentence you wrote. This is ADR-0001, and it is also why
`git blame` is not the answer: squash-merges erase the trail, so the reason lives beside the rule.

Read it back with `cargo xtask why <quirk-id | operation | error-code | header | query-key>`.
