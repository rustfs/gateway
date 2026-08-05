# `spec/` — the operation IR

## Single source of truth

```
model/s3.json           pinned upstream Smithy model. Read-only, protected, never hand-edited.
model/overlays/*.toml   THE ONLY HAND-WRITTEN SOURCE. Every protocol exception lives here,
                        each with an `id`, a `target`, `evidence[]` and `cases[]`.
        |
        |  cargo xtask codegen     (P1-03; strips smithy.api#documentation and the
        |                           smithy.rules#endpoint* client traits first)
        v
   IR   spec/ir/*.json            one JSON document per operation, shape frozen by ir.schema.json
        |
        +--> spec/operations/*.toml     generated, read-only
        +--> OPERATIONS.md              generated, read-only (wire-level reverse index)
        +--> generated/**               generated, read-only
```

Everything below the arrow is a build product. To change wire behaviour you change an
overlay entry and re-run codegen; editing a generated file fails CI. `xtask spec verify`
asserts a zero diff, which is what stops the "same rule written in two places" failure
mode from reappearing at the governance layer.

`spec/ir/samples/*.json` are the one exception: they are **hand-written goldens**.
P1-03 is correct when its generated IR matches them byte for byte. They are inputs to
codegen review, not outputs of codegen.

## What this schema freezes

`spec/ir.schema.json` (draft 2020-12, `ir_version: "1"`) is the output contract of
codegen and the input contract of every backend that consumes it: DTOs, codecs, the
route table, `OPERATIONS.md`, the error-code table, the conformance skeleton. No backend
reads the Smithy AST again.

Top level, all keys required: `ir_version`, `operation`, `http`, `auth`, `payload`,
`checksum`, `input`, `output`, `shapes`, `xml`, `errors`, `derived_resources`,
`head_mirrors`, `quirk_refs`, `quirks`, `ext_points`.

Three rules do the load-bearing work:

1. **`additionalProperties: false` on every object** (60 object nodes, zero exceptions).
   A leaked `smithy.api#documentation` trait fails validation instead of quietly entering
   the wire contract and drowning every future `grep`.
2. **No defaults on anything that renders.** `Timestamp` must state its `format`, `ETag`
   must state its `render` (`HeaderQuoted` / `XmlQuoted` / `XmlBare`), a `List` must state
   `flattened` and `wrapper_name`. A rendering context that can be inferred is a rendering
   context that will be inferred wrongly.
3. **Routing and parameter validation are separate.** `http.predicates` decides *which*
   operation a request is; it is an ordered first-match table, not a disjoint partition, so
   `precedence` is explicit and `?acl&tagging` matching two selectors is normal. A merely
   mandatory parameter (`?analytics` requires `id`) is `input.fields[].required` plus
   `missing_error`, so omitting it is a 400, never a 501.

Two conventions keep generated documents stable: keys whose value is the neutral one
(`default`, `omit_when`, `missing_error`) are emitted only when meaningful, and everything
else is always emitted. Map-valued fields (`empty_value_policy`, `shapes`) are emitted in
sorted key order.

### Checks the schema cannot express

These belong in `xtask ir validate` (`validate_semantics`), and each diagnostic carries
what failed / where (JSON Pointer) / which rule (schema path or quirk id):
`quirks[].id` is exactly the union of every `quirk_refs`; at most one `Payload` binding;
a key is never both `QueryPresent` and `QueryAbsent`; `xml.element_order` covers exactly
the `BodyXml` output members (and is empty when `unwrapped_output` is true, because then
the single member *is* the root); each shape's `element_order` covers exactly its own
`BodyXml` members; every referenced shape exists; `head_mirrors` names a real operation;
`quirk_refs` resolve against `model/overlays/*.toml`.

### Shared id conventions

`quirk_id` and `case_id` use the same patterns as `conformance/case.schema.json`
(`^q-…-NNNN$`, `^c-…-NNNN$`) so that the two directions of the reference close: a quirk
names the cases that would fail if it were flipped, and each case names the quirks it
exercises. The mutation gate builds its coverage matrix from that pair, and a quirk no case
references fails CI.

**Open question for review:** `conformance/case.schema.json` describes quirk ids as coming
from `spec/quirks/*.toml`, while the Epic, this file and P1-03 place the only hand-written
source at `model/overlays/*.toml` — and anything under `spec/` is a generated artifact. One
of the two must move before P1-03 wires up `check_quirks_evidence.sh`.

### `shapes` — the one addition beyond the task sketch

Nested structures need element order, empty-value policy, XML attributes and per-member
rendering just as much as top-level members do (`Object.ETag` is `XmlQuoted` while
`GetObjectAttributes` needs `XmlBare`), so `Structure{shape}` references have to resolve
somewhere. They resolve inside the same document: `shapes` carries every reachable shape.
This denormalizes shape definitions across operation files on purpose — an IR document is
self-contained, no consumer needs a second file, and divergence is impossible because
every copy comes from one codegen run.

## Dialect extension points (`ext_points`)

The P1-08 spike has not reported yet, so the schema deliberately expresses **both**
possible outcomes and codegen picks one:

- `strategy: "ExtField"` — the spike succeeded. One generated codec plus a runtime vtable;
  `cfg_feature` must be `null`. Axiom A5 (generated code stays minimal and diffable) holds.
- `strategy: "GeneratedVariant"` — the spike failed. A second generated codec behind
  `cfg_feature`, i.e. generated code doubles for that dialect, exactly as upstream's
  39k-line `generated_minio.rs`. A5 is dead and the Epic's axiom table needs revision.

Everything else about an extension point (`parent_shape`, `local_name`, `dialect`,
`position: AfterKnownFields`, `unknown_policy`) is identical under both outcomes, so the
spike's verdict changes one enum value and a feature name, not the IR shape. If the verdict
requires anything more than that, it is a schema change — see below.

## Freeze and change process

This file is frozen as of the `IR-FREEZE: approved` review on the P1-01 issue and enters
`AGENTS.md` protected-files. From then on:

- **Adding an optional key, or a value to an open enum** (`quirk.kind` is a pattern, not an
  enum, precisely so new AWS behaviour never needs this): PR touching `spec/ir.schema.json`,
  one reviewer, samples regenerated, `ir_version` unchanged.
- **Any change that invalidates an existing document** — removing a key, tightening a
  constraint, adding a required key, adding a variant to `predicate` / `binding` / `type`:
  bump `ir_version` and repeat the freeze review. Every consumer between P2 and P10 reads
  this shape; a silent breaking change is a project-wide rebuild.
- If an AWS behaviour turns out to be inexpressible, do **not** work around it in codegen.
  Record it on the P1-01 issue and either extend the schema or write it into that issue's
  scope fence.

## Samples

| File | Exercises |
|---|---|
| `spec/ir/samples/GetBucketLocation.json` | unwrapped output (the member *is* the root), `empty_value_policy: emit` for the null us-east-1 constraint, `StringEnum` with a legacy alias, subresource routing by `QueryPresent` |
| `spec/ir/samples/PutObject.json` | streaming `Payload` blob, `PrefixHeaders` (`x-amz-meta-`, packed `ChecksumSpec`), `OpaqueString` for `Expires`, `ETag{HeaderQuoted}`, `Timestamp{Iso8601}` on the one header that uses it, `missing_error: MissingContentLength`, secret-hygiene quirk on the SSE-C group |
| `spec/ir/samples/ListObjectsV2.json` | `QueryEquals("list-type","2")`, flattened lists, nested `shapes` with their own element order, `element_order` as a wire contract, `url_encoded_fields` with dotted paths, `omit_when: RequestField` for `Owner`, `default` values, opaque pagination tokens |

Enum value lists, field sets and sibling orders in the samples are transcribed by hand from
the AWS API reference. They are the golden that P1-03 must reproduce, so the first codegen
run is also the first reconciliation against the pinned model: where they disagree, the
pinned model plus a recorded capture wins and the golden is corrected in the same PR.
