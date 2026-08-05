#!/usr/bin/env python3
# Copyright 2026 Beijing Henghesha Technology Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Semantic diff between the pinned Smithy models and a candidate copy.

Responsible for: deciding whether an upstream model release changes anything a
server implementation can observe on the wire, and describing the change in
terms a reviewer can act on.

NOT responsible for: bumping the pin, generating code, or judging whether a
changed operation is in scope. Nothing here writes to the repository.

The point of this script is the *filter*, not the diff. AWS ships a model
release every 2-4 weeks and rewrites documentation prose in most of them. A
byte diff would therefore report a change every time, the weekly drift job
would file an issue every time, and within a quarter nobody would read them.
So the comparison runs over a projection of each model that keeps only
wire-affecting facts:

  * which operations exist, and their HTTP method / URI / status code
  * each structure member: target shape, optionality, default
  * HTTP bindings (label, query, header, prefix headers, payload, response code)
  * XML names and shapes (xmlName, xmlAttribute, xmlFlattened, xmlNamespace)
  * error shapes and per-operation error lists
  * enum and intEnum values

Explicitly ignored: `smithy.api#documentation` (1,870 occurrences in the S3
model), `smithy.api#examples`, `smithy.api#externalDocumentation`, and the
`smithy.rules#endpoint*` family, which are client-side endpoint resolution
rules that a server never evaluates. See model/PROVENANCE.md.

Traits that are in neither list are not silently dropped: they are reported in
a separate "unclassified" section so that a trait AWS invents next year cannot
slip through unnoticed. That section is advisory, never breaking.

Exit codes:
  0  no wire-affecting difference
  1  differences found
  2  usage or I/O error

Usage:
  python3 model/tools/drift.py --against <dir-with-s3.json-and-sts.json>
  python3 model/tools/drift.py --against <dir> --markdown drift.md
  python3 model/tools/drift.py --against <dir> --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_CURRENT = os.path.join(REPO_ROOT, "model")
MODELS = ("s3", "sts")

# Traits that change what bytes go on the wire, or whether a request is valid.
WIRE_TRAITS = frozenset(
    {
        # cardinality / defaults
        "smithy.api#required",
        "smithy.api#default",
        "smithy.api#clientOptional",
        "smithy.api#sparse",
        "smithy.api#addedDefault",
        # HTTP binding
        "smithy.api#http",
        "smithy.api#httpLabel",
        "smithy.api#httpQuery",
        "smithy.api#httpQueryParams",
        "smithy.api#httpHeader",
        "smithy.api#httpPrefixHeaders",
        "smithy.api#httpPayload",
        "smithy.api#httpResponseCode",
        "smithy.api#httpChecksumRequired",
        "smithy.api#httpError",
        "smithy.api#hostLabel",
        "smithy.api#endpoint",
        # XML shape
        "smithy.api#xmlName",
        "smithy.api#xmlAttribute",
        "smithy.api#xmlFlattened",
        "smithy.api#xmlNamespace",
        # payload semantics
        "smithy.api#streaming",
        "smithy.api#requiresLength",
        "smithy.api#mediaType",
        "smithy.api#timestampFormat",
        "smithy.api#enumValue",
        "smithy.api#enum",
        "smithy.api#error",
        "smithy.api#idempotencyToken",
        # validation that a server must enforce
        "smithy.api#length",
        "smithy.api#pattern",
        "smithy.api#range",
        "smithy.api#uniqueItems",
        # AWS protocol traits
        "aws.protocols#restXml",
        "aws.protocols#httpChecksum",
        "aws.api#service",
        "aws.auth#sigv4",
        "aws.auth#unsignedPayload",
        "aws.customizations#s3UnwrappedXmlOutput",
    }
)

# Traits deliberately dropped before comparison. Each one is either prose or a
# client-side concern; none of them changes a byte on the wire.
IGNORED_TRAITS = frozenset(
    {
        "smithy.api#documentation",
        "smithy.api#examples",
        "smithy.api#externalDocumentation",
        "smithy.api#title",
        "smithy.api#suppress",
        "smithy.api#tags",
        "smithy.api#since",
        "smithy.api#unstable",
        "smithy.api#internal",
        "smithy.api#recommended",
        "smithy.api#deprecated",
        "smithy.api#references",
        "smithy.api#paginated",
        "smithy.api#readonly",
        "smithy.api#idempotent",
        "smithy.api#auth",
        "smithy.api#optionalAuth",
        "smithy.rules#endpointRuleSet",
        "smithy.rules#endpointBdd",
        "smithy.rules#endpointTests",
        "smithy.rules#clientContextParams",
        "smithy.rules#staticContextParams",
        "smithy.rules#contextParam",
        "smithy.rules#operationContextParams",
        "smithy.waiters#waitable",
        "smithy.test#smokeTests",
        "smithy.test#httpRequestTests",
        "smithy.test#httpResponseTests",
    }
)


# --------------------------------------------------------------------------
# Projection
# --------------------------------------------------------------------------


def _split_traits(traits):
    """Return (wire traits, unclassified trait names)."""
    traits = traits or {}
    wire = {k: v for k, v in traits.items() if k in WIRE_TRAITS}
    unknown = sorted(k for k in traits if k not in WIRE_TRAITS and k not in IGNORED_TRAITS)
    return wire, unknown


def _target(node):
    if isinstance(node, dict):
        return node.get("target")
    return None


def _enum_values(shape):
    """Enum values for both Smithy 2.0 enum shapes and 1.0 string+enum trait."""
    stype = shape.get("type")
    if stype in ("enum", "intEnum"):
        values = []
        for name, member in (shape.get("members") or {}).items():
            trait = (member.get("traits") or {}).get("smithy.api#enumValue")
            values.append(str(trait) if trait is not None else name)
        return sorted(values)
    legacy = (shape.get("traits") or {}).get("smithy.api#enum")
    if isinstance(legacy, list):
        return sorted(str(e.get("value", e.get("name"))) for e in legacy)
    return None


def project(model):
    """Reduce a Smithy JSON AST to the facts a server can observe."""
    shapes = model.get("shapes") or {}
    projected = {}
    unknown_traits = {}

    for sid, shape in shapes.items():
        wire, unknown = _split_traits(shape.get("traits"))
        if unknown:
            unknown_traits[sid] = unknown

        entry = {"type": shape.get("type"), "traits": wire}

        members = {}
        for name, member in (shape.get("members") or {}).items():
            mwire, munknown = _split_traits(member.get("traits"))
            if munknown:
                unknown_traits[f"{sid}${name}"] = munknown
            members[name] = {"target": _target(member), "traits": mwire}
        if members:
            entry["members"] = members

        for key in ("member", "key", "value", "input", "output"):
            if key in shape:
                entry[key] = _target(shape[key])
        if "errors" in shape:
            entry["errors"] = sorted(filter(None, (_target(e) for e in shape["errors"])))
        if "operations" in shape:
            entry["operations"] = sorted(filter(None, (_target(o) for o in shape["operations"])))

        enum = _enum_values(shape)
        if enum is not None:
            entry["enum"] = enum

        projected[sid] = entry

    return {"shapes": projected, "unknown_traits": unknown_traits}


def _reachable(projected, roots):
    """Shape ids reachable from `roots`, so shapes that exist only because an
    operation was added are not reported as separate additions."""
    seen = set()
    stack = list(roots)
    while stack:
        sid = stack.pop()
        if sid in seen or sid not in projected:
            continue
        seen.add(sid)
        entry = projected[sid]
        for key in ("member", "key", "value", "input", "output"):
            if entry.get(key):
                stack.append(entry[key])
        for target in entry.get("errors", []):
            stack.append(target)
        for member in (entry.get("members") or {}).values():
            if member.get("target"):
                stack.append(member["target"])
    return seen


# --------------------------------------------------------------------------
# Diff
# --------------------------------------------------------------------------


class Change:
    __slots__ = ("category", "detail", "breaking", "shape")

    def __init__(self, category, detail, breaking=False, shape=None):
        self.category = category
        self.detail = detail
        self.breaking = breaking
        self.shape = shape

    def as_dict(self):
        return {
            "category": self.category,
            "detail": self.detail,
            "breaking": self.breaking,
            "shape": self.shape,
        }


class SemanticDiff:
    """Wire-affecting differences between two models, grouped for review."""

    ORDER = (
        "service",
        "operations",
        "http-binding",
        "members",
        "xml",
        "errors",
        "enums",
        "shapes",
        "unclassified",
    )

    def __init__(self, model_name):
        self.model_name = model_name
        self.changes = []
        self.impacted_operations = []

    def add(self, category, detail, breaking=False, shape=None):
        self.changes.append(Change(category, detail, breaking, shape))

    def is_empty(self):
        return not self.changes

    def breaking(self):
        return [c for c in self.changes if c.breaking]

    def changed_shapes(self):
        return {c.shape for c in self.changes if c.shape}

    def as_dict(self):
        return {
            "model": self.model_name,
            "changes": [c.as_dict() for c in self.changes],
            "impacted_operations": self.impacted_operations,
        }

    def render_markdown(self):
        if self.is_empty():
            return f"### `{self.model_name}`\n\nNo wire-affecting change.\n"
        lines = [f"### `{self.model_name}`", ""]
        breaking = self.breaking()
        lines.append(
            f"{len(self.changes)} wire-affecting change(s), {len(breaking)} of them breaking."
        )
        lines.append("")
        seen = set()
        for category in list(self.ORDER) + sorted({c.category for c in self.changes}):
            if category in seen:
                continue
            seen.add(category)
            items = [c for c in self.changes if c.category == category]
            if not items:
                continue
            lines.append(f"**{category}**")
            lines.append("")
            for change in items:
                mark = "**BREAKING** " if change.breaking else ""
                lines.append(f"- {mark}{change.detail}")
            lines.append("")
        if self.impacted_operations:
            lines.append(f"**impacted operations ({len(self.impacted_operations)})**")
            lines.append("")
            for op in self.impacted_operations:
                lines.append(f"- `{op}` -> `spec/operations/{op.split('#')[-1]}.toml`")
            lines.append("")
        return "\n".join(lines) + "\n"


def _fmt(value):
    if isinstance(value, (dict, list)):
        return f"`{json.dumps(value, sort_keys=True, separators=(',', ':'))}`"
    return f"`{value}`"


HTTP_TRAITS = {
    "smithy.api#http",
    "smithy.api#httpLabel",
    "smithy.api#httpQuery",
    "smithy.api#httpQueryParams",
    "smithy.api#httpHeader",
    "smithy.api#httpPrefixHeaders",
    "smithy.api#httpPayload",
    "smithy.api#httpResponseCode",
    "smithy.api#httpError",
    "smithy.api#httpChecksumRequired",
    "smithy.api#hostLabel",
}
XML_TRAITS = {
    "smithy.api#xmlName",
    "smithy.api#xmlAttribute",
    "smithy.api#xmlFlattened",
    "smithy.api#xmlNamespace",
}


def _trait_category(name):
    if name in HTTP_TRAITS:
        return "http-binding"
    if name in XML_TRAITS:
        return "xml"
    return "members"


def _diff_traits(diff, shape, owner, current, candidate):
    """Compare two wire-trait maps. Any change to a binding or an XML name is
    breaking: it moves bytes, so a client that worked stops working."""
    for name in sorted(set(current) | set(candidate)):
        before, after = current.get(name), candidate.get(name)
        if before == after:
            continue
        category = _trait_category(name)
        short = name.split("#", 1)[-1]

        if name == "smithy.api#required":
            if after is not None:
                diff.add("members", f"{owner}: optional -> required", True, shape)
            else:
                diff.add("members", f"{owner}: required -> optional", shape=shape)
            continue

        if before is None:
            breaking = category in ("http-binding", "xml")
            diff.add(category, f"{owner}: gained `{short}` = {_fmt(after)}", breaking, shape)
        elif after is None:
            diff.add(category, f"{owner}: lost `{short}` (was {_fmt(before)})", True, shape)
        else:
            diff.add(category, f"{owner}: `{short}` {_fmt(before)} -> {_fmt(after)}", True, shape)


def diff_models(model_name, current_model, candidate_model):
    diff = SemanticDiff(model_name)
    cur = project(current_model)
    cand = project(candidate_model)
    cur_shapes, cand_shapes = cur["shapes"], cand["shapes"]

    cur_ops = {s for s, e in cur_shapes.items() if e["type"] == "operation"}
    cand_ops = {s for s, e in cand_shapes.items() if e["type"] == "operation"}

    for sid in sorted(cand_ops - cur_ops):
        diff.add("operations", f"operation added: `{sid}`", shape=sid)
    for sid in sorted(cur_ops - cand_ops):
        diff.add("operations", f"operation removed: `{sid}`", True, sid)

    # Shapes that exist only to support an added/removed operation are not
    # independent news; fold them into the operation entry above.
    added_only = _reachable(cand_shapes, cand_ops - cur_ops)
    removed_only = _reachable(cur_shapes, cur_ops - cand_ops)

    for sid in sorted(set(cand_shapes) - set(cur_shapes) - added_only):
        diff.add("shapes", f"shape added: `{sid}` ({cand_shapes[sid]['type']})", shape=sid)
    for sid in sorted(set(cur_shapes) - set(cand_shapes) - removed_only):
        entry = cur_shapes[sid]
        category = "errors" if "smithy.api#error" in entry["traits"] else "shapes"
        diff.add(category, f"shape removed: `{sid}` ({entry['type']})", True, sid)

    for sid in sorted(set(cur_shapes) & set(cand_shapes)):
        a, b = cur_shapes[sid], cand_shapes[sid]

        if a["type"] != b["type"]:
            diff.add("shapes", f"`{sid}`: type `{a['type']}` -> `{b['type']}`", True, sid)

        _diff_traits(diff, sid, f"`{sid}`", a["traits"], b["traits"])

        for key in ("member", "key", "value", "input", "output"):
            if a.get(key) != b.get(key):
                diff.add(
                    "members", f"`{sid}`.{key}: {_fmt(a.get(key))} -> {_fmt(b.get(key))}", True, sid
                )

        a_errors, b_errors = set(a.get("errors") or []), set(b.get("errors") or [])
        for e in sorted(b_errors - a_errors):
            diff.add("errors", f"`{sid}`: error added `{e}`", shape=sid)
        for e in sorted(a_errors - b_errors):
            diff.add("errors", f"`{sid}`: error removed `{e}`", True, sid)

        a_enum, b_enum = a.get("enum"), b.get("enum")
        if a_enum is not None or b_enum is not None:
            a_enum, b_enum = set(a_enum or []), set(b_enum or [])
            for v in sorted(b_enum - a_enum):
                diff.add("enums", f"`{sid}`: value added `{v}`", shape=sid)
            for v in sorted(a_enum - b_enum):
                diff.add("enums", f"`{sid}`: value removed `{v}`", True, sid)

        a_mem = a.get("members") or {}
        b_mem = b.get("members") or {}
        if a["type"] in ("enum", "intEnum") and b["type"] in ("enum", "intEnum"):
            continue  # enum members are covered by the value diff above
        for name in sorted(set(b_mem) - set(a_mem)):
            required = "smithy.api#required" in b_mem[name]["traits"]
            diff.add(
                "members",
                f"`{sid}`.`{name}` added -> `{b_mem[name]['target']}`"
                + (" (required)" if required else " (optional)"),
                required,
                sid,
            )
        for name in sorted(set(a_mem) - set(b_mem)):
            diff.add("members", f"`{sid}`.`{name}` removed", True, sid)
        for name in sorted(set(a_mem) & set(b_mem)):
            ma, mb = a_mem[name], b_mem[name]
            if ma["target"] != mb["target"]:
                diff.add(
                    "members",
                    f"`{sid}`.`{name}`: target `{ma['target']}` -> `{mb['target']}`",
                    True,
                    sid,
                )
            _diff_traits(diff, sid, f"`{sid}`.`{name}`", ma["traits"], mb["traits"])

    # Advisory: traits we neither compare nor knowingly ignore.
    cur_unknown = {k: set(v) for k, v in cur["unknown_traits"].items()}
    cand_unknown = {k: set(v) for k, v in cand["unknown_traits"].items()}
    appeared = {}
    for owner, names in cand_unknown.items():
        new = names - cur_unknown.get(owner, set())
        for name in new:
            appeared.setdefault(name, 0)
            appeared[name] += 1
    for name, count in sorted(appeared.items()):
        diff.add(
            "unclassified",
            f"trait `{name}` appears on {count} shape(s) and is neither compared nor "
            f"ignored - classify it in model/tools/drift.py",
        )

    # Attribution: an operation is impacted when any shape in its closure moved.
    # This is what turns a shape-level diff into a review assignment.
    changed = diff.changed_shapes()
    if changed:
        impacted = set()
        for ops, shapes_map in ((cand_ops, cand_shapes), (cur_ops, cur_shapes)):
            for op in ops:
                if _reachable(shapes_map, [op]) & changed:
                    impacted.add(op)
        diff.impacted_operations = sorted(impacted)

    return diff


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _load(path, name):
    candidates = [path] if os.path.isfile(path) else [os.path.join(path, f"{name}.json")]
    for candidate in candidates:
        if os.path.isfile(candidate):
            with open(candidate, "r", encoding="utf-8") as handle:
                return json.load(handle)
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--against",
        required=True,
        help="directory holding the candidate s3.json / sts.json (or a single json file)",
    )
    parser.add_argument("--current", default=DEFAULT_CURRENT, help="pinned model directory")
    parser.add_argument("--model", choices=MODELS, help="compare only this model")
    parser.add_argument("--markdown", help="write the rendered report to this path")
    parser.add_argument("--json", action="store_true", help="print machine-readable output")
    args = parser.parse_args(argv)

    names = [args.model] if args.model else list(MODELS)
    diffs = []
    for name in names:
        current = _load(args.current, name)
        candidate = _load(args.against, name)
        if current is None:
            print(f"error: no pinned {name} model under {args.current}", file=sys.stderr)
            return 2
        if candidate is None:
            print(f"error: no candidate {name} model under {args.against}", file=sys.stderr)
            return 2
        diffs.append(diff_models(name, current, candidate))

    total = sum(len(d.changes) for d in diffs)
    breaking = sum(len(d.breaking()) for d in diffs)

    header = [
        "## Semantic model diff",
        "",
        "Compared the pinned models in `model/` against the candidate release.",
        "",
        f"- wire-affecting changes: **{total}**",
        f"- breaking: **{breaking}**",
        "",
        "Ignored by design: documentation prose and the `smithy.rules#endpoint*` "
        "client-side resolution traits. See `model/PROVENANCE.md`.",
        "",
    ]
    report = "\n".join(header) + "\n".join(d.render_markdown() for d in diffs)

    if args.json:
        print(json.dumps({"total": total, "breaking": breaking, "models": [d.as_dict() for d in diffs]}, indent=2))
    else:
        if total == 0:
            print("semantic diff is empty (documentation-only changes ignored)")
        else:
            print(report)

    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as handle:
            handle.write(report)

    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
