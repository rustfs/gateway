#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_error_codes_json_fields.sh
#
# WHAT THIS CHECKS
#   That the two published renderings of the error-code authority are usable
#   documents rather than merely present ones. Five properties:
#
#     1. Three fields — every code entry of `generated/error_codes.json`
#        carries `constant`, `status` and `server_fault`, in that order, and
#        nothing else. The field set is read out of the emitter's
#        `JSON_FIELDS` declaration as well, so a field dropped from the
#        producer is not a rename this guard follows silently.
#     2. Three indexes — one reverse index per field, named by `JSON_INDEXES`.
#     3. Both directions — each index is exactly the inverse of the forward
#        table. Every forward fact appears under its key, AND every code an
#        index lists is backed by that code's own entry.
#     4. Same codes as `generated/ERROR_CODES.md`, with the same status and the
#        same constant. Two renderings of one input that name different codes
#        are two answers, and a reader has no way to tell which one the runtime
#        took.
#     5. `by_server_fault["true"]` is exactly the set of codes in the 5xx band,
#        in both directions. That set is the whole contract an SDK acts on: it
#        retries those and opens a circuit breaker on them.
#
# WHY
#   rustfs/backlog#1694. `cargo xtask spec verify` proves each file equals what
#   the emitter emits; it cannot notice that the emitter stopped emitting a
#   field, inverted an index off the wrong one, or let the two renderings
#   disagree. A document that answers every question it is asked except the one
#   it was built for looks green from every other angle.
#
#   Property 3's second direction is the one that matters. An index that keeps
#   a code after the fact that put it there was deleted still looks like an
#   index, and a check that only walked forward would pass over it.
#
# HOW TO EXEMPT
#   Not applicable. Both files are generated: change
#   `model/overlays/error-status.toml` or the emitter in
#   `crates/codegen/src/emit/error_status.rs` and run `cargo xtask codegen`.
#
# USAGE
#   scripts/check_error_codes_json_fields.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_error_codes_json_fields.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
cd "$ROOT_DIR"

INDEX="generated/error_codes.json"
MARKDOWN="generated/ERROR_CODES.md"
EMITTER="crates/codegen/src/emit/error_status.rs"

command -v python3 >/dev/null 2>&1 || {
    printf 'check_error_codes_json_fields.sh: required command is missing: python3\n' >&2
    exit 1
}

# Deliberately not `|| exit 0`. All three inputs are produced by every codegen
# run and exist in every checkout, so an absent one means this guard is running
# where it cannot see what it checks — and a check that reports success without
# checking anything is indistinguishable from one that passed.
for input in "$INDEX" "$MARKDOWN" "$EMITTER"; do
    if [[ ! -f "$input" ]]; then
        printf 'check_error_codes_json_fields.sh: cannot read %s — refusing to report success without checking\n' \
            "$input" >&2
        exit 1
    fi
done

python3 - "$INDEX" "$MARKDOWN" "$EMITTER" <<'PYEOF'
import json
import pathlib
import re
import sys

index_path, markdown_path, emitter_path = (pathlib.Path(a) for a in sys.argv[1:4])

status = 0


def bad(message):
    global status
    status = 1
    print(f"check_error_codes_json_fields: {message}", file=sys.stderr)


FIELDS = ["constant", "status", "server_fault"]
INDEXES = {"constant": "by_constant", "status": "by_status", "server_fault": "by_server_fault"}

try:
    document = json.loads(index_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    print(f"check_error_codes_json_fields: {index_path}: {error}", file=sys.stderr)
    raise SystemExit(1)

emitter_text = emitter_path.read_text(encoding="utf-8")
for label, declaration, expected in (
    ("JSON_FIELDS", r"pub const JSON_FIELDS: \[&str; (\d+)\] = \[(.*?)\];", FIELDS),
    ("JSON_INDEXES", r"pub const JSON_INDEXES: \[&str; (\d+)\] = \[(.*?)\];", [INDEXES[f] for f in FIELDS]),
):
    declared = re.search(declaration, emitter_text, re.S)
    if declared is None:
        bad(f"{emitter_path}: no `{label}` declaration; the field set has no source")
        continue
    names = re.findall(r'"([^"]+)"', declared.group(2))
    if int(declared.group(1)) != len(expected) or names != expected:
        bad(f"{emitter_path}: declares {label} {names}; this guard and the document require {expected}")

codes = document.get("codes")
if not isinstance(codes, dict) or not codes:
    bad(f"{index_path}: no `codes` table; the reverse index has nothing to point at")
    raise SystemExit(status or 1)

if not isinstance(document.get("generated_by"), str):
    bad(f"{index_path}: carries no `generated_by`; a generated file must say it is one")

# ------------------------------------------------------- 1. three fields, in order
for name, entry in sorted(codes.items()):
    if not isinstance(entry, dict):
        bad(f"{index_path}: entry for {name} is not an object")
        continue
    present = list(entry.keys())
    if present != FIELDS:
        missing = [field for field in FIELDS if field not in present]
        extra = [field for field in present if field not in FIELDS]
        detail = []
        if missing:
            detail.append(f"missing {missing}")
        if extra:
            detail.append(f"undeclared {extra}")
        if not detail:
            detail.append(f"out of order: {present}")
        bad(f"{index_path}: {name} carries the wrong fields — {', '.join(detail)}")
    if "constant" in entry and not isinstance(entry["constant"], str):
        bad(f"{index_path}: {name}.constant is not a string")
    if "status" in entry and not isinstance(entry["status"], int):
        bad(f"{index_path}: {name}.status is not an integer")
    if "server_fault" in entry and not isinstance(entry["server_fault"], bool):
        bad(f"{index_path}: {name}.server_fault is not a boolean")

# ------------------------------------------------------------- 2. three indexes
for field, index_name in INDEXES.items():
    if not isinstance(document.get(index_name), dict):
        bad(f"{index_path}: no `{index_name}` object; the `{field}` field cannot be entered by value")

if status:
    raise SystemExit(status)

# --------------------------------------------------------------- 3. both directions
for field, index_name in INDEXES.items():
    reverse = document[index_name]
    expected = {}
    for name, entry in codes.items():
        expected.setdefault(str(entry[field]).lower() if field == "server_fault" else str(entry[field]), []).append(name)
    for key in expected:
        expected[key] = sorted(set(expected[key]))

    for key, names in sorted(expected.items()):
        listed = reverse.get(key)
        if listed is None:
            bad(f"{index_path}: {index_name} has no entry for {key!r}, named by {names}")
            continue
        for name in names:
            if name not in listed:
                bad(f"{index_path}: {name} carries {field} {key!r} but {index_name}[{key!r}] omits it")
    for key, listed in sorted(reverse.items()):
        if not isinstance(listed, list):
            bad(f"{index_path}: {index_name}[{key!r}] is not a list")
            continue
        for name in listed:
            entry = codes.get(name)
            if entry is None:
                bad(f"{index_path}: {index_name}[{key!r}] names {name}, which has no entry")
                continue
            own = str(entry[field]).lower() if field == "server_fault" else str(entry[field])
            if key != own:
                bad(
                    f"{index_path}: {index_name}[{key!r}] names {name}, whose {field} is {own!r} — "
                    "a stale index outlives the fact that built it"
                )

# ------------------------------------- 4. the same codes as the Markdown, with the same values
markdown = markdown_path.read_text(encoding="utf-8")
section = markdown.split("## Every code", 1)
rendered = {}
if len(section) > 1:
    for name, code_status, constant in re.findall(
        r"^\| `(\w+)` \| (\d+) \| `ErrorCode::(\w+)` \|", section[-1], re.M
    ):
        rendered[name] = (int(code_status), constant)
if not rendered:
    bad(f"{markdown_path}: no code rows found under `## Every code`; the comparison would be vacuous")
else:
    for name in sorted(set(rendered) - set(codes)):
        bad(f"{index_path}: {name} is in {markdown_path} but has no entry; run `cargo xtask codegen`")
    for name in sorted(set(codes) - set(rendered)):
        bad(f"{index_path}: {name} has an entry but is absent from {markdown_path}")
    for name in sorted(set(rendered) & set(codes)):
        entry = codes[name]
        if (entry["status"], entry["constant"]) != rendered[name]:
            bad(
                f"{name}: {markdown_path} renders {rendered[name]} and {index_path} carries "
                f"({entry['status']}, {entry['constant']!r}); two renderings of one row disagree"
            )

# ----------------------------------------------------- 5. the 5xx allowlist, in both directions
faulted = {name for name, entry in codes.items() if entry["server_fault"]}
in_band = {name for name, entry in codes.items() if entry["status"] >= 500}
for name in sorted(in_band - faulted):
    bad(f"{name} is answered {codes[name]['status']} but is not flagged `server_fault`")
for name in sorted(faulted - in_band):
    bad(f"{name} is flagged `server_fault` but is answered {codes[name]['status']}")
listed = document["by_server_fault"].get("true", [])
if sorted(listed) != sorted(faulted):
    bad(
        f"by_server_fault['true'] lists {sorted(listed)} and the entries flag {sorted(faulted)}; "
        "that list is the set an SDK retries, so it may not be approximate"
    )

sys.exit(status)
PYEOF
