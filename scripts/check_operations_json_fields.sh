#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_operations_json_fields.sh
#
# WHAT THIS CHECKS
#   That `generated/OPERATIONS.json` is a usable wire reverse index. Four
#   properties:
#
#     1. Seven fields — every operation entry carries `method`, `path_shape`,
#        `query_keys`, `key_headers`, `host_classes`, `error_codes` and
#        `precedence`, in that order, and nothing else. Missing one is a
#        failure; so is an eighth nobody declared.
#     2. Seven indexes — one reverse index per field, so every fact a failing
#        request hands you is a key you can enter the document by.
#     3. Both directions — each index is exactly the inverse of the forward
#        table. Every forward fact appears under its key, AND every name an
#        index lists is backed by that operation's own entry.
#     4. Same membership as `OPERATIONS.md` — the two renderings of one IR name
#        the same operations.
#
# WHY
#   The reverse index exists because an agent holding a failure has a query
#   key, a header or an error code, not an operation name. A field that
#   silently stopped being emitted leaves that agent with a document that
#   answers every question it is asked and omits the one it was built for, and
#   nothing about the file's shape says so.
#
#   Property 3's second direction is the one that matters. An index that keeps
#   an operation after the fact that put it there was deleted still looks like
#   an index, and a check that only walked forward would pass over it.
#
# HOW TO EXEMPT
#   Not applicable. The file is generated: change `model/overlays/**` or the
#   emitter in `crates/codegen/src/emit/operations_json.rs` and run
#   `cargo xtask codegen`.
#
# USAGE
#   scripts/check_operations_json_fields.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_operations_json_fields.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
cd "$ROOT_DIR"

INDEX="generated/OPERATIONS.json"
MARKDOWN="OPERATIONS.md"
EMITTER="crates/codegen/src/emit/operations_json.rs"

command -v python3 >/dev/null 2>&1 || {
    printf 'check_operations_json_fields.sh: required command is missing: python3\n' >&2
    exit 1
}

# Deliberately not `|| exit 0`. All three inputs are produced by every codegen
# run and exist in every checkout, so an absent one means this guard is running
# where it cannot see what it checks — and a check that reports success without
# checking anything is indistinguishable from one that passed.
for input in "$INDEX" "$MARKDOWN" "$EMITTER"; do
    if [[ ! -f "$input" ]]; then
        printf 'check_operations_json_fields.sh: cannot read %s — refusing to report success without checking\n' \
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
    print(f"check_operations_json_fields: {message}", file=sys.stderr)


FIELDS = [
    "method",
    "path_shape",
    "query_keys",
    "key_headers",
    "host_classes",
    "error_codes",
    "precedence",
]
# field -> (index name, whether the field is a list of keys)
INDEXES = {
    "method": ("by_method", False),
    "path_shape": ("by_path_shape", False),
    "query_keys": ("by_query_key", True),
    "key_headers": ("by_key_header", True),
    "host_classes": ("by_host_class", True),
    "error_codes": ("by_error_code", True),
    "precedence": ("by_precedence", False),
}

try:
    document = json.loads(index_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    print(f"check_operations_json_fields: {index_path}: {error}", file=sys.stderr)
    raise SystemExit(1)

# The emitter is the declaration of the field set; the document is the output. Reading both keeps
# a field that was dropped from the emitter from being a rename this guard follows silently.
emitter_text = emitter_path.read_text(encoding="utf-8")
declared = re.search(r"pub const FIELDS: \[&str; (\d+)\] = \[(.*?)\];", emitter_text, re.S)
if declared is None:
    bad(f"{emitter_path}: no `FIELDS` declaration; the field set has no source")
else:
    names = re.findall(r'"([^"]+)"', declared.group(2))
    if int(declared.group(1)) != 7 or names != FIELDS:
        bad(f"{emitter_path}: declares fields {names}; this guard and the wire index require {FIELDS}")

operations = document.get("operations")
if not isinstance(operations, dict) or not operations:
    bad(f"{index_path}: no `operations` table; the reverse index has nothing to point at")
    raise SystemExit(status or 1)

if not isinstance(document.get("generated_by"), str):
    bad(f"{index_path}: carries no `generated_by`; a generated file must say it is one")

# ------------------------------------------------------- 1. seven fields, in order
for name, entry in sorted(operations.items()):
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
        bad(f"{index_path}: {name} carries the wrong wire fields — {', '.join(detail)}")
    for field in ("query_keys", "key_headers", "host_classes", "error_codes"):
        value = entry.get(field)
        if field in entry and not (isinstance(value, list) and all(isinstance(item, str) for item in value)):
            bad(f"{index_path}: {name}.{field} is not a list of strings")
    if "precedence" in entry and not isinstance(entry["precedence"], int):
        bad(f"{index_path}: {name}.precedence is not an integer")
    for field in ("method", "path_shape"):
        if field in entry and not isinstance(entry[field], str):
            bad(f"{index_path}: {name}.{field} is not a string")

# ------------------------------------------------------------- 2. seven indexes
for field, (index_name, _) in INDEXES.items():
    if not isinstance(document.get(index_name), dict):
        bad(f"{index_path}: no `{index_name}` object; the `{field}` field cannot be entered from the wire")

if status:
    raise SystemExit(status)

# --------------------------------------------------------------- 3. both directions
def keys_of(entry, field, is_list):
    value = entry.get(field)
    if is_list:
        return [str(item) for item in value]
    return [str(value)]


for field, (index_name, is_list) in INDEXES.items():
    reverse = document[index_name]
    expected = {}
    for name, entry in operations.items():
        for key in keys_of(entry, field, is_list):
            expected.setdefault(key, []).append(name)
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
            entry = operations.get(name)
            if entry is None:
                bad(f"{index_path}: {index_name}[{key!r}] names {name}, which has no entry")
                continue
            if key not in keys_of(entry, field, is_list):
                bad(
                    f"{index_path}: {index_name}[{key!r}] names {name}, but its {field} does not "
                    "carry that key — a stale index outlives the fact that built it"
                )

# ----------------------------------------------- 4. the same operations as the Markdown
markdown = markdown_path.read_text(encoding="utf-8")
section = markdown.split("## Operation detail", 1)
documented = set(re.findall(r"^### (\w+)$", section[-1], re.M)) if len(section) > 1 else set()
if not documented:
    bad(f"{markdown_path}: no operation sections found; the membership comparison would be vacuous")
else:
    for name in sorted(documented - set(operations)):
        bad(f"{index_path}: {name} is in {markdown_path} but has no entry; run `cargo xtask codegen`")
    for name in sorted(set(operations) - documented):
        bad(f"{index_path}: {name} has an entry but is absent from {markdown_path}")

sys.exit(status)
PYEOF
