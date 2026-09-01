#!/usr/bin/env bash
set -euo pipefail

# Standard operation/Input names come from codegen or a reviewed manual-operation overlay; their
# reverse mapping stays beside the hand-written Operation impl. This guard makes the authorities
# agree without adding a forbidden rustfs-gateway-types -> rustfs-gateway-core dependency.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if ! command -v python3 >/dev/null 2>&1; then
    printf 'check_has_operation_coverage: required command is missing: python3\n' >&2
    exit 1
fi

python3 - "$ROOT_DIR" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
ops_dir = root / "crates/core/src/ops"
spec_dir = root / "spec/operations"
overlay_ops_dir = root / "model/overlays/ops"

if not ops_dir.is_dir():
    raise SystemExit("check_has_operation_coverage: required operation directory is missing")
if not spec_dir.is_dir():
    raise SystemExit("check_has_operation_coverage: required spec directory is missing")
if not overlay_ops_dir.is_dir():
    raise SystemExit("check_has_operation_coverage: required operation overlay directory is missing")


# Compiled once, then matched with an offset. Cutting a fresh `source[index:]` slice copies
# the whole remainder of the file on every character, which makes an otherwise linear blanking
# pass quadratic in file length; `pattern.match(source, index)` matches at the same place
# without the copy. No pattern here carries `^`, `\A`, `\b` or a lookbehind, so anchoring at
# the offset is exactly what slicing to it already meant.
RAW_STRING_RE = re.compile(r'(?:b|c)?r(#+)?"')
LIFETIME_RE = re.compile(r"'[A-Za-z_][A-Za-z0-9_]*")


def code_only(source: str) -> str:
    """Replace Rust comments and literals with spaces while preserving token positions."""
    out = list(source)
    index = 0
    block_depth = 0
    while index < len(source):
        if block_depth:
            if source.startswith("/*", index):
                out[index:index + 2] = "  "
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                out[index:index + 2] = "  "
                block_depth -= 1
                index += 2
            else:
                if source[index] != "\n":
                    out[index] = " "
                index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = len(source) if end < 0 else end
            out[index:end] = " " * (end - index)
            index = end
            continue
        if source.startswith("/*", index):
            out[index:index + 2] = "  "
            block_depth = 1
            index += 2
            continue
        raw = RAW_STRING_RE.match(source, index)
        if raw:
            hashes = raw.group(1) or ""
            end = source.find('"' + hashes, raw.end())
            if end < 0:
                raise SystemExit("check_has_operation_coverage: unterminated raw string")
            end += 1 + len(hashes)
            out[index:end] = " " * (end - index)
            index = end
            continue
        quote = index + 1 if source[index] in {"b", "c"} and index + 1 < len(source) else index
        if quote < len(source) and source[quote] == '"':
            start = index
            index = quote + 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == '"':
                    index += 1
                    break
                index += 1
            else:
                raise SystemExit("check_has_operation_coverage: unterminated string")
            out[start:index] = " " * (index - start)
            continue
        if source[index] == "'":
            lifetime = LIFETIME_RE.match(source, index)
            if lifetime and (
                index + len(lifetime.group(0)) >= len(source)
                or source[index + len(lifetime.group(0))] != "'"
            ):
                index += 1
                continue
            start = index
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == "'":
                    index += 1
                    break
                else:
                    index += 1
            else:
                raise SystemExit("check_has_operation_coverage: unterminated character literal")
            out[start:index] = " " * (index - start)
            continue
        index += 1
    if block_depth:
        raise SystemExit("check_has_operation_coverage: unterminated block comment")
    return "".join(out)


def impl_blocks(source: str, trait: str) -> list[tuple[str, str]]:
    pattern = re.compile(rf"\bimpl\s+{trait}\s+for\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{{")
    blocks = []
    for match in pattern.finditer(source):
        start = source.find("{", match.start())
        depth = 0
        for end in range(start, len(source)):
            if source[end] == "{":
                depth += 1
            elif source[end] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append((match.group(1), source[start + 1:end]))
                    break
        else:
            raise SystemExit(f"check_has_operation_coverage: unclosed {trait} impl")
    return blocks


mappings = {}
for path in sorted(ops_dir.glob("*.rs")):
    source = code_only(path.read_text())
    operations = [
        (marker, body)
        for marker, body in impl_blocks(source, "Operation")
        if "OperationOrigin::Standard" in body
    ]
    reverse = impl_blocks(source, "HasOperation")
    if not operations and not reverse:
        continue
    if len(operations) != 1 or len(reverse) != 1:
        raise SystemExit(
            f"check_has_operation_coverage: {path.relative_to(root)} must contain one standard Operation and one HasOperation impl"
        )
    marker, operation_body = operations[0]
    input_match = re.search(r"\btype\s+Input\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", operation_body)
    if input_match is None:
        raise SystemExit(f"check_has_operation_coverage: {marker} does not declare one simple Input type")
    input_type = input_match.group(1)
    reverse_input, reverse_body = reverse[0]
    op_match = re.search(r"\btype\s+Op\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", reverse_body)
    if op_match is None or reverse_input != input_type or op_match.group(1) != marker:
        raise SystemExit(f"check_has_operation_coverage: {marker} reverse mapping disagrees with Input {input_type}")
    if input_type != f"{marker}Input":
        raise SystemExit(f"check_has_operation_coverage: {marker} must map from {marker}Input, found {input_type}")
    if marker in mappings:
        raise SystemExit(f"check_has_operation_coverage: duplicate standard operation {marker}")
    mappings[marker] = input_type

spec_names = set()
for path in sorted(spec_dir.glob("*.toml")):
    match = re.search(r'^\[operation\]\s*\nname\s*=\s*"([^"]+)"', path.read_text(), re.MULTILINE)
    if match is None:
        raise SystemExit(f"check_has_operation_coverage: {path.relative_to(root)} lacks an operation name")
    spec_names.add(match.group(1))

for path in sorted(overlay_ops_dir.glob("*.toml")):
    source = path.read_text()
    if "[[manual]]" not in source:
        continue
    declarations = re.findall(
        r'\[\[manual\]\](.*?)(?=\n\[\[|\n\[[^[]|\Z)', source, re.DOTALL
    )
    if len(declarations) != 1:
        raise SystemExit(
            f"check_has_operation_coverage: {path.relative_to(root)} must contain one manual declaration"
        )
    operations_match = re.search(r'^operations\s*=\s*\[(.*?)\]\s*$', declarations[0], re.MULTILINE | re.DOTALL)
    if operations_match is None:
        raise SystemExit(
            f"check_has_operation_coverage: {path.relative_to(root)} manual declaration lacks operations"
        )
    manual_names = re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"', operations_match.group(1))
    if not manual_names:
        raise SystemExit(
            f"check_has_operation_coverage: {path.relative_to(root)} manual declaration is empty"
        )
    for name in manual_names:
        if re.search(rf'^\[op\.{re.escape(name)}\]\s*$', source, re.MULTILINE) is None:
            raise SystemExit(
                f"check_has_operation_coverage: manual operation {name} lacks an overlay row"
            )
        if name in spec_names:
            raise SystemExit(f"check_has_operation_coverage: duplicate operation authority {name}")
        spec_names.add(name)

mapping_names = set(mappings)
if mapping_names != spec_names:
    missing = sorted(spec_names - mapping_names)
    extra = sorted(mapping_names - spec_names)
    detail = f"missing {missing[0]}" if missing else f"unexpected {extra[0]}"
    raise SystemExit(f"check_has_operation_coverage: codegen/per-operation sets disagree: {detail}")
if not mappings:
    raise SystemExit("check_has_operation_coverage: no standard reverse mappings were observed")
PY
