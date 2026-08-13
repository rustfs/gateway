#!/usr/bin/env bash
set -euo pipefail

# Standard operation/Input names come from codegen; their reverse mapping stays beside the
# hand-written Operation impl. This guard makes the two authorities agree without adding a
# forbidden rustfs-gateway-types -> rustfs-gateway-core dependency.

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

if not ops_dir.is_dir():
    raise SystemExit("check_has_operation_coverage: required operation directory is missing")
if not spec_dir.is_dir():
    raise SystemExit("check_has_operation_coverage: required spec directory is missing")


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
        raw = re.match(r'(?:b|c)?r(#+)?"', source[index:])
        if raw:
            hashes = raw.group(1) or ""
            end = source.find('"' + hashes, index + raw.end())
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
            lifetime = re.match(r"'[A-Za-z_][A-Za-z0-9_]*", source[index:])
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

mapping_names = set(mappings)
if mapping_names != spec_names:
    missing = sorted(spec_names - mapping_names)
    extra = sorted(mapping_names - spec_names)
    detail = f"missing {missing[0]}" if missing else f"unexpected {extra[0]}"
    raise SystemExit(f"check_has_operation_coverage: codegen/per-operation sets disagree: {detail}")
if not mappings:
    raise SystemExit("check_has_operation_coverage: no standard reverse mappings were observed")
PY
