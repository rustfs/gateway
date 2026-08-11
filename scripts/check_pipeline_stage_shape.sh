#!/usr/bin/env bash
set -euo pipefail

# The request pipeline's state carrier owns its data. Borrowing the wire request
# would make later async stages self-referential and force pinning or unsafe code.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if ! command -v python3 >/dev/null 2>&1; then
    printf 'check_pipeline_stage_shape: required command is missing: python3\n' >&2
    exit 1
fi

python3 - "$ROOT_DIR" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
source = root / "crates/gateway/src/request_config.rs"
if not source.is_file():
    print("check_pipeline_stage_shape: required input is missing: crates/gateway/src/request_config.rs", file=sys.stderr)
    raise SystemExit(1)

text = source.read_text()
code = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
code = re.sub(r"//[^\n]*", "", code)

carrier = re.search(
    r"\bpub\(crate\)\s+struct\s+RequestConfig\s*<([^>{}]*)>\s*\{([^}]*)\}",
    code,
    re.S,
)
if carrier is None:
    print("check_pipeline_stage_shape: RequestConfig carrier is missing", file=sys.stderr)
    raise SystemExit(1)
parameters = carrier.group(1).strip()
if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", parameters) or "'" in parameters:
    print("crates/gateway/src/request_config.rs: RequestConfig must not carry a lifetime parameter", file=sys.stderr)
    raise SystemExit(1)

alias_pattern = re.compile(
    r"\btype\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*<[^;=]+>)?\s*=\s*([^;]+);",
    re.S,
)
aliases = {}
for match in alias_pattern.finditer(code):
    aliases.setdefault(match.group(1), []).append(match.group(2))

type_definitions = dict(aliases)
struct_pattern = re.compile(
    r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*<[^>{}();]*>)?\s*([({;])",
    re.S,
)
for match in struct_pattern.finditer(code):
    delimiter = match.group(2)
    if delimiter == ";":
        type_definitions.setdefault(match.group(1), []).append("")
        continue
    closing = "}" if delimiter == "{" else ")"
    depth = 1
    index = match.end()
    start = index
    while index < len(code) and depth:
        if code[index] == delimiter:
            depth += 1
        elif code[index] == closing:
            depth -= 1
        index += 1
    if depth == 0:
        type_definitions.setdefault(match.group(1), []).append(code[start : index - 1])

enum_pattern = re.compile(
    r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*<[^>{}();]*>)?\s*\{",
    re.S,
)
for match in enum_pattern.finditer(code):
    depth = 1
    index = match.end()
    start = index
    while index < len(code) and depth:
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
        index += 1
    if depth == 0:
        type_definitions.setdefault(match.group(1), []).append(code[start : index - 1])

borrowed_types = set()
changed = True
while changed:
    changed = False
    for type_name, definitions in type_definitions.items():
        if type_name in borrowed_types:
            continue
        if any(
            "&" in definition
            or any(re.search(rf"\b{re.escape(borrowed)}\b", definition) for borrowed in borrowed_types)
            for definition in definitions
        ):
            borrowed_types.add(type_name)
            changed = True

carrier_body = carrier.group(2)
if "&" in carrier_body or any(
    re.search(rf"\b{re.escape(type_name)}\b", carrier_body)
    for type_name in borrowed_types
):
    print("crates/gateway/src/request_config.rs: RequestConfig must own its carried state", file=sys.stderr)
    raise SystemExit(1)

implemented = re.findall(r"\bimpl\s+RequestConfig\s*<\s*([^>]+)\s*>", code)
returned = re.findall(r"->\s*RequestConfig\s*<\s*([^>]+)\s*>", code)
arguments = implemented + returned
if not arguments:
    print("check_pipeline_stage_shape: RequestConfig state closure is missing", file=sys.stderr)
    raise SystemExit(1)
for argument in arguments:
    if "'" in argument:
        print("crates/gateway/src/request_config.rs: request stage must not carry a lifetime parameter", file=sys.stderr)
        raise SystemExit(1)

declarations = {
    match.group(1): match.group(2)
    for match in re.finditer(
        r"(?m)^\s*pub\(crate\)\s+struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*(<[^;{}()]*>)?\s*(?:;|\{|\()",
        code,
    )
}
stages = {argument.strip() for argument in arguments if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", argument.strip())}
for stage in sorted(stages & declarations.keys()):
    if declarations[stage] and "'" in declarations[stage]:
        print(f"crates/gateway/src/request_config.rs: {stage} must not carry a lifetime parameter", file=sys.stderr)
        raise SystemExit(1)
PY
