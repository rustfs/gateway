#!/usr/bin/env bash
set -euo pipefail

# Trailer ownership must remain part of the EOF event. A shared mutable slot
# makes "not received yet" indistinguishable from "received no trailers".

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if ! command -v python3 >/dev/null 2>&1; then
    printf 'check_no_shared_trailers: required command is missing: python3\n' >&2
    exit 1
fi

python3 - "$ROOT_DIR" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
source = root / "crates/stream/src"
if not source.is_dir():
    print("check_no_shared_trailers: required input is missing: crates/stream/src", file=sys.stderr)
    raise SystemExit(1)

violations = []
files = sorted(source.rglob("*.rs"))
if not files:
    print("check_no_shared_trailers: no Rust sources found", file=sys.stderr)
    raise SystemExit(1)

texts = {path: path.read_text() for path in files}
aliases = {}
alias_pattern = re.compile(
    r"\btype\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*<([^;]+?)>)?\s*=\s*([^;]+);",
    re.S,
)


def split_top_level(value):
    parts = []
    start = 0
    depth = 0
    pairs = {"<": ">", "(": ")", "[": "]", "{": "}"}
    closings = set(pairs.values())
    for index, character in enumerate(value):
        if character in pairs:
            depth += 1
        elif character in closings:
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    parts.append(value[start:].strip())
    return tuple(part for part in parts if part)


for text in texts.values():
    for match in alias_pattern.finditer(text):
        parameters = tuple(
            (name.group(1), "=" in parameter)
            for parameter in split_top_level(match.group(2) or "")
            if (name := re.match(r"\s*(?:const\s+)?([A-Za-z_][A-Za-z0-9_]*)", parameter))
        )
        aliases.setdefault(match.group(1), []).append((parameters, match.group(3)))

qualified_name = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Za-z_][A-Za-z0-9_]*)$")


def outer_name_and_argument(expression):
    expression = expression.strip()
    match = re.match(
        r"^(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Za-z_][A-Za-z0-9_]*)\s*<",
        expression,
    )
    if not match:
        return None
    depth = 1
    index = match.end()
    start = index
    while index < len(expression) and depth:
        if expression[index] == "<":
            depth += 1
        elif expression[index] == ">":
            depth -= 1
        index += 1
    if depth or expression[index:].strip():
        return None
    return match.group(1), expression[start : index - 1]


def is_trailer_type(expression, seen=frozenset()):
    expression = expression.strip()
    match = qualified_name.fullmatch(expression)
    if not match:
        return False
    name = match.group(1)
    if name == "TrailingHeaders":
        return True
    if name in seen:
        return False
    return any(
        not parameters and is_trailer_type(rhs, seen | {name})
        for parameters, rhs in aliases.get(name, ())
    )


def is_optional_trailer_type(expression, seen=frozenset()):
    expression = expression.strip()
    outer = outer_name_and_argument(expression)
    if outer and outer[0] == "Option":
        return is_trailer_type(outer[1])
    match = qualified_name.fullmatch(expression)
    if not match:
        return False
    name = match.group(1)
    if name in seen:
        return False
    return any(
        not parameters and is_optional_trailer_type(rhs, seen | {name})
        for parameters, rhs in aliases.get(name, ())
    )


wrapper_kinds = {
    "Mutex": "Mutex",
    "RwLock": "RwLock",
    "OnceCell": "OnceCell",
    "OnceLock": "OnceLock",
}
import_alias_pattern = re.compile(
    r"\b(Mutex|RwLock|OnceCell|OnceLock)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
for text in texts.values():
    for match in import_alias_pattern.finditer(text):
        wrapper_kinds[match.group(2)] = match.group(1)

changed = True
while changed:
    changed = False
    for alias, definitions in aliases.items():
        for parameters, rhs in definitions:
            outer = outer_name_and_argument(rhs)
            if (
                parameters
                and outer
                and outer[0] in wrapper_kinds
                and outer[1].strip() == parameters[0][0]
                and all(
                    defaulted and not re.search(rf"\b{re.escape(name)}\b", rhs)
                    for name, defaulted in parameters[1:]
                )
                and alias not in wrapper_kinds
            ):
                wrapper_kinds[alias] = wrapper_kinds[outer[0]]
                changed = True

wrapper_names = "|".join(re.escape(name) for name in sorted(wrapper_kinds, key=len, reverse=True))
wrapper_pattern = re.compile(
    rf"\b(?:[A-Za-z_][A-Za-z0-9_]*::)*({wrapper_names})\s*<"
)
for path, text in texts.items():
    for match in wrapper_pattern.finditer(text):
        depth = 1
        index = match.end()
        start = index
        while index < len(text) and depth:
            if text[index] == "<":
                depth += 1
            elif text[index] == ">":
                depth -= 1
            index += 1
        if depth:
            continue
        arguments = split_top_level(text[start : index - 1])
        if not arguments:
            continue
        argument = arguments[0]
        wrapper = wrapper_kinds[match.group(1)]
        shared = (
            is_optional_trailer_type(argument)
            if wrapper in {"Mutex", "RwLock"}
            else is_trailer_type(argument) or is_optional_trailer_type(argument)
        )
        if shared:
            line = text.count("\n", 0, match.start()) + 1
            violations.append(f"{path.relative_to(root)}:{line}: shared mutable trailer slot")

if violations:
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)
PY
