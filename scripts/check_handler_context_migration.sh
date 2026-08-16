#!/usr/bin/env bash
set -euo pipefail

# Keeps each reviewed Handler migration batch explicit until the temporary
# one-argument bridge can be removed at the end of backlog#1861. There are no
# exemptions; expand the exact reviewed-path census in the migration PR.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_handler_context_migration: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'

python3 - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
expected = {
    "crates/core/examples/dialect_overlay.rs": 1,
    "crates/core/tests/codec_binding.rs": 3,
    "crates/core/tests/dialect.rs": 2,
    "crates/core/tests/registration.rs": 4,
    "crates/core/tests/static_dispatch.rs": 1,
}


def fail(message: str) -> None:
    print(f"check_handler_context_migration: {message}", file=sys.stderr)
    raise SystemExit(1)


def skip_quoted(source: str, start: int, quote: str) -> int:
    index = start + 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
        elif source[index] == quote:
            return index + 1
        else:
            index += 1
    fail("a reviewed Rust source has an unterminated quoted literal")


def raw_string_end(source: str, start: int) -> int | None:
    match = re.match(r'(?:br|rb|cr|r)(\#*)"', source[start:])
    if not match:
        return None
    marker = '"' + match.group(1)
    body = start + match.end()
    end = source.find(marker, body)
    if end < 0:
        fail("a reviewed Rust source has an unterminated raw string")
    return end + len(marker)


def tokens(source: str) -> list[str]:
    result: list[str] = []
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            index = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", index):
            depth = 1
            index += 2
            while index < len(source) and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                fail("a reviewed Rust source has an unterminated block comment")
            continue
        raw_end = raw_string_end(source, index)
        if raw_end is not None:
            index = raw_end
            continue
        if source.startswith(('b"', 'c"'), index):
            index = skip_quoted(source, index + 1, '"')
            continue
        if source[index] == '"':
            index = skip_quoted(source, index, '"')
            continue
        if source.startswith("b'", index):
            index = skip_quoted(source, index + 1, "'")
            continue
        if source[index] == "'":
            closing = source.find("'", index + 1, min(len(source), index + 8))
            if closing >= 0:
                index = skip_quoted(source, index, "'")
                continue
            result.append("'")
            index += 1
            continue
        if source[index].isalpha() or source[index] == "_":
            end = index + 1
            while end < len(source) and (source[end].isalnum() or source[end] == "_"):
                end += 1
            result.append(source[index:end])
            index = end
            continue
        if not source[index].isspace():
            result.append(source[index])
        index += 1
    return result


def handler_methods(source: str) -> list[dict[str, list[str]]]:
    stream = tokens(source)
    implementations: list[dict[str, list[str]]] = []
    index = 0
    while index < len(stream):
        if stream[index] != "impl":
            index += 1
            continue
        cursor = index + 1
        handler = False
        while cursor < len(stream) and stream[cursor] not in ("{", ";"):
            if stream[cursor] == "Handler" and cursor + 1 < len(stream) and stream[cursor + 1] == "<":
                handler = True
            cursor += 1
        if cursor >= len(stream) or stream[cursor] != "{":
            index += 1
            continue
        depth = 1
        methods: dict[str, list[str]] = {}
        cursor += 1
        while cursor < len(stream) and depth:
            token = stream[cursor]
            if token == "{":
                depth += 1
            elif token == "}":
                depth -= 1
            elif handler and depth == 1 and token == "fn":
                if cursor + 1 >= len(stream):
                    fail("a reviewed Handler impl ends after fn")
                name = stream[cursor + 1]
                if name in methods:
                    fail(f"a reviewed Handler impl defines {name} twice")
                body_start = cursor + 2
                while body_start < len(stream) and stream[body_start] not in ("{", ";"):
                    body_start += 1
                if body_start >= len(stream) or stream[body_start] != "{":
                    fail(f"a reviewed Handler method {name} has no body")
                body_depth = 1
                body_end = body_start + 1
                while body_end < len(stream) and body_depth:
                    if stream[body_end] == "{":
                        body_depth += 1
                    elif stream[body_end] == "}":
                        body_depth -= 1
                    body_end += 1
                if body_depth:
                    fail(f"a reviewed Handler method {name} has unbalanced braces")
                methods[name] = stream[body_start + 1 : body_end - 1]
                cursor = body_end
                continue
            cursor += 1
        if depth:
            fail("a reviewed Handler impl has unbalanced braces")
        if handler:
            implementations.append(methods)
        index = cursor
    return implementations


def contains_sequence(tokens: list[str], sequence: list[str]) -> bool:
    width = len(sequence)
    return any(tokens[index : index + width] == sequence for index in range(len(tokens) - width + 1))


total = 0
for relative, wanted in expected.items():
    path = root / relative
    if not path.is_file() or path.is_symlink():
        fail(f"reviewed migration source is missing or not a regular file: {relative}")
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read reviewed migration source {relative}: {error}")
    implementations = handler_methods(source)
    if len(implementations) != wanted:
        fail(f"{relative} has {len(implementations)} Handler impls, expected {wanted}")
    for ordinal, methods in enumerate(implementations, start=1):
        if "call" not in methods or "call_with_context" not in methods:
            fail(f"{relative} Handler impl {ordinal} is not on the reviewed two-entry migration bridge")
        bridge = [
            "let", "(", "_source", ",", "context", ")", "=",
            "rustfs_gateway_core", ":", ":", "HandlerCancellationSource", ":", ":", "pair", "(", ")", ";",
            "self", ".", "call_with_context", "(", "request", ",", "context", ")", ".", "await",
        ]
        if not contains_sequence(methods["call"], bridge):
            fail(f"{relative} Handler impl {ordinal} drops or bypasses the migration context source")
    total += len(implementations)

if total != 11:
    fail(f"reviewed migration census is {total}, expected 11")
print("check_handler_context_migration: 11 reviewed Handler impls preserve both migration entries")
PY
