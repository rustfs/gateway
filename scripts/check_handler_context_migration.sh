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
    "crates/conformance/src/fixture/handlers_bucket.rs": 40,
    "crates/conformance/src/fixture/handlers_object.rs": 32,
    "crates/conformance/src/observation/select_error_tests.rs": 1,
    "crates/core/examples/dialect_overlay.rs": 1,
    "crates/core/tests/codec_binding.rs": 3,
    "crates/core/tests/dialect.rs": 2,
    "crates/core/tests/registration.rs": 4,
    "crates/core/tests/static_dispatch.rs": 1,
    "crates/gateway/examples/custom_authorizer.rs": 1,
    "crates/gateway/examples/minimal.rs": 2,
    "crates/gateway/src/dispatch.rs": 3,
    "crates/gateway/src/lib.rs": 1,
    "crates/gateway/tests/assembly_order.rs": 1,
    "crates/gateway/tests/authz_contract.rs": 1,
    "crates/gateway/tests/authz_contract/oracle.rs": 1,
    "crates/gateway/tests/authz_consumption.rs": 2,
    "crates/gateway/tests/cors_runtime.rs": 2,
    "crates/gateway/tests/credential_runtime.rs": 1,
    "crates/gateway/tests/handler_panic.rs": 1,
    "crates/gateway/tests/monomorphic.rs": 6,
    "crates/gateway/tests/naming_policy.rs": 1,
    "crates/gateway/tests/patch_layer_landings.rs": 1,
    "crates/gateway/tests/precondition_contract.rs": 2,
    "crates/gateway/tests/replica_put.rs": 2,
    "crates/gateway/tests/sse_runtime.rs": 2,
    "crates/gateway/tests/support/handlers.rs": 9,
    "crates/gateway/tests/support/select.rs": 1,
    "crates/macros/src/expand.rs": 1,
    "crates/macros/tests/equivalence.rs": 4,
}
facade_dual = {
    "crates/conformance/src/fixture/handlers_bucket.rs",
    "crates/conformance/src/fixture/handlers_object.rs",
    "crates/conformance/src/observation/select_error_tests.rs",
    "crates/gateway/examples/custom_authorizer.rs",
    "crates/gateway/examples/minimal.rs",
    "crates/gateway/src/dispatch.rs",
    "crates/gateway/src/lib.rs",
    "crates/gateway/tests/assembly_order.rs",
    "crates/gateway/tests/authz_contract.rs",
    "crates/gateway/tests/authz_contract/oracle.rs",
    "crates/gateway/tests/authz_consumption.rs",
    "crates/gateway/tests/cors_runtime.rs",
    "crates/gateway/tests/credential_runtime.rs",
    "crates/gateway/tests/handler_panic.rs",
    "crates/gateway/tests/monomorphic.rs",
    "crates/gateway/tests/naming_policy.rs",
    "crates/gateway/tests/patch_layer_landings.rs",
    "crates/gateway/tests/precondition_contract.rs",
    "crates/gateway/tests/replica_put.rs",
    "crates/gateway/tests/sse_runtime.rs",
    "crates/gateway/tests/support/handlers.rs",
    "crates/gateway/tests/support/select.rs",
    "crates/macros/src/expand.rs",
    "crates/macros/tests/equivalence.rs",
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


# Compiled once, then matched with an offset. Cutting a fresh `source[start:]` slice copies
# the whole remainder of the file on every character, which makes an otherwise linear
# tokenizer quadratic in file length; `pattern.match(source, start)` matches at the same place
# without the copy. No pattern here carries `^`, `\A`, `\b` or a lookbehind, so anchoring at
# the offset is exactly what slicing to it already meant. `tokens()` calls this at every
# character, so the copy was per-character too.
RAW_STRING_RE = re.compile(r'(?:br|rb|cr|r)(\#*)"')


def raw_string_end(source: str, start: int) -> int | None:
    match = RAW_STRING_RE.match(source, start)
    if not match:
        return None
    marker = '"' + match.group(1)
    body = match.end()
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
        while cursor < len(stream) and stream[cursor] not in ("{", ";"):
            cursor += 1
        if cursor >= len(stream) or stream[cursor] != "{":
            index += 1
            continue
        header = stream[index + 1 : cursor]
        try:
            trait_end = header.index("for")
        except ValueError:
            trait_end = 0
        handler = any(
            header[position] == "Handler" and header[position + 1] == "<"
            for position in range(max(0, trait_end - 1))
        )
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
        if relative in facade_dual:
            if "call_with_context" not in methods or "call" not in methods:
                fail(f"{relative} Handler impl {ordinal} is not on the reviewed facade migration bridge")
            if relative == "crates/gateway/src/dispatch.rs" and ordinal == 1:
                legacy_source = [
                    "let", "(", "_source", ",", "context", ")", "=",
                    "HandlerCancellationSource", ":", ":", "pair", "(", ")", ";",
                ]
                legacy_layered = ["run_layered", ":", ":", "<", "O", ",", "B", ">", "(", "&", "self", ".", "backend", ",", "layers", ",", "request", ",", "context", ")", ".", "await"]
                contextual_backend = ["self", ".", "backend", ".", "call_with_context", "(", "request", ",", "context", ")", ".", "await"]
                contextual_layered = ["run_layered", ":", ":", "<", "O", ",", "B", ">", "(", "&", "self", ".", "backend", ",", "layers", ",", "request", ",", "context", ")", ".", "await"]
                if (
                    not contains_sequence(methods["call"], legacy_source)
                    or not contains_sequence(methods["call"], legacy_layered)
                    or not contains_sequence(methods["call_with_context"], contextual_backend)
                    or not contains_sequence(methods["call_with_context"], contextual_layered)
                ):
                    fail(f"{relative} Handler impl {ordinal} does not preserve layered context forwarding")
            elif relative == "crates/gateway/src/dispatch.rs" and ordinal == 2:
                cancellation = ["context", ".", "cancelled", "(", ")", ".", "await"]
                deadline = ["HandlerCancellation", ":", ":", "Deadline"]
                observed = ["self", ".", "observed", ".", "store", "(", "true", ",", "Ordering", ":", ":", "Release", ")"]
                if (
                    not contains_sequence(methods["call_with_context"], cancellation)
                    or not contains_sequence(methods["call_with_context"], deadline)
                    or not contains_sequence(methods["call_with_context"], observed)
                ):
                    fail(f"{relative} Handler impl {ordinal} does not observe deadline cancellation")
            elif relative == "crates/gateway/tests/monomorphic.rs" and ordinal == 1:
                cancellation = ["context", ".", "cancellation_reason", "(", ")", ".", "is_none", "(", ")"]
                if not contains_sequence(methods["call_with_context"], cancellation):
                    fail(f"{relative} Handler impl {ordinal} does not inspect its context cancellation state")
            elif relative == "crates/gateway/tests/assembly_order.rs":
                legacy = ["self", ".", "note", "(", ")", ";", "self", ".", "inner", ".", "call", "(", "request", ")"]
                contextual = [
                    "self", ".", "note", "(", ")", ";",
                    "self", ".", "inner", ".", "call_with_context", "(", "request", ",", "context", ")",
                ]
                if methods["call"] != legacy or methods["call_with_context"] != contextual:
                    fail(f"{relative} Handler impl {ordinal} does not forward the same request context")
            elif methods["call"] != methods["call_with_context"]:
                fail(f"{relative} Handler impl {ordinal} has diverged legacy and context bodies")
            continue
        if "call" not in methods or "call_with_context" not in methods:
            fail(f"{relative} Handler impl {ordinal} is not on the reviewed two-entry migration bridge")
        source_authority = "rustfs_gateway_core" if relative.startswith("crates/core/") else "rustfs_gateway"
        bridge = [
            "let", "(", "_source", ",", "context", ")", "=",
            source_authority, ":", ":", "HandlerCancellationSource", ":", ":", "pair", "(", ")", ";",
            "self", ".", "call_with_context", "(", "request", ",", "context", ")", ".", "await",
        ]
        if not contains_sequence(methods["call"], bridge):
            fail(f"{relative} Handler impl {ordinal} drops or bypasses the migration context source")
    total += len(implementations)

if total != 129:
    fail(f"reviewed migration census is {total}, expected 129")
print(f"check_handler_context_migration: {total} reviewed Handler impls preserve their context migration mode")
PY
