#!/usr/bin/env bash
set -euo pipefail

# WHAT: Binds c-lim-0020 to the real no-length PutObject socket refusal.
# WHY: A codec-only 411 does not prove the wire case is non-streaming or that the connection closes.
# HOW TO EXEMPT: There is no exemption; the codec, corpus, socket, and close-policy evidence are required.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CASE="${ROOT}/conformance/cases/object/c-object-0030.toml"
WIRED="${ROOT}/crates/conformance/tests/wired.rs"

fail() {
    printf 'check_missing_content_length: %s\n' "$1" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
for path in "$CASE" "$WIRED"; do
    [[ -f "$path" ]] || fail "required evidence is missing: ${path#"$ROOT"/}"
done

python3 - "$CASE" "$WIRED" <<'PYEOF'
import re
import sys
import tomllib
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"check_missing_content_length: {message}")


def rust_code(text: str) -> str:
    out = list(text)
    index = 0
    block_depth = 0
    while index < len(text):
        if block_depth:
            if text.startswith("/*", index):
                out[index:index + 2] = "  "
                block_depth += 1
                index += 2
            elif text.startswith("*/", index):
                out[index:index + 2] = "  "
                block_depth -= 1
                index += 2
            else:
                if text[index] != "\n":
                    out[index] = " "
                index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = len(text) if end < 0 else end
            for cursor in range(index, end):
                out[cursor] = " "
            index = end
            continue
        if text.startswith("/*", index):
            out[index:index + 2] = "  "
            block_depth = 1
            index += 2
            continue
        prefix = None
        for candidate in ("br", "rb", "r", "b"):
            if text.startswith(candidate, index):
                quote = index + len(candidate)
                if quote < len(text) and text[quote] in ('"', "'"):
                    prefix = candidate
                    break
        quote_at = index + len(prefix) if prefix is not None else index
        if quote_at < len(text) and text[quote_at] in ('"', "'"):
            quote = text[quote_at]
            if quote == "'" and prefix is None:
                lifetime = re.match(r"'[A-Za-z_][A-Za-z0-9_]*", text[index:])
                lifetime_end = index + len(lifetime.group(0)) if lifetime else index
                if lifetime and (lifetime_end >= len(text) or text[lifetime_end] != "'"):
                    index = lifetime_end
                    continue
            cursor = quote_at + 1
            while cursor < len(text):
                if text[cursor] == "\\":
                    cursor += 2
                    continue
                if text[cursor] == quote:
                    cursor += 1
                    break
                cursor += 1
            else:
                fail("Rust evidence contains an unterminated literal")
            for masked in range(index, cursor):
                if text[masked] != "\n":
                    out[masked] = " "
            index = cursor
            continue
        index += 1
    if block_depth:
        fail("Rust evidence contains an unterminated block comment")
    return "".join(out)


def function_bounds(code: str, name: str) -> tuple[int, int]:
    marker = f"fn {name}("
    if code.count(marker) != 1:
        fail(f"{name} is missing or duplicated")
    start = code.index(marker)
    brace = code.find("{", start)
    if brace < 0:
        fail(f"{name} has no body")
    depth = 0
    for cursor in range(brace, len(code)):
        if code[cursor] == "{":
            depth += 1
        elif code[cursor] == "}":
            depth -= 1
            if depth == 0:
                return brace, cursor + 1
    fail(f"{name} has an unterminated body")


def function_body(code: str, name: str) -> str:
    start, end = function_bounds(code, name)
    return code[start:end]


case_path, wired_path = map(Path, sys.argv[1:])
case_text = case_path.read_text()
if case_text.count("# c-lim-0020 / c-object-0030") != 1:
    fail("c-lim-0020 corpus identity is missing or duplicated")
try:
    case = tomllib.loads(case_text)
except tomllib.TOMLDecodeError as error:
    fail(f"corpus evidence is invalid TOML: {error}")

if case.get("case", {}).get("id") != "c-object-0030":
    fail("c-lim-0020 corpus case ID drifted")
if case.get("case", {}).get("operation") != "PutObject":
    fail("c-lim-0020 is not bound to PutObject")
request = case.get("request", {})
raw_head = request.get("raw_head_utf8")
if not isinstance(raw_head, str) or not raw_head.startswith("PUT "):
    fail("c-lim-0020 no longer sends a raw PUT request head")
headers = raw_head.split("\r\n")[1:-2]
names = {line.split(":", 1)[0].strip().lower() for line in headers if ":" in line}
if "content-length" in names or "transfer-encoding" in names:
    fail("c-lim-0020 request gained declared or chunked framing")
if request.get("sign", {}).get("mode") != "sigv4_unsigned_payload":
    fail("c-lim-0020 is no longer the plain non-streaming PutObject form")
expect = case.get("expect", {})
if expect.get("status") != 411:
    fail("c-lim-0020 no longer requires status 411")
if expect.get("error", {}).get("code") != "MissingContentLength":
    fail("c-lim-0020 no longer requires MissingContentLength")
if expect.get("connection_after") != "closed":
    fail("c-lim-0020 no longer requires the connection to close")

wired_text = wired_path.read_text()
wired_code = rust_code(wired_text)
wired_name = "a_refusal_that_did_not_drain_the_body_ends_the_connection_over_a_socket"
wired_start, wired_end = function_bounds(wired_code, wired_name)
wired_body = wired_code[wired_start:wired_end]
wired_raw = wired_text[wired_start:wired_end]
for token in ("run_over_a_socket(id)", "outcome.verdict, Verdict::Passed"):
    if token not in wired_body:
        fail(f"c-lim-0020 socket evidence lost {token!r}")
if '"c-object-0030"' not in wired_raw:
    fail("c-lim-0020 socket evidence lost the corpus case")

print("OK: c-lim-0020 rejects a non-streaming PutObject without Content-Length as 411 and closes the socket")
PYEOF
