#!/usr/bin/env bash
set -euo pipefail

# WHAT: Binds c-lim-0021 to the real oversized declared-body socket refusal.
# WHY: A close intention is not proof that the server answered before reading the promised body.
# HOW TO EXEMPT: There is no exemption; the socket, status, code, and no-drain evidence are required.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SOURCE="${ROOT}/crates/gateway/tests/connection_teardown.rs"
SOCKET_TIMING="${ROOT}/crates/gateway/tests/socket_timing.rs"
WIRE_GUARD="${ROOT}/scripts/check_wire_case_coverage.sh"

fail() {
    printf 'check_declared_body_limit: %s\n' "$1" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
for path in "$SOURCE" "$SOCKET_TIMING" "$WIRE_GUARD"; do
    [[ -f "$path" ]] || fail "required evidence is missing: ${path#"$ROOT"/}"
done

python3 - "$SOURCE" "$SOCKET_TIMING" "$WIRE_GUARD" <<'PYEOF'
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"check_declared_body_limit: {message}")


def code_view(text: str) -> str:
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
        raw = re.match(r'(?:br|rb|r)(?P<hashes>#{0,255})"', text[index:])
        if raw:
            terminator = '"' + raw.group("hashes")
            end = text.find(terminator, index + raw.end())
            if end < 0:
                fail("Rust evidence contains an unterminated raw string")
            end += len(terminator)
            for cursor in range(index, end):
                if text[cursor] != "\n":
                    out[cursor] = " "
            index = end
            continue
        prefix = "b" if text.startswith(('b"', "b'"), index) else ""
        quote_at = index + len(prefix)
        if quote_at < len(text) and text[quote_at] in ('"', "'"):
            quote = text[quote_at]
            if quote == "'" and not prefix:
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
    marker = f"async fn {name}("
    if code.count(marker) != 1:
        fail("c-lim-0021 executable socket evidence is missing or duplicated")
    start = code.index(marker)
    brace = code.find("{", start)
    if brace < 0:
        fail("c-lim-0021 socket evidence has no body")
    depth = 0
    for cursor in range(brace, len(code)):
        if code[cursor] == "{":
            depth += 1
        elif code[cursor] == "}":
            depth -= 1
            if depth == 0:
                return start, cursor + 1
    fail("c-lim-0021 socket evidence has an unterminated body")


source_path, socket_timing_path, wire_guard_path = map(Path, sys.argv[1:])
source = source_path.read_text()
code = code_view(source)
name = "c_wire_0063_c_lim_0021_an_over_large_body_is_refused_on_the_socket_before_it_is_sent"
start, end = function_bounds(code, name)
body = code[start:end]
raw_body = source[start:end]

if source.count(f"#[tokio::test]\nasync fn {name}()") != 1:
    fail("c-lim-0021 evidence is not an active tokio test")
if socket_timing_path.read_text().count('#[path = "connection_teardown.rs"]\nmod connection_teardown;') != 1:
    fail("c-lim-0021 socket module is not active in the socket-timing target")
if wire_guard_path.read_text().count(f"crates/gateway/tests/connection_teardown.rs::{name}") != 1:
    fail("c-lim-0021 no longer shares the c-wire-0063 evidence edge")

required_code = {
    "the declared body ceiling": "max_body_bytes: 16",
    "a real TCP connection": "TcpStream::connect(local_addr).await",
    "the request-head write": ".write_all(",
    "the bounded terminal read": "stream.read_to_end(&mut response)",
    "the response deadline": "tokio::time::timeout(Duration::from_secs(5)",
    "the status assertion": "wire.starts_with(",
    "the error-code assertion": "ErrorCode::ENTITY_TOO_LARGE.as_str()",
    "the close assertion": "wire.to_ascii_lowercase().contains(",
}
for label, token in required_code.items():
    if token not in body:
        fail(f"c-lim-0021 socket evidence lost {label}")

head = 'b"POST / HTTP/1.1\\r\\nHost: localhost\\r\\nContent-Length: 4096\\r\\n\\r\\n"'
if raw_body.count(head) != 1:
    fail("c-lim-0021 no longer sends only an oversized declared request head")
if raw_body.count('"HTTP/1.1 400 "') != 1:
    fail("c-lim-0021 no longer requires status 400")
if raw_body.count('"connection: close\\r\\n"') != 1:
    fail("c-lim-0021 no longer requires an observed close announcement")

print("OK: c-lim-0021 refuses an oversized declared body before it is sent and closes the real socket")
PYEOF
