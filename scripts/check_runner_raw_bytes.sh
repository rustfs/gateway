#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# WHAT THIS CHECKS
#   The conformance runner keeps a raw TCP request path, writes the declared
#   byte slice directly, and does not acquire an HTTP or S3 client dependency.
#   A TLS record layer is not such a client: it carries the same bytes.
#
# WHY
#   P8-01 cases include malformed framing. A client library would normalise the
#   bytes before the system under test could observe the defect.
#
# HOW TO EXEMPT
#   There is no exemption. A higher-level client may support setup, but the case
#   request itself must retain the raw socket path checked here.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
MANIFEST="${REPO_DIR}/crates/conformance/Cargo.toml"
SOCKET="${REPO_DIR}/crates/conformance/src/socket.rs"
CONN="${REPO_DIR}/crates/conformance/src/conn.rs"

if [[ ! -f "$MANIFEST" || ! -f "$SOCKET" || ! -f "$CONN" ]]; then
    printf 'check_runner_raw_bytes: runner manifest, conn source, or socket source is missing\n' >&2
    exit 1
fi

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_runner_raw_bytes)" || exit 1
"$PYTHON" - "$MANIFEST" "$SOCKET" "$CONN" <<'PYEOF'
import pathlib
import re
import sys
import tomllib

manifest_path, socket_path, conn_path = map(pathlib.Path, sys.argv[1:])

try:
    manifest = tomllib.loads(manifest_path.read_text())
    socket_source = socket_path.read_text()
    conn_source = conn_path.read_text()
except (OSError, tomllib.TOMLDecodeError) as error:
    print(f"check_runner_raw_bytes: {error}", file=sys.stderr)
    raise SystemExit(1)

# `rustls` and `webpki-roots` are the TLS record layer and its public trust anchors. They carry the
# authored bytes opaquely and parse no HTTP, so they cannot normalise the malformed framing a
# negative case exists to send; every other addition still has to be argued for here. `rcgen` only
# mints the throwaway certificate the production listener serves when a case declares
# `[connection.tls]`; it never sees a request byte.
allowed_dependencies = {"rustfs-gateway", "bytes", "http", "http-body", "tokio", "rustls", "webpki-roots", "rcgen"}
dependencies = manifest.get("dependencies", {})
if not isinstance(dependencies, dict):
    print("check_runner_raw_bytes: [dependencies] must be a table", file=sys.stderr)
    raise SystemExit(1)

actual_dependencies = set(dependencies)
if actual_dependencies != allowed_dependencies:
    unexpected = sorted(actual_dependencies - allowed_dependencies)
    missing = sorted(allowed_dependencies - actual_dependencies)
    if unexpected:
        print(
            "check_runner_raw_bytes: unlisted dependency can normalize case bytes: " + ", ".join(unexpected),
            file=sys.stderr,
        )
    if missing:
        print(
            "check_runner_raw_bytes: expected facade dependency is missing: " + ", ".join(missing),
            file=sys.stderr,
        )
    raise SystemExit(1)


def strip_non_code(source):
    """Replace Rust comments and string contents with spaces, preserving offsets."""
    output = list(source)
    index = 0
    length = len(source)
    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = length if end < 0 else end
            output[index:end] = " " * (end - index)
            index = end
            continue
        if source.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < length and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            output[index:end] = ["\n" if char == "\n" else " " for char in source[index:end]]
            index = end
            continue

        prefix_end = index
        if source.startswith("br", index):
            prefix_end = index + 2
        elif source.startswith("r", index):
            prefix_end = index + 1
        if prefix_end != index:
            quote = prefix_end
            while quote < length and source[quote] == "#":
                quote += 1
            if quote < length and source[quote] == '"':
                hashes = quote - prefix_end
                marker = '"' + ("#" * hashes)
                end = source.find(marker, quote + 1)
                end = length if end < 0 else end + len(marker)
                output[index:end] = ["\n" if char == "\n" else " " for char in source[index:end]]
                index = end
                continue

        if source[index] == '"':
            end = index + 1
            escaped = False
            while end < length:
                char = source[end]
                if char == '"' and not escaped:
                    end += 1
                    break
                if char == "\\" and not escaped:
                    escaped = True
                else:
                    escaped = False
                end += 1
            output[index:end] = ["\n" if char == "\n" else " " for char in source[index:end]]
            index = end
            continue
        index += 1
    return "".join(output)


def function_body(source, signature, label):
    match = re.search(signature, source)
    if match is None:
        print(f"check_runner_raw_bytes: {label} is missing", file=sys.stderr)
        raise SystemExit(1)
    opening = source.find("{", match.end())
    if opening < 0:
        print(f"check_runner_raw_bytes: {label} has no body", file=sys.stderr)
        raise SystemExit(1)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    print(f"check_runner_raw_bytes: {label} has an unterminated body", file=sys.stderr)
    raise SystemExit(1)


socket_code = strip_non_code(socket_source)
conn_code = strip_non_code(conn_source)

open_body = function_body(
    socket_code,
    r"pub\s+fn\s+open\s*\(\s*addr\s*:\s*SocketAddr\s*\)",
    "Connection::open",
)
if re.search(r"TcpStream\s*::\s*connect\s*\(\s*addr\s*\)", open_body) is None:
    print("check_runner_raw_bytes: Connection::open does not open raw TCP", file=sys.stderr)
    raise SystemExit(1)

write_body = function_body(
    socket_code,
    r"pub\s+fn\s+write\s*\(\s*&mut\s+self\s*,\s*bytes\s*:\s*&\s*\[\s*u8\s*\]\s*\)",
    "Connection::write",
)
if re.search(r"self\s*\.\s*stream\s*\.\s*write_all\s*\(\s*bytes\s*\)", write_body) is None:
    print("check_runner_raw_bytes: Connection::write does not write its byte slice verbatim", file=sys.stderr)
    raise SystemExit(1)

payload_body = function_body(
    socket_code,
    r"pub\s+fn\s+write_body\s*\(\s*&mut\s+self\s*,\s*bytes\s*:\s*&\s*\[\s*u8\s*\]\s*\)",
    "Connection::write_body",
)
if re.search(r"self\s*\.\s*write\s*\(\s*bytes\s*\)\s*\?", payload_body) is None:
    print("check_runner_raw_bytes: Connection::write_body does not forward its chunk bytes", file=sys.stderr)
    raise SystemExit(1)

if re.search(r"connection\s*\.\s*write\s*\(\s*&\s*head\s*\.\s*bytes\s*\)\s*\?", conn_code) is None:
    print("check_runner_raw_bytes: conn transport does not pass the case head to Connection::write", file=sys.stderr)
    raise SystemExit(1)
if re.search(r"connection\s*\.\s*write_body\s*\(\s*bytes\s*\)\s*\?", conn_code) is None:
    print("check_runner_raw_bytes: conn transport does not pass data chunks to Connection::write_body", file=sys.stderr)
    raise SystemExit(1)
PYEOF

printf 'OK: runner sends raw bytes (no SDK client)\n'
