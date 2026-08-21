#!/usr/bin/env bash
set -euo pipefail

# Checks the P3-01 capability boundary: the HTTP crate consumes the raw request,
# exposes only WireRequest views, and no downstream production module accepts a
# raw http::Request again. HeaderMap and Uri remain legal as internal projections
# and response types; the boundary is about the inbound request capability.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

python3 - "$ROOT" <<'PYEOF'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
wire_path = root / "crates/http/src/wire.rs"
if not wire_path.is_file():
    raise SystemExit("check_wire_boundary: required input is missing: crates/http/src/wire.rs")


def source_without_comments_or_literals(text: str) -> str:
    out: list[str] = []
    index = 0
    block_depth = 0
    quote = ""
    while index < len(text):
        pair = text[index:index + 2]
        char = text[index]
        if block_depth:
            if pair == "/*":
                block_depth += 1
                index += 2
            elif pair == "*/":
                block_depth -= 1
                index += 2
            else:
                out.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if quote:
            if char == "\\":
                out.extend((" ", " "))
                index += 2
            elif char == quote:
                out.append(" ")
                quote = ""
                index += 1
            else:
                out.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if pair == "//":
            newline = text.find("\n", index)
            if newline == -1:
                out.extend(" " * (len(text) - index))
                break
            out.extend(" " * (newline - index))
            index = newline
            continue
        if pair == "/*":
            block_depth = 1
            out.extend((" ", " "))
            index += 2
            continue
        if char == '"':
            quote = char
            out.append(" ")
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


wire = source_without_comments_or_literals(wire_path.read_text())
accept = "pub fn accept(request: Request<B>, limits: &Limits) -> Result<Self, WireReject>"
if wire.count(accept) != 1:
    raise SystemExit("check_wire_boundary: WireRequest::accept no longer consumes exactly one Request<B> by value")
if wire.count("request.into_parts()") != 1:
    raise SystemExit("check_wire_boundary: the consumed request is not split exactly once inside acceptance")
if re.search(r"\bpub\s+(?:const\s+)?fn\s+into_parts\b", wire):
    raise SystemExit("check_wire_boundary: WireRequest exposes an into_parts escape hatch")

struct_match = re.search(r"pub\s+struct\s+WireRequest\s*<[^>]+>\s*\{(?P<body>.*?)\n\}", wire, re.S)
if struct_match is None:
    raise SystemExit("check_wire_boundary: WireRequest struct could not be located")
for line in struct_match.group("body").splitlines():
    field = line.strip()
    if field and ":" in field and re.match(r"pub(?:\([^)]*\))?\s+", field):
        raise SystemExit(f"check_wire_boundary: WireRequest exposes a raw field: {field}")

for match in re.finditer(r"\bpub\s+(?:const\s+)?fn\s+", wire):
    signature_end = wire.find("{", match.start())
    if signature_end == -1:
        raise SystemExit("check_wire_boundary: public function signature has no body")
    signature = wire[match.start():signature_end]
    returns = signature.partition("->")[2]
    if re.search(r"\b(?:HeaderMap|Uri|Parts)\b|\bRequest\s*<", returns):
        compact = " ".join(signature.split())
        raise SystemExit(f"check_wire_boundary: public API returns a raw request capability: {compact}")

production_files: list[Path] = []
for crate in ("core", "sig", "types"):
    source_root = root / f"crates/{crate}/src"
    if not source_root.is_dir():
        raise SystemExit(f"check_wire_boundary: required input is missing: crates/{crate}/src")
    for path in source_root.rglob("*.rs"):
        if path.name == "tests.rs" or path.name.endswith("_tests.rs") or "tests" in path.parts:
            continue
        production_files.append(path)

raw_request = re.compile(
    r"\bhttp\s*::\s*Request\b"
    r"|\buse\s+http\s*::\s*Request\b"
    r"|\buse\s+http\s*::\s*\{[^}]*\bRequest\b[^}]*\}"
    r"|\bRequest\s*<"
)
for path in production_files:
    source = source_without_comments_or_literals(path.read_text())
    if raw_request.search(source):
        relative = path.relative_to(root)
        raise SystemExit(f"check_wire_boundary: downstream production code regains a raw request: {relative}")

print("OK: WireRequest consumes the raw request and no downstream production API regains it")
PYEOF
