#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SERVICE="${ROOT_DIR}/crates/gateway/src/service.rs"
EVIDENCE="${ROOT_DIR}/crates/gateway/tests/pipeline.rs"

fail() {
    printf 'check_governor_position: %s\n' "$1" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
[[ -f "$SERVICE" ]] || fail 'the S3Service pipeline is missing'
[[ -f "$EVIDENCE" ]] || fail 'c-lim-0040 runtime evidence is missing'

python3 - "$ROOT_DIR" "$SERVICE" "$EVIDENCE" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1]).resolve()
service_path = Path(sys.argv[2])
evidence_path = Path(sys.argv[3])


def fail(message: str) -> None:
    raise SystemExit(f"check_governor_position: {message}")


# Compiled once, then matched with an offset. Cutting a fresh `source[index:]` slice copies
# the whole remainder of the file on every character, which makes an otherwise linear masking
# pass quadratic in file length; `pattern.match(source, index)` matches at the same place
# without the copy. No pattern here carries `^`, `\A`, `\b` or a lookbehind, so anchoring at
# the offset is exactly what slicing to it already meant. Each `.end()` is now an absolute
# offset into `source`.
RAW_STRING_RE = re.compile(r'(?:b)?r(#{0,255})"')
IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def rust_code(source: str, path: Path) -> str:
    code = list(source)
    index = 0

    def mask(start: int, end: int) -> None:
        for position in range(start, end):
            if source[position] != "\n":
                code[position] = " "

    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = len(source) if end < 0 else end
            mask(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            depth, end = 1, index + 2
            while end < len(source) and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                fail(f"{path.relative_to(root)} has an unterminated block comment")
            mask(index, end)
            index = end
            continue
        raw = RAW_STRING_RE.match(source, index)
        if raw:
            delimiter = '"' + raw.group(1)
            close = source.find(delimiter, raw.end())
            if close < 0:
                fail(f"{path.relative_to(root)} has an unterminated raw string")
            end = close + len(delimiter)
            mask(index, end)
            index = end
            continue
        prefix = 2 if source.startswith('b"', index) else 1 if source[index:index + 1] == '"' else 0
        if prefix:
            end, escaped = index + prefix, False
            while end < len(source):
                char = source[end]
                end += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    break
            else:
                fail(f"{path.relative_to(root)} has an unterminated string")
            mask(index, end)
            index = end
            continue
        byte_character = source.startswith("b'", index)
        if byte_character or source[index:index + 1] == "'":
            quote = index + 1 if byte_character else index
            body = quote + 1
            identifier = IDENTIFIER_RE.match(source, body)
            if not byte_character and identifier and source[identifier.end():identifier.end() + 1] != "'":
                index = identifier.end()
                continue
            end, escaped = body, False
            while end < len(source) and source[end] != "\n":
                char = source[end]
                end += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "'":
                    mask(index, end)
                    index = end
                    break
            else:
                fail(f"{path.relative_to(root)} has an unterminated character literal")
            continue
        index += 1
    return "".join(code)


def balanced_end(code: str, opening: int, path: Path) -> int:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [code[opening]]
    position = opening + 1
    while position < len(code) and stack:
        char = code[position]
        if char in pairs:
            stack.append(char)
        elif char in pairs.values():
            if pairs[stack[-1]] != char:
                fail(f"{path.relative_to(root)} has mismatched Rust delimiters")
            stack.pop()
        position += 1
    if stack:
        fail(f"{path.relative_to(root)} has an unterminated Rust delimiter")
    return position


def function(code: str, pattern: str, path: Path, description: str) -> str:
    matches = list(re.finditer(pattern, code))
    if len(matches) != 1:
        fail(f"{description} is missing or duplicated")
    opening = code.find("{", matches[0].end())
    if opening < 0:
        fail(f"{description} has no function body")
    return code[matches[0].start():balanced_end(code, opening, path)]


try:
    service_source = service_path.read_text(encoding="utf-8")
    evidence_source = evidence_path.read_text(encoding="utf-8")
except (OSError, UnicodeError) as error:
    fail(f"cannot read a guard input: {error}")

service = function(
    rust_code(service_source, service_path),
    r"\basync\s+fn\s+run\s*<B\s*,\s*M>\s*\(",
    service_path,
    "the S3Service request pipeline",
)
markers = (
    ("routed stage", r"let\s+config\s*=\s*config\.routed\(\)\s*;"),
    ("governor call", r"\.governor\s*\.try_acquire\s*\("),
    ("governed stage", r"let\s+config\s*=\s*config\.governed\(\)\s*;"),
    ("sealed body", r"SealedBody::seal\s*\("),
    ("body read", r"\bsealed\s*\.read\s*\("),
    ("body-read stage", r"state\.config\.body_read\(\)"),
)
positions = []
for description, pattern in markers:
    found = list(re.finditer(pattern, service))
    if len(found) != 1:
        fail(f"c-lim-0039 {description} is missing or duplicated in the real request pipeline")
    positions.append(found[0].start())
if positions != sorted(positions):
    fail("c-lim-0039 governor must remain after routing and before every body-read boundary")

evidence = function(
    rust_code(evidence_source, evidence_path),
    r"\basync\s+fn\s+c_lim_0040_refusing_governor_answers_before_the_body_is_read\s*\(\s*\)",
    evidence_path,
    "c-lim-0040 runtime evidence",
)
signature = "async fn c_lim_0040_refusing_governor_answers_before_the_body_is_read() {"
lines = rust_code(evidence_source, evidence_path).splitlines()
if lines.count(signature) != 1:
    fail("c-lim-0040 active runtime evidence is missing or duplicated")
index = lines.index(signature)
attributes = []
cursor = index - 1
while cursor >= 0 and lines[cursor].startswith("#["):
    attributes.append(lines[cursor])
    cursor -= 1
if attributes != ["#[tokio::test]"]:
    fail("c-lim-0040 must be one unconditional tokio test")
required = (
    ("refusing governor", r"\.governor\s*\(\s*RefuseEverything\s*\)"),
    ("counted body", r"CountingBody::new\s*\("),
    ("503 refusal", r"assert_eq!\s*\(\s*response\.status\(\)\s*,\s*http::StatusCode::SERVICE_UNAVAILABLE\s*\)"),
    ("zero body reads", r"assert_eq!\s*\(\s*read\.load\s*\(\s*Ordering::SeqCst\s*\)\s*,\s*0\s*,"),
)
for description, pattern in required:
    if len(re.findall(pattern, evidence)) != 1:
        fail(f"c-lim-0040 runtime evidence lost its {description}")

print("OK: c-lim-0039 fixes governor position; c-lim-0040 observes refusal before zero body reads")
PY
