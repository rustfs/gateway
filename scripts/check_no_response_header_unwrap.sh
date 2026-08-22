#!/usr/bin/env bash
set -euo pipefail

# A response header value can contain storage or request bytes. Turning the
# HTTP grammar check into expect/unwrap makes malformed input a remote panic.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if ! command -v python3 >/dev/null 2>&1; then
    printf 'check_no_response_header_unwrap: required command is missing: python3\n' >&2
    exit 1
fi

python3 - "$ROOT_DIR" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
source_roots = [root / "crates/core/src", root / "crates/gateway/src"]
required = {
    "crates/core/src/codec/response.rs": (
        "pub fn set_header",
        "pub fn set_prefixed_header",
        "pub fn override_header_value",
    ),
    "crates/gateway/src/render.rs": ("pub fn render",),
    "crates/gateway/src/invariants.rs": ("pub(crate) fn enforce",),
}

for directory in source_roots:
    if not directory.is_dir():
        print(
            f"check_no_response_header_unwrap: required input is missing: {directory.relative_to(root)}",
            file=sys.stderr,
        )
        raise SystemExit(1)

for relative, markers in required.items():
    path = root / relative
    if not path.is_file():
        print(f"check_no_response_header_unwrap: required input is missing: {relative}", file=sys.stderr)
        raise SystemExit(1)
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if text.count(marker) != 1:
            print(
                f"check_no_response_header_unwrap: {relative} must contain exactly one `{marker}`; "
                "the response-header authority moved and this guard was not updated",
                file=sys.stderr,
            )
            raise SystemExit(1)

RAW_STRING = re.compile(r'(?:b|c)?r(#*)"')
CHAR_LITERAL = re.compile(r"'(?:\\.|[^'\\])'")


def mask(text: str) -> str:
    """Blank comments and literals while preserving offsets and newlines."""
    out = list(text)
    index = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, min(end, len(out))):
            if out[position] != "\n":
                out[position] = " "

    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = len(text) if end < 0 else end
            blank(index, end)
            index = end
            continue
        if text.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < len(text) and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise ValueError("unterminated block comment")
            blank(index, end)
            index = end
            continue
        raw = RAW_STRING.match(text, index)
        if raw:
            delimiter = '"' + raw.group(1)
            close = text.find(delimiter, raw.end())
            if close < 0:
                raise ValueError("unterminated raw string")
            end = close + len(delimiter)
            blank(index, end)
            index = end
            continue
        quote = index + 1 if text[index] in "bc" and index + 1 < len(text) else index
        if text[quote] == '"':
            end = quote + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                elif text[end] == '"':
                    end += 1
                    break
                else:
                    end += 1
            else:
                raise ValueError("unterminated string literal")
            blank(index, end)
            index = end
            continue
        char = CHAR_LITERAL.match(text, index)
        if char:
            blank(index, char.end())
            index = char.end()
            continue
        index += 1
    return "".join(out)


def balanced_end(code: str, opening: int) -> int:
    depth = 0
    for position in range(opening, len(code)):
        if code[position] == "{":
            depth += 1
        elif code[position] == "}":
            depth -= 1
            if depth == 0:
                return position
    raise ValueError("unbalanced item body")


def cfg_test_spans(code: str) -> list[tuple[int, int]]:
    spans = []
    for marker in re.finditer(r"#\[cfg\(test\)\]", code):
        opening = code.find("{", marker.end())
        terminator = code.find(";", marker.end())
        if opening < 0 and terminator < 0:
            raise ValueError("cfg(test) item has no terminator")
        if opening < 0 or (0 <= terminator < opening):
            spans.append((marker.start(), terminator))
        else:
            spans.append((marker.start(), balanced_end(code, opening)))
    return spans


def covered(position: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= position <= end for start, end in spans)


HEADER_WRITE = re.compile(
    r"\bheaders(?:_mut\s*\(\s*\))?\s*\.\s*(?:insert|append)\s*\("
    r"|\.\s*(?:set_header|set_prefixed_header)\s*\("
)
PANIC = re.compile(r"\.\s*(?:unwrap|expect)\s*\(")
FUNCTION = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\b")

violations = []
function_count = 0
subject_count = 0
files = sorted(
    {
        path
        for directory in source_roots
        for path in directory.rglob("*.rs")
        if path.name != "tests.rs" and not path.name.endswith("_tests.rs") and "tests" not in path.parts
    }
)
if not files:
    print("check_no_response_header_unwrap: no Rust source is visible", file=sys.stderr)
    raise SystemExit(1)

for path in files:
    try:
        text = path.read_text(encoding="utf-8")
        code = mask(text)
        test_spans = cfg_test_spans(code)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"check_no_response_header_unwrap: cannot scan {path.relative_to(root)}: {error}", file=sys.stderr)
        raise SystemExit(1)

    header_types = {"HeaderValue"}
    header_types.update(re.findall(r"\bHeaderValue\s+as\s+([A-Za-z_][A-Za-z0-9_]*)", code))
    header_types.update(
        re.findall(
            r"\btype\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*HeaderValue\b",
            code,
        )
    )
    type_names = "|".join(sorted(map(re.escape, header_types), key=len, reverse=True))
    header_type = re.compile(rf"\b(?:{type_names})\b")
    header_parse = re.compile(
        rf"\b(?:{type_names})\s*::\s*(?:from_bytes|from_str|try_from)\s*\("
        rf"|\.\s*parse\s*::\s*<\s*(?:{type_names})\s*>\s*\("
    )

    for function in FUNCTION.finditer(code):
        if covered(function.start(), test_spans):
            continue
        opening = code.find("{", function.end())
        terminator = code.find(";", function.end())
        if opening < 0 or (0 <= terminator < opening):
            continue
        try:
            end = balanced_end(code, opening)
        except ValueError as error:
            print(f"check_no_response_header_unwrap: cannot scan {path.relative_to(root)}: {error}", file=sys.stderr)
            raise SystemExit(1)
        function_count += 1
        body = code[opening : end + 1]
        signature = code[function.start() : opening]
        parses_header = header_parse.search(body) is not None
        writes_header = HEADER_WRITE.search(body) is not None
        returns_header = header_type.search(signature) is not None
        if not parses_header and not writes_header and not returns_header:
            continue
        subject_count += 1
        panic = PANIC.search(body)
        if panic is None:
            continue
        line = text.count("\n", 0, opening + panic.start()) + 1
        violations.append(
            f"{path.relative_to(root)}:{line}: panic-capable response header construction in "
            f"`{function.group(1)}`; propagate or handle the HeaderValue rejection"
        )

if function_count == 0 or subject_count == 0:
    print(
        "check_no_response_header_unwrap: found no response-header construction subject; "
        "a guard with no input must fail",
        file=sys.stderr,
    )
    raise SystemExit(1)

if violations:
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)

print(
    f"OK: response header construction has no unwrap/expect "
    f"({len(files)} file(s), {subject_count} subject function(s))"
)
PY
