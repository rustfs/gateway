#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_expired_token_construction.sh
#
# WHAT THIS CHECKS
#   Enforces that `AuthError::ExpiredToken` is constructed in exactly one place
#   in production Rust code: `PendingSessionRefusal::answer(&SignatureMatch)` in
#   `crates/gateway/src/ext/session_answer.rs`.
#
#   1. Both authority files (`crates/gateway/src/ext/session_answer.rs` and
#      `crates/sig/src/verdict.rs`) exist and are regular files.
#   2. `crates/gateway/src/ext/session_answer.rs` retains the proof-gated
#      `PendingSessionRefusal::answer(self, _: &SignatureMatch) -> AuthError`
#      method and contains exactly one non-test `ExpiredToken` token, strictly
#      inside `answer`'s body.
#   3. `crates/sig/src/verdict.rs` contains `ExpiredToken` only as the enum
#      variant declaration in `AuthError` and its two `Self::ExpiredToken =>`
#      match arms in `AuthError::code` and `AuthError::message` — never in a
#      constructor or conversion returning the variant.
#   4. Every other non-test Rust source under `crates/`, `xtask/`, and `compat/`
#      contains zero non-comment, non-string, non-`#[cfg(test)]` `ExpiredToken`
#      tokens (catching direct `AuthError::ExpiredToken`, `use` imports, and
#      type aliases alike).
#
# WHY
#   `rustfs/gateway#1575` restricts `400 ExpiredToken` to callers that proved
#   possession of the session secret and issued token via a constant-time
#   `SignatureMatch`. `rustfs/gateway#1584` closes the residual where a future
#   edit could construct `AuthError::ExpiredToken` directly outside
#   `PendingSessionRefusal::answer`, bypassing the proof and turning expired
#   sessions into an access-key existence oracle.
#
# HOW TO EXEMPT
#   There is no exemption. Any path that may report an expired session must
#   obtain a `PendingSessionRefusal` from `Credentials` and pass a verified
#   `&SignatureMatch` to `PendingSessionRefusal::answer`.
#
# USAGE
#   scripts/check_expired_token_construction.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_expired_token_construction.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_expired_token_construction)" || exit 1

"$PYTHON" - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
session_answer = root / "crates/gateway/src/ext/session_answer.rs"
verdict_file = root / "crates/sig/src/verdict.rs"


def fail(message: str) -> None:
    print(f"check_expired_token_construction: {message}", file=sys.stderr)
    raise SystemExit(1)


for required, label in (
    (session_answer, "crates/gateway/src/ext/session_answer.rs"),
    (verdict_file, "crates/sig/src/verdict.rs"),
):
    if not required.is_file() or required.is_symlink():
        fail(f"required input is missing: {label}")

if not (root / "crates").is_dir():
    fail("required input is missing: crates")

RAW_STRING_RE = re.compile(r'(?:b|c)?r(#*)"')
LIFETIME_RE = re.compile(r"'[A-Za-z_][A-Za-z0-9_]*(?!')")
EXPIRED_TOKEN_RE = re.compile(r"\bExpiredToken\b")


def mask_rust(source: str) -> str:
    """Blank comments and string/char literals while preserving exact byte offsets and newlines."""
    chars = list(source)
    length = len(source)
    index = 0

    def blank(start: int, end: int) -> None:
        for offset in range(start, end):
            if chars[offset] != "\n":
                chars[offset] = " "

    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = length if end < 0 else end
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                fail("unterminated block comment")
            blank(start, index)
            continue
        raw = RAW_STRING_RE.match(source, index)
        if raw:
            start = index
            marker = '"' + raw.group(1)
            end = source.find(marker, raw.end())
            if end < 0:
                fail("unterminated raw string")
            index = end + len(marker)
            blank(start, index)
            continue
        lifetime = LIFETIME_RE.match(source, index)
        if lifetime:
            index = lifetime.end()
            continue
        quote = index + 1 if source[index] in "bc" and index + 1 < length else index
        if source[quote] in "\"'":
            start = index
            delimiter = source[quote]
            cursor = quote + 1
            while cursor < length:
                if source[cursor] == "\\":
                    cursor += 2
                elif source[cursor] == delimiter:
                    cursor += 1
                    break
                else:
                    cursor += 1
            else:
                fail("unterminated literal")
            blank(start, cursor)
            index = cursor
            continue
        index += 1
    return "".join(chars)


def strip_cfg_test_items(masked: str) -> str:
    """Blank every `#[cfg(test)]` item (braced block or bodyless declaration), keeping newlines."""
    chars = list(masked)
    length = len(masked)

    def blank(start: int, end: int) -> None:
        for offset in range(start, end):
            if chars[offset] != "\n":
                chars[offset] = " "

    for marker in re.finditer(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]", masked):
        brace = masked.find("{", marker.end())
        semicolon = masked.find(";", marker.end())
        if brace < 0 and semicolon < 0:
            continue
        if brace < 0 or (0 <= semicolon < brace):
            blank(marker.start(), semicolon + 1)
            continue
        depth = 0
        cursor = brace
        while cursor < length:
            if masked[cursor] == "{":
                depth += 1
            elif masked[cursor] == "}":
                depth -= 1
                if depth == 0:
                    cursor += 1
                    break
            cursor += 1
        blank(marker.start(), cursor)
    return "".join(chars)


def brace_span(masked: str, header_end: int, label: str) -> tuple[int, int]:
    opening = masked.find("{", header_end)
    if opening < 0:
        fail(f"{label} has no body")
    depth = 0
    for cursor in range(opening, len(masked)):
        if masked[cursor] == "{":
            depth += 1
        elif masked[cursor] == "}":
            depth -= 1
            if depth == 0:
                return opening, cursor + 1
    fail(f"{label} has an unterminated body")
    raise AssertionError("unreachable")


# 1. Verify the sole construction site in crates/gateway/src/ext/session_answer.rs.
try:
    session_source = session_answer.read_text(encoding="utf-8")
except (OSError, UnicodeError) as error:
    fail(f"cannot read session_answer.rs: {error}")

session_prod = strip_cfg_test_items(mask_rust(session_source))
if re.search(r"\b(?:struct|enum|type|trait)\s+SignatureMatch\b", session_prod):
    fail("crates/gateway/src/ext/session_answer.rs must not shadow SignatureMatch")
impl_matches = list(re.finditer(r"\bimpl\s+PendingSessionRefusal\b", session_prod))
if len(impl_matches) != 1:
    fail("crates/gateway/src/ext/session_answer.rs must define exactly one `impl PendingSessionRefusal` block")
impl_start, impl_end = brace_span(session_prod, impl_matches[0].end(), "impl PendingSessionRefusal")
answer_re = re.compile(
    r"\bpub\s+(?:const\s+)?fn\s+answer\s*\(\s*self\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s*&\s*(?:[A-Za-z0-9_:]+::)?SignatureMatch\s*\)\s*->\s*(?:[A-Za-z0-9_:]+::)?AuthError\b"
)
answer_matches = list(answer_re.finditer(session_prod))
if len(answer_matches) != 1 or not (impl_start < answer_matches[0].start() and answer_matches[0].end() < impl_end):
    fail(
        "crates/gateway/src/ext/session_answer.rs must define exactly one proof-gated "
        "`pub const fn answer(self, _: &SignatureMatch) -> AuthError` entry inside `impl PendingSessionRefusal`"
    )
answer_start, answer_end = brace_span(session_prod, answer_matches[0].end(), "PendingSessionRefusal::answer")
session_hits = list(EXPIRED_TOKEN_RE.finditer(session_prod))
if len(session_hits) != 1:
    fail(
        f"crates/gateway/src/ext/session_answer.rs has {len(session_hits)} non-test ExpiredToken "
        "token(s); expected exactly 1 inside PendingSessionRefusal::answer"
    )
hit = session_hits[0]
if not (answer_start < hit.start() and hit.end() < answer_end):
    line = session_source.count("\n", 0, hit.start()) + 1
    fail(
        f"crates/gateway/src/ext/session_answer.rs:{line}: ExpiredToken outside "
        "PendingSessionRefusal::answer(&SignatureMatch)"
    )

# 2. Verify crates/sig/src/verdict.rs only declares the variant and matches it in code()/message().
try:
    verdict_source = verdict_file.read_text(encoding="utf-8")
except (OSError, UnicodeError) as error:
    fail(f"cannot read verdict.rs: {error}")

verdict_prod = strip_cfg_test_items(mask_rust(verdict_source))
enum_matches = list(re.finditer(r"\bpub\s+enum\s+AuthError\b", verdict_prod))
code_matches = list(re.finditer(r"\bpub\s+const\s+fn\s+code\s*\(\s*&self\s*\)\s*->\s*&'static\s+str\b", verdict_prod))
message_matches = list(re.finditer(r"\bpub\s+const\s+fn\s+message\s*\(\s*&self\s*\)\s*->\s*&'static\s+str\b", verdict_prod))
if len(enum_matches) != 1 or len(code_matches) != 1 or len(message_matches) != 1:
    fail("crates/sig/src/verdict.rs is missing AuthError enum, code(), or message()")

enum_span = brace_span(verdict_prod, enum_matches[0].end(), "enum AuthError")
code_span = brace_span(verdict_prod, code_matches[0].end(), "AuthError::code")
message_span = brace_span(verdict_prod, message_matches[0].end(), "AuthError::message")

verdict_hits = list(EXPIRED_TOKEN_RE.finditer(verdict_prod))
seen_enum = 0
seen_code = 0
seen_message = 0
for match in verdict_hits:
    pos = match.start()
    line = verdict_source.count("\n", 0, pos) + 1
    after = verdict_prod[match.end() : match.end() + 40].lstrip()
    before = verdict_prod[max(0, pos - 40) : pos].rstrip()
    if enum_span[0] < pos < enum_span[1] and after.startswith(","):
        seen_enum += 1
    elif code_span[0] < pos < code_span[1] and before.endswith("Self::") and after.startswith("=>"):
        seen_code += 1
    elif message_span[0] < pos < message_span[1] and before.endswith("Self::") and after.startswith("=>"):
        seen_message += 1
    else:
        fail(
            f"crates/sig/src/verdict.rs:{line}: unexpected ExpiredToken reference outside the enum "
            "declaration and code()/message() match arms"
        )

if (seen_enum, seen_code, seen_message) != (1, 1, 1):
    fail(
        "crates/sig/src/verdict.rs ExpiredToken census drifted "
        f"(enum={seen_enum}, code={seen_code}, message={seen_message}; expected 1, 1, 1)"
    )

# 3. Scan every other non-test Rust source under crates/, xtask/, and compat/.
scan_roots = [root / name for name in ("crates", "xtask", "compat") if (root / name).is_dir()]
scanned = 0
violations: list[str] = []
for scan_root in scan_roots:
    for dirpath, dirnames, filenames in os.walk(scan_root):
        dirnames[:] = sorted(d for d in dirnames if d not in ("generated", "target", "tests", ".git"))
        for name in sorted(filenames):
            if not name.endswith(".rs"):
                continue
            if name == "tests.rs" or name.endswith("_tests.rs"):
                continue
            path = Path(dirpath) / name
            relative = path.relative_to(root).as_posix()
            if relative in ("crates/gateway/src/ext/session_answer.rs", "crates/sig/src/verdict.rs"):
                continue
            if not path.is_file():
                continue
            scanned += 1
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                fail(f"cannot read {relative}: {error}")
            if "ExpiredToken" not in text:
                continue
            prod = strip_cfg_test_items(mask_rust(text))
            for match in EXPIRED_TOKEN_RE.finditer(prod):
                line = text.count("\n", 0, match.start()) + 1
                violations.append(
                    f"{relative}:{line}: AuthError::ExpiredToken may only be constructed in "
                    "crates/gateway/src/ext/session_answer.rs inside PendingSessionRefusal::answer(&SignatureMatch)"
                )

if scanned == 0:
    fail("no non-test Rust sources were scanned")

if violations:
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)

print(
    "OK: AuthError::ExpiredToken is constructed only in "
    f"crates/gateway/src/ext/session_answer.rs::PendingSessionRefusal::answer ({scanned} other production files scanned)"
)
PY
