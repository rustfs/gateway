#!/usr/bin/env python3
"""Lexically inspect Rust trait declarations for the operation-registry policies."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path


def fail(prefix: str, message: str) -> None:
    print(f"{prefix}: {message}", file=sys.stderr)
    raise SystemExit(1)


def mask_rust(source: str) -> str:
    """Preserve code and newlines while blanking comments and string/character literals."""

    raw_pattern = re.compile(r'(?:b?r)(?P<hashes>#{0,255})"')
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
            if end < 0:
                end = length
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
                raise ValueError("unterminated block comment")
            blank(start, index)
            continue

        raw = raw_pattern.match(source, index) if source[index] in "br" else None
        if raw:
            start = index
            hashes = raw.group("hashes")
            index = raw.end()
            terminator = '"' + hashes
            end = source.find(terminator, index)
            if end < 0:
                raise ValueError("unterminated raw string")
            index = end + len(terminator)
            blank(start, index)
            continue

        quote_offset = 1 if source.startswith('b"', index) else 0
        if source[index + quote_offset : index + quote_offset + 1] == '"':
            start = index
            index += quote_offset + 1
            escaped = False
            while index < length:
                char = source[index]
                index += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    break
            else:
                raise ValueError("unterminated string")
            blank(start, index)
            continue

        # A lifetime begins with an apostrophe too, so only mask a character literal when a
        # closing apostrophe occurs before whitespace or an identifier can continue.
        if source[index] == "'":
            closing = index + 1
            escaped = False
            while closing < min(length, index + 12):
                char = source[closing]
                if not escaped and char == "'":
                    closing += 1
                    blank(index, closing)
                    index = closing
                    break
                if not escaped and (char.isspace() or char in "(){}[];,."):
                    break
                escaped = not escaped and char == "\\"
                if char != "\\":
                    escaped = False
                closing += 1
            else:
                index += 1
            if index == closing:
                continue

        index += 1

    return "".join(chars)


def rust_sources(root: Path, prefix: str) -> list[Path]:
    crates = root / "crates"
    if not crates.is_dir():
        fail(prefix, "required source directory is missing: crates")
    try:
        listed = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "crates"],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        fail(prefix, f"cannot enumerate Rust inputs: {error}")

    paths = []
    for item in listed.split(b"\0"):
        if not item:
            continue
        relative = Path(os.fsdecode(item))
        if relative.suffix != ".rs" or "generated" in relative.parts:
            continue
        paths.append(relative)
    paths.sort()
    if not paths:
        fail(prefix, "no non-generated Rust source found under crates")
    return paths


def traits(masked: str) -> list[tuple[str, int, int, int]]:
    found = []
    cursor = 0
    pattern = re.compile(r"\btrait\s+([A-Za-z_][A-Za-z0-9_]*)")
    while match := pattern.search(masked, cursor):
        opening = masked.find("{", match.end())
        if opening < 0:
            raise ValueError(f"trait {match.group(1)} has no body")
        depth = 1
        closing = opening + 1
        while closing < len(masked) and depth:
            if masked[closing] == "{":
                depth += 1
            elif masked[closing] == "}":
                depth -= 1
            closing += 1
        if depth:
            raise ValueError(f"trait {match.group(1)} has an unterminated body")
        found.append((match.group(1), match.start(), opening, closing - 1))
        cursor = closing
    return found


def inspect(root: Path, rule: str) -> None:
    prefix = "check_no_bundle_trait" if rule == "no-bundle" else "check_dyn_policy"
    violations: list[tuple[Path, int, str]] = []
    authorities = {
        (Path("crates/core/src/handler.rs"), "Handler"): 0,
        (Path("crates/core/src/op.rs"), "Operation"): 0,
    }
    sources = rust_sources(root, prefix)

    for relative in sources:
        path = root / relative
        try:
            source = path.read_text(encoding="utf-8")
            masked = mask_rust(source)
            declarations = traits(masked)
        except (OSError, UnicodeError, ValueError) as error:
            fail(prefix, f"cannot inspect {relative}: {error}")

        if rule == "dyn-policy":
            for macro in re.finditer(r"(?:\basync_trait\s*::\s*)?\basync_trait\b", masked):
                line = source.count("\n", 0, macro.start()) + 1
                violations.append((relative, line, "async_trait is forbidden; write BoxFuture explicitly"))

        for name, start, opening, closing in declarations:
            authority = (relative, name)
            if authority in authorities:
                authorities[authority] += 1
            line = source.count("\n", 0, start) + 1
            header = masked[start:opening]
            body = masked[opening + 1 : closing]

            if rule == "no-bundle":
                obligations = len(re.findall(r"\bHandler\s*<", header))
                if obligations >= 2:
                    violations.append((relative, line, f"trait {name} bundles {obligations} Handler obligations"))
                continue

            if authority in authorities:
                continue
            if re.search(r"\basync\s+fn\b", body):
                violations.append((relative, line, f"trait {name} uses async fn instead of BoxFuture"))
            if re.search(r"->\s*impl\b(?:(?![;{]).)*\bFuture\b", body, re.DOTALL):
                violations.append((relative, line, f"trait {name} returns impl Future instead of BoxFuture"))

    required = [key for key in authorities if rule == "dyn-policy" or key[1] == "Handler"]
    for authority in required:
        count = authorities[authority]
        if count != 1:
            fail(prefix, f"required policy authority {authority[0]}::{authority[1]} occurs {count} times")

    if violations:
        for relative, line, message in violations:
            print(f"{prefix}: {relative}:{line}: {message}", file=sys.stderr)
        raise SystemExit(1)

    if rule == "no-bundle":
        print(f"{prefix}: OK: no trait bundles multiple Handler obligations ({len(sources)} files scanned)")
    else:
        print(f"{prefix}: OK: only core Operation and Handler may use AFIT/RPITIT ({len(sources)} files scanned)")


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[2] not in {"no-bundle", "dyn-policy"}:
        print("usage: trait_policy_scan.py <repository-root> <no-bundle|dyn-policy>", file=sys.stderr)
        raise SystemExit(2)
    inspect(Path(sys.argv[1]), sys.argv[2])


if __name__ == "__main__":
    main()
