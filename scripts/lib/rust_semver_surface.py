#!/usr/bin/env python3
"""Token-level guards for the two source-shape rules in ADR-0004."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    offset: int


OPENING = {"(": ")", "[": "]", "{": "}"}
CLOSING = {value: key for key, value in OPENING.items()}


def fail(message: str) -> None:
    print(f"ADR-0004 guard: {message}", file=sys.stderr)
    raise SystemExit(1)


def git_files(root: Path, *pathspecs: str) -> list[str]:
    try:
        output = subprocess.run(
            [
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                *pathspecs,
            ],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"cannot enumerate source inputs: {error}")
    return sorted(os.fsdecode(item) for item in output.split(b"\0") if item)


def rust_tokens(source: str, label: str) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    while index < len(source):
        if source[index].isspace():
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
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
                fail(f"{label}: unterminated block comment")
            continue

        raw = re.match(r'(?:b|c)?r(#+)?"', source[index:])
        if raw:
            hashes = raw.group(1) or ""
            end = source.find('"' + hashes, index + raw.end())
            if end < 0:
                fail(f"{label}: unterminated raw string")
            index = end + 1 + len(hashes)
            continue

        quote = index + 1 if source[index] in {"b", "c"} and index + 1 < len(source) else index
        if quote < len(source) and source[quote] == '"':
            cursor = quote + 1
            while cursor < len(source):
                if source[cursor] == "\\":
                    cursor += 2
                elif source[cursor] == '"':
                    cursor += 1
                    break
                else:
                    cursor += 1
            else:
                fail(f"{label}: unterminated string")
            index = cursor
            continue

        if source[index] == "'":
            lifetime = re.match(r"'[A-Za-z_][A-Za-z0-9_]*", source[index:])
            if lifetime and (
                index + len(lifetime.group(0)) >= len(source)
                or source[index + len(lifetime.group(0))] != "'"
            ):
                tokens.append(Token("punct", "'", index))
                index += 1
                continue
            cursor = index + 1
            while cursor < len(source):
                if source[cursor] == "\\":
                    cursor += 2
                elif source[cursor] == "'":
                    cursor += 1
                    break
                else:
                    cursor += 1
            else:
                fail(f"{label}: unterminated character literal")
            index = cursor
            continue

        identifier = re.match(r"[A-Za-z_][A-Za-z0-9_]*", source[index:])
        if identifier:
            value = identifier.group(0)
            tokens.append(Token("ident", value, index))
            index += len(value)
            continue

        punctuation = next(
            (
                value
                for value in ("..=", "::", "=>", "->", "==", "!=", "<=", ">=", "&&", "||", "..")
                if source.startswith(value, index)
            ),
            source[index],
        )
        tokens.append(Token("punct", punctuation, index))
        index += len(punctuation)
    return tokens


def delimiter_pairs(tokens: list[Token], label: str) -> dict[int, int]:
    stack: list[tuple[int, str]] = []
    pairs: dict[int, int] = {}
    for index, token in enumerate(tokens):
        if token.value in OPENING:
            stack.append((index, token.value))
        elif token.value in CLOSING:
            if not stack or stack[-1][1] != CLOSING[token.value]:
                fail(f"{label}: unmatched delimiter {token.value}")
            opening, _ = stack.pop()
            pairs[opening] = index
            pairs[index] = opening
    if stack:
        fail(f"{label}: unterminated delimiter {stack[-1][1]}")
    return pairs


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def generated_inputs(root: Path) -> list[str]:
    files = git_files(root, "generated/dto/*", "generated/dto/**")
    files = [name for name in files if name.endswith(".rs")]
    if not files:
        fail("generated/dto Rust inputs are missing")
    return files


def next_item(tokens: list[Token], pairs: dict[int, int], start: int) -> int:
    cursor = start
    while cursor + 1 < len(tokens) and tokens[cursor].value == "#" and tokens[cursor + 1].value == "[":
        cursor = pairs[cursor + 1] + 1
    if cursor < len(tokens) and tokens[cursor].value == "pub":
        cursor += 1
        if cursor < len(tokens) and tokens[cursor].value == "(":
            cursor = pairs[cursor] + 1
    return cursor


def is_non_exhaustive_attribute(
    tokens: list[Token], pairs: dict[int, int], start: int, end: int
) -> bool:
    if start >= end or tokens[start].kind != "ident":
        return False
    if tokens[start].value == "non_exhaustive":
        return True
    if tokens[start].value != "cfg_attr" or start + 1 >= end or tokens[start + 1].value != "(":
        return False
    arguments = top_level_segments(tokens, pairs, start + 2, pairs[start + 1])
    return any(is_non_exhaustive_attribute(tokens, pairs, item_start, item_end) for item_start, item_end in arguments[1:])


def check_non_exhaustive(root: Path) -> int:
    violations: list[tuple[str, int]] = []
    for relative in generated_inputs(root):
        path = root / relative
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            fail(f"cannot read {relative}: {error}")
        tokens = rust_tokens(source, relative)
        pairs = delimiter_pairs(tokens, relative)
        for index in range(len(tokens) - 1):
            if tokens[index].value != "#" or tokens[index + 1].value != "[":
                continue
            end = pairs[index + 1]
            forbidden = is_non_exhaustive_attribute(tokens, pairs, index + 2, end)
            item = next_item(tokens, pairs, end + 1)
            if forbidden and item < len(tokens) and tokens[item].value == "struct":
                violations.append((relative, line_number(source, tokens[index].offset)))

    for relative, line in violations:
        print(
            f"{relative}:{line}: dto struct carries #[non_exhaustive], which forbids "
            "..Default::default() (rule: docs/adr/0004-semver-policy.md P1)",
            file=sys.stderr,
        )
    return 1 if violations else 0


def top_level_segments(tokens: list[Token], pairs: dict[int, int], start: int, end: int) -> list[tuple[int, int]]:
    segments: list[tuple[int, int]] = []
    segment = start
    cursor = start
    while cursor < end:
        if tokens[cursor].value in OPENING:
            cursor = pairs[cursor] + 1
            continue
        if tokens[cursor].value == ",":
            segments.append((segment, cursor))
            segment = cursor + 1
        cursor += 1
    segments.append((segment, end))
    return segments


def top_level_token(
    tokens: list[Token], pairs: dict[int, int], start: int, end: int, values: set[str]
) -> int | None:
    cursor = start
    while cursor < end:
        if tokens[cursor].value in values:
            return cursor
        if tokens[cursor].value in OPENING:
            cursor = pairs[cursor] + 1
            continue
        cursor += 1
    return None


def expression_with_block_end(
    tokens: list[Token], pairs: dict[int, int], start: int, end: int
) -> int | None:
    if start >= end:
        return None
    if tokens[start].value == "{":
        return pairs[start] + 1
    if tokens[start].value not in {"if", "match", "unsafe", "loop", "while", "for", "const", "async"}:
        return None
    cursor = start + 1
    while cursor < end:
        if tokens[cursor].value != "{":
            if tokens[cursor].value in OPENING:
                cursor = pairs[cursor] + 1
                continue
            cursor += 1
            continue
        closing = pairs[cursor]
        following = tokens[closing + 1].value if closing + 1 < end else None
        # A struct pattern in `if let` / `while let` / `for`, or a struct
        # scrutinee before the real control-flow body, is not the arm boundary.
        if following in {"=", "in", "{"}:
            cursor = closing + 1
            continue
        result = closing + 1
        while tokens[start].value == "if" and result < end and tokens[result].value == "else":
            branch = result + 1
            if branch < end and tokens[branch].value == "if":
                nested = expression_with_block_end(tokens, pairs, branch, end)
                return nested if nested is not None else result
            if branch < end and tokens[branch].value == "{":
                result = pairs[branch] + 1
            else:
                break
        return result
    return None


def pattern_ranges(tokens: list[Token], pairs: dict[int, int]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []

    for index, token in enumerate(tokens):
        if token.value == "let":
            ending = top_level_token(tokens, pairs, index + 1, len(tokens), {"=", ";"})
            if ending is not None and tokens[ending].value == "=":
                ranges.append((index + 1, ending))
        elif token.value == "for":
            ending = top_level_token(tokens, pairs, index + 1, len(tokens), {"in"})
            if ending is not None and tokens[ending].value == "in":
                ranges.append((index + 1, ending))
        elif token.value == "fn":
            opening = None
            angle_depth = 0
            for probe in range(index + 1, len(tokens)):
                if tokens[probe].value == "<":
                    angle_depth += 1
                elif tokens[probe].value == ">" and angle_depth:
                    angle_depth -= 1
                elif not angle_depth and tokens[probe].value in {"(", "{", ";"}:
                    opening = probe
                    break
            if opening is not None and tokens[opening].value == "(":
                for start, end in top_level_segments(tokens, pairs, opening + 1, pairs[opening]):
                    colon = top_level_token(tokens, pairs, start, end, {":"})
                    if colon is not None:
                        ranges.append((start, colon))
        elif token.value == "match":
            body = top_level_token(tokens, pairs, index + 1, len(tokens), {"{"})
            if body is not None:
                cursor = body + 1
                body_end = pairs[body]
                while cursor < body_end:
                    while cursor < body_end and tokens[cursor].value == ",":
                        cursor += 1
                    arrow = top_level_token(tokens, pairs, cursor, body_end, {"=>"})
                    if arrow is None:
                        break
                    guard = top_level_token(tokens, pairs, cursor, arrow, {"if"})
                    ranges.append((cursor, guard if guard is not None else arrow))
                    expression = arrow + 1
                    block_end = expression_with_block_end(tokens, pairs, expression, body_end)
                    if block_end is not None:
                        cursor = block_end
                    else:
                        comma = top_level_token(tokens, pairs, expression, body_end, {","})
                        cursor = body_end if comma is None else comma + 1

        if token.value == "matches" and index + 2 < len(tokens) and tokens[index + 1].value == "!":
            opening = index + 2
            if tokens[opening].value in OPENING:
                arguments = top_level_segments(tokens, pairs, opening + 1, pairs[opening])
                if len(arguments) >= 2:
                    ranges.append(arguments[1])

    # Closure parameters. A single `|` in expression-start position opens the parameter list.
    for index, token in enumerate(tokens):
        if token.value != "|":
            continue
        previous = tokens[index - 1].value if index else None
        if previous not in {None, "=", "(", "[", "{", ",", ";", "=>", "move", "async"}:
            continue
        closing = None
        probe = index + 1
        while probe < len(tokens):
            if tokens[probe].value == "|":
                closing = probe
                break
            if tokens[probe].value in OPENING:
                probe = pairs[probe] + 1
                continue
            if tokens[probe].value in {";", "=>"}:
                break
            probe += 1
        if closing is None:
            # A single `|` in a match pattern or expression is not a closure.
            continue
        for start, end in top_level_segments(tokens, pairs, index + 1, closing):
            colon = top_level_token(tokens, pairs, start, end, {":"})
            ranges.append((start, colon if colon is not None else end))

    # Destructuring assignment. `let` ranges above are harmless duplicates.
    for index, token in enumerate(tokens):
        if token.value != "=":
            continue
        previous = index - 1
        if previous < 0:
            continue
        if tokens[previous].value == ")":
            ranges.append((pairs[previous] + 1, previous))
        elif tokens[previous].value == "}":
            opening = pairs[previous]
            start = opening - 1
            while start >= 1 and tokens[start - 1].value == "::":
                start -= 2
            ranges.append((start, index))
    return ranges


def dto_names(root: Path) -> set[str]:
    names: set[str] = set()
    for relative in generated_inputs(root):
        path = root / relative
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            fail(f"cannot read {relative}: {error}")
        tokens = rust_tokens(source, relative)
        delimiter_pairs(tokens, relative)
        for index in range(len(tokens) - 1):
            if tokens[index].value == "struct" and tokens[index + 1].kind == "ident":
                names.add(tokens[index + 1].value)
            if tokens[index].value == "as" and tokens[index + 1].kind == "ident":
                names.add(tokens[index + 1].value)
    if not names:
        fail("generated/dto declares no struct names")
    return names


def canonical_namespace(tokens: list[Token], start: int, end: int, relative: str) -> bool:
    for index in range(start, end - 2):
        left, separator, right = (tokens[index + offset].value for offset in range(3))
        if separator != "::":
            continue
        if (left, right) in {("rustfs_gateway_types", "dto"), ("rustfs_gateway", "dto")}:
            return True
        if relative.startswith("crates/types/") and (left, right) == ("crate", "ops"):
            return True
        if (
            left in {"rustfs_gateway_types", "rustfs_gateway"}
            and separator == "::"
            and right == "{"
            and any(token.value == "dto" for token in tokens[index + 3 : end])
        ):
            return True
    return False


def local_dto_bindings(
    tokens: list[Token], names: set[str], relative: str
) -> tuple[set[str], set[str]]:
    aliases: set[str] = set()
    namespaces: set[str] = set()
    for index, token in enumerate(tokens):
        if token.value != "use":
            continue
        ending = next(
            (probe for probe in range(index + 1, len(tokens)) if tokens[probe].value == ";"),
            len(tokens),
        )
        statement = tokens[index + 1 : ending]
        if not canonical_namespace(statement, 0, len(statement), relative):
            continue
        if any(item.value == "*" for item in statement):
            aliases.update(names)
        for offset, item in enumerate(statement):
            if item.kind == "ident" and item.value in names:
                if offset + 2 < len(statement) and statement[offset + 1].value == "as":
                    aliases.add(statement[offset + 2].value)
                else:
                    aliases.add(item.value)
            if item.value == "as" and 0 < offset < len(statement) - 1:
                original = statement[offset - 1].value
                renamed = statement[offset + 1].value
                if original not in names:
                    namespaces.add(renamed)
            if item.value in {"dto", "ops"}:
                following = statement[offset + 1].value if offset + 1 < len(statement) else None
                if following != "::":
                    namespaces.add(item.value)

    for index, token in enumerate(tokens):
        if token.value == "type" and index + 2 < len(tokens):
            alias = tokens[index + 1].value
            ending = next(
                (probe for probe in range(index + 2, len(tokens)) if tokens[probe].value == ";"),
                len(tokens),
            )
            statement = tokens[index + 2 : ending]
            if (
                (
                    canonical_namespace(statement, 0, len(statement), relative)
                    or any(item.value in namespaces for item in statement)
                )
                and any(item.kind == "ident" and item.value in names for item in statement)
            ):
                aliases.add(alias)
    return aliases, namespaces


def is_dto_reference(
    tokens: list[Token], index: int, aliases: set[str], namespaces: set[str], relative: str
) -> bool:
    if tokens[index].value in aliases:
        return True
    if index == 0 or tokens[index - 1].value != "::":
        return False
    start = index - 2
    while start >= 2 and tokens[start - 1].value == "::":
        start -= 2
    return (
        any(token.value in namespaces for token in tokens[start:index])
        or canonical_namespace(tokens, start, index, relative)
    )


def has_top_level_rest(tokens: list[Token], pairs: dict[int, int], opening: int) -> bool:
    cursor = opening + 1
    ending = pairs[opening]
    while cursor < ending:
        if tokens[cursor].value in OPENING:
            cursor = pairs[cursor] + 1
            continue
        if tokens[cursor].value == "..":
            return True
        cursor += 1
    return False


def check_destructuring(root: Path) -> int:
    names = dto_names(root)
    violations: list[tuple[str, int, str]] = []
    for relative in git_files(root, "*.rs"):
        parts = Path(relative).parts
        if "generated" in parts or "target" in parts:
            continue
        path = root / relative
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            fail(f"cannot read {relative}: {error}")
        tokens = rust_tokens(source, relative)
        pairs = delimiter_pairs(tokens, relative)
        ranges = pattern_ranges(tokens, pairs)
        aliases, namespaces = local_dto_bindings(tokens, names, relative)
        for index, token in enumerate(tokens):
            if token.kind != "ident" or token.value not in names | aliases:
                continue
            if not is_dto_reference(tokens, index, aliases, namespaces, relative):
                continue
            opening = index + 1
            if opening >= len(tokens) or tokens[opening].value != "{":
                continue
            if not any(start <= index < end for start, end in ranges):
                continue
            if has_top_level_rest(tokens, pairs, opening):
                continue
            violations.append((relative, line_number(source, token.offset), token.value))

    for relative, line, name in violations:
        print(
            f"{relative}:{line}: exhaustive destructuring of dto {name}; add top-level `..` "
            "(rule: docs/adr/0004-semver-policy.md P3)",
            file=sys.stderr,
        )
    return 1 if violations else 0


def main() -> int:
    if len(sys.argv) != 3:
        fail("usage: rust_semver_surface.py <non-exhaustive|destructuring> <root>")
    mode = sys.argv[1]
    root = Path(sys.argv[2])
    if not (root / "docs/adr/0004-semver-policy.md").is_file():
        fail("rule input is missing: docs/adr/0004-semver-policy.md")
    if mode == "non-exhaustive":
        return check_non_exhaustive(root)
    if mode == "destructuring":
        return check_destructuring(root)
    fail(f"unknown mode: {mode}")


if __name__ == "__main__":
    raise SystemExit(main())
