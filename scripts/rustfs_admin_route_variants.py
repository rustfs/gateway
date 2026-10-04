#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Narrow the inventory's supported tuple-enum dispatch to one registered variant.

This is a deliberately limited source reader, not a Rust interpreter. Unreadable dispatch
conditions, guarded arms and ambiguous registrations fail instead of producing body facts.
The inventory supplies its literal-aware delimiter readers; no RustFS runtime is imported.
"""

import re


def select_variant(text, enum, variant, close, split, fail):
    """Retain common code and the reachable arms of `self.0` dispatch only."""
    out = []
    while text:
        branch = re.search(r"\bif\b[^{};]*\bself\.0\b|\bmatch\b[^{};]*\bself\.0\b", text)
        if not branch:
            return "".join(out) + text
        if re.search(r"\breturn\s*$", text[:branch.start()]):
            fail(f"unreadable {enum} variant return expression")
        out.append(text[:branch.start()])
        rest = text[branch.start():]
        if rest.startswith("match"):
            opening = rest.index("{")
            if not re.fullmatch(r"match\s+self\.0\s*", rest[:opening]):
                fail(f"unreadable {enum} variant dispatch: {rest[:opening]!r}")
            ending = close(rest, opening, "{", "}")
            arms = rest[opening + 1:ending]
            chosen = None
            while arms.strip(" \t\r\n,"):
                arms = arms.lstrip(" \t\r\n,")
                arm = re.match(rf"({enum}::\w+(?:\s*\|\s*{enum}::\w+)*)\s*=>\s*", arms)
                if not arm:
                    fail(f"unreadable {enum} variant match arm: {arms[:80]!r}")
                rhs = arms[arm.end():]
                if rhs.startswith("{"):
                    end = close(rhs, 0, "{", "}") + 1
                else:
                    value = split(rhs)[0]
                    end = len(value)
                if variant in re.findall(rf"{enum}::(\w+)", arm.group(1)):
                    if chosen is not None:
                        fail(f"duplicate match arm for variant {enum}::{variant}")
                    chosen = rhs[:end]
                arms = rhs[end:]
            if chosen is None:
                fail(f"no match arm for variant {enum}::{variant}")
            selected = select_variant(chosen, enum, variant, close, split, fail)
            out.append(selected)
            if returns_unconditionally(selected, close):
                return "".join(out)
            text = rest[ending + 1:]
            continue
        condition = re.match(rf"if\s+matches!\(\s*self\.0\s*,\s*({enum}::\w+(?:\s*\|\s*{enum}::\w+)*)\s*\)\s*\{{", rest)
        if not condition:
            fail(f"unreadable {enum} variant condition: {rest[:80]!r}")
        opening = condition.end() - 1
        ending = close(rest, opening, "{", "}")
        yes = rest[opening + 1:ending]
        tail = rest[ending + 1:]
        no = ""
        otherwise = re.match(r"\s*else\s*\{", tail)
        if otherwise:
            no_end = close(tail, otherwise.end() - 1, "{", "}")
            no = tail[otherwise.end():no_end]
            tail = tail[no_end + 1:]
        elif re.match(r"\s*else\b", tail):
            fail(f"unreadable {enum} variant condition: else without a block")
        selected = yes if variant in re.findall(rf"{enum}::(\w+)", condition.group(1)) else no
        selected = select_variant(selected, enum, variant, close, split, fail)
        out.append("{" + selected + "}")
        # This supported early-return shape is unconditional. Nothing after it is reachable.
        if returns_unconditionally(selected, close):
            return "".join(out)
        text = tail
    return "".join(out)


def returns_unconditionally(text, close):
    """Recognize only an unconditional return, allowing enclosing blocks."""
    text = text.strip()
    while text.startswith("{") and close(text, 0, "{", "}") == len(text) - 1:
        text = text[1:-1].strip()
    return re.fullmatch(r"return\s+[^{};]+;", text) is not None


def constructor(expression, fail):
    """A reference to an ordinary handler, or to a tuple handler holding one unit variant."""
    plain = re.fullmatch(r"&(?:[a-z_]+::)*([A-Za-z_]\w*)\s*(?:\{\s*\})?", expression)
    if plain:
        return plain.group(1), None
    bound = re.fullmatch(r"&([A-Za-z_]\w*)\(\s*([A-Za-z_]\w*)::([A-Za-z_]\w*)\s*\)", expression)
    if bound:
        return bound.group(1), (bound.group(2), bound.group(3))
    fail(f"unreadable registration handler constructor {expression!r}")


def handler_type(source, name, relative, fail):
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
        return name
    for candidate in [relative] + sorted(source.files):
        found = re.search(rf"\b(?:static|const)\s+{name}\s*:\s*([A-Za-z_][A-Za-z0-9_]*)", source.files[candidate])
        if found:
            return found.group(1)
    fail(f"{relative}: handler value {name} has no static or const declaration")


def handler_body(source, type_name, variant, admin, matching_close, split_args, fail):
    for relative, text in source.files.items():
        if not relative.startswith(admin.as_posix() + "/"):
            continue
        match = re.search(rf"impl\s+Operation\s+for\s+{type_name}\s*\{{", text)
        if not match:
            continue
        end = matching_close(text, match.end() - 1, "{", "}")
        block = text[match.start():end]
        if variant is not None:
            enum, name = variant
            if not re.search(rf"\bstruct\s+{type_name}\s*\(\s*{enum}\s*\)\s*;", text):
                fail(f"{relative}: {type_name} is not the registered tuple handler")
            declaration = re.search(rf"\benum\s+{enum}\s*\{{", text)
            if not declaration:
                fail(f"{relative}: missing variant enum {enum}")
            variants = text[declaration.end():matching_close(text, declaration.end() - 1, "{", "}")]
            if name not in [value.strip() for value in split_args(variants)]:
                fail(f"{relative}: unknown unit variant {enum}::{name}")
            block = select_variant(block, enum, name, matching_close, split_args, fail)
        # One level of same-file free functions: the work a handler delegates in its own file.
        # Methods are excluded on purpose: every handler has a `call`, and pulling in the other
        # handlers' `call` bodies would give each handler its neighbours' facts.
        called = set(re.findall(r"\b([a-z_][a-z0-9_]*)\(", block))
        helpers = []
        for free in re.finditer(r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([a-z_][a-z0-9_]*)\b", text, re.M):
            if free.group(1) not in called:
                continue
            brace = text.find("{", free.end())
            if brace == -1:
                continue
            helpers.append(text[free.start():matching_close(text, brace, "{", "}")])
        stream_types = set(re.findall(r"impl\s+(?:futures::)?(?:Stream|ByteStream)\s+for\s+(\w+)", text))
        return relative, block + "\n".join(helpers), stream_types
    fail(f"no `impl Operation for {type_name}` under {admin}")
