#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Narrow the inventory's supported tuple-enum dispatch to one registered variant.

This is a deliberately limited source reader, not a Rust interpreter. Unreadable dispatch
conditions, guarded arms and ambiguous registrations fail instead of producing body facts.
The inventory supplies its literal-aware delimiter readers; no RustFS runtime is imported.
"""

import re

# An optional path before a trait or type name: `crate::admin::router::`, `super::`, `futures::stream::`.
PATH = r"(?:[A-Za-z_][A-Za-z0-9_]*::)*"


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


def normalize_dispatch_alias(block, close, fail):
    """Accept one immutable tuple-field binding and its final match in Operation::call."""
    bindings = list(re.finditer(r"\blet\s+([^;{}=]+?)\s*=\s*(&?\s*self\.0[^;{}]*);", block))
    if not bindings:
        return block
    binding = bindings[0]
    alias, value = binding.groups()
    if len(bindings) != 1 or not re.fullmatch(r"\w+", alias) or value != "self.0":
        fail("unreadable tuple variant alias")
    call = re.search(r"\bfn\s+call\b[^{};]*\{\s*$", block[:binding.start()])
    if not call:
        fail("the variant alias must be the first binding in call")
    start = block.index("{", call.start())
    end = close(block, start, "{", "}")
    body = block[binding.end():end]
    for assignment in re.finditer(r"\blet\s+([^;{}=]+)\s*=\s*([^;{}]*)", body):
        if re.search(rf"\b{alias}\b", assignment[1]) or re.match(rf"&?\s*{alias}\b", assignment[2]):
            fail("shadowed or chained variant alias")
    uses = list(re.finditer(rf"\b(?:match|if)\b[^{{}};]*\b{alias}\b[^{{}};]*\{{", body))
    if len(uses) != 1 or not re.fullmatch(rf"match\s+{alias}\s*\{{", uses[0][0]):
        fail("expected one direct match on the variant alias")
    dispatch = uses[0]
    if body[close(body, dispatch.end() - 1, "{", "}") + 1:].strip():
        fail("the variant alias match must be the final expression in call")
    offset = binding.end()
    return block[:offset + dispatch.start()] + "match self.0 {" + block[offset + dispatch.end():]


def returns_unconditionally(text, close):
    """Recognize only an unconditional return, allowing enclosing blocks."""
    text = text.strip()
    while text.startswith("{") and close(text, 0, "{", "}") == len(text) - 1:
        text = text[1:-1].strip()
    return re.fullmatch(r"return\s+[^{};]+;", text) is not None


def enum_array_sites(source, relative, text, close, split, resolve, module_file, fail):
    """Trace a registration loop through its imported static array and pure enum accessors."""
    for loop in re.finditer(r"\bfor\s+(\w+)\s+in\s+&([A-Z][A-Z0-9_]*)\s*\{", text):
        body = text[loop.end():close(text, loop.end() - 1, "{", "}")]
        if not re.search(r"\.insert\s*\(", body):
            continue
        item, array = loop.groups()
        # This supported loop is the first statement. The router cannot have been shadowed.
        function = re.search(r"\bfn\s+register(?:_\w+)?\s*\(\s*(\w+)\s*:\s*&mut\s+S3Router<AdminOperation>\s*\)"
                             r"\s*(?:->[^{};]+)?\{\s*$", text[:loop.start()])
        if not function or item == function[1]:
            fail(f"{relative}: {array} must directly register on the function's router")
        binding = re.fullmatch(
            rf'\s*let (\w+) = {item}\.(\w+)\(\);\s*{function[1]}\.insert\(\s*\1\.(\w+)\(\),\s*'
            rf'(&format!\(\s*"[^"\\]*"\s*,\s*)\1\.(\w+)\(\)\s*\),\s*AdminOperation\({item}\),?\s*\)\?;\s*', body)
        if not binding or binding[1] == function[1]:
            fail(f"{relative}: unreadable registration loop over {array}")
        _, getter, verb, format_start, selector = binding.groups()
        modules = [mod for mod, names in re.findall(r"\buse (\w+)::(\{[^}]+\}|\w+);", text)
                   if array in split(names.strip("{}"))]
        if len(modules) != 1:
            fail(f"{relative}: cannot resolve the module defining {array}")
        defining = module_file(source, relative, modules[0])
        defs = source.files[defining]
        decl = re.search(rf"\bstatic\s+{array}\s*:\s*\[(\w+);\s*(\d+)\]\s*=\s*\[", defs)
        if not decl:
            fail(f"{defining}: missing handler array {array}")
        handler, size = decl.groups()
        items = split(defs[decl.end():close(defs, decl.end() - 1, "[", "]")])
        if len(items) != int(size) or not items:
            fail(f"{defining}: unreadable handler array {array}")
        struct = re.search(rf"\bstruct\s+{handler}\s*\(\s*(\w+)\s*\)\s*;", defs)
        if not struct:
            fail(f"{defining}: missing tuple handler {handler}")
        enum = struct.group(1)
        declaration = re.search(rf"\benum\s+{enum}\s*\{{([^{{}}]*)\}}", defs)
        if not declaration:
            fail(f"{defining}: missing unit enum {enum}")
        members = set(split(declaration[1]))
        if not all(re.fullmatch(r"\w+", name) for name in members):
            fail(f"{defining}: unsupported variants in {enum}")

        def accessor(owner, name, signature):
            bodies = []
            for impl in re.finditer(rf"\bimpl\s+{owner}\s*\{{", defs):
                block = defs[impl.end():close(defs, impl.end() - 1, "{", "}")]
                for fn in re.finditer(rf"\bfn\s+{name}\s*{signature}\s*\{{", block):
                    bodies.append(block[fn.end():close(block, fn.end() - 1, "{", "}")].strip())
            if len(bodies) != 1:
                fail(f"{defining}: unresolved accessor {owner}::{name}")
            return bodies[0]

        def cases(name, result_type, value_pattern):
            body = accessor(enum, name, rf"\(self\)\s*->\s*{result_type}")
            match = re.fullmatch(r"match\s+self\s*\{(.*)\}", body, re.S)
            if not match:
                fail(f"{defining}: expected {enum}::{name} to match self")
            values = {}
            for arm in split(match.group(1)):
                row = re.fullmatch(rf"(Self::\w+(?:\s*\|\s*Self::\w+)*)\s*=>\s*{value_pattern}", arm)
                if not row:
                    fail(f"{defining}: unreadable {enum}::{name} match arm")
                for variant in re.findall(r"Self::(\w+)", row[1]):
                    if variant in values:
                        fail(f"{defining}: duplicate {enum}::{variant} in {name}")
                    values[variant] = row[2]
            if values.keys() != members:
                fail(f"{defining}: incomplete {enum}::{name} match")
            return values

        if accessor(handler, getter, rf"\(&self\)\s*->\s*{enum}") != "self.0":
            fail(f"{defining}: {handler}::{getter} must return the registered variant")
        verbs = cases(verb, "Method", r"Method::([A-Z]+)")
        paths = cases(selector, r"&'static str", r'("[^"\\{}]*")')
        for item_expr in items:
            ctor = re.fullmatch(rf"{handler}\(\s*{enum}::(\w+)\s*\)", item_expr)
            if not ctor or ctor[1] not in verbs or ctor[1] not in paths:
                fail(f"{defining}: incomplete route binding for {item_expr}")
            variant = ctor[1]
            path = resolve(format_start + paths[variant] + ")", source, relative)
            yield loop.start(), verbs[variant], path, handler, (enum, variant), defining


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
        found = re.search(rf"\b(?:static|const)\s+{name}\s*:\s*{PATH}([A-Za-z_][A-Za-z0-9_]*)", source.files[candidate])
        if found:
            return found.group(1)
    fail(f"{relative}: handler value {name} has no static or const declaration")


def shared_seals(source, called, admin, matching_close, seals):
    """The caller-secret markers of the shared helpers in `handlers/mod.rs` a handler calls.

    Only the seal is lent, never the helper's text: a shared helper's body reads are not the
    handler's. Helpers inside the file's `#[cfg(test)]` module are not followed.
    """
    text = source.files.get((admin / "handlers/mod.rs").as_posix(), "")
    test_module = re.search(r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*mod\s+\w+\s*\{", text)
    text = text[:test_module.start()] if test_module else text
    lent = []
    for free in re.finditer(r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([a-z_][a-z0-9_]*)\b", text, re.M):
        brace = text.find("{", free.end())
        if free.group(1) not in called or brace == -1:
            continue
        body = text[brace:matching_close(text, brace, "{", "}")]
        lent.extend(marker for marker in seals if marker in body)
    return lent


def removal_body_reader(source, relative, block, close, fail):
    """Follow the removal module's parent JSON reader, only down the literal plaintext branch it calls."""
    field = "read_site_replication_json"
    parent = "rustfs/src/admin/handlers/site_replication.rs"
    if relative != parent[:-3] + "/removal.rs" or not re.search(rf"\b{field}\s*\(", block):
        return ""
    body = r'read_site_replication_json\(\s*req,\s*"",\s*false\s*\)'
    child = source.files[relative]
    owner = source.files.get(parent, "")
    if (not re.search(r"^use super::\*;", child, re.M) or re.search(rf"\bfn {field}\b", child)
            or not re.search(r"^mod removal;", owner, re.M)
            or len(re.findall(body, block)) != len(re.findall(rf"\b{field}\s*\(", block))):
        fail(f"{relative}: unresolved site-removal body reader")

    def function(name):
        matches = list(re.finditer(rf"^async fn {name}\b[^;{{}}]*\{{", owner, re.M))
        if len(matches) != 1:
            fail(f"{parent}: missing or ambiguous {name}")
        start = matches[0].end()
        return " ".join(owner[start:close(owner, start - 1, "{", "}")].split())

    if function(field) != ("let body = read_site_replication_body(req, secret_key, compat_encrypted).await?; "
                           "parse_site_replication_json(&body)"):
        fail(f"{parent}: unsupported JSON reader")
    if not re.fullmatch(r"let body = if compat_encrypted \{ read_compatible_admin_body\(req.take_body\(\), [A-Z_]+, "
                        r"req.uri\(\).path\(\), secret_key\)\.await\? \} else \{ read_plain_admin_body\(req.take_body\(\)\)"
                        r"\.await\? \}; Ok\(body\)", function("read_site_replication_body")):
        fail(f"{parent}: unsupported plaintext branch")
    plain = function("read_plain_admin_body")
    if not re.fullmatch(r"let body = input\s*\.store_all_limited\([A-Z_]+\)\s*\.await(?:\s*\.map_err\([^;]*\))?\?; Ok\(body.to_vec\(\)\)", plain):
        fail(f"{parent}: unsupported plaintext body buffering")
    return plain


def handler_body(source, type_name, variant, admin, matching_close, split_args, fail, seals=(), defining_file=None):
    for relative, text in source.files.items():
        if not relative.startswith(admin.as_posix() + "/"):
            continue
        if defining_file is not None and relative != defining_file:
            continue
        pattern = rf"impl\s+{PATH}Operation\s+for\s+{type_name}\s*\{{"
        if defining_file is not None and len(re.findall(pattern, text)) != 1:
            fail(f"{relative}: expected one impl Operation for {type_name}")
        match = re.search(pattern, text)
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
            block = normalize_dispatch_alias(block, matching_close, fail)
            block = select_variant(block, enum, name, matching_close, split_args, fail)
            if re.search(rf"\bmatch\b[^{{}};]*\{{\s*{enum}::", block):
                fail(f"{relative}: unresolved {enum} variant dispatch")
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
        # A free-function call, path-qualified or not, never a method call: `x.name(` is not `name(`.
        reached = block + "\n".join(helpers)
        helpers.append(removal_body_reader(source, relative, reached, matching_close, fail))
        lent = shared_seals(source, set(re.findall(r"(?<![.\w])(?:\w+::)*([a-z_][a-z0-9_]*)\(", reached)), admin,
                            matching_close, seals)
        helpers.extend(f"/* sealed by a shared helper: {marker} */" for marker in lent)
        stream_types = set(re.findall(rf"impl\s+{PATH}(?:Stream|ByteStream)\s+for\s+(\w+)", text))
        return relative, block + "\n".join(helpers), stream_types
    fail(f"no `impl Operation for {type_name}` under {admin}")
