#!/usr/bin/env python3
# Copyright 2026 RustFS Team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Generate the RustFS admin route inventory from a RustFS checkout (rustfs/backlog#1744).

WHAT THIS DOES
  Reads three independent RustFS authorities at one commit and refuses to write anything unless
  they agree route for route:
    1. rustfs/src/admin/route_policy.rs     ADMIN_ROUTE_POLICY_SPECS + DEFERRED_ADMIN_ROUTE_POLICIES
    2. rustfs/src/admin/route_registration_test.rs   expected_admin_route_matrix()
    3. every `.insert(Method::X, <path>, AdminOperation(..))` site under rustfs/src/admin
  Per route it then records the method, path pattern, registration group, auth mode, IAM action,
  whether a body is sealed with the caller's secret, and whether a body is streamed or buffered.
  The query-discriminated routes the admin router claims before its path table
  (`parse_replication_extension_request`, `parse_misc_extension_request`) are recorded beside them.
  Every count in the output is computed from the rows; nothing is typed in by hand.
WHY
  The historical "318" was a hand-copied snapshot. The inventory must be regenerated, not edited.
USAGE
  gen_rustfs_admin_route_inventory.py --rustfs <checkout> --out <json>
  gen_rustfs_admin_route_inventory.py --rustfs <checkout> --check <json>   (exit 1 on any drift)
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys

import rustfs_admin_route_variants as variants

FORMAT = "rustfs-admin-route-inventory/1"
ADMIN = pathlib.Path("rustfs/src/admin")
SECRET_REQUEST = ("read_compatible_admin_body",)
SECRET_RESPONSE = ("encode_compatible_admin_payload", "encode_config_payload")
BUFFERED_READS = (
    "store_all_limited",
    "read_compatible_admin_body",
    "read_body(",
    "read_json_body",
    "read_plain_admin_body",
)
STREAMED_READS = ("drain_client_devnull", "drain_site_replication_devnull")
STREAMED_RESPONSES = ("StreamingBlob", "ReaderStream", "StreamBody", "async_stream")


class InventoryError(Exception):
    """A disagreement between RustFS authorities, or a shape this generator cannot read."""


def fail(message):
    raise InventoryError(message)


def squash(text):
    return re.sub(r"\s+", " ", text)


def literal_end(text, index, prefixed=False):
    """The index just past a string, raw string or char literal starting at `index`, else None."""
    char = text[index]
    if char == "r" and (prefixed or index == 0 or not (text[index - 1].isalnum() or text[index - 1] == "_")):
        match = re.match(r'r(#*)"', text[index:])
        if match:
            closing = '"' + match.group(1)
            end = text.find(closing, index + match.end())
            if end == -1:
                fail(f"unterminated raw string at offset {index}")
            return end + len(closing)
    if char == "b" and index + 1 < len(text) and text[index + 1] in "\"'r" and (
        index == 0 or not (text[index - 1].isalnum() or text[index - 1] == "_")
    ):
        return literal_end(text, index + 1, prefixed=True)
    if char == '"':
        position = index + 1
        while position < len(text):
            if text[position] == "\\":
                position += 2
                continue
            if text[position] == '"':
                return position + 1
            position += 1
        fail(f"unterminated string at offset {index}")
    if char == "'":
        # A char literal ('x', '\n', '\u{7f}'); a lifetime ('a) has no closing quote.
        match = re.match(r"'(?:\\x[0-9a-fA-F]{2}|\\u\{[0-9a-fA-F]+\}|\\.|[^\\'])'", text[index:])
        if match:
            return index + match.end()
    return None


def strip_comments(text):
    """Blanks `//` and `/* */` comments outside literals, keeping offsets and line structure."""
    out, index = [], 0
    while index < len(text):
        end = literal_end(text, index)
        if end is not None:
            out.append(text[index:end])
            index = end
        elif text.startswith("//", index):
            stop = text.find("\n", index)
            stop = len(text) if stop == -1 else stop
            out.append(" " * (stop - index))
            index = stop
        elif text.startswith("/*", index):
            stop = text.find("*/", index + 2)
            stop = len(text) if stop == -1 else stop + 2
            out.append(re.sub(r"[^\n]", " ", text[index:stop]))
            index = stop
        else:
            out.append(text[index])
            index += 1
    return "".join(out)


def matching_close(text, open_index, open_char, close_char):
    depth, index = 0, open_index
    while index < len(text):
        end = literal_end(text, index)
        if end is not None:
            index = end
            continue
        char = text[index]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    fail(f"unbalanced {open_char}{close_char} at offset {open_index}: {text[open_index:open_index + 80]!r}")


def split_args(text):
    args, depth, start, index = [], 0, 0, 0
    while index < len(text):
        end = literal_end(text, index)
        if end is not None:
            index = end
            continue
        char = text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            args.append(text[start:index].strip())
            start = index + 1
        index += 1
    if text[start:].strip():
        args.append(text[start:].strip())
    return args


class Source:
    def __init__(self, root):
        self.root = root
        self.files = {}
        paths = sorted((root / ADMIN).rglob("*.rs")) + sorted((root / "rustfs/src/server").glob("*.rs"))
        for path in paths:
            relative = path.relative_to(root).as_posix()
            try:
                self.files[relative] = strip_comments(path.read_text(encoding="utf-8"))
            except InventoryError as error:
                fail(f"{relative}: {error}")
        self.string_consts = self._string_consts()

    def text(self, relative):
        if relative not in self.files:
            fail(f"RustFS source file {relative} is missing")
        return self.files[relative]

    def _string_consts(self):
        found = {}
        pattern = re.compile(r'(?:pub(?:\([a-z]+\))?\s+)?const\s+([A-Z][A-Z0-9_]*)\s*:\s*&(?:\'static\s+)?str\s*=\s*"([^"]*)"\s*;')
        for relative, text in self.files.items():
            for name, value in pattern.findall(text):
                found.setdefault(name, {})[relative] = value
        return found

    def const(self, name, relative):
        values = self.string_consts.get(name)
        if not values:
            fail(f"{relative}: unresolved string constant {name}")
        if relative in values:
            return values[relative]
        distinct = set(values.values())
        if len(distinct) != 1:
            fail(f"{relative}: constant {name} is ambiguous across {sorted(values)}")
        return distinct.pop()


def resolve_path(expr, source, relative, prefix=None, bound=None):
    bound = bound or {}
    expr = expr.strip()
    expr = re.sub(r"^&", "", expr)
    expr = re.sub(r"\.as_str\(\)$", "", expr).strip()
    if re.fullmatch(r'"[^"]*"', expr):
        return expr[1:-1]
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", expr):
        return source.const(expr, relative)
    match = re.fullmatch(r'format!\((.*)\)', expr, re.S)
    if not match:
        fail(f"{relative}: cannot resolve route path expression {expr!r}")
    args = split_args(match.group(1))
    template = args[0]
    if not re.fullmatch(r'"[^"]*"', template):
        fail(f"{relative}: format string is not a literal: {expr!r}")
    template = template[1:-1]
    positional = [resolve_path(arg, source, relative, prefix, bound) for arg in args[1:]]

    def named(match_):
        name = match_.group(1)
        if name == "":
            if not positional:
                fail(f"{relative}: too few format arguments in {expr!r}")
            return positional.pop(0)
        if name in bound:
            return bound[name]
        if name == "prefix":
            if prefix is None:
                fail(f"{relative}: `{{prefix}}` outside a known prefix loop in {expr!r}")
            return prefix
        return source.const(name, relative)

    rendered = re.sub(r"(?<!\{)\{([A-Za-z0-9_]*)\}(?!\})", named, template)
    if positional:
        fail(f"{relative}: unused format arguments in {expr!r}")
    return rendered.replace("{{", "{").replace("}}", "}")


def functions(text):
    """Top-level and impl-level `fn` bodies: name -> list of (start, end)."""
    found = {}
    for match in re.finditer(r"\bfn\s+([a-z_][a-z0-9_]*)\s*(?:<[^>{]*>)?\s*\(", text):
        brace = text.find("{", match.end())
        semicolon = text.find(";", match.end())
        if brace == -1 or (semicolon != -1 and semicolon < brace and "where" not in text[match.end():semicolon]):
            continue
        end = matching_close(text, brace, "{", "}")
        found.setdefault(match.group(1), []).append((match.start(), end))
    return found


def enclosing_function(spans, offset):
    best = None
    for name, ranges in spans.items():
        for start, end in ranges:
            if start <= offset <= end and (best is None or start > best[1]):
                best = (name, start)
    return best[0] if best else None


# ── authority 1: the route policy ─────────────────────────────────────────────────────────────


def read_policy(source):
    relative = (ADMIN / "route_policy.rs").as_posix()
    text = source.text(relative)
    actions = dict(re.findall(r'const\s+([A-Z][A-Z0-9_]*)\s*:\s*AdminActionRef\s*=\s*AdminActionRef::new\("([^"]+)"\)', text))
    policy = {}

    def table(name):
        match = re.search(rf"pub const {name}\s*:\s*&\[\w+\]\s*=\s*&\[", text)
        if not match:
            fail(f"{relative}: {name} not found")
        close = matching_close(text, match.end() - 1, "[", "]")
        return text[match.end():close]

    for kind, body in (("spec", table("ADMIN_ROUTE_POLICY_SPECS")), ("deferred", table("DEFERRED_ADMIN_ROUTE_POLICIES"))):
        for match in re.finditer(r"\b(admin|public|deferred)\(", body):
            close = matching_close(body, match.end() - 1, "(", ")")
            args = split_args(squash(body[match.end():close]))
            constructor = match.group(1)
            method = re.fullmatch(r"HttpMethod::(\w+)", args[0])
            path = re.fullmatch(r'"([^"]+)"', args[1])
            if not method or not path:
                fail(f"{relative}: unreadable policy row {args}")
            key = f"{method.group(1).upper()} {path.group(1)}"
            if key in policy:
                fail(f"{relative}: duplicate policy row {key}")
            if constructor == "admin":
                if args[2] not in actions:
                    fail(f"{relative}: unknown action constant {args[2]}")
                row = {"auth_mode": "sigv4-admin", "iam_action": actions[args[2]], "auth_detail": None,
                       "risk": args[3].split("::")[1].lower()}
            elif constructor == "public":
                row = {"auth_mode": "anonymous", "iam_action": None, "auth_detail": args[2].split("::")[1],
                       "risk": args[3].split("::")[1].lower()}
            else:
                row = {"auth_mode": "custom", "iam_action": None, "auth_detail": args[2].split("::")[1], "risk": None}
            if (kind == "deferred") != (constructor == "deferred"):
                fail(f"{relative}: {constructor} row inside the {kind} table: {key}")
            policy[key] = row
    return policy


# ── authority 2: the registration matrix ──────────────────────────────────────────────────────


def read_matrix(source):
    relative = (ADMIN / "route_registration_test.rs").as_posix()
    text = source.text(relative)
    match = re.search(r"fn expected_admin_route_matrix\(\)\s*->\s*Vec<RouteMatrixEntry>\s*\{", text)
    if not match:
        fail(f"{relative}: expected_admin_route_matrix not found")
    body = text[match.end():matching_close(text, match.end() - 1, "{", "}")]
    prefixes = {
        "route": "",
        "route_sample": "",
        "admin_route": source.const("ADMIN_PREFIX", relative),
        "admin_route_sample": source.const("ADMIN_PREFIX", relative),
        "table_route": source.const("TABLE_CATALOG_PREFIX", relative),
        "table_route_sample": source.const("TABLE_CATALOG_PREFIX", relative),
        "compat_table_route": source.const("TABLE_CATALOG_COMPAT_PREFIX", relative),
        "compat_table_route_sample": source.const("TABLE_CATALOG_COMPAT_PREFIX", relative),
    }
    rows, helpers = {}, {}
    for call in re.finditer(r"\b(" + "|".join(prefixes) + r")\(", body):
        close = matching_close(body, call.end() - 1, "(", ")")
        args = split_args(squash(body[call.end():close]))
        method = re.fullmatch(r"Method::(\w+)", args[0])
        if not method:
            fail(f"{relative}: unreadable matrix row {args}")
        path = prefixes[call.group(1)] + resolve_path(args[1], source, relative)
        key = f"{method.group(1)} {path}"
        if key in rows:
            fail(f"{relative}: duplicate matrix row {key}")
        rows[key] = call.group(1)
        helpers[call.group(1)] = helpers.get(call.group(1), 0) + 1
    return rows, helpers


# ── authority 3: the insert sites, and what each handler does ─────────────────────────────────


def register_graph(source):
    """Maps every `register_*` function to the files and names it calls, and the insert sites."""
    mod_text = source.text((ADMIN / "mod.rs").as_posix())
    top = re.search(r"fn register_admin_routes\([^)]*\)\s*->[^{]*\{", mod_text)
    if not top:
        fail("rustfs/src/admin/mod.rs: register_admin_routes not found")
    body = mod_text[top.end():matching_close(mod_text, top.end() - 1, "{", "}")]
    groups = re.findall(r"\b([a-z_]+)::(register_[a-z_]+)\(r\)\?", body)
    if not groups:
        fail("rustfs/src/admin/mod.rs: no registration groups found")
    return groups


def insert_sites(source):
    sites = []
    for relative, text in source.files.items():
        if not relative.startswith(ADMIN.as_posix() + "/") or relative.endswith("_test.rs") or "/tests" in relative:
            continue
        spans = functions(text)
        test_module = re.search(r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*mod\s+\w+\s*\{", text)
        test_start = test_module.start() if test_module else -1
        loop = re.search(r"for prefix in \[([A-Z_,\s]+)\]", text)
        for loop_match in re.finditer(r"for \((\w+),\s*(\w+),\s*(\w+)\) in \[", text):
            if test_start != -1 and loop_match.start() > test_start:
                continue
            names = loop_match.groups()
            close = matching_close(text, loop_match.end() - 1, "[", "]")
            body_open = text.find("{", close)
            body = text[body_open:matching_close(text, body_open, "{", "}")]
            insert = re.search(r"\.insert\(", body)
            if not insert:
                continue
            insert_open = body_open + insert.end() - 1
            call = split_args(squash(text[insert_open + 1:matching_close(text, insert_open, "(", ")")]))
            if len(re.findall(r"\.insert\(", body)) != 1:
                fail(f"{relative}: variant loop must have exactly one insert")
            wrapper = re.fullmatch(r"AdminOperation\((\w+)\)", call[2])
            if call[0] != names[0] or (wrapper.group(1) if wrapper else call[2]) != names[2]:
                fail(f"{relative}: loop insert {call} does not bind the loop's own names {names}")
            for item in re.finditer(r"\(", text[loop_match.end():close]):
                start = loop_match.end() + item.start()
                if text[loop_match.end():start].count("(") - text[loop_match.end():start].count(")") != 0:
                    continue
                parts = split_args(squash(text[start + 1:matching_close(text, start, "(", ")")]))
                method = re.fullmatch(r"Method::(\w+)", parts[0]) if len(parts) == 3 else None
                if not method:
                    fail(f"{relative}: unreadable loop row {parts}")
                if wrapper:
                    handler, variant = variants.constructor(parts[2], fail)
                else:
                    operation = re.fullmatch(r"AdminOperation\((.*)\)", parts[2])
                    if not operation:
                        fail(f"{relative}: unreadable loop row {parts}")
                    handler, variant = variants.constructor(operation.group(1), fail)
                bound = {names[1]: resolve_path(parts[1], source, relative)}
                sites.append({
                    "method": method.group(1),
                    "path": resolve_path(call[1], source, relative, None, bound),
                    "handler": handler,
                    "variant": variant,
                    "file": relative,
                    "function": enclosing_function(spans, loop_match.start()),
                })
        for match in re.finditer(r"\.insert\(\s*Method::(\w+)\s*,", text):
            if test_start != -1 and match.start() > test_start:
                continue
            open_index = text.find("(", match.start())
            close = matching_close(text, open_index, "(", ")")
            args = split_args(squash(text[open_index + 1:close]))
            if len(args) != 3:
                fail(f"{relative}: insert with {len(args)} arguments: {args}")
            handler = re.fullmatch(r"AdminOperation\(&(?:[a-z_]+::)*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\{\s*\})?\)", args[2])
            if not handler:
                fail(f"{relative}: unreadable operation {args[2]!r}")
            prefixes = [None]
            if re.search(r'format!\(\s*"[^"]*(?<!\{)\{prefix\}', args[1]):
                if not loop:
                    fail(f"{relative}: `{{prefix}}` without a `for prefix in [..]` loop")
                prefixes = [source.const(name.strip(), relative) for name in loop.group(1).split(",") if name.strip()]
            for prefix in prefixes:
                sites.append({
                    "method": match.group(1),
                    "path": resolve_path(args[1], source, relative, prefix),
                    "handler": handler.group(1),
                    "file": relative,
                    "function": enclosing_function(spans, match.start()),
                })
    return sites


def handler_type(source, name, relative):
    return variants.handler_type(source, name, relative, fail)


def handler_body(source, type_name, variant=None):
    return variants.handler_body(source, type_name, variant, ADMIN, matching_close, split_args, fail)


def body_facts(text, stream_types):
    request_secret = any(marker in text for marker in SECRET_REQUEST)
    response_secret = any(marker in text for marker in SECRET_RESPONSE)
    caller_secret = {
        (False, False): "none",
        (True, False): "request-on-minio-alias",
        (False, True): "response-on-minio-alias",
        (True, True): "request-and-response-on-minio-alias",
    }[(request_secret, response_secret)]
    if any(marker in text for marker in BUFFERED_READS):
        request_body = "buffered"
    elif any(marker in text for marker in STREAMED_READS):
        request_body = "streamed"
    elif "req.input" in text:
        request_body = "handed-on"
    else:
        request_body = "not-read"
    streamed = any(marker in text for marker in STREAMED_RESPONSES) or any(
        re.search(rf"\b{name}\b", text) for name in stream_types
    )
    response_body = "streamed" if streamed else "buffered"
    return caller_secret, request_body, response_body


# ── out-of-table routes the admin router claims first ─────────────────────────────────────────


def extension_routes(source):
    relative = (ADMIN / "router.rs").as_posix()
    text = source.text(relative)
    rows = []
    for function, enum, target_rule in (
        ("parse_replication_extension_request", "ReplicationExtRoute", "bucket"),
        ("parse_misc_extension_request", "MiscExtRoute", None),
    ):
        match = re.search(rf"fn {function}\([^)]*\)\s*->[^{{]*\{{", text)
        if not match:
            fail(f"{relative}: {function} not found")
        body = text[match.end():matching_close(text, match.end() - 1, "{", "}")]
        methods = [(m.start(), m.group(1)) for m in re.finditer(r"method\s*[!=]=\s*Method::(\w+)", body)]
        for variant in re.finditer(rf"{enum}::(\w+)(\s*\{{[^}}]*\}})?", body):
            before = body[:variant.start()]
            keys = re.findall(r'query_value_exact\(uri,\s*"([^"]+)"\)', before)
            if not keys:
                fail(f"{relative}: {enum}::{variant.group(1)} has no preceding query key")
            key = keys[-1]
            conditions = [c for c in re.findall(r"\bif\s+(.*?)\{", before, re.S) if f'"{key}"' in c or "value" in c]
            if not conditions:
                fail(f"{relative}: {enum}::{variant.group(1)} has no condition naming {key}")
            condition = conditions[-1]
            equals = re.search(r'value\s*==\s*"([^"]*)"|as_deref\(\)\s*==\s*Some\("([^"]*)"\)', condition)
            if equals:
                value_rule = f"equals:{equals.group(1) if equals.group(1) is not None else equals.group(2)}"
            elif "value.is_empty()" in condition:
                value_rule = "equals:"
            elif ".is_some()" in condition:
                value_rule = "present"
            else:
                fail(f"{relative}: unreadable discriminator condition {squash(condition)!r}")
            method = [name for start, name in methods if start < variant.start() and "!=" not in body[start:start + 12]]
            negated = [name for start, name in methods if "!=" in body[start:start + 12]]
            method_name = (method[-1] if method else negated[0] if negated else None)
            if method_name is None:
                fail(f"{relative}: {enum}::{variant.group(1)} has no method")
            fields = variant.group(2) or ""
            if target_rule:
                target = target_rule
            elif "object" in fields:
                target = "object"
            elif "None" in fields:
                target = "service"
            else:
                target = "bucket"
            rows.append({
                "name": f"{enum}::{variant.group(1)}" + ("" if not fields else f"[{target}]"),
                "variant": variant.group(1),
                "fields": fields,
                "method": method_name,
                "target": target,
                "query_discriminator": {"key": key, "rule": value_rule},
                "auth_mode": "custom",
                "auth_detail": "SignatureRequiredThenHandlerCheck",
            })
    actions = {}
    for function in ("replication_extension_policy_action", "authorize_misc_extension_request"):
        match = re.search(rf"fn {function}\([^)]*\)[^{{]*\{{", text)
        if not match:
            fail(f"{relative}: {function} not found")
        body = text[match.end():matching_close(text, match.end() - 1, "{", "}")]
        for arm in re.finditer(r"((?:\w+Route::\w+(?:\s*\{[^}]*\})?\s*\|?\s*)+)=>(.*?)(?=\w+Route::\w+(?:\s*\{[^}]*\})?\s*(?:\||=>)|\Z)", body, re.S):
            action = re.search(r"Action::\w+\((\w+)::(\w+)\)", arm.group(2))
            if not action:
                continue
            for route in re.finditer(r"(\w+)Route::(\w+)(\s*\{[^}]*\})?", arm.group(1)):
                actions.setdefault((route.group(2), squash(route.group(3) or "")), (action.group(1), action.group(2)))
    for row in rows:
        variant, fields = row.pop("variant"), squash(row.pop("fields"))
        found = actions.get((variant, fields)) or actions.get((variant, ""))
        if found is None:
            candidates = [a for (v, f), a in actions.items() if v == variant and (("None" in f) == ("None" in fields))]
            found = candidates[0] if len(candidates) == 1 else None
        if found is None:
            fail(f"{relative}: no authorisation action for {row['name']}")
        row["iam_action_enum"], row["iam_action"] = found
    return rows


# ── the policy wire spelling of each action ───────────────────────────────────────────────────


def action_wire_names(root):
    """`{enum: {variant: wire}}` for every policy action enum."""
    relative = "crates/policy/src/policy/action.rs"
    path = root / relative
    if not path.is_file():
        fail(f"RustFS source file {relative} is missing")
    text = strip_comments(path.read_text(encoding="utf-8"))
    names = {}
    for enum in re.finditer(r"pub enum (\w+)\s*\{", text):
        body = text[enum.end():matching_close(text, enum.end() - 1, "{", "}")]
        found = dict((variant, wire) for wire, variant in re.findall(
            r'#\[strum\(serialize\s*=\s*"([^"]+)"\)\]\s*([A-Z][A-Za-z0-9]*)\s*,', body))
        if found:
            names[enum.group(1)] = found
    if "AdminAction" not in names:
        fail(f"{relative}: no AdminAction wire spellings found")
    return names


def wire_name(action, names, enum):
    """The policy spelling of `action`, looked up in `enum` first and otherwise only if unique."""
    if action is None:
        return None
    if ":" in action:
        return action
    if action in names.get(enum, {}):
        return names[enum][action]
    candidates = {table[action] for table in names.values() if action in table}
    if len(candidates) != 1:
        fail(f"no unique policy wire spelling for {action} (preferred enum {enum})")
    return candidates.pop()


# ── assembly ──────────────────────────────────────────────────────────────────────────────────


def surface(path, source):
    relative = (ADMIN / "mod.rs").as_posix()
    admin = source.const("ADMIN_PREFIX", relative)
    if path.startswith(source.const("TABLE_CATALOG_COMPAT_PREFIX", relative) + "/"):
        return "table-catalog-compat"
    if path.startswith(source.const("TABLE_CATALOG_PREFIX", relative) + "/"):
        return "table-catalog"
    if path.startswith(admin + "/v4/"):
        return "admin-v4"
    if path.startswith(admin + "/"):
        return "admin-v3"
    return "root"


def router_admits_anonymous(method, path, row, source):
    """Mirrors `S3Router::check_access` for a registered route: which requests pass unsigned."""
    oidc = (ADMIN / "handlers/oidc.rs").as_posix()
    admin = source.const("ADMIN_PREFIX", oidc)
    if row["auth_mode"] == "anonymous":
        return True
    oidc_paths = (
        admin + source.const("OIDC_PUBLIC_PROVIDERS_SUFFIX", oidc),
        admin + source.const("OIDC_LOGOUT_SUFFIX", oidc),
    )
    oidc_prefixes = (
        admin + source.const("OIDC_AUTHORIZE_SUFFIX", oidc),
        admin + source.const("OIDC_CALLBACK_SUFFIX", oidc),
    )
    if path in oidc_paths or path.startswith(oidc_prefixes):
        return True
    zip_path = admin + source.const("ADMIN_OBJECT_ZIP_DOWNLOADS_PATH", (ADMIN / "router.rs").as_posix()) + "/"
    return method == "GET" and path.startswith(zip_path) and path.endswith(".zip")


def generate(root):
    commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], check=True, capture_output=True, text=True).stdout
    if dirty.strip():
        fail(f"{root} has uncommitted changes; an inventory must name a commit")
    source = Source(root)
    policy = read_policy(source)
    matrix, helpers = read_matrix(source)
    sites = insert_sites(source)
    registered = {}
    for site in sites:
        key = f"{site['method']} {site['path']}"
        if key in registered:
            fail(f"{site['file']}: {key} is inserted twice")
        registered[key] = site

    for left_name, left, right_name, right in (
        ("route policy", set(policy), "registration matrix", set(matrix)),
        ("registration matrix", set(matrix), "insert sites", set(registered)),
    ):
        if left != right:
            only_left = sorted(left - right)[:5]
            only_right = sorted(right - left)[:5]
            fail(f"{left_name} and {right_name} disagree: only in {left_name} {only_left}; only in {right_name} {only_right}")

    groups = register_graph(source)
    group_of_function = {}
    for module, function in groups:
        group_of_function.setdefault(function, module)
    calls = {}
    for relative, text in source.files.items():
        for name, ranges in functions(text).items():
            if name.startswith("register_"):
                for start, end in ranges:
                    calls.setdefault(name, set()).update(re.findall(r"\b(register_[a-z_]+)\(", text[start:end]))
    owner = {}
    for module, function in groups:
        stack, seen = [function], set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            owner.setdefault(current, module)
            stack.extend(calls.get(current, ()))

    routes = []
    for key in sorted(registered):
        site = registered[key]
        if site["function"] not in owner:
            fail(f"{site['file']}: {key} is inserted by {site['function']}, which no registration group reaches")
        type_name = handler_type(source, site["handler"], site["file"])
        handler_file, body, stream_types = handler_body(source, type_name, site.get("variant"))
        caller_secret, request_body, response_body = body_facts(body, stream_types)
        row = policy[key]
        method, path = key.split(" ", 1)
        admin_prefix = source.const("ADMIN_PREFIX", (ADMIN / "mod.rs").as_posix())
        routes.append({
            "method": method,
            "path": path,
            "group": owner[site["function"]],
            "surface": surface(path, source),
            "path_params": re.findall(r"\{([^}]+)\}", path),
            "minio_admin_alias": path.startswith(admin_prefix + "/"),
            "query_discriminators": [],
            "auth_mode": row["auth_mode"],
            "iam_action": row["iam_action"],
            "iam_action_wire": None,
            "auth_detail": row["auth_detail"],
            "risk": row["risk"],
            "router_admits_anonymous": router_admits_anonymous(method, path, row, source),
            "handler": type_name,
            "handler_file": handler_file,
            "caller_secret_body": caller_secret,
            "request_body": request_body,
            "response_body": response_body,
        })

    names = action_wire_names(root)
    for row in routes:
        row["iam_action_wire"] = wire_name(row["iam_action"], names, "AdminAction")
    extensions = extension_routes(source)
    for row in extensions:
        row["iam_action_wire"] = wire_name(row["iam_action"], names, row.pop("iam_action_enum"))
    return {
        "format": FORMAT,
        "source": {
            "repository": "https://github.com/rustfs/rustfs",
            "commit": commit,
            "authorities": [
                "rustfs/src/admin/route_policy.rs",
                "rustfs/src/admin/route_registration_test.rs",
                "rustfs/src/admin/**/*.rs insert sites",
                "rustfs/src/admin/router.rs extension parsers",
            ],
            "registration_groups": len(groups),
            "matrix_helper_calls": dict(sorted(helpers.items())),
        },
        "census": census(routes, extensions),
        "routes": routes,
        "extension_routes": extensions,
    }


def tally(rows, field):
    counts = {}
    for row in rows:
        value = row[field]
        value = "null" if value is None else str(value).lower() if isinstance(value, bool) else value
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def census(routes, extensions):
    return {
        "routes": len(routes),
        "extension_routes": len(extensions),
        "by_auth_mode": tally(routes, "auth_mode"),
        "by_auth_detail": tally(routes, "auth_detail"),
        "by_surface": tally(routes, "surface"),
        "by_group": tally(routes, "group"),
        "by_caller_secret_body": tally(routes, "caller_secret_body"),
        "by_request_body": tally(routes, "request_body"),
        "by_response_body": tally(routes, "response_body"),
        "with_path_params": sum(1 for row in routes if row["path_params"]),
        "with_minio_admin_alias": sum(1 for row in routes if row["minio_admin_alias"]),
        "router_admits_anonymous": sum(1 for row in routes if row["router_admits_anonymous"]),
        "distinct_iam_actions": len({row["iam_action"] for row in routes if row["iam_action"]}),
    }


def render(document):
    """One route per line, so a regenerated inventory diffs route by route."""
    lines = ["{"]
    for field in ("format", "source", "census"):
        lines.append(f"  {json.dumps(field)}: {json.dumps(document[field], sort_keys=False)},")
    for field in ("routes", "extension_routes"):
        rows = document[field]
        lines.append(f"  {json.dumps(field)}: [")
        for index, row in enumerate(rows):
            comma = "," if index + 1 < len(rows) else ""
            lines.append(f"    {json.dumps(row, sort_keys=False)}{comma}")
        lines.append("  ]" + ("," if field == "routes" else ""))
    lines.append("}")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rustfs", required=True, type=pathlib.Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", type=pathlib.Path)
    group.add_argument("--check", type=pathlib.Path)
    args = parser.parse_args()
    try:
        rendered = render(generate(args.rustfs))
    except (InventoryError, subprocess.CalledProcessError) as error:
        print(f"gen_rustfs_admin_route_inventory: {error}", file=sys.stderr)
        return 1
    if args.out:
        args.out.write_text(rendered, encoding="utf-8")
        return 0
    if not args.check.is_file():
        print(f"gen_rustfs_admin_route_inventory: {args.check} is missing", file=sys.stderr)
        return 1
    if args.check.read_text(encoding="utf-8") != rendered:
        print(f"gen_rustfs_admin_route_inventory: {args.check} drifted from {args.rustfs}; regenerate with --out", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
