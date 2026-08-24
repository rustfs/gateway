#!/usr/bin/env bash
set -euo pipefail

# The protected quirk ledger is useful only when every number is derived from the canonical
# overlay and every typed source reaches both a production consumer and bilateral case evidence.
# Generated Rust is deliberately excluded: a checked-in generated file is an output, not proof
# that the hand-written source is wired.
#
# What "wired" means here, exactly, because gateway#242 was read out of this word:
#   * for a TYPED CONTRACT it is a join to an executable emitter binding that declares a constant;
#   * for a lowered-IR MUTABLE rule it is a join to `model/overlays/ops/*.toml`;
#   * for a runtime-contract MUTABLE rule it is the same executable-emitter join as a contract.
# The second is a declaration by one hand-written overlay that another hand-written overlay's rule
# belongs to an operation. It is NOT evidence that any running code reads the lowered value, and it
# cannot be: this guard never builds anything. Three of the ids it counted as wired had a lowered
# value with no reader at all — `q-lc-0001`, `q-bkt-0001`, `q-bkt-0007` — and the corpus could not
# have noticed, because nothing built a response from them.
# The dynamic proof is `cargo xtask conformance mutate`, which flips the rule, rebuilds, and reports
# whether a case caught it. A row this guard calls wired and that command calls INERT is the exact
# gap; read the two together, never this one alone.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

python3 - "$ROOT_DIR" <<'PYEOF'
from __future__ import annotations

import pathlib
import hashlib
import json
import os
import re
import sqlite3
import sys
import tomllib
from collections import defaultdict

root = pathlib.Path(sys.argv[1])
overlay_dir = root / "model/overlays/quirks"
ops_dir = root / "model/overlays/ops"
case_dir = root / "conformance/cases"

EXPECTED = {
    "records": 348,
    "mutable": 98,
    "typed_contracts": 160,
    "untyped_contracts": 90,
    "typed_sources": 258,
    "dimensions": 177,
    "wired": 256,
    "emitted_constants": 170,
}
CAPABILITY_BLOCKS = {"q-cors-0006", "q-cors-0047"}

errors: list[str] = []

# Guard self-tests run this whole-repository parser once per isolated mutation. The optional cache
# stores parse products only: every invocation still discovers the current inventory, reads every
# input, rebuilds every derived set, and computes a fresh verdict. Content hashes make a changed
# file a mandatory cache miss, so a mutation can never inherit the baseline parse or verdict.
cache_path = os.environ.get("GATEWAY_QUIRK_LEDGER_PARSE_CACHE")
cache_connection: sqlite3.Connection | None = None
memory_cache: dict[str, dict[str, object]] = {"toml": {}, "rust": {}}


def cache_key(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def fail(message: str) -> None:
    errors.append(message)


def open_parse_cache() -> sqlite3.Connection | None:
    if not cache_path:
        return None
    destination = pathlib.Path(cache_path)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(destination)
        connection.execute("CREATE TABLE IF NOT EXISTS parse_cache (kind TEXT, hash TEXT, value TEXT, PRIMARY KEY(kind, hash))")
        return connection
    except (OSError, sqlite3.DatabaseError):
        # A corrupt acceleration cache is not a policy result; discard that exact file and rebuild.
        try:
            connection.close()
        except (NameError, sqlite3.Error):
            pass
        try:
            destination.unlink(missing_ok=True)
            connection = sqlite3.connect(destination)
            connection.execute(
                "CREATE TABLE parse_cache (kind TEXT, hash TEXT, value TEXT, PRIMARY KEY(kind, hash))"
            )
            return connection
        except (OSError, sqlite3.DatabaseError) as error:
            fail(f"parse cache rebuild failed: {error}")
            return None


cache_connection = open_parse_cache()


def cached_parse(kind: str, key: str) -> object | None:
    if key in memory_cache[kind]:
        return memory_cache[kind][key]
    if cache_connection is None:
        return None
    try:
        row = cache_connection.execute(
            "SELECT value FROM parse_cache WHERE kind = ? AND hash = ?", (kind, key)
        ).fetchone()
        if row is None:
            return None
        value = json.loads(row[0])
        memory_cache[kind][key] = value
        return value
    except (json.JSONDecodeError, TypeError):
        # A malformed value invalidates only that content-hash entry. Re-parse the live file and
        # replace the row below; cache corruption must not masquerade as a policy failure.
        try:
            cache_connection.execute(
                "DELETE FROM parse_cache WHERE kind = ? AND hash = ?", (kind, key)
            )
            return None
        except sqlite3.DatabaseError as error:
            fail(f"parse cache row quarantine failed: {error}")
            return None
    except sqlite3.DatabaseError as error:
        fail(f"parse cache read failed: {error}")
        return None


def store_parse(kind: str, key: str, value: object) -> None:
    memory_cache[kind][key] = value
    if cache_connection is None:
        return
    try:
        cache_connection.execute(
            "INSERT OR REPLACE INTO parse_cache(kind, hash, value) VALUES (?, ?, ?)",
            (kind, key, json.dumps(value, separators=(",", ":"))),
        )
    except (sqlite3.DatabaseError, TypeError, ValueError) as error:
        fail(f"parse cache write failed: {error}")


def save_parse_cache() -> None:
    if cache_connection is None:
        return
    try:
        cache_connection.commit()
        cache_connection.close()
    except sqlite3.DatabaseError as error:
        fail(f"parse cache commit failed: {error}")


def load_toml(path: pathlib.Path) -> dict:
    try:
        text = path.read_text()
        key = cache_key(text)
        cached = cached_parse("toml", key)
        if isinstance(cached, dict):
            return cached
        parsed = tomllib.loads(text)
        store_parse("toml", key, parsed)
        return parsed
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"{path.relative_to(root)}: {error}")
        return {}


# Compiled once, then matched with an offset. Cutting a fresh `text[index:]` slice copies the
# whole remainder of the file on every character, which makes an otherwise linear lexer
# quadratic in file length; `pattern.match(text, index)` matches at the same place without the
# copy. No pattern here carries `^`, `\A`, `\b` or a lookbehind, so anchoring at the offset is
# exactly what slicing to it already meant.
RAW_STRING_RE = re.compile(r'(?:b|c)?r(#+)?"')
LIFETIME_RE = re.compile(r"'[A-Za-z_][A-Za-z0-9_]*")
IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def rust_tokens(text: str) -> list[tuple[str, str, int]]:
    """Lex the Rust subset needed by this guard while discarding comments and literals as code."""
    key = cache_key(text)
    cached = cached_parse("rust", key)
    if isinstance(cached, list):
        return cached
    tokens: list[tuple[str, str, int]] = []
    index = 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
            continue
        if text.startswith("/*", index):
            depth = 1
            index += 2
            while index < len(text) and depth:
                if text.startswith("/*", index):
                    depth += 1
                    index += 2
                elif text.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            continue
        raw = RAW_STRING_RE.match(text, index)
        if raw:
            hashes = raw.group(1) or ""
            content_start = raw.end()
            terminator = '"' + hashes
            content_end = text.find(terminator, content_start)
            if content_end < 0:
                content_end = len(text)
                index = len(text)
            else:
                index = content_end + len(terminator)
            tokens.append(("string", text[content_start:content_end], content_start))
            continue
        quote_index = index + 1 if text[index] in {"b", "c"} and index + 1 < len(text) and text[index + 1] == '"' else index
        if text[quote_index] == '"':
            content_start = quote_index + 1
            cursor = content_start
            while cursor < len(text):
                if text[cursor] == "\\":
                    cursor += 2
                elif text[cursor] == '"':
                    break
                else:
                    cursor += 1
            tokens.append(("string", text[content_start:cursor], content_start))
            index = min(cursor + 1, len(text))
            continue
        if text[index] == "'":
            # A lifetime is code; a quoted character is not.
            lifetime = LIFETIME_RE.match(text, index)
            if lifetime and (index + len(lifetime.group(0)) >= len(text) or text[index + len(lifetime.group(0))] != "'"):
                tokens.append(("punct", "'", index))
                index += 1
                continue
            cursor = index + 1
            while cursor < len(text):
                if text[cursor] == "\\":
                    cursor += 2
                elif text[cursor] == "'":
                    cursor += 1
                    break
                else:
                    cursor += 1
            index = cursor
            continue
        identifier = IDENTIFIER_RE.match(text, index)
        if identifier:
            value = identifier.group(0)
            tokens.append(("ident", value, index))
            index += len(value)
            continue
        if text.startswith("::", index):
            tokens.append(("punct", "::", index))
            index += 2
            continue
        tokens.append(("punct", text[index], index))
        index += 1
    store_parse("rust", key, tokens)
    return tokens


def matching_delimiter(tokens: list[tuple[str, str, int]], start: int) -> int | None:
    pairs = {"(": ")", "[": "]", "{": "}"}
    opening = tokens[start][1]
    if opening not in pairs:
        return None
    stack = [pairs[opening]]
    for index in range(start + 1, len(tokens)):
        value = tokens[index][1]
        if value in pairs:
            stack.append(pairs[value])
        elif stack and value == stack[-1]:
            stack.pop()
            if not stack:
                return index
    return None


def calls(tokens: list[tuple[str, str, int]]) -> list[tuple[str, int, int, list[tuple[str, str, int]]]]:
    found = []
    for index, token in enumerate(tokens):
        if token[0] != "ident" or (index and tokens[index - 1][1] == "fn"):
            continue
        opening = index + 1
        if opening < len(tokens) and tokens[opening][1] == "!":
            opening += 1
        if opening >= len(tokens) or tokens[opening][1] != "(":
            continue
        end = matching_delimiter(tokens, opening)
        if end is not None:
            found.append((token[1], index, end, tokens[opening + 1 : end]))
    return found


def qualified_variants(tokens: list[tuple[str, str, int]], namespace: str) -> set[str]:
    return {
        tokens[index + 2][1]
        for index in range(len(tokens) - 2)
        if tokens[index][1] == namespace and tokens[index + 1][1] == "::" and tokens[index + 2][0] == "ident"
    }


def first_qualified_variant(tokens: list[tuple[str, str, int]], namespace: str) -> str | None:
    for index in range(len(tokens) - 2):
        if tokens[index][1] == namespace and tokens[index + 1][1] == "::" and tokens[index + 2][0] == "ident":
            return tokens[index + 2][1]
    return None


def emitted_names(tokens: list[tuple[str, str, int]]) -> set[str]:
    return {
        name
        for kind, value, _ in tokens
        if kind == "string"
        for name in re.findall(r"\b[A-Z][A-Z0-9_]*_[A-Z0-9_]+\b", value)
    }


def production_tokens(tokens: list[tuple[str, str, int]]) -> list[tuple[str, str, int]]:
    """Discard cfg-gated and test items before production identifiers are collected."""
    active: list[tuple[str, str, int]] = []
    index = 0
    while index < len(tokens):
        if tokens[index][1] != "#" or index + 1 >= len(tokens) or tokens[index + 1][1] != "[":
            active.append(tokens[index])
            index += 1
            continue

        attributes_start = index
        cursor = index
        gated = False
        while cursor + 1 < len(tokens) and tokens[cursor][1] == "#" and tokens[cursor + 1][1] == "[":
            attribute_end = matching_delimiter(tokens, cursor + 1)
            if attribute_end is None:
                raise ValueError("unterminated outer attribute")
            attribute = tokens[cursor + 2 : attribute_end]
            names = [value for kind, value, _ in attribute if kind == "ident"]
            gated = gated or bool(names) and (
                names[0] == "cfg"
                or names[0] == "test"
                or names[:2] == ["tokio", "test"]
                or names[0] == "cfg_attr" and "cfg" in names[1:]
            )
            cursor = attribute_end + 1

        if not gated:
            active.extend(tokens[attributes_start:cursor])
            index = cursor
            continue

        item_start = cursor
        probe_stack: list[str] = []
        block_item = False
        semicolon_item = False
        for probe in range(item_start, len(tokens)):
            value = tokens[probe][1]
            if value in {"(", "["}:
                probe_stack.append({"(": ")", "[": "]"}[value])
            elif probe_stack and value == probe_stack[-1]:
                probe_stack.pop()
            elif not probe_stack and value in {"=", ";", ",", "{"}:
                break
            elif not probe_stack and tokens[probe][0] == "ident" and value in {
                "fn",
                "impl",
                "trait",
                "struct",
                "enum",
                "union",
                "mod",
                "macro_rules",
            }:
                block_item = True
                break
            elif not probe_stack and tokens[probe][0] == "ident" and value in {"let", "const", "static", "type", "use"}:
                semicolon_item = True
            elif not probe_stack and value == "!":
                block_item = True
                break

        stack: list[str] = []
        item_end = None
        for candidate in range(item_start, len(tokens)):
            value = tokens[candidate][1]
            if value in {"(", "[", "{"}:
                if value == "{" and not stack and (block_item or not semicolon_item):
                    closing = matching_delimiter(tokens, candidate)
                    if closing is None:
                        raise ValueError("unterminated cfg-gated block item")
                    item_end = closing + 1
                    if item_end < len(tokens) and tokens[item_end][1] == ";":
                        item_end += 1
                    break
                stack.append({"(": ")", "[": "]", "{": "}"}[value])
            elif stack and value == stack[-1]:
                stack.pop()
            elif not stack and value in {";", ","}:
                item_end = candidate + 1
                break
        if item_end is None:
            raise ValueError("could not bound cfg-gated item")
        index = item_end
    return active


def toml_quirk_refs(value: object) -> set[str]:
    references: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"quirks", "quirk_refs"} and isinstance(item, list):
                references.update(reference for reference in item if isinstance(reference, str))
            references.update(toml_quirk_refs(item))
    elif isinstance(value, list):
        for item in value:
            references.update(toml_quirk_refs(item))
    return references


records: dict[str, tuple[dict, pathlib.Path]] = {}
for path in sorted(overlay_dir.glob("*.toml")):
    for record in load_toml(path).get("quirk", []):
        quirk_id = record.get("id")
        if not isinstance(quirk_id, str):
            fail(f"{path.relative_to(root)}: quirk without a string id")
            continue
        if quirk_id in records:
            fail(f"{quirk_id}: duplicate source in {records[quirk_id][1].relative_to(root)} and {path.relative_to(root)}")
        records[quirk_id] = (record, path)

mutable: set[str] = set()
mutable_contracts: set[str] = set()
typed_contracts: set[str] = set()
untyped_contracts: set[str] = set()
typed_sources: set[str] = set()
dimensions: set[str] = set()

for quirk_id, (record, path) in records.items():
    classification = record.get("classification")
    has_range = "codec_min" in record or "codec_max" in record
    if has_range and not ("codec_min" in record and "codec_max" in record):
        fail(f"{quirk_id}: a codec range must declare both codec_min and codec_max")
    source_kinds = [
        name
        for name, present in (
            ("codec_value", "codec_value" in record),
            ("codec_range", has_range),
            ("mutation_sources", "mutation_sources" in record),
            ("contract_value", "contract_value" in record),
        )
        if present
    ]
    if len(source_kinds) > 1:
        fail(f"{quirk_id}: multiple typed sources {source_kinds}")
    typed = len(source_kinds) == 1
    if classification == "mutable":
        mutable.add(quirk_id)
        if not typed:
            fail(f"{quirk_id}: mutable record has no unique typed source")
        elif source_kinds == ["contract_value"]:
            mutable_contracts.add(quirk_id)
    elif classification == "contract":
        if typed:
            if source_kinds != ["contract_value"]:
                fail(f"{quirk_id}: contract record has the wrong source kind {source_kinds}")
            typed_contracts.add(quirk_id)
        else:
            untyped_contracts.add(quirk_id)
    else:
        fail(f"{quirk_id}: unknown classification {classification!r} in {path.relative_to(root)}")
    if typed:
        typed_sources.add(quirk_id)
        dimension = record.get("mutation_dimension")
        if not isinstance(dimension, str) or not dimension:
            fail(f"{quirk_id}: typed source has no mutation_dimension")
        else:
            dimensions.add(dimension)
    cases = record.get("cases")
    if not isinstance(cases, list) or not cases or any(not isinstance(case, str) for case in cases):
        fail(f"{quirk_id}: cases must be a non-empty string list")
    elif len(cases) != len(set(cases)):
        fail(f"{quirk_id}: duplicate case backlink")


def expect_count(name: str, actual: int) -> None:
    expected = EXPECTED[name]
    if actual != expected:
        fail(f"ledger {name}: expected {expected}, found {actual}")


expect_count("records", len(records))
expect_count("mutable", len(mutable))
expect_count("typed_contracts", len(typed_contracts))
expect_count("untyped_contracts", len(untyped_contracts))
expect_count("typed_sources", len(typed_sources))
expect_count("dimensions", len(dimensions))

if not CAPABILITY_BLOCKS.issubset(typed_contracts):
    fail("capability exclusions must remain typed contract sources")

# Mutable sources join to parsed operation-overlay values, never to raw TOML text. This excludes
# comments while retaining deliberate sharing across operations inside the one codec resolver.
# The join proves the rule is CLAIMED by an operation, not that its lowered value is read — see the
# note at the top of this file, and `cargo xtask conformance mutate` for the claim this cannot make.
operation_overlays = [(path, toml_quirk_refs(load_toml(path))) for path in sorted(ops_dir.glob("*.toml"))]
mutable_wired: set[str] = set()
for quirk_id in sorted(mutable - mutable_contracts):
    consumers = [path for path, references in operation_overlays if quirk_id in references]
    if consumers:
        mutable_wired.add(quirk_id)
    else:
        fail(f"{quirk_id}: mutable source is claimed by no operation overlay")

# Parse each family emitter as Rust tokens. Each typed contract must join to one executable emitter
# binding, and that binding must declare at least one constant. The discriminator is needed for the
# few dimensions intentionally shared by several different typed ContractValue variants.
emitter_paths = [
    root / "crates/codegen/src/emit/naming_contracts.rs",
    root / "crates/codegen/src/emit/range_contracts.rs",
    root / "crates/codegen/src/emit/runtime_contracts.rs",
    *sorted((root / "crates/codegen/src/emit/runtime_contracts").glob("*.rs")),
]
emitter_texts = {path: path.read_text() for path in emitter_paths}

dimension_tokens = rust_tokens((root / "crates/model/src/overlay/mutation_dimension.rs").read_text())
variant_to_name: dict[str, str] = {}
for index in range(len(dimension_tokens) - 4):
    if (
        dimension_tokens[index][1] == "Self"
        and dimension_tokens[index + 1][1] == "::"
        and dimension_tokens[index + 2][0] == "ident"
        and dimension_tokens[index + 3][1] == "="
        and dimension_tokens[index + 4][1] == ">"
    ):
        following = dimension_tokens[index + 5 : index + 8]
        names = [value for kind, value, _ in following if kind == "string"]
        if names:
            variant_to_name[dimension_tokens[index + 2][1]] = names[0]
name_to_variant = {name: variant for variant, name in variant_to_name.items()}


def split_arguments(tokens: list[tuple[str, str, int]]) -> list[list[tuple[str, str, int]]]:
    arguments: list[list[tuple[str, str, int]]] = [[]]
    stack: list[str] = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    for token in tokens:
        value = token[1]
        if value in pairs:
            stack.append(pairs[value])
        elif stack and value == stack[-1]:
            stack.pop()
        if value == "," and not stack:
            arguments.append([])
        else:
            arguments[-1].append(token)
    return arguments


# (dimension variant, optional ContractValue discriminator, constants, emitter path)
emitter_bindings: list[tuple[str, str | None, set[str], pathlib.Path]] = []
for path, text in emitter_texts.items():
    tokens = rust_tokens(text)
    invocations = calls(tokens)
    source_calls = []
    for name, start, end, inner in invocations:
        dimensions_in_call = qualified_variants(inner, "MutationDimension")
        if name in {"render_enum", "render_contract", "emit_policy"}:
            arguments = split_arguments(inner)
            if name in {"render_contract", "emit_policy"} and len(arguments) >= 3:
                bare = [value for kind, value, _ in arguments[2] if kind == "ident"]
                dimensions_in_call.update(bare[:1])
            constants = emitted_names(inner)
            if len(dimensions_in_call) == 1 and constants:
                emitter_bindings.append((next(iter(dimensions_in_call)), None, constants, path))
        if name in {"unique", "unique_kind"} and len(dimensions_in_call) == 1:
            discriminators = qualified_variants(inner, "ContractValue") if name == "unique_kind" else set()
            source_calls.append((start, end, next(iter(dimensions_in_call)), discriminators))

    emitting_calls = [call for call in invocations if call[0] in {"writeln", "render_str_slice"}]
    for source_index, (start, end, dimension, discriminators) in enumerate(source_calls):
        next_start = source_calls[source_index + 1][0] if source_index + 1 < len(source_calls) else len(tokens)
        constants = set().union(
            *(emitted_names(inner) for _, emit_start, _, inner in emitting_calls if end < emit_start < next_start),
            set(),
        )
        if constants:
            discriminator = next(iter(discriminators)) if len(discriminators) == 1 else None
            emitter_bindings.append((dimension, discriminator, constants, path))

all_constants = set().union(*(binding[2] for binding in emitter_bindings), set())
expect_count("emitted_constants", len(all_constants))

# Parse the ambiguous dimension/value pairs through the canonical model decoder so that a source
# cannot silently bind to another consumer that happens to share its mutation dimension.
ambiguous_variants = {
    variant
    for variant in {binding[0] for binding in emitter_bindings}
    if sum(1 for binding in emitter_bindings if binding[0] == variant) > 1
}
ambiguous_names = {variant_to_name[variant] for variant in ambiguous_variants if variant in variant_to_name}
contract_variant_by_value: dict[tuple[str, str], str] = {}
for path in sorted((root / "crates/model/src/overlay").glob("*.rs")):
    tokens = rust_tokens(path.read_text())
    for index, token in enumerate(tokens):
        if token[0] != "string" or token[1] not in ambiguous_names:
            continue
        value_tokens = [candidate for candidate in tokens[index + 1 : index + 8] if candidate[0] == "string"]
        if not value_tokens:
            continue
        arrow = next(
            (
                offset
                for offset in range(index + 1, min(index + 18, len(tokens) - 1))
                if tokens[offset][1] == "=" and tokens[offset + 1][1] == ">"
            ),
            None,
        )
        if arrow is None:
            continue
        variant = first_qualified_variant(tokens[arrow + 2 : arrow + 90], "ContractValue")
        if variant is not None:
            contract_variant_by_value[(token[1], value_tokens[0][1])] = variant

# Real Rust identifier uses are collected after lexing, with use/re-export statements removed.
# Comments, normal strings and character literals therefore cannot manufacture a consumer.
production_identifiers: dict[pathlib.Path, set[str]] = {}
production_paths = (
    sorted((root / "crates/types/src/scalar").rglob("*.rs"))
    + sorted((root / "crates/core/src").rglob("*.rs"))
    + sorted((root / "crates/sig/src").rglob("*.rs"))
)
for path in production_paths:
    relative = path.relative_to(root)
    if "generated" in relative.parts:
        continue
    if "tests" in relative.parts or path.name.endswith("_tests.rs"):
        continue
    try:
        tokens = production_tokens(rust_tokens(path.read_text()))
    except ValueError as error:
        fail(f"{relative}: {error}")
        continue
    identifiers: set[str] = set()
    skip_use = False
    for kind, value, _ in tokens:
        if kind == "ident" and value == "use" and not skip_use:
            skip_use = True
            continue
        if skip_use:
            if value == ";":
                skip_use = False
            continue
        if kind == "ident":
            identifiers.add(value)
    production_identifiers[path] = identifiers

# Two namespace policies are selected in executable code generation. Only string arms of the
# active `let policy = match operation` expression count, and the selected policy must feed format!.
decode_path = root / "crates/codegen/src/emit/codec/decode.rs"
decode_tokens = rust_tokens(decode_path.read_text())
generated_consumer_constants: set[str] = set()
for index in range(len(decode_tokens) - 6):
    if [token[1] for token in decode_tokens[index : index + 5]] != ["let", "policy", "=", "match", "operation"]:
        continue
    brace = index + 5
    if brace >= len(decode_tokens) or decode_tokens[brace][1] != "{":
        continue
    end = matching_delimiter(decode_tokens, brace)
    if end is None:
        continue
    function_start = next(
        (
            candidate
            for candidate in range(index - 1, -1, -1)
            if decode_tokens[candidate][1] == "fn"
            and candidate + 1 < len(decode_tokens)
            and decode_tokens[candidate + 1][1] == "root_namespace_guard"
        ),
        None,
    )
    if function_start is None:
        continue
    function_brace = next(
        (candidate for candidate in range(function_start, index) if decode_tokens[candidate][1] == "{"),
        None,
    )
    function_end = matching_delimiter(decode_tokens, function_brace) if function_brace is not None else None
    if function_end is None:
        continue
    format_uses_policy = any(
        name == "format"
        and any(token[1] == "policy" or token[0] == "string" and "{policy}" in token[1] for token in inner)
        for name, start, _, inner in calls(decode_tokens)
        if end < start < function_end
    )
    if format_uses_policy:
        match_body = decode_tokens[brace + 1 : end]
        stack: list[str] = []
        pairs = {"(": ")", "[": "]", "{": "}"}
        for offset in range(len(match_body) - 2):
            value = match_body[offset][1]
            if value in pairs:
                stack.append(pairs[value])
            elif stack and value == stack[-1]:
                stack.pop()
            if stack or value != "=" or match_body[offset + 1][1] != ">":
                continue
            expression = match_body[offset + 2 :]
            if expression and expression[0][1] == "{":
                expression_end = matching_delimiter(expression, 0)
                expression = expression[1:expression_end] if expression_end is not None else []
            else:
                expression = expression[:1]
            if len(expression) == 1 and expression[0][0] == "string" and "crate::contracts::" in expression[0][1]:
                generated_consumer_constants.update(emitted_names(expression))


def consumer_identity(path: pathlib.Path) -> str:
    relative = path.relative_to(root).as_posix()
    if relative.startswith("crates/types/src/scalar/"):
        return "rustfs-gateway-types::scalar"
    if relative.startswith("crates/core/src/"):
        return "rustfs-gateway-core"
    if relative.startswith("crates/sig/src/"):
        return "rustfs-gateway-sig"
    return relative


contract_joined: set[str] = set()
for quirk_id in sorted(typed_contracts | mutable_contracts):
    record = records[quirk_id][0]
    dimension_name = record["mutation_dimension"]
    dimension_variant = name_to_variant.get(dimension_name)
    candidates = [binding for binding in emitter_bindings if binding[0] == dimension_variant]
    if len(candidates) > 1:
        contract_variant = contract_variant_by_value.get((dimension_name, record["contract_value"]))
        candidates = [binding for binding in candidates if binding[1] == contract_variant]
    if len(candidates) != 1:
        fail(f"{quirk_id}: expected one declared emitter binding, found {len(candidates)}")
        continue
    _, _, constants, emitter = candidates[0]
    identities_by_constant: dict[str, set[str]] = {}
    for constant in constants:
        identities = {
            consumer_identity(path)
            for path, identifiers in production_identifiers.items()
            if constant in identifiers
            and (
                (emitter.name == "naming_contracts.rs" and path.relative_to(root).as_posix().startswith("crates/types/src/scalar/"))
                or (emitter.name == "range_contracts.rs" and path.relative_to(root).as_posix() == "crates/types/src/scalar/range.rs")
                or (
                    emitter.name not in {"naming_contracts.rs", "range_contracts.rs"}
                    and (
                        path.relative_to(root).as_posix().startswith("crates/core/src/")
                        or (
                            constant.startswith(("SIGNATURE_", "SIGV2_"))
                            and path.relative_to(root).as_posix().startswith("crates/sig/src/")
                        )
                    )
                )
            )
        }
        if constant in generated_consumer_constants and emitter.name not in {"naming_contracts.rs", "range_contracts.rs"}:
            identities.add("rustfs-gateway-codegen::codec::decode")
        identities_by_constant[constant] = identities
    if all(len(identities) == 1 for identities in identities_by_constant.values()):
        contract_joined.add(quirk_id)
    else:
        detail = {constant: sorted(identities) for constant, identities in identities_by_constant.items()}
        fail(f"{quirk_id}: emitted constants lack one production consumer identity: {detail}")

production_joined = mutable_wired | contract_joined
if production_joined != typed_sources:
    fail(
        "typed production join drifted: "
        f"missing={sorted(typed_sources - production_joined)}, extra={sorted(production_joined - typed_sources)}"
    )
wired = production_joined - CAPABILITY_BLOCKS
if production_joined - wired != CAPABILITY_BLOCKS:
    fail(f"capability exclusions drifted: {sorted(production_joined - wired)}")
expect_count("wired", len(wired))

# Build the bilateral case index. A TOML case takes precedence over a same-named unit control.
# Direct Rust cases are accepted only when they are executable test functions and name the quirk
# in that test's own block; comments elsewhere in the file do not create evidence.
toml_cases: dict[str, tuple[list[str], pathlib.Path]] = {}
for path in sorted(case_dir.rglob("*.toml")):
    case = load_toml(path).get("case", {})
    case_id = case.get("id")
    if not isinstance(case_id, str):
        continue
    if case_id in toml_cases:
        fail(f"{case_id}: duplicate TOML case")
    toml_cases[case_id] = (case.get("quirks", []), path)

direct_cases: dict[str, list[tuple[set[str], pathlib.Path]]] = defaultdict(list)
case_function = re.compile(r'(c_(?:[a-z0-9]+_)*?\d{4})(?:_[a-z0-9_]*)?')
for path in sorted((root / "crates").rglob("*.rs")):
    if "generated" in path.relative_to(root).parts:
        continue
    text = path.read_text()
    tokens = rust_tokens(text)
    index = 0
    depth = 0
    while index < len(tokens):
        value = tokens[index][1]
        if depth or value != "#" or index + 1 >= len(tokens) or tokens[index + 1][1] != "[":
            if value == "{":
                depth += 1
            elif value == "}" and depth:
                depth -= 1
            index += 1
            continue

        cursor = index
        test_attributes = 0
        gated = False
        while cursor + 1 < len(tokens) and tokens[cursor][1] == "#" and tokens[cursor + 1][1] == "[":
            attribute_end = matching_delimiter(tokens, cursor + 1)
            if attribute_end is None:
                fail(f"{path.relative_to(root)}: unterminated direct-case attribute")
                cursor = len(tokens)
                break
            names = [item for kind, item, _ in tokens[cursor + 2 : attribute_end] if kind == "ident"]
            if names == ["test"] or names[:2] == ["tokio", "test"]:
                test_attributes += 1
            if names and (
                names[0] in {"cfg", "ignore", "should_panic"}
                or names[0] == "cfg_attr" and {"cfg", "ignore", "should_panic"}.intersection(names[1:])
            ):
                gated = True
            cursor = attribute_end + 1
        if cursor >= len(tokens):
            break

        fn_index = next(
            (
                probe
                for probe in range(cursor, len(tokens))
                if tokens[probe][1] == "fn"
                or tokens[probe][1] in {"#", "{", "}", ";"}
            ),
            None,
        )
        if fn_index is None or tokens[fn_index][1] != "fn" or fn_index + 1 >= len(tokens):
            index = cursor
            continue
        name = tokens[fn_index + 1][1]
        matched_name = case_function.fullmatch(name)
        body_start = next((probe for probe in range(fn_index + 2, len(tokens)) if tokens[probe][1] in {"{", ";"}), None)
        if body_start is None or tokens[body_start][1] != "{":
            index = fn_index + 1
            continue
        body_end = matching_delimiter(tokens, body_start)
        if body_end is None:
            fail(f"{path.relative_to(root)}: unterminated direct-case function {name}")
            break
        if matched_name and test_attributes == 1 and not gated:
            body_tokens = tokens[body_start + 1 : body_end]
            string_bindings: dict[str, set[str]] = {}
            for binding_index in range(len(body_tokens) - 3):
                if (
                    body_tokens[binding_index][1] == "let"
                    and body_tokens[binding_index + 1][0] == "ident"
                    and body_tokens[binding_index + 2][1] == "="
                    and body_tokens[binding_index + 3][0] == "string"
                ):
                    string_bindings[body_tokens[binding_index + 1][1]] = set(
                        re.findall(r'\bq-[a-z0-9-]+-\d{4}\b', body_tokens[binding_index + 3][1])
                    )
            assertion_arguments = [
                inner
                for call_name, call_start, _, inner in calls(body_tokens)
                if call_name in {"assert", "assert_eq", "assert_ne", "panic"}
                and call_start >= 3
                and body_tokens[call_start - 3][1] == "::"
                and body_tokens[call_start - 2][1] == "core"
                and body_tokens[call_start - 1][1] == "::"
                and call_start + 1 < len(body_tokens)
                and body_tokens[call_start + 1][1] == "!"
            ]
            direct_backlinks = {
                quirk_id
                for arguments in assertion_arguments
                for kind, literal, _ in arguments
                if kind == "string"
                for quirk_id in re.findall(r'\bq-[a-z0-9-]+-\d{4}\b', literal)
            }
            referenced_bindings = {
                value for arguments in assertion_arguments for kind, value, _ in arguments if kind == "ident"
            }
            backlinks = direct_backlinks | set().union(
                *(string_bindings[name] for name in referenced_bindings if name in string_bindings),
                set(),
            )
            case_id = matched_name.group(1).replace("_", "-")
            direct_cases[case_id].append((backlinks, path))
        index = body_end + 1

for quirk_id in sorted(wired):
    record = records[quirk_id][0]
    for case_id in record["cases"]:
        if case_id in toml_cases:
            backlinks, path = toml_cases[case_id]
            if not isinstance(backlinks, list) or backlinks.count(quirk_id) != 1:
                fail(f"{quirk_id} -> {case_id}: missing unique backlink in {path.relative_to(root)}")
            continue
        direct = direct_cases.get(case_id, [])
        matching = [(backlinks, path) for backlinks, path in direct if quirk_id in backlinks]
        if len(matching) != 1:
            fail(f"{quirk_id} -> {case_id}: expected one executable direct-case backlink, found {len(matching)}")

for case_id, (backlinks, path) in toml_cases.items():
    if not isinstance(backlinks, list) or len(backlinks) != len(set(backlinks)):
        fail(f"{path.relative_to(root)}: case quirks must be unique")
        continue
    for quirk_id in backlinks:
        if quirk_id not in wired:
            continue
        if records[quirk_id][0]["cases"].count(case_id) != 1:
            fail(f"{case_id} -> {quirk_id}: missing unique source backlink")

for case_id, cases in direct_cases.items():
    for backlinks, path in cases:
        for quirk_id in backlinks & wired:
            if records[quirk_id][0]["cases"].count(case_id) != 1:
                fail(f"{case_id} -> {quirk_id}: direct case in {path.relative_to(root)} has no unique source backlink")

quirk_specs = {path.stem for path in (root / "spec/quirks").glob("*.toml")}
contract_specs = {path.stem for path in (root / "spec/contracts").glob("*.toml")}
if quirk_specs != mutable:
    fail(f"spec/quirks id set drifted: missing={sorted(mutable - quirk_specs)}, extra={sorted(quirk_specs - mutable)}")
if contract_specs != typed_contracts:
    expected_contracts = typed_contracts
    fail(
        "spec/contracts id set drifted: "
        f"missing={sorted(expected_contracts - contract_specs)}, extra={sorted(contract_specs - expected_contracts)}"
    )

save_parse_cache()

if errors:
    for error in errors:
        print(f"check_quirk_ledger: {error}", file=sys.stderr)
    raise SystemExit(1)

print("OK: quirk ledger 348 overlay facts = 258 proven sources (98 mutable + 160 typed contracts) + 90 deferred; 177 dimensions; 256 wired; 2 capability blocks")
PYEOF
