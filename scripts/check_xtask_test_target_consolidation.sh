#!/usr/bin/env bash
set -euo pipefail

# Keep xtask integration contracts in one active Cargo target so all-target clippy stays inside the
# repository's 30-second feedback budget. There are no exemptions.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

command -v python3 >/dev/null 2>&1 || {
    printf '%s\n' 'required command is missing: python3' >&2
    exit 1
}

python3 - "$REPO_ROOT" <<'PYEOF'
from pathlib import Path
import re
import sys
import tomllib

root = Path(sys.argv[1]).resolve()
crate = root / "xtask"
tests = crate / "tests"
modules = ("cli_contract", "scaffold_must_be_red", "toolchain_contract", "why_contract")


def fail(message: str) -> None:
    raise SystemExit(f"xtask test-target consolidation violation: {message}")


def rust_views(source: str, path: Path) -> tuple[str, str]:
    comments_removed = list(source)
    code_only = list(source)
    index = 0

    def mask(start: int, end: int, *, comment: bool) -> None:
        for position in range(start, end):
            if source[position] != "\n":
                code_only[position] = " "
                if comment:
                    comments_removed[position] = " "

    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = len(source) if end < 0 else end
            mask(index, end, comment=True)
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
            mask(index, end, comment=True)
            index = end
            continue
        raw = re.match(r'(?:b)?r(#{0,255})"', source[index:])
        if raw:
            delimiter = '"' + raw.group(1)
            close = source.find(delimiter, index + raw.end())
            if close < 0:
                fail(f"{path.relative_to(root)} has an unterminated raw string")
            end = close + len(delimiter)
            mask(index, end, comment=False)
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
            mask(index, end, comment=False)
            index = end
            continue
        byte_character = source.startswith("b'", index)
        if byte_character or source[index:index + 1] == "'":
            quote = index + 1 if byte_character else index
            body = quote + 1
            # An apostrophe followed by an identifier without an immediate closing apostrophe is
            # a lifetime, not a character literal. It must remain visible to the Rust-token scan.
            identifier = re.match(r"[A-Za-z_][A-Za-z0-9_]*", source[body:])
            if not byte_character and identifier and source[body + identifier.end():body + identifier.end() + 1] != "'":
                index = body + identifier.end()
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
                    mask(index, end, comment=False)
                    index = end
                    break
            else:
                fail(f"{path.relative_to(root)} has an unterminated character literal")
            continue
        index += 1
    return "".join(comments_removed), "".join(code_only)


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


try:
    manifest = tomllib.loads((crate / "Cargo.toml").read_text())
except (OSError, tomllib.TOMLDecodeError) as error:
    fail(f"cannot parse xtask/Cargo.toml: {error}")
package = manifest.get("package")
if not isinstance(package, dict) or package.get("autotests") is not False:
    fail("xtask must set package.autotests = false")
build = package.get("build")
if build not in (None, False):
    if not isinstance(build, str) or not build or "\\" in build:
        fail("xtask package build target must be false, absent, or a resolvable path")
    try:
        build_path = (crate / build).resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve xtask package build target: {error}")
else:
    build_path = None
targets = manifest.get("test")
if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], dict):
    fail("xtask must declare exactly one explicit [[test]] target")
target = targets[0]
if target != {"name": "integration", "path": "tests/integration.rs"}:
    fail("xtask test target must be exactly integration at tests/integration.rs")

try:
    test_entries = tuple(tests.rglob("*"))
except OSError as error:
    fail(f"cannot inspect xtask/tests: {error}")
for entry in test_entries:
    if entry.is_symlink():
        fail(f"{entry.relative_to(root)} may not be a symlink")
actual = tuple(
    sorted(
        path.relative_to(tests).with_suffix("").as_posix()
        for path in test_entries
        if path.is_file() and path.suffix == ".rs" and path.name != "integration.rs"
    )
)
if actual != modules:
    fail("xtask integration source inventory does not match the frozen module suite")

protected: set[Path] = set()
for module in modules:
    path = tests / f"{module}.rs"
    if path.is_symlink():
        fail(f"{path.relative_to(root)} may not be a symlink")
    try:
        resolved = path.resolve(strict=True)
        source = path.read_text()
    except OSError as error:
        fail(f"cannot read {path.relative_to(root)}: {error}")
    if resolved in protected:
        fail("xtask integration sources must resolve to unique files")
    protected.add(resolved)
    _, code = rust_views(source, path)
    if re.search(r"#!\s*\[\s*(?:cfg|cfg_attr)\b", code):
        fail(f"{path.relative_to(root)} may not disable its module with a file-level cfg")

license_header = """// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
"""
harness_path = tests / "integration.rs"
harness = license_header + """
//! Consolidated integration-test entry point for `xtask`.
//!
//! Responsible for: registering every xtask integration-test source in one Cargo target.
//! NOT responsible for: test behavior or repository automation implementation.
//! Upstream: the xtask integration-test modules. Downstream: Cargo's test harness.

""" + "\n".join(f'#[path = "{module}.rs"]\nmod {module};' for module in modules) + "\n"
try:
    if harness_path.read_text() != harness:
        fail("xtask integration harness must register each frozen source exactly once")
except OSError as error:
    fail(f"cannot read xtask/tests/integration.rs: {error}")
protected.add(harness_path.resolve())
if build_path in protected:
    fail("xtask package build target reuses a registered integration entry")

# Explicit non-test targets may not create another entry for a registered source or the harness.
for kind in ("lib", "bin", "example", "bench"):
    raw = manifest.get(kind, [] if kind != "lib" else None)
    entries = [] if raw is None else [raw] if kind == "lib" else raw
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        fail(f"xtask has an invalid {kind} target inventory")
    for entry in entries:
        raw_path = entry.get("path")
        if raw_path is None:
            continue
        if not isinstance(raw_path, str) or not raw_path or "\\" in raw_path:
            fail(f"xtask has an unresolvable {kind} target path")
        if (crate / raw_path).resolve() in protected:
            fail(f"xtask {kind} target reuses a registered integration entry")

registered = {tests / f"{module}.rs" for module in modules} | {harness_path}
for path in crate.rglob("*.rs"):
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {path.relative_to(root)}: {error}")
    if resolved in protected and path not in registered:
        fail(f"{path.relative_to(root)} aliases a registered integration entry")
    if path == harness_path:
        continue
    try:
        source = path.read_text()
    except OSError as error:
        fail(f"cannot read {path.relative_to(root)}: {error}")
    comments_removed, code = rust_views(source, path)
    for attribute in re.finditer(r"#\s*!?\s*\[", code):
        opening = code.find("[", attribute.start(), attribute.end())
        end = balanced_end(code, opening, path)
        body = code[opening + 1:end - 1]
        for match in re.finditer(r"\bpath\s*=", body):
            start = opening + 1 + match.end()
            literal = re.match(r'\s*"([^"\n]+)"', comments_removed[start:])
            if literal is None or "\\" in literal.group(1):
                fail(f"{path.relative_to(root)} has an unresolvable path attribute")
            if (path.parent / literal.group(1)).resolve() in protected:
                fail(f"{path.relative_to(root)} reuses a registered integration entry through #[path]")
    for include in re.finditer(r"\binclude\s*!\s*([({\[])", code):
        opening = include.end() - 1
        end = balanced_end(code, opening, path)
        arguments = comments_removed[opening + 1:end - 1]
        literal = re.fullmatch(r'\s*"([^"\n]+)"\s*', arguments)
        if literal is None or "\\" in literal.group(1):
            fail(f"{path.relative_to(root)} has an unresolvable include")
        if (path.parent / literal.group(1)).resolve() in protected:
            fail(f"{path.relative_to(root)} includes a registered integration entry")

print("xtask test-target consolidation guard passed")
PYEOF
