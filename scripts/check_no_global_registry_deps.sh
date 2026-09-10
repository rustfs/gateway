#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_global_registry_deps.sh
#
# WHAT THIS CHECKS
#   That no manifest in the workspace declares a dependency on a link-time
#   global-registry / life-before-main crate: `inventory`, `linkme` or `ctor`
#   (any dependency kind, including dev- and build-dependencies).
#
# WHY
#   ADR-0003: operation registration is explicit and compile-time, not
#   collected from a link-section at startup. Global registries look convenient
#   and cost three properties this project cannot give up:
#
#     - Determinism. Registration order depends on link order, so the routing
#       table can differ between a debug build, a release build, and an LTO
#       build. Protocol behaviour must not depend on the linker.
#     - Discoverability. `rustfs-gateway` is meant to be readable by both humans and
#       agents: "where is this operation registered?" must be answerable by
#       grep, not by knowing that a macro emitted a static into a link section.
#     - Dead-code elimination. Registry entries are unconditionally live, so
#       a consumer that only needs ten operations still links all of them.
#
#   The failure mode is also silent: `inventory`/`linkme` entries in a staticlib
#   or behind `--gc-sections` simply disappear, and the operation 404s in
#   production while every test passes. `ctor` is banned for the same reason
#   one level down: it runs arbitrary code before `main`, in unspecified order,
#   outside any panic or tracing context.
#
# HOW TO EXEMPT
#   There is no allowance. Supersede ADR-0003 and change this guard in the same
#   reviewed change; a text file must not silently weaken an absolute ban.
#
# USAGE
#   scripts/check_no_global_registry_deps.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_no_global_registry_deps.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_no_global_registry_deps: %s\n' "$*" >&2
    exit 1
}

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_no_global_registry_deps)" || exit 1
[[ -f "${ROOT_DIR}/docs/adr/0003-no-global-registry-crates.md" ]] || \
    fail 'rule input is missing: docs/adr/0003-no-global-registry-crates.md'

"$PYTHON" - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(sys.argv[1])
BANNED = {"inventory", "linkme", "ctor"}


def fail(message: str) -> None:
    print(f"check_no_global_registry_deps: {message}", file=sys.stderr)
    raise SystemExit(1)


def dependency_tables(document: dict[str, Any]) -> Iterator[tuple[str, Any]]:
    for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
        if kind in document:
            yield kind, document[kind]

    workspace = document.get("workspace", {})
    if not isinstance(workspace, dict):
        fail("[workspace] must be a TOML table")
    for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
        if kind in workspace:
            yield f"workspace.{kind}", workspace[kind]

    targets = document.get("target", {})
    if not isinstance(targets, dict):
        fail("[target] must be a TOML table")
    for selector, target in targets.items():
        if not isinstance(target, dict):
            fail(f"[target.{selector}] must be a TOML table")
        for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
            if kind in target:
                yield f"target.{selector}.{kind}", target[kind]


def is_banned(package: str) -> bool:
    return package.lower() in BANNED


def declaration_line(source: str, alias: str, package: str) -> int:
    lines = source.splitlines()
    quoted_alias = re.escape(alias)
    alias_key = rf"(?:{quoted_alias}|'(?:{quoted_alias})'|\"(?:{quoted_alias})\")"
    alias_patterns = (
        re.compile(rf"^\s*{alias_key}\s*="),
        re.compile(rf"^\s*.*\.{alias_key}\s*="),
        re.compile(rf"^\s*\[.*\.{alias_key}\]\s*$"),
    )
    for number, line in enumerate(lines, 1):
        if any(pattern.search(line) for pattern in alias_patterns):
            return number

    if package.lower() != alias.lower():
        quoted_package = re.escape(package)
        package_pattern = re.compile(rf"\bpackage\s*=\s*['\"]{quoted_package}['\"]")
        for number, line in enumerate(lines, 1):
            if package_pattern.search(line):
                return number
    fail(
        f"cannot locate declaration line for [{alias}] resolving to {package} "
        "(rule: docs/adr/0003-no-global-registry-crates.md)"
    )


try:
    listed = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "Cargo.toml",
            "*/Cargo.toml",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
except (OSError, subprocess.CalledProcessError) as error:
    fail(f"cannot enumerate Cargo.toml inputs: {error}")

manifests = sorted(os.fsdecode(item) for item in listed.split(b"\0") if item)
if not manifests:
    fail(f"no Cargo.toml found under {ROOT}")

violations: list[tuple[str, int, str, str, str]] = []
for manifest in manifests:
    path = ROOT / manifest
    try:
        source = path.read_text(encoding="utf-8")
        document = tomllib.loads(source)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse {manifest}: {error}")

    for scope, dependencies in dependency_tables(document):
        if not isinstance(dependencies, dict):
            fail(f"{manifest}: [{scope}] must be a TOML table")
        for alias, declaration in dependencies.items():
            if isinstance(declaration, str):
                package = alias
            elif isinstance(declaration, dict):
                package = declaration.get("package", alias)
                if not isinstance(package, str):
                    fail(f"{manifest}: [{scope}].{alias} has a non-string package")
            else:
                fail(f"{manifest}: [{scope}].{alias} has an invalid dependency declaration")
            if is_banned(package):
                violations.append(
                    (manifest, declaration_line(source, alias, package), scope, alias, package)
                )

for manifest, line, scope, alias, package in violations:
    print(
        f"{manifest}:{line}: [{scope}].{alias} resolves to banned package "
        f"'{package}' (rule: docs/adr/0003-no-global-registry-crates.md)",
        file=sys.stderr,
    )

if violations:
    print(
        "\nGlobal registry crates are banned by ADR-0003. Register operations "
        "explicitly with a const table or generated match.",
        file=sys.stderr,
    )
    raise SystemExit(1)
PY
