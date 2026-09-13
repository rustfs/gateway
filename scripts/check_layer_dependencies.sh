#!/usr/bin/env bash
set -euo pipefail

# Checks the internal dependency DAG declared by AGENTS.md. With
# GATEWAY_LAYER_MODE=ring it checks the ring-0/1 prohibition and the one dated
# compat-s3s exception instead. Dependencies are parsed as TOML, including
# renamed, workspace-inherited and target-specific declarations. Internal dev
# edges are intentionally exempt from the layer DAG; ring boundaries are not.
# There is no allowance: changing either boundary requires changing AGENTS.md.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
MODE="${GATEWAY_LAYER_MODE:-layer}"

fail() {
    printf 'check_%s_dependencies: %s\n' "$MODE" "$*" >&2
    exit 1
}

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_layer_dependencies)" || exit 1
[[ -f "${ROOT_DIR}/AGENTS.md" ]] || fail 'rule input is missing: AGENTS.md'

"$PYTHON" - "$ROOT_DIR" "$MODE" <<'PY'
from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Iterator

root = Path(sys.argv[1])
mode = sys.argv[2]
layers = [
    ("rustfs-gateway-corpus", set()),
    ("rustfs-gateway-macros", set()),
    ("rustfs-gateway-model", set()),
    ("rustfs-gateway-stream", set()),
    ("rustfs-gateway-xml", set()),
    ("rustfs-gateway-codegen", {"rustfs-gateway-model"}),
    ("rustfs-gateway-types", {"rustfs-gateway-xml", "rustfs-gateway-stream"}),
    ("rustfs-gateway-goldens", {"rustfs-gateway-types", "rustfs-gateway-corpus"}),
    ("rustfs-gateway-http", {"rustfs-gateway-types", "rustfs-gateway-stream"}),
    ("rustfs-gateway-sig", {"rustfs-gateway-http", "rustfs-gateway-types", "rustfs-gateway-stream"}),
    (
        "rustfs-gateway-core",
        {
            "rustfs-gateway-sig",
            "rustfs-gateway-http",
            "rustfs-gateway-types",
            "rustfs-gateway-xml",
            "rustfs-gateway-stream",
        },
    ),
    # After core: the replica write is a dialect operation built on core's dialect mechanism.
    (
        "rustfs-gateway-dialect-minio",
        {"rustfs-gateway-core", "rustfs-gateway-sig", "rustfs-gateway-types", "rustfs-gateway-xml"},
    ),
    ("rustfs-gateway-server", set()),
    (
        "rustfs-gateway",
        {
            "rustfs-gateway-core",
            "rustfs-gateway-sig",
            "rustfs-gateway-http",
            "rustfs-gateway-macros",
            "rustfs-gateway-server",
            "rustfs-gateway-types",
            "rustfs-gateway-xml",
            "rustfs-gateway-stream",
        },
    ),
    ("rustfs-gateway-fs", {"rustfs-gateway"}),
    ("rustfs-gateway-conformance", {"rustfs-gateway"}),
    (
        "xtask",
        {
            "rustfs-gateway",
            "rustfs-gateway-conformance",
            "rustfs-gateway-core",
            "rustfs-gateway-codegen",
            "rustfs-gateway-model",
        },
    ),
]
allowed = dict(layers)
rank = {name: index for index, (name, _) in enumerate(layers)}
stream_external = {"bitflags", "bytes", "http", "http-body"}
dispatcher_name = "rustfs-gateway-xtask-dispatch"
dispatcher_manifest = "crates/xtask-dispatch/Cargo.toml"
dispatcher_allowed_dependencies: set[str] = set()
dispatcher_audit_sentinel = "complete"

required_agents_fragments = [
    "- **Ring 0/1 — protocol kernel and runtime**: every package under `crates/`. Zero rustfs dependencies.",
    "  runtime host, with no internal crate dependency:\n        rustfs-gateway-server                    listener, TLS, hyper, admission, shutdown",
    "        rustfs-gateway-types ──▶ rustfs-gateway-stream ──▶ bitflags / bytes / http / http-body",
    "        rustfs-gateway ──▶ rustfs-gateway-macros          public facade re-export of optional registration sugar",
    "        rustfs-gateway ──▶ rustfs-gateway-server          optional self-held listener assembly; server remains internally independent",
    "        rustfs-gateway-xtask-dispatch (crates/xtask-dispatch)   std-only cargo xtask process selection",
    "        xtask ──▶ gateway + conformance + core + codegen + model   generation and diagnostics only",
]


def fail(message: str) -> None:
    print(f"check_{mode}_dependencies: {message}", file=sys.stderr)
    raise SystemExit(1)


def git_files() -> list[str]:
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
                "Cargo.toml",
                "crates/*/Cargo.toml",
                "xtask/Cargo.toml",
            ],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"cannot enumerate Cargo.toml inputs: {error}")
    files = sorted(os.fsdecode(item) for item in output.split(b"\0") if item)
    if "Cargo.toml" not in files or len(files) < 2:
        fail("workspace Cargo.toml inputs are missing")
    return files


def all_manifests() -> list[str]:
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
                "Cargo.toml",
                "**/Cargo.toml",
            ],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"cannot enumerate dispatcher census inputs: {error}")
    return sorted(os.fsdecode(item) for item in output.split(b"\0") if item)


def load(relative: str) -> tuple[str, dict[str, Any]]:
    try:
        source = (root / relative).read_text(encoding="utf-8")
        return source, tomllib.loads(source)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse {relative}: {error}")


def audit_dispatcher() -> str:
    found: list[str] = []
    for relative in all_manifests():
        path = root / relative
        if path.is_symlink():
            fail(f"{relative}: dispatcher census manifest must not be a symlink")
        _, document = load(relative)
        package = document.get("package", {})
        if not isinstance(package, dict) or package.get("name") != dispatcher_name:
            continue
        found.append(relative)
        if relative != dispatcher_manifest:
            fail(f"{relative}: {dispatcher_name} must live only at {dispatcher_manifest}")
        for kind, dependency_table in tables(document):
            if dependency_table:
                fail(f"{relative}: the std-only dispatcher may not declare {kind}")
    if len(found) > 1:
        fail(f"{dispatcher_name} must have at most one canonical manifest")
    return dispatcher_audit_sentinel


try:
    agents = (root / "AGENTS.md").read_text(encoding="utf-8")
except (OSError, UnicodeError) as error:
    fail(f"cannot read AGENTS.md: {error}")
for fragment in required_agents_fragments:
    if agents.count(fragment) != 1:
        fail(f"AGENTS.md dependency matrix drifted at {fragment!r}")

try:
    macro_expansion = (root / "crates/macros/src/expand.rs").read_text(encoding="utf-8")
except (OSError, UnicodeError) as error:
    fail(f"cannot read facade macro expansion: {error}")
if "::rustfs_gateway_core" in macro_expansion:
    fail("macro expansion reaches past the public facade into rustfs_gateway_core")
if macro_expansion.count("::rustfs_gateway::Handler<#operations>") != 1:
    fail("macro expansion does not use the unique public facade Handler path")


def tables(document: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = document.get(kind, {})
        if not isinstance(value, dict):
            fail(f"[{kind}] must be a TOML table")
        yield kind, value
    targets = document.get("target", {})
    if not isinstance(targets, dict):
        fail("[target] must be a TOML table")
    for selector, target in targets.items():
        if not isinstance(target, dict):
            fail(f"[target.{selector}] must be a TOML table")
        for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
            value = target.get(kind, {})
            if not isinstance(value, dict):
                fail(f"[target.{selector}.{kind}] must be a TOML table")
            yield kind, value


def resolve(alias: str, value: Any, workspace: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if isinstance(value, str):
        return alias, {}
    if not isinstance(value, dict):
        fail(f"dependency {alias!r} has an invalid declaration")
    merged = dict(value)
    if value.get("workspace") is True:
        inherited = workspace.get(alias)
        if inherited is None:
            fail(f"dependency {alias!r} inherits a missing [workspace.dependencies] entry")
        if isinstance(inherited, str):
            inherited = {}
        if not isinstance(inherited, dict):
            fail(f"workspace dependency {alias!r} has an invalid declaration")
        merged = {**inherited, **value}
    package = merged.get("package", alias)
    if not isinstance(package, str):
        fail(f"dependency {alias!r} has a non-string package")
    return package, merged


def line_for(source: str, alias: str, package: str) -> int:
    key = re.escape(alias)
    patterns = [
        re.compile(rf"^\s*(?:{key}|'(?:{key})'|\"(?:{key})\")\s*=", re.MULTILINE),
        re.compile(rf"^\s*\[.*\.(?:{key}|'(?:{key})'|\"(?:{key})\")\]\s*$", re.MULTILINE),
    ]
    for pattern in patterns:
        match = pattern.search(source)
        if match:
            return source.count("\n", 0, match.start()) + 1
    match = re.search(rf"\bpackage\s*=\s*['\"]{re.escape(package)}['\"]", source)
    return source.count("\n", 0, match.start()) + 1 if match else 1


if dispatcher_allowed_dependencies:
    fail("the std-only dispatcher dependency allowance must remain empty")
if audit_dispatcher() != dispatcher_audit_sentinel:
    fail("structured dispatcher audit failed without a diagnostic")
files = git_files()
documents = {relative: load(relative) for relative in files}
root_doc = documents["Cargo.toml"][1]
workspace = root_doc.get("workspace", {})
if not isinstance(workspace, dict) or not isinstance(workspace.get("dependencies", {}), dict):
    fail("[workspace.dependencies] must be a TOML table")
workspace_dependencies = workspace.get("dependencies", {})

packages: dict[str, tuple[str, str, dict[str, Any]]] = {}
for relative, (source, document) in documents.items():
    if relative == "Cargo.toml":
        continue
    package = document.get("package", {})
    if not isinstance(package, dict) or not isinstance(package.get("name"), str):
        fail(f"{relative}: [package].name is missing")
    name = package["name"]
    if name in packages:
        fail(f"duplicate package name {name!r}")
    packages[name] = (relative, source, document)

# The dispatcher is pre-governed for a later slice. It may be absent today, but
# if present the structured census above has already proved its canonical path
# and that every normal/dev/build/target dependency table is empty.
packages.pop(dispatcher_name, None)

if mode == "layer":
    if set(packages) != set(allowed):
        fail(f"layer matrix/package drift: missing={sorted(set(packages) - set(allowed))}, stale={sorted(set(allowed) - set(packages))}")
    for crate, dependencies in layers:
        for dependency in dependencies:
            if dependency not in rank or rank[dependency] >= rank[crate]:
                fail(f"allow matrix is not a DAG: {crate} -> {dependency}")
    violations = []
    for crate, (relative, source, document) in packages.items():
        for kind, dependency_table in tables(document):
            if kind == "dev-dependencies" and crate not in {"rustfs-gateway-server", "xtask"}:
                continue
            for alias, declaration in dependency_table.items():
                package, _ = resolve(alias, declaration, workspace_dependencies)
                if package in packages and package in allowed[crate]:
                    continue
                if package not in packages and (crate != "rustfs-gateway-stream" or package in stream_external):
                    continue
                violations.append((relative, line_for(source, alias, package), crate, kind, alias, package))
    for relative, line, crate, kind, alias, package in violations:
        print(
            f"{relative}:{line}: {crate} [{kind}].{alias} resolves to forbidden internal package {package} "
            "(rule: AGENTS.md Dependency Boundaries)",
            file=sys.stderr,
        )
    raise SystemExit(1 if violations else 0)

if mode != "ring":
    fail(f"unknown mode {mode!r}")

local = set(packages)
violations = []
types_feature_checked = False
for crate, (relative, source, document) in packages.items():
    metadata = document.get("package", {}).get("metadata", {}).get("gateway", {})
    if crate != "xtask" and (not isinstance(metadata, dict) or metadata.get("ring") not in {0, 1}):
        violations.append((relative, 1, f"{crate} lacks a valid [package.metadata.gateway] ring = 0/1"))
    for kind, dependency_table in tables(document):
        for alias, declaration in dependency_table.items():
            package, merged = resolve(alias, declaration, workspace_dependencies)
            line = line_for(source, alias, package)
            if package in local:
                continue
            if package == "rustfs" or package.startswith(("rustfs-", "rustfs_")):
                violations.append((relative, line, f"{crate} [{kind}].{alias} resolves to forbidden RustFS/ring-2 package {package}"))
            if package == "s3s" or package.startswith("s3s-"):
                if crate != "rustfs-gateway-types":
                    violations.append((relative, line, f"{crate} [{kind}].{alias} resolves to s3s package {package} outside compat-s3s"))
                    continue
                if merged.get("optional") is not True:
                    violations.append((relative, line, f"{alias} must be optional behind compat-s3s"))
                features = document.get("features", {})
                feature = features.get("compat-s3s") if isinstance(features, dict) else None
                if not isinstance(feature, list) or f"dep:{alias}" not in feature:
                    violations.append((relative, line, f"compat-s3s must explicitly contain dep:{alias}"))
    if crate == "rustfs-gateway-types":
        features = document.get("features", {})
        if not isinstance(features, dict) or "compat-s3s" not in features:
            violations.append((relative, 1, "compat-s3s feature is missing"))
        else:
            lines = source.splitlines()
            feature_line = next((index for index, line in enumerate(lines) if re.match(r"^\s*compat-s3s\s*=", line)), None)
            nearby = lines[max(0, (feature_line or 0) - 4) : (feature_line or 0) + 1]
            if feature_line is None or not any(re.search(r"# DELETE BY:\s*\S+", line) for line in nearby):
                violations.append((relative, (feature_line or 0) + 1, "compat-s3s lacks a nearby # DELETE BY: <milestone> marker"))
            # A narrower feature may enable one s3s revision (the production seam), but only under
            # the name of the revision it links, only as a part of compat-s3s, and only with the
            # same expiry marker; otherwise a second feature would be a second, unreviewed s3s door.
            s3s_revisions = {}
            for _, dependency_table in tables(document):
                for alias, declaration in dependency_table.items():
                    package, merged = resolve(alias, declaration, workspace_dependencies)
                    if package == "s3s" or package.startswith("s3s-"):
                        s3s_revisions[alias] = str(merged.get("rev", ""))
            umbrella = features.get("compat-s3s") or []
            for name, members in features.items():
                if name == "compat-s3s" or not isinstance(members, list):
                    continue
                enabled = [member[4:] for member in members if isinstance(member, str) and member.startswith("dep:") and member[4:] in s3s_revisions]
                if not enabled:
                    continue
                line_index = next((index for index, line in enumerate(lines) if re.match(rf"^\s*{re.escape(name)}\s*=", line)), 0)
                expected = {f"compat-s3s-{s3s_revisions[alias][:8]}" for alias in enabled}
                if len(enabled) != 1 or name not in expected or len(s3s_revisions[enabled[0]]) < 8:
                    violations.append((relative, line_index + 1, f"feature {name} enables {', '.join(enabled)} but is not compat-s3s-<rev8> of exactly one s3s revision"))
                if name not in umbrella:
                    violations.append((relative, line_index + 1, f"feature {name} enables s3s but compat-s3s does not include it"))
                window = lines[max(0, line_index - 6) : line_index + 1]
                if not any(re.search(r"# DELETE BY:\s*\S+", line) for line in window):
                    violations.append((relative, line_index + 1, f"feature {name} lacks a nearby # DELETE BY: <milestone> marker"))
        types_feature_checked = True
if not types_feature_checked:
    violations.append(("crates/types/Cargo.toml", 1, "rustfs-gateway-types package is missing"))
for relative, line, message in violations:
    print(f"{relative}:{line}: {message} (rule: AGENTS.md Dependency Boundaries)", file=sys.stderr)
raise SystemExit(1 if violations else 0)
PY
