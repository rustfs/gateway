#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_recorder_not_default.sh
#
# WHAT THIS CHECKS
#   The corpus recorder (`crates/corpus-recorder`, rustfs/backlog#1763) can only ever be
#   compiled into a build that asked for it by name:
#     1. its `corpus-record` feature exists, and its own `default` feature set is empty;
#     2. every one of its normal dependencies is `optional`, so a build without the feature
#        compiles no code and links nothing;
#     3. every module and re-export in its `src/lib.rs` sits behind
#        `#[cfg(feature = "corpus-record")]`;
#     4. no workspace manifest reaches `corpus-record`, or the recorder dependency, from its
#        `default` feature set, directly or through other features;
#     5. no workspace manifest depends on the recorder except as an `optional` dependency or a
#        dev-dependency.
#
# WHY
#   A recorder in a production build writes every request it serves to disk: bodies with user
#   data, heads with authentication material. That is an irreversible incident, so the first
#   line of defence is that the code is simply absent unless a test build names the feature.
#   `tests/recorder/symbols.rs` measures the result on a compiled object; this guard keeps the
#   manifests from drifting into a shape where that measurement would stop meaning anything.
#
# HOW TO EXEMPT
#   There is no exemption. A host that wants the recorder declares its own opt-in feature that
#   enables an optional dependency, and never puts that feature in `default`.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_recorder_not_default)" || exit 1

"$PYTHON" - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
RECORDER = "rustfs-gateway-corpus-recorder"
FEATURE = "corpus-record"
MANIFEST = "crates/corpus-recorder/Cargo.toml"
LIB = "crates/corpus-recorder/src/lib.rs"
violations: list[str] = []


def fail(message: str) -> None:
    print(f"check_recorder_not_default: {message}", file=sys.stderr)
    raise SystemExit(1)


for required in (MANIFEST, LIB):
    if not (root / required).is_file():
        fail(f"required input is missing: {required}")

try:
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "Cargo.toml", "**/Cargo.toml"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
except (OSError, subprocess.CalledProcessError) as error:
    fail(f"cannot enumerate Cargo.toml inputs: {error}")
manifests = sorted({item.decode() for item in listed.split(b"\0") if item} | {MANIFEST})

documents: dict[str, dict] = {}
for relative in manifests:
    try:
        documents[relative] = tomllib.loads((root / relative).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        fail(f"{relative}: cannot parse: {error}")

workspace_deps = documents.get("Cargo.toml", {}).get("workspace", {}).get("dependencies", {})


def dependency_tables(document: dict):
    for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
        yield kind, document.get(kind, {})
    for selector, target in document.get("target", {}).items():
        for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
            yield f"target.{selector}.{kind}", target.get(kind, {})


def package_of(alias: str, declaration) -> tuple[str, dict]:
    merged = dict(declaration) if isinstance(declaration, dict) else {}
    if merged.get("workspace") is True:
        inherited = workspace_deps.get(alias, {})
        merged = {**(inherited if isinstance(inherited, dict) else {}), **merged}
    return merged.get("package", alias), merged


# 1-3: the recorder crate itself.
recorder = documents[MANIFEST]
if recorder.get("package", {}).get("name") != RECORDER:
    fail(f"{MANIFEST} does not declare package {RECORDER}")
recorder_features = recorder.get("features", {})
if FEATURE not in recorder_features:
    violations.append(f"{MANIFEST}: the `{FEATURE}` feature is missing")
if recorder_features.get("default", []) != []:
    violations.append(f"{MANIFEST}: the `default` feature set must be empty, found {recorder_features.get('default')}")
for alias, declaration in recorder.get("dependencies", {}).items():
    _, merged = package_of(alias, declaration)
    if merged.get("optional") is not True:
        violations.append(f"{MANIFEST}: dependency `{alias}` is not optional, so a build without `{FEATURE}` links it")

gate = f'#[cfg(feature = "{FEATURE}")]'
lines = (root / LIB).read_text(encoding="utf-8").splitlines()
items = 0
for index, line in enumerate(lines):
    stripped = line.strip()
    if re.match(r"^(pub(\([^)]*\))?\s+)?(mod|use)\b", stripped) or re.match(r"^pub\s+use\b", stripped):
        items += 1
        previous = lines[index - 1].strip() if index else ""
        if previous != gate:
            violations.append(f"{LIB}:{index + 1}: `{stripped}` is not behind {gate}")
if items == 0:
    violations.append(f"{LIB}: found no module or re-export at all, so the gate cannot be checked")

# 4-5: every manifest in the workspace, the recorder included.
for relative, document in documents.items():
    features = document.get("features", {})
    recorder_aliases = set()
    for kind, table in dependency_tables(document):
        for alias, declaration in table.items():
            package, merged = package_of(alias, declaration)
            if package != RECORDER or relative == MANIFEST:
                continue
            recorder_aliases.add(alias)
            if not kind.endswith("dev-dependencies") and merged.get("optional") is not True:
                violations.append(f"{relative}: [{kind}].{alias} depends on the recorder without `optional = true`")

    def reaches_recorder(member: str) -> bool:
        name = member.removeprefix("dep:").split("/", 1)[0].rstrip("?")
        if relative == MANIFEST and member == FEATURE:
            return True
        return name in recorder_aliases or member.endswith(f"/{FEATURE}")

    seen: set[str] = set()
    pending = list(features.get("default", []))
    while pending:
        member = pending.pop()
        if member in seen:
            continue
        seen.add(member)
        if reaches_recorder(member):
            violations.append(f"{relative}: the `default` feature set reaches `{member}`, which compiles the recorder in")
        elif member in features:
            pending.extend(features[member])

for violation in violations:
    print(f"check_recorder_not_default: {violation}", file=sys.stderr)
if violations:
    raise SystemExit(1)
print(f"OK: {FEATURE} is in no default feature set across {len(documents)} manifest(s); the recorder is optional everywhere and gated in {items} item(s)")
PY
