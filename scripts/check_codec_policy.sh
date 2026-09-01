#!/usr/bin/env bash
set -euo pipefail

# Proves that Lifecycle keeps two deliberately different XML policies:
# the generic HTTP codec is lenient when no dialect is selected, while the
# persisted MinIO dialect accepts only its registered field and blocks a
# lossy rewrite on every other unknown. Runtime tests prove the behavior; this
# guard makes the selected/unselected wiring and its protected ledger record
# impossible to drift independently.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

command -v python3 >/dev/null 2>&1 || {
    printf 'check_codec_policy: required command is missing: python3\n' >&2
    exit 1
}

python3 - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path


root = Path(sys.argv[1])


def fail(message: str) -> None:
    print(f"check_codec_policy: {message}", file=sys.stderr)
    raise SystemExit(1)


def source(path: str) -> str:
    candidate = root / path
    if not candidate.is_file():
        fail(f"required input is missing: {path}")
    return candidate.read_text(encoding="utf-8")


def require(pattern: str, text: str, message: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        fail(message)


ext = source("crates/types/src/ext.rs")
require(
    r"pub fn security_relevant\(\) -> Self \{\s*Self::new\(UnknownElementPolicy::AllowRegistered\)\s*\}",
    ext,
    "security-relevant persisted XML no longer defaults to AllowRegistered",
)

dialect = source("crates/dialect-minio/src/lib.rs")
for pattern, message in [
    (r'const PARENT: &\'static str = "LifecycleRule";', "DelMarkerExpiration changed parent"),
    (r'const LOCAL_NAME: &\'static str = "DelMarkerExpiration";', "DelMarkerExpiration changed local name"),
    (r'const INSERT_AFTER: &\'static str = "Expiration";', "DelMarkerExpiration changed insertion slot"),
    (
        r"pub fn new\(\) -> Result<Self, ExtError> \{\s*let mut policy = CodecPolicy::security_relevant\(\);\s*policy\.register::<DelMarkerExpiration>\(\)\?;\s*Ok\(Self \{ policy \}\)\s*\}",
        "the selected MinIO lifecycle dialect no longer registers DelMarkerExpiration",
    ),
    (
        r"pub fn without_extensions\(\) -> Self \{\s*Self \{\s*policy: CodecPolicy::security_relevant\(\),\s*\}\s*\}",
        "the no-dialect control no longer carries an empty fail-closed policy",
    ),
]:
    require(pattern, dialect, message)

persistence = source("crates/types/src/persistence/lifecycle.rs")
static_children = re.search(r"const STATIC_RULE_CHILDREN: &\[&str\] = &\[(.*?)\];", persistence, re.DOTALL)
if static_children is None:
    fail("cannot locate LifecycleRule's static child set")
if '"DelMarkerExpiration"' in static_children.group(1):
    fail("DelMarkerExpiration bypasses the runtime extension policy as a static child")
require(
    r'policy\.decode_unknown\("LifecycleRule", child, &mut extensions\)\?;',
    persistence,
    "unknown LifecycleRule children no longer flow through the borrowed policy",
)
require(
    r'policy\.validate_slots\("LifecycleRule", &\["Expiration"\]\)\?;',
    persistence,
    "the persisted writer no longer validates the exact extension insertion slot",
)

case = source("conformance/cases/lifecycle/c-lifecycle-0018.toml")
quirks = re.search(r'^quirks = \[(.*?)\]$', case, re.MULTILINE)
if quirks is None or set(re.findall(r'"([^"]+)"', quirks.group(1))) != {"q-lc-0006", "q-lc-0015"}:
    fail("c-lifecycle-0018 no longer binds both leniency and dialect selection")
not_contains = re.search(r'^not_contains_utf8 = \[(.*?)\]$', case, re.MULTILINE)
if not_contains is None or set(re.findall(r'"([^"]+)"', not_contains.group(1))) != {
    "DelMarkerExpiration",
    "FutureKnob",
}:
    fail("c-lifecycle-0018 no longer proves the unselected codec drops both unknown children")

overlay = source("model/overlays/quirks/lifecycle.toml")
records = re.findall(r'\[\[quirk\]\]\n(.*?)(?=\n\[\[quirk\]\]|\Z)', overlay, re.DOTALL)
records = [record for record in records if re.search(r'^id\s*=\s*"q-lc-0015"$', record, re.MULTILINE)]
if len(records) != 1:
    fail("the lifecycle overlay must declare q-lc-0015 exactly once")
record = records[0]
if not re.search(r'^classification\s*=\s*"contract"$', record, re.MULTILINE) or not re.search(
    r'^target\s*=\s*"PersistedLifecycleRule\.DelMarkerExpiration"$', record, re.MULTILINE
):
    fail("q-lc-0015 no longer names the persisted DelMarkerExpiration contract")
if not re.search(r'^cases\s*=\s*\["c-lifecycle-0018"\]$', record, re.MULTILINE):
    fail("q-lc-0015 is not bound to its no-dialect control case")
if "[[quirk.evidence]]" not in record:
    fail("q-lc-0015 has no protocol evidence")

ledger = source("crates/conformance/tests/lifecycle_family.rs")
if ledger.count('"q-lc-0015"') != 1:
    fail("the deterministic lifecycle ledger does not declare q-lc-0015 exactly once")

tests = source("crates/dialect-minio/tests/integration.rs")
for name in [
    "registered_lifecycle_field_survives_real_rmw_in_its_exact_slot",
    "without_the_registration_preserves_bytes_and_blocks_rmw",
    "unregistered_persisted_sibling_preserves_bytes_and_blocks_rmw",
    "malformed_persisted_lifecycle_document_is_never_absent_or_rewritten",
]:
    if name not in tests:
        fail(f"the executable lifecycle policy matrix lost {name}")

print("check_codec_policy: selected and unselected Lifecycle XML policies are bound")
PY
