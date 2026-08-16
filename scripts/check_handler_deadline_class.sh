#!/usr/bin/env bash
set -euo pipefail

# Locks the explicit handler-deadline class of every standard operation. Third-party
# operations migrate separately before registration makes their class mandatory.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_handler_deadline_class: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'

python3 - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
authority = root / "crates/core/src/registry/mod.rs"
registration = root / "crates/core/src/registry/reject.rs"
ops_dir = root / "crates/core/src/ops"


def fail(message: str) -> None:
    print(f"check_handler_deadline_class: {message}", file=sys.stderr)
    raise SystemExit(1)


if not authority.is_file() or authority.is_symlink():
    fail("deadline-class authority is missing or not a regular file")
if not registration.is_file() or registration.is_symlink():
    fail("registration deadline check is missing or not a regular file")
if not ops_dir.is_dir() or ops_dir.is_symlink():
    fail("standard operation directory is missing or not a directory")

try:
    source = authority.read_text(encoding="utf-8")
    registration_source = registration.read_text(encoding="utf-8")
except (OSError, UnicodeError) as error:
    fail(f"cannot read deadline-class source: {error}")

registration_check = """        if spec.deadline_class().is_none() {
            return Err(RegistryError::MissingHandlerDeadlineClass { name });
        }
"""
if registration_source.count(registration_check) != 1:
    fail("standard registration does not fail closed without a handler deadline class")

signature = "fn standard_handler_deadline_class(name: &str) -> Option<HandlerDeadlineClass>"
if source.count(signature) != 1:
    fail("deadline-class authority function is missing or duplicated")
start = source.find("{", source.find(signature) + len(signature))
if start < 0:
    fail("deadline-class authority function has no body")
depth = 1
index = start + 1
while index < len(source) and depth:
    if source[index] == "{":
        depth += 1
    elif source[index] == "}":
        depth -= 1
    index += 1
if depth:
    fail("deadline-class authority function has unbalanced braces")
body = source[start + 1 : index - 1]

arm_pattern = re.compile(
    r'((?:"[A-Za-z0-9]+"\s*\|\s*)*"[A-Za-z0-9]+")\s*=>\s*'
    r'Some\(HandlerDeadlineClass::(Standard|Extended)\)'
)
declared: dict[str, str] = {}
for names, deadline_class in arm_pattern.findall(body):
    for name in re.findall(r'"([A-Za-z0-9]+)"', names):
        if name in declared:
            fail(f"standard operation {name} declares two deadline classes")
        declared[name] = deadline_class
if re.search(r'_\s*=>\s*Some\(', body):
    fail("deadline-class authority has an implicit wildcard class")
if not re.search(r'_\s*=>\s*None', body):
    fail("deadline-class authority does not fail closed for unknown operations")

operations: set[str] = set()
for path in sorted(ops_dir.glob("*.rs")):
    if path.name == "mod.rs":
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read standard operation source {path.name}: {error}")
    names = re.findall(r'^\s*const NAME: &\'static str = "([A-Za-z0-9]+)";\s*$', text, re.MULTILINE)
    if len(names) != 1:
        fail(f"standard operation source {path.name} has {len(names)} exact NAME declarations")
    name = names[0]
    if name in operations:
        fail(f"standard operation name is duplicated: {name}")
    operations.add(name)

if len(operations) != 72:
    fail(f"standard operation census is {len(operations)}, expected 72")
missing = sorted(operations - declared.keys())
extra = sorted(declared.keys() - operations)
if missing or extra:
    fail(f"deadline-class authority differs from standard operations: missing={missing}, extra={extra}")
if declared.get("CompleteMultipartUpload") != "Extended":
    fail("CompleteMultipartUpload must use the Extended handler deadline")
wrong_standard = sorted(name for name in operations - {"CompleteMultipartUpload"} if declared.get(name) != "Standard")
if wrong_standard:
    fail(f"standard handler deadline drifted for: {wrong_standard}")

reviewed_third_party_sources = {
    "crates/core/examples/dialect_overlay.rs": 1,
    "crates/core/src/authz/mod.rs": 1,
    "crates/core/tests/dialect.rs": 3,
    "crates/core/tests/static_dispatch.rs": 1,
    "crates/gateway/examples/minimal.rs": 1,
    "crates/gateway/tests/support/mod.rs": 5,
}
reviewed_builders = 0
for relative, expected_builders in reviewed_third_party_sources.items():
    path = root / relative
    if not path.is_file() or path.is_symlink():
        fail(f"reviewed third-party deadline source is missing or not a regular file: {relative}")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read reviewed third-party deadline source {relative}: {error}")
    builders = list(re.finditer(r"OperationSpec::builder\(.*?\.build\(\)", text, re.DOTALL))
    if len(builders) != expected_builders:
        fail(f"reviewed third-party builder census drifted for {relative}: {len(builders)} != {expected_builders}")
    for builder in builders:
        chain = builder.group(0)
        standard = chain.count(".handler_deadline_class(HandlerDeadlineClass::Standard)")
        extended = chain.count(".handler_deadline_class(HandlerDeadlineClass::Extended)")
        if standard != 1 or extended:
            fail(f"reviewed third-party builder lacks one explicit Standard deadline class: {relative}")
    reviewed_builders += len(builders)
if reviewed_builders != 12:
    fail(f"reviewed third-party builder census is {reviewed_builders}, expected 12")

print(
    "check_handler_deadline_class: 72 standard operations and 12 reviewed third-party builders "
    "have explicit deadline classes (83 Standard, 1 Extended)"
)
PY
