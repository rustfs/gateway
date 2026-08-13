#!/usr/bin/env bash
set -euo pipefail
# REQUIRES-PR

# Checks the Breaking Change marker for the protected surface declared in AGENTS.md.
# New ADRs and new conformance cases are deliberately unrestricted; changing an
# accepted ADR or deleting a case is not. There is no allowance outside the
# Breaking Change process described by AGENTS.md (rustfs/backlog#1723).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_protected_files: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
command -v git >/dev/null 2>&1 || fail 'required command is missing: git'
[[ -f "${ROOT_DIR}/AGENTS.md" ]] || fail 'rule input is missing: AGENTS.md'
[[ -n "${GATEWAY_PROTECTED_BASE:-}" ]] || fail 'required input is missing: GATEWAY_PROTECTED_BASE'
[[ -n "${GATEWAY_PROTECTED_HEAD:-}" ]] || fail 'required input is missing: GATEWAY_PROTECTED_HEAD'
[[ -n "${GATEWAY_PR_BODY+x}" ]] || fail 'required input is missing: GATEWAY_PR_BODY'

python3 - "$ROOT_DIR" "$GATEWAY_PROTECTED_BASE" "$GATEWAY_PROTECTED_HEAD" "$GATEWAY_PR_BODY" <<'PY'
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
base, head, body = sys.argv[2:]


def fail(message: str) -> None:
    print(f"check_protected_files: {message}", file=sys.stderr)
    raise SystemExit(1)


def git(*arguments: str) -> bytes:
    try:
        return subprocess.run(
            ["git", *arguments], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"git {' '.join(arguments)} failed: {error}")


agents = (root / "AGENTS.md").read_text(encoding="utf-8")
section_match = re.search(r"^## Protected Files\n(.*?)(?=^## )", agents, re.MULTILINE | re.DOTALL)
if not section_match:
    fail("cannot locate AGENTS.md Protected Files section")
before_pending = section_match.group(1).split("**Pending", 1)[0]
actual_rows = []
for line in before_pending.splitlines():
    if not line.startswith("|"):
        continue
    first = line.split("|", 2)[1].strip()
    if first not in {"Path", "---"} and not set(first) <= {"-", ":", " "}:
        actual_rows.append(first)
expected_rows = [
    "`LICENSE`, `NOTICE`",
    "`docs/adr/**`",
    "`rust-toolchain.toml`, `rustfmt.toml`",
    "`docs/msrv.md` and every `rust-version` in `Cargo.toml`",
    "`spec/ir.schema.json`",
    "`conformance/case.schema.json`",
    "`model/s3.json`, `model/sts.json`, their `.sha256` sidecars, `model/PROVENANCE.md`",
    "`generated/dto/field_counts.txt`",
    "`crates/core/tests/golden/route-table.txt`",
    "`model/overlays/**`",
    "`spec/quirks/**`",
    "`spec/contracts/**`",
    "`spec/third-party/aws-signing-test-suite.lock`",
]
if actual_rows != expected_rows:
    fail(f"AGENTS.md protected path table drifted: expected={expected_rows!r}, found={actual_rows!r}")

git("rev-parse", "--verify", base)
git("rev-parse", "--verify", head)
fields = git("diff", "--name-status", "-z", "--find-renames", base, head).split(b"\0")
changes: list[tuple[str, str | None, str]] = []
index = 0
while index < len(fields) and fields[index]:
    status = fields[index].decode("utf-8")
    index += 1
    old = None
    if status[0] in {"R", "C"}:
        old = fields[index].decode("utf-8")
        index += 1
    path = fields[index].decode("utf-8")
    index += 1
    changes.append((status[0], old, path))

exact = {
    "LICENSE",
    "NOTICE",
    "rust-toolchain.toml",
    "rustfmt.toml",
    "docs/msrv.md",
    "spec/ir.schema.json",
    "conformance/case.schema.json",
    "model/s3.json",
    "model/sts.json",
    "model/s3.json.sha256",
    "model/sts.json.sha256",
    "model/PROVENANCE.md",
    "generated/dto/field_counts.txt",
    "crates/core/tests/golden/route-table.txt",
    "spec/third-party/aws-signing-test-suite.lock",
}
violations: set[tuple[str, str]] = set()
for status, old, path in changes:
    candidates = [path] + ([old] if old else [])
    for candidate in candidates:
        if candidate in exact:
            violations.add((candidate, "protected contract path changed"))
        elif candidate.startswith("model/overlays/"):
            violations.add((candidate, "protocol overlay changed"))
        elif candidate.startswith(("spec/quirks/", "spec/contracts/")):
            violations.add((candidate, "generated protocol rule changed"))
        elif candidate.startswith("docs/adr/") and not (status in {"A", "C"} and old is None):
            violations.add((candidate, "accepted ADR changed or moved"))
    if status in {"D", "R"}:
        removed = old if old else path
        if removed.startswith("conformance/cases/"):
            violations.add((removed, "conformance case deleted or moved"))

cargo_diff = git("diff", "--unified=0", base, head, "--", "Cargo.toml", "*/Cargo.toml", "*/*/Cargo.toml")
for raw_line in cargo_diff.decode("utf-8").splitlines():
    if raw_line.startswith(("+++", "---")):
        continue
    if re.match(r"^[+-]\s*rust-version\s*=", raw_line):
        violations.add(("Cargo.toml", "rust-version contract changed"))

if not violations:
    print("check_protected_files: no protected contract change")
    raise SystemExit(0)

for path, reason in sorted(violations):
    print(f"{path}: {reason} (rule: AGENTS.md Protected Files)", file=sys.stderr)
if "BREAKING" not in body:
    fail("protected change requires literal BREAKING in the PR description")
print("check_protected_files: protected change carries BREAKING declaration")
PY
