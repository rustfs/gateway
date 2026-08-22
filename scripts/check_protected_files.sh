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
[[ -n "${GATEWAY_PR_BODY_JSON+x}" ]] || fail 'required input is missing: GATEWAY_PR_BODY_JSON'
# The pull-request body arrives JSON-encoded because the workflow prints this step's env
# block into the CI log, where the runner reads a line beginning `::` as a workflow
# command (rustfs/gateway#224). A raw newline here means the encoding did not happen, so
# the body could be forging or suppressing annotations already. Fail closed.
[[ "$GATEWAY_PR_BODY_JSON" != *$'\n'* ]] ||
    fail 'GATEWAY_PR_BODY_JSON must be a single-line JSON string (rule: rustfs/gateway#224)'
[[ "$GATEWAY_PR_BODY_JSON" != *$'\r'* ]] ||
    fail 'GATEWAY_PR_BODY_JSON must be a single-line JSON string (rule: rustfs/gateway#224)'
[[ -n "${GATEWAY_PROTECTED_BASE:-}" ]] || fail 'required input is missing: GATEWAY_PROTECTED_BASE'
[[ -n "${GATEWAY_PROTECTED_HEAD:-}" ]] || fail 'required input is missing: GATEWAY_PROTECTED_HEAD'

python3 - "$ROOT_DIR" "$GATEWAY_PROTECTED_BASE" "$GATEWAY_PROTECTED_HEAD" "$GATEWAY_PR_BODY_JSON" <<'PY'
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
base, head, body_json = sys.argv[2:]


def fail(message: str) -> None:
    print(f"check_protected_files: {message}", file=sys.stderr)
    raise SystemExit(1)


try:
    decoded = json.loads(body_json)
except ValueError as error:
    fail(f"GATEWAY_PR_BODY_JSON is not JSON (rule: rustfs/gateway#224): {error}")
# A pull request with no description arrives as JSON null.
if decoded is None:
    decoded = ""
if not isinstance(decoded, str):
    fail(f"GATEWAY_PR_BODY_JSON must decode to a string, got {type(decoded).__name__}")
body = decoded


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
    "`model/overlays/error-status.toml`",
    "`generated/ERROR_CODES.md`, `generated/error_codes.json`",
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

new_adr_rows: list[tuple[int, str]] = []
for status, old, path in changes:
    match = re.fullmatch(r"docs/adr/([0-9]{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md", path)
    if status != "A" or old is not None or match is None:
        continue
    try:
        source = git("show", f"{head}:{path}").decode("utf-8")
    except UnicodeError as error:
        fail(f"new ADR is not UTF-8: {path}: {error}")
    title = re.search(rf"^# ADR-{match.group(1)}: (.+)$", source, re.MULTILINE)
    adr_status = re.search(r"^- Status: (.+)$", source, re.MULTILINE)
    if title is None or adr_status is None:
        continue
    number = int(match.group(1), 10)
    new_adr_rows.append(
        (number, f"| {number:04d} | {title.group(1)} | {adr_status.group(1)} |\n")
    )

readme_index_only = False
if new_adr_rows:
    try:
        base_readme = git("show", f"{base}:docs/adr/README.md").decode("utf-8")
        head_readme = git("show", f"{head}:docs/adr/README.md").decode("utf-8")
    except UnicodeError as error:
        fail(f"ADR index is not UTF-8: {error}")
    expected = base_readme.splitlines(keepends=True)
    index_rows = [offset for offset, line in enumerate(expected) if re.match(r"^\| [0-9]{4} \|", line)]
    if index_rows:
        insert_at = index_rows[-1] + 1
        expected[insert_at:insert_at] = [row for _, row in sorted(new_adr_rows)]
        readme_index_only = "".join(expected) == head_readme

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
    "generated/ERROR_CODES.md",
    "generated/error_codes.json",
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
        elif candidate == "docs/adr/README.md" and status == "M" and old is None and readme_index_only:
            continue
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
