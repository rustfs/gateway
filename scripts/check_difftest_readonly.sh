#!/usr/bin/env bash
set -euo pipefail
# REQUIRES-PR

# =============================================================================
# WHAT THIS CHECKS
#   The gateway/s3s differential reads the gateway; it does not steer it
#   (rustfs/backlog#1762, a-df-0019). A pull request that changes the
#   differential (crates/difftest/**) and anything the gateway is built from
#   together must say why in its description, on a line of its own. "Built
#   from" is every path except the differential itself, documentation
#   (*.md, docs/**), CI (.github/**, scripts/**), and the evidence the
#   gateway is measured against (conformance/**, corpus/**, fuzz/**,
#   Cargo.lock): a crate's source, build script or manifest, the model and
#   its overlays, generated code, the compat tree all count.
#       Difftest-coupled change: <why the gateway source changed, in a sentence>
#
# WHY
#   The differential is only evidence while the gateway is built without
#   looking at it. The quiet failure is a gateway change made because a diff
#   was red — a decoder bent toward s3s's behaviour — landing in the same pull
#   request as the register or sample edit that hides it. Changing both is
#   sometimes right (a real gateway bug the diff found); it is never silent.
#
# HOW TO EXEMPT
#   The justification line is the exemption, and reviewers read it.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_difftest_readonly: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
command -v git >/dev/null 2>&1 || fail 'required command is missing: git'
[[ -n "${GATEWAY_PR_BODY_JSON+x}" ]] || fail 'required input is missing: GATEWAY_PR_BODY_JSON'
# Encoded as one JSON line for the reason check_protected_files.sh gives (rustfs/gateway#224).
[[ "$GATEWAY_PR_BODY_JSON" != *$'\n'* ]] ||
    fail 'GATEWAY_PR_BODY_JSON must be a single-line JSON string (rule: rustfs/gateway#224)'
[[ "$GATEWAY_PR_BODY_JSON" != *$'\r'* ]] ||
    fail 'GATEWAY_PR_BODY_JSON must be a single-line JSON string (rule: rustfs/gateway#224)'
[[ -n "${GATEWAY_DIFFTEST_BASE:-}" ]] || fail 'required input is missing: GATEWAY_DIFFTEST_BASE'
[[ -n "${GATEWAY_DIFFTEST_HEAD:-}" ]] || fail 'required input is missing: GATEWAY_DIFFTEST_HEAD'

python3 - "$ROOT_DIR" "$GATEWAY_DIFFTEST_BASE" "$GATEWAY_DIFFTEST_HEAD" "$GATEWAY_PR_BODY_JSON" <<'PY'
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
base, head, body_json = sys.argv[2:]


def fail(message: str) -> None:
    print(f"check_difftest_readonly: {message}", file=sys.stderr)
    raise SystemExit(1)


try:
    body = json.loads(body_json)
except ValueError as error:
    fail(f"GATEWAY_PR_BODY_JSON is not JSON (rule: rustfs/gateway#224): {error}")
if body is None:
    body = ""
if not isinstance(body, str):
    fail(f"GATEWAY_PR_BODY_JSON must decode to a string, got {type(body).__name__}")
# What a reviewer sees: HTML comments and fenced blocks are not arguments anyone read.
body = re.sub(r"<!--.*?(?:-->|\Z)", "", body, flags=re.DOTALL)
body = re.sub(r"^\s*(```|~~~).*?(?:^\s*\1.*?$|\Z)", "", body, flags=re.DOTALL | re.MULTILINE)

try:
    listed = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--no-renames", f"{base}...{head}"], cwd=root, check=True, capture_output=True
    ).stdout
except (OSError, subprocess.CalledProcessError) as error:
    fail(f"cannot diff {base}...{head}: {error}")
paths = [path.decode("utf-8", "replace") for path in listed.split(b"\0") if path]

NOT_GATEWAY = ("crates/difftest/", "docs/", ".github/", "scripts/", "conformance/", "corpus/", "fuzz/")
difftest = [path for path in paths if path.startswith("crates/difftest/")]
gateway = [
    path
    for path in paths
    if not path.startswith(NOT_GATEWAY) and not path.endswith(".md") and path != "Cargo.lock"
]
if not difftest or not gateway:
    print(f"check_difftest_readonly: {len(difftest)} differential path(s), {len(gateway)} gateway path(s); not coupled")
    raise SystemExit(0)

argued = any(
    re.fullmatch(r"\s*(?:[-*]\s+)?Difftest-coupled change: (.*\S)\s*", line) and len(line.split(":", 1)[1].strip()) >= 20
    for line in body.splitlines()
)
if argued:
    print(f"check_difftest_readonly: differential and gateway source change together, with the argument in the description")
    raise SystemExit(0)
for path in gateway[:10]:
    print(f"{path}: gateway input changed alongside crates/difftest/** (a-df-0019)", file=sys.stderr)
fail("a pull request changing the differential and what the gateway is built from together needs a `Difftest-coupled change: <why>` line (20+ characters) in its description")
PY
