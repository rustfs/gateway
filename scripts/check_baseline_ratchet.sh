#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# WHAT THIS CHECKS
#   The failures in conformance/baseline.json are a subset of the failures in
#   the preceding committed baseline. A baseline may improve, never excuse a
#   newly failing case.
#
# WHY
#   Baseline-aware reporting tolerates known failures. Without this ratchet, a
#   regression can be hidden by recording it as newly known in the same PR.
#
# HOW TO EXEMPT
#   There is no exemption. Fix the regression instead of widening the baseline.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
CANDIDATE="${REPO_DIR}/conformance/baseline.json"

if [[ ! -f "$CANDIDATE" ]]; then
    printf 'check_baseline_ratchet: missing %s\n' "$CANDIDATE" >&2
    exit 1
fi

previous="$(mktemp "${TMPDIR:-/tmp}/gateway-baseline.XXXXXX")"
trap 'rm -f "$previous"' EXIT

# Before a commit, compare the working file with HEAD. In CI, actions/checkout
# checks out the pull-request merge commit and HEAD^ is the base branch, so the
# comparison covers the whole PR rather than only its last commit.
baseline_ref="HEAD^"
if ! git -C "$REPO_DIR" diff --quiet HEAD -- conformance/baseline.json; then
    baseline_ref="HEAD"
fi

if ! git -C "$REPO_DIR" show "${baseline_ref}:conformance/baseline.json" >"$previous" 2>/dev/null; then
    printf 'check_baseline_ratchet: cannot read %s:conformance/baseline.json\n' "$baseline_ref" >&2
    exit 1
fi

python3 - "$previous" "$CANDIDATE" <<'PYEOF'
import json
import pathlib
import sys

def failures(path):
    try:
        document = json.loads(pathlib.Path(path).read_text())
        cases = document["cases"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        print(f"check_baseline_ratchet: {path}: {error}", file=sys.stderr)
        raise SystemExit(1)
    if not isinstance(cases, dict):
        print(f"check_baseline_ratchet: {path}: cases must be an object", file=sys.stderr)
        raise SystemExit(1)
    return {case for case, verdict in cases.items() if verdict == "failed"}

old = failures(sys.argv[1])
new = failures(sys.argv[2])
regressions = sorted(new - old)
if regressions:
    for case in regressions:
        print(f"check_baseline_ratchet: new baseline failure: {case}", file=sys.stderr)
    raise SystemExit(1)

print("OK: baseline failures are a subset of previous")
PYEOF
