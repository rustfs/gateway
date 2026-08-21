#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# WHAT THIS CHECKS
#   Two directions of the same ratchet, against the preceding committed baseline:
#     1. The failures in conformance/baseline.json are a subset of the previous
#        failures. A baseline may improve, never excuse a newly failing case.
#     2. No case the previous baseline recorded as `passed` is now recorded as
#        `skipped`. Downgrading a case to "did not run" is the other way to buy
#        silence, and it is cheaper than recording a failure because a skip has
#        no diagnosis attached to argue with.
#
# WHY
#   Baseline-aware reporting tolerates known failures. Without this ratchet, a
#   regression can be hidden by recording it as newly known in the same PR.
#
#   Rule 2 arrived with rustfs/gateway#192. Until then a skip could not regress
#   at all, so the whole shape was free: rustfs/gateway#203 found the `object/`
#   domain running against `Unwired` — every case a skip — and #214's mutation
#   lost all thirty-nine `acl` cases while the runner still reported
#   `0 regression(s)` and exit 0. The runner now treats a recorded pass that
#   skips as a regression, and this rule is the half that stops the same PR
#   rewriting the record instead of the code.
#
#   The rule deliberately compares only ids the previous baseline already named.
#   A case that is new since that baseline has nothing to be downgraded from,
#   and the corpus-wide completeness gate in crates/conformance/tests/corpus.rs
#   is what requires it to be recorded at all.
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

def verdicts(path):
    try:
        document = json.loads(pathlib.Path(path).read_text())
        cases = document["cases"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        print(f"check_baseline_ratchet: {path}: {error}", file=sys.stderr)
        raise SystemExit(1)
    if not isinstance(cases, dict):
        print(f"check_baseline_ratchet: {path}: cases must be an object", file=sys.stderr)
        raise SystemExit(1)
    return cases

old = verdicts(sys.argv[1])
new = verdicts(sys.argv[2])

failed = sorted(
    case for case, verdict in new.items() if verdict == "failed" and old.get(case) != "failed"
)
for case in failed:
    print(f"check_baseline_ratchet: new baseline failure: {case}", file=sys.stderr)

# Only ids the previous baseline already named: a case added since it has nothing to be
# downgraded from, and the corpus-wide gate is what requires it to carry a row at all.
downgraded = sorted(
    case for case, verdict in new.items() if verdict == "skipped" and old.get(case) == "passed"
)
for case in downgraded:
    print(
        f"check_baseline_ratchet: {case} was recorded as passing and is now recorded as skipped; "
        "a case that stops running is a regression, not a new baseline",
        file=sys.stderr,
    )

if failed or downgraded:
    raise SystemExit(1)

print("OK: baseline failures are a subset of previous, and no recorded pass was downgraded to a skip")
PYEOF
