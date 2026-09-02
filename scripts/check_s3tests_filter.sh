#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_s3tests_filter.sh
#
# WHAT THIS CHECKS
#   Three rules over ci/s3tests/filter.txt, the pytest marker expression the
#   weekly Ceph s3-tests run selects with:
#
#     1. No exclusion is added. The clause set may shrink — measuring more is
#        always allowed — and may never grow against the preceding committed
#        version of the file.
#     2. `fails_on_rgw` is never excluded, in any spelling.
#     3. `fails_on_aws` stays excluded, and the expression is non-empty and
#        parses as a chain of `not <marker>` clauses.
#
# WHY RULE 1
#   An excluded case is not a failing case, it is an absent one. It leaves no
#   trace in the report, nothing to grep for, and no entry in
#   ci/s3tests/xfail.txt to shrink. Widening the filter is therefore the one
#   way to make this suite green that also makes it worthless, and it is
#   cheaper than any other. Known gaps go in the xfail list, where they are
#   counted, grouped by capability domain, and ratcheted.
#
# WHY RULE 2, SPECIFICALLY
#   `fails_on_rgw` marks the ~39 cases Ceph's own gateway does not pass. Those
#   usually encode the *correct* AWS behaviour, which makes them the target of
#   this project rather than noise in it. They also look exactly like the other
#   `fails_on_*` markers, so excluding them reads as consistency. It is not:
#   it is the single most valuable subset of the suite being deleted, and the
#   diff that does it is one word long.
#
# WHY RULE 3
#   The mirror image. `fails_on_aws` marks the ~202 cases real AWS S3 does not
#   pass — RGW-specific behaviour. This project is measured against AWS
#   fidelity, so passing those would be the defect. Dropping the exclusion
#   would fill the xfail list with cases nobody should ever fix.
#
# HOW TO EXEMPT
#   There is no exemption for rules 2 and 3. Rule 1 is answered by removing an
#   exclusion, never by adding one.
#
# USAGE
#   scripts/check_s3tests_filter.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_s3tests_filter.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
RELATIVE="ci/s3tests/filter.txt"
CANDIDATE="${REPO_DIR}/${RELATIVE}"

if [[ ! -f "$CANDIDATE" ]]; then
    printf 'check_s3tests_filter: missing %s\n' "$CANDIDATE" >&2
    exit 1
fi

previous="$(mktemp "${TMPDIR:-/tmp}/gateway-filter.XXXXXX")"
trap 'rm -f "$previous"' EXIT

baseline_ref="HEAD^"
if ! git -C "$REPO_DIR" diff --quiet HEAD -- "$RELATIVE"; then
    baseline_ref="HEAD"
fi
if ! git -C "$REPO_DIR" show "${baseline_ref}:${RELATIVE}" >"$previous" 2>/dev/null; then
    # First introduction: nothing to widen against yet. Rules 2 and 3 still apply,
    # and they are the two that carry the weight.
    : >"$previous"
fi

python3 - "$previous" "$CANDIDATE" "$RELATIVE" <<'PYEOF'
import re
import sys
from pathlib import Path

CLAUSE = re.compile(r"^(?:and\s+)?not\s+([A-Za-z_][A-Za-z0-9_]*)$")


def markers(path, label, required):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        print(f"check_s3tests_filter: cannot read {label}: {error}", file=sys.stderr)
        raise SystemExit(1)
    found = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = CLAUSE.match(line)
        if match is None:
            if not required:
                continue
            print(
                f"check_s3tests_filter: {label}:{number}: every clause must read "
                f"`[and] not <marker>`, got {line!r}. A filter this guard cannot parse is a "
                "filter it cannot ratchet.",
                file=sys.stderr,
            )
            raise SystemExit(1)
        found.add(match.group(1))
    return found


previous_path, candidate_path, relative = sys.argv[1], sys.argv[2], sys.argv[3]
old = markers(previous_path, f"previous {relative}", required=False)
new = markers(candidate_path, relative, required=True)

failed = False
if not new:
    print(f"check_s3tests_filter: {relative} excludes nothing at all; the marker expression is empty", file=sys.stderr)
    failed = True

if "fails_on_rgw" in new:
    print(
        "check_s3tests_filter: fails_on_rgw is excluded. Those are the cases Ceph's own gateway "
        "does not pass, which usually means they encode the correct AWS behaviour — they are the "
        "target of this project, not noise in it.",
        file=sys.stderr,
    )
    failed = True

if "fails_on_aws" not in new:
    print(
        "check_s3tests_filter: fails_on_aws is no longer excluded. Those cases record behaviour "
        "real AWS S3 does not have, so passing them would be the defect.",
        file=sys.stderr,
    )
    failed = True

added = sorted(new - old)
if added and old:
    print(
        f"check_s3tests_filter: {len(added)} marker exclusion(s) were added: {', '.join(added)}. "
        "An excluded case is an absent case, not a failing one: it leaves no entry to shrink and "
        "nothing to grep. Record the gap in ci/s3tests/xfail.txt instead.",
        file=sys.stderr,
    )
    failed = True

if failed:
    raise SystemExit(1)

removed = sorted(old - new)
print(
    f"OK: filter excludes {len(new)} marker(s), fails_on_rgw is measured, "
    f"{len(added)} added, {len(removed)} removed"
)
PYEOF
