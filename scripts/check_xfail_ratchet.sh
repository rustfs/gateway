#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_xfail_ratchet.sh
#
# WHAT THIS CHECKS
#   Three rules over ci/s3tests/xfail.txt, against the preceding committed
#   version of the same file:
#
#     1. The entry set may shrink freely, and may only grow when the header's
#        `# generation: <n>` also went up. A tolerated failure is a guarantee
#        quietly withdrawn, so widening the set is a decision somebody signs
#        rather than a line somebody appends.
#     2. The generation never goes down, and moves by at most one. A generation
#        that can jump is a generation that can be used to bank future room.
#     3. The file parses: one `# generation:` header, no duplicate entries.
#
# WHY
#   Baseline-aware reporting is the only form of an external suite that
#   survives contact with a young implementation — a runner that fails on the
#   first red is switched off within a week. The cost of that tolerance is that
#   the cheapest way to turn the job green stops being "fix the bug" and
#   becomes "paste the failure into the list". This guard is what makes the
#   second option more expensive than the first.
#
#   It is the same shape as scripts/check_baseline_ratchet.sh, which guards
#   conformance/baseline.json for the internal suite, and for the same reason.
#   The difference is the escape: the conformance baseline has none, because a
#   case there is one this repository wrote and can fix. An external suite of
#   ~980 cases needs a way to record a first baseline at all, and the
#   generation is that way — visible, one line, and reviewed.
#
# HOW TO EXEMPT
#   There is no path-level exemption. To add an entry, raise the generation in
#   the same pull request and say in the description why each addition is a gap
#   worth tolerating and which issue is expected to close it.
#
# USAGE
#   scripts/check_xfail_ratchet.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_xfail_ratchet.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
RELATIVE="ci/s3tests/xfail.txt"
CANDIDATE="${REPO_DIR}/${RELATIVE}"

if [[ ! -f "$CANDIDATE" ]]; then
    printf 'check_xfail_ratchet: missing %s\n' "$CANDIDATE" >&2
    exit 1
fi

previous="$(mktemp "${TMPDIR:-/tmp}/gateway-xfail.XXXXXX")"
trap 'rm -f "$previous"' EXIT

# Before a commit, compare the working file with HEAD. In CI, actions/checkout
# checks out the pull-request merge commit and HEAD^ is the base branch, so the
# comparison covers the whole pull request rather than only its last commit.
baseline_ref="HEAD^"
if ! git -C "$REPO_DIR" diff --quiet HEAD -- "$RELATIVE"; then
    baseline_ref="HEAD"
fi

if ! git -C "$REPO_DIR" show "${baseline_ref}:${RELATIVE}" >"$previous" 2>/dev/null; then
    # The pull request that first introduces the list has no previous version to
    # ratchet against. An absent predecessor is the empty set at generation 0,
    # which is the strictest reading available and still lets the file be born.
    printf '# generation: 0\n' >"$previous"
fi

python3 - "$previous" "$CANDIDATE" "$RELATIVE" <<'PYEOF'
import re
import sys
from pathlib import Path


OWNER_ISSUE = re.compile(r"https://github\.com/rustfs/(?:gateway|backlog)/issues/[1-9][0-9]*")


def read(path, label):
    generation = None
    entries = []
    excluded = {}
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        print(f"check_xfail_ratchet: cannot read {label}: {error}", file=sys.stderr)
        raise SystemExit(1)
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("# generation:"):
            value = line[len("# generation:"):].strip()
            if not value.isdigit():
                print(f"check_xfail_ratchet: {label}:{number}: generation must be a non-negative integer", file=sys.stderr)
                raise SystemExit(1)
            if generation is not None:
                print(f"check_xfail_ratchet: {label}:{number}: the generation is declared more than once", file=sys.stderr)
                raise SystemExit(1)
            generation = int(value)
            continue
        if not line or line.startswith("#"):
            continue
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        fields = entry.split()
        case_id = fields[0]
        if case_id in entries or case_id in excluded:
            print(f"check_xfail_ratchet: {label}:{number}: duplicate entry {case_id}", file=sys.stderr)
            raise SystemExit(1)
        if len(fields) == 1:
            entries.append(case_id)
            continue
        # `<case-id> excluded <owner issue URL> <reason>`: the same shape and the same rules as an
        # excluded SDK in ci/mint/baseline.txt (scripts/check_mint_baseline.sh).
        if fields[1] != "excluded" or len(fields) < 3 or not OWNER_ISSUE.fullmatch(fields[2]):
            print(
                f"check_xfail_ratchet: {label}:{number}: the exclusion of {case_id} names no owner; expected "
                "`<case-id> excluded <owner issue URL> <reason>` with an issue in rustfs/gateway or rustfs/backlog",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if len(fields[3:]) < 3:
            print(
                f"check_xfail_ratchet: {label}:{number}: the exclusion of {case_id} gives no reason; say in at "
                "least three words why its outcome cannot be judged",
                file=sys.stderr,
            )
            raise SystemExit(1)
        excluded[case_id] = fields[2]
    if generation is None:
        print(f"check_xfail_ratchet: {label}: no `# generation: <n>` header", file=sys.stderr)
        raise SystemExit(1)
    return set(entries), excluded, generation


previous_path, candidate_path, relative = sys.argv[1], sys.argv[2], sys.argv[3]
old_entries, old_excluded, old_generation = read(previous_path, f"previous {relative}")
new_entries, new_excluded, new_generation = read(candidate_path, relative)

# An exclusion is a wider tolerance than an entry: an entry still turns FIXED when the case passes,
# an exclusion reports nothing either way. So a new exclusion, including an entry turned into one,
# is a widening that needs the generation, exactly like a new entry.
added_exclusions = sorted(set(new_excluded) - set(old_excluded))
if added_exclusions and new_generation == old_generation:
    print(
        f"check_xfail_ratchet: {len(added_exclusions)} exclusion(s) were added without raising the generation "
        f"(still {old_generation}):",
        file=sys.stderr,
    )
    for case_id in added_exclusions[:10]:
        print(f"  + {case_id} excluded", file=sys.stderr)
    raise SystemExit(1)
# An exclusion turned back into a plain entry, or removed, narrows the tolerance: always allowed.
old_entries = old_entries | set(old_excluded)

failed = False
if new_generation < old_generation:
    print(
        f"check_xfail_ratchet: the generation went backwards, {old_generation} -> {new_generation}; "
        "a generation only ever moves forward",
        file=sys.stderr,
    )
    failed = True
elif new_generation > old_generation + 1:
    print(
        f"check_xfail_ratchet: the generation jumped {old_generation} -> {new_generation}; "
        "one pull request raises it by at most one, or it becomes room banked in advance",
        file=sys.stderr,
    )
    failed = True

added = sorted(new_entries - old_entries)
if added and new_generation == old_generation:
    print(
        f"check_xfail_ratchet: {len(added)} entr(y/ies) were added without raising the generation "
        f"(still {old_generation}). The list only grows in a pull request that argues each addition:",
        file=sys.stderr,
    )
    for entry in added[:10]:
        print(f"  + {entry}", file=sys.stderr)
    if len(added) > 10:
        print(f"  … and {len(added) - 10} more", file=sys.stderr)
    failed = True

# Rule 4: an entry is backed by a measurement. ci/s3tests/outcomes.txt is the per-case record
# of the run that measured this generation (ci/s3tests/report.py --outcomes). Every plain
# entry must be recorded there as failed or errored, and the record must be of this generation.
# An entry no run ever saw failing is a guess, and a guess in the tolerated set is a regression
# nobody will ever be told about.
outcomes_path = Path(candidate_path).with_name("outcomes.txt")
if new_entries or new_excluded:
    if not outcomes_path.is_file():
        print(
            "check_xfail_ratchet: ci/s3tests/outcomes.txt is missing; a non-empty xfail list needs the "
            "per-case record of the run that measured it",
            file=sys.stderr,
        )
        raise SystemExit(1)
    recorded = {}
    outcomes_generation = None
    for number, raw in enumerate(outcomes_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if line.startswith("# generation:"):
            outcomes_generation = int(line[len("# generation:"):].strip() or "-1")
            continue
        if not line or line.startswith("#"):
            continue
        outcome, _, case_id = line.partition(" ")
        if outcome not in {"passed", "failed", "errored", "skipped"} or not case_id:
            print(f"check_xfail_ratchet: outcomes.txt:{number}: expected `<outcome> <case-id>`", file=sys.stderr)
            raise SystemExit(1)
        recorded[case_id] = outcome
    if outcomes_generation != new_generation:
        print(
            f"check_xfail_ratchet: ci/s3tests/outcomes.txt records generation {outcomes_generation}, but the "
            f"xfail list is at {new_generation}; refresh them together from one record run",
            file=sys.stderr,
        )
        failed = True
    unmeasured = sorted(entry for entry in new_entries if recorded.get(entry) not in {"failed", "errored"})
    if unmeasured:
        print(
            f"check_xfail_ratchet: {len(unmeasured)} xfail entr(y/ies) are not recorded as failing in "
            "ci/s3tests/outcomes.txt:",
            file=sys.stderr,
        )
        for entry in unmeasured[:10]:
            print(f"  ? {entry} ({recorded.get(entry, 'not recorded')})", file=sys.stderr)
        failed = True

if failed:
    raise SystemExit(1)

removed = len(old_entries - new_entries)
print(
    f"OK: xfail {len(new_entries)} entr(y/ies) at generation {new_generation} "
    f"(previous {len(old_entries)} at {old_generation}; {len(added)} added, {removed} removed)"
)
PYEOF
