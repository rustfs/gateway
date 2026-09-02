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
import sys
from pathlib import Path


def read(path, label):
    generation = None
    entries = []
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
        if entry in entries:
            print(f"check_xfail_ratchet: {label}:{number}: duplicate entry {entry}", file=sys.stderr)
            raise SystemExit(1)
        entries.append(entry)
    if generation is None:
        print(f"check_xfail_ratchet: {label}: no `# generation: <n>` header", file=sys.stderr)
        raise SystemExit(1)
    return set(entries), generation


previous_path, candidate_path, relative = sys.argv[1], sys.argv[2], sys.argv[3]
old_entries, old_generation = read(previous_path, f"previous {relative}")
new_entries, new_generation = read(candidate_path, relative)

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

if failed:
    raise SystemExit(1)

removed = len(old_entries - new_entries)
print(
    f"OK: xfail {len(new_entries)} entr(y/ies) at generation {new_generation} "
    f"(previous {len(old_entries)} at {old_generation}; {len(added)} added, {removed} removed)"
)
PYEOF
