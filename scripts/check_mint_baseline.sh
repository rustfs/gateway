#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_mint_baseline.sh
#
# WHAT THIS CHECKS
#   Four rules over ci/mint/baseline.txt, the second against the preceding
#   committed version of the same file:
#
#     1. The file parses: one `# generation: <n>` header, one `<sdk> <failures>`
#        line per SDK, no SDK twice.
#     2. A count may go down freely, and may only go up when the generation
#        went up by exactly one in the same change. The generation never goes
#        down and never jumps.
#     3. The SDK set is exactly MINT_SDKS in ci/mint/pins.env, in both
#        directions. An SDK the runner runs without a line would be judged
#        against nothing; a line for an SDK nobody runs is a tolerance that can
#        never be measured again.
#     4. Its input files exist. A missing baseline fails; it does not skip.
#
# WHY
#   The cheapest way to turn a red scheduled mint run green is to raise the
#   count for whichever SDK went red. This guard makes that a signed, one-line,
#   reviewed decision (the generation) instead of an edit nobody notices. It is
#   the per-SDK analogue of scripts/check_xfail_ratchet.sh.
#
# HOW TO EXEMPT
#   None. To raise a count, raise the generation by one in the same pull
#   request and attribute every added failure in the description.
#
# USAGE
#   scripts/check_mint_baseline.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_mint_baseline.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
RELATIVE="ci/mint/baseline.txt"
CANDIDATE="${REPO_DIR}/${RELATIVE}"
PINS="${REPO_DIR}/ci/mint/pins.env"

for required in "$CANDIDATE" "$PINS"; do
    if [[ ! -f "$required" ]]; then
        printf 'check_mint_baseline: required input is missing: %s\n' "${required#"${REPO_DIR}/"}" >&2
        exit 1
    fi
done

previous="$(mktemp "${TMPDIR:-/tmp}/gateway-mint-baseline.XXXXXX")"
trap 'rm -f "$previous"' EXIT

# Before a commit, compare the working file with HEAD. In CI, actions/checkout checks out the
# pull-request merge commit and HEAD^ is the base branch, so the comparison covers the whole
# pull request rather than only its last commit.
baseline_ref="HEAD^"
if ! git -C "$REPO_DIR" diff --quiet HEAD -- "$RELATIVE"; then
    baseline_ref="HEAD"
fi
if ! git -C "$REPO_DIR" show "${baseline_ref}:${RELATIVE}" >"$previous" 2>/dev/null; then
    # The change that first introduces the baseline has no predecessor. An absent one is every
    # SDK at zero failures, generation 0: the strictest reading that still lets the file be born.
    printf '# generation: 0\n' >"$previous"
fi

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_mint_baseline)" || exit 1
"$PYTHON" - "$previous" "$CANDIDATE" "$PINS" "$RELATIVE" <<'PYEOF'
import re
import sys
from pathlib import Path

previous_path, candidate_path, pins_path, relative = sys.argv[1:5]


def fail(message: str) -> None:
    print(f"check_mint_baseline: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: str, label: str, require_entries: bool) -> tuple[int, dict[str, int]]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read {label}: {error}")
    generation = None
    counts: dict[str, int] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("# generation:"):
            value = line[len("# generation:"):].strip()
            if not re.fullmatch(r"[0-9]+", value):
                fail(f"{label}:{number}: generation must be a non-negative integer")
            if generation is not None:
                fail(f"{label}:{number}: the generation is declared more than once")
            generation = int(value)
            continue
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        parts = entry.split()
        if len(parts) != 2 or not re.fullmatch(r"[A-Za-z0-9._-]+", parts[0]) or not re.fullmatch(r"[0-9]+", parts[1]):
            fail(f"{label}:{number}: expected `<sdk> <failures>`")
        if parts[0] in counts:
            fail(f"{label}:{number}: {parts[0]} is listed more than once")
        counts[parts[0]] = int(parts[1])
    if generation is None:
        fail(f"{label}: no `# generation: <n>` header")
    if require_entries and not counts:
        fail(f"{label} names no SDK")
    return generation, counts


old_generation, old_counts = read(previous_path, f"previous {relative}", False)
new_generation, new_counts = read(candidate_path, relative, True)

census = None
for line in Path(pins_path).read_text(encoding="utf-8").splitlines():
    match = re.fullmatch(r'\s*MINT_SDKS="?([^"]*)"?\s*', line)
    if match is not None:
        census = match.group(1).split()
if not census:
    fail("ci/mint/pins.env declares no MINT_SDKS census")
missing = sorted(set(census) - set(new_counts))
extra = sorted(set(new_counts) - set(census))
if missing or extra:
    fail(
        f"{relative} does not match the census in ci/mint/pins.env: "
        f"no line for [{', '.join(missing)}]; lines for SDKs the runner does not run [{', '.join(extra)}]"
    )

failed = False
if new_generation < old_generation:
    print(
        f"check_mint_baseline: the generation went backwards, {old_generation} -> {new_generation}",
        file=sys.stderr,
    )
    failed = True
elif new_generation > old_generation + 1:
    print(
        f"check_mint_baseline: the generation jumped {old_generation} -> {new_generation}; one pull request "
        "raises it by at most one, or it becomes room banked in advance",
        file=sys.stderr,
    )
    failed = True

raised = sorted(sdk for sdk, count in new_counts.items() if count > old_counts.get(sdk, 0))
if raised and new_generation != old_generation + 1:
    print(
        f"check_mint_baseline: {len(raised)} SDK count(s) went up without raising the generation "
        f"(still {new_generation}); a tolerated failure is added only in a pull request that argues it:",
        file=sys.stderr,
    )
    for sdk in raised:
        print(f"  {sdk}: {old_counts.get(sdk, 0)} -> {new_counts[sdk]}", file=sys.stderr)
    failed = True

if failed:
    raise SystemExit(1)

lowered = sum(1 for sdk, count in new_counts.items() if count < old_counts.get(sdk, 0))
print(
    f"OK: mint baseline {len(new_counts)} SDK(s), {sum(new_counts.values())} tolerated failure(s) at generation "
    f"{new_generation} (previous generation {old_generation}; {len(raised)} raised, {lowered} lowered)"
)
PYEOF
