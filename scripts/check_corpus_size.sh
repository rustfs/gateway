#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_corpus_size.sh
#
# WHAT THIS CHECKS
#   `corpus/` stays under the hard ceiling, and reports how much of the soft target it
#   is using. Both numbers are read out of `crates/corpus/src/store.rs` so the ceiling
#   the tool enforces and the ceiling CI enforces cannot drift apart.
#
# WHY
#   rustfs/backlog#1763 caps the in-repository corpus at a 20 MB target and a 50 MB hard
#   limit, and keeps the full capture in a CI artifact instead. The reason is clone time:
#   tens of thousands of recorded requests reach hundreds of megabytes, and a repository
#   nobody can clone quickly is a repository whose gate nobody runs. The soft target is
#   reported rather than enforced so that the number is visible one pull request before
#   it matters, which is the same argument scripts/ci_budget.sh makes about the clock.
#
# HOW TO EXEMPT
#   There is no exemption. Lower the per-bucket cap (`corpus ingest --cap N`) or move the
#   full capture to a CI artifact; both shrink the tree without deleting a check.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

command -v python3 >/dev/null 2>&1 || {
    printf 'check_corpus_size: required command is missing: python3\n' >&2
    exit 1
}

for required in corpus crates/corpus/src/store.rs; do
    if [[ ! -e "${ROOT_DIR}/${required}" ]]; then
        printf 'check_corpus_size: required input is missing: %s\n' "$required" >&2
        exit 1
    fi
done

python3 - "$ROOT_DIR" <<'PYEOF'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
store = (root / "crates/corpus/src/store.rs").read_text()


def limit(name: str) -> int:
    match = re.search(rf"pub const {name}: u64 = ([0-9]+) \* 1024 \* 1024;", store)
    if match is None:
        print(f"check_corpus_size: cannot read {name} from crates/corpus/src/store.rs", file=sys.stderr)
        raise SystemExit(1)
    return int(match.group(1)) * 1024 * 1024


soft = limit("SOFT_SIZE_LIMIT_BYTES")
hard = limit("HARD_SIZE_LIMIT_BYTES")
if soft >= hard:
    print("check_corpus_size: the soft target is not below the hard ceiling", file=sys.stderr)
    raise SystemExit(1)

total = sum(path.stat().st_size for path in (root / "corpus").rglob("*") if path.is_file())
megabytes = total / (1024 * 1024)

if total > hard:
    print(
        f"check_corpus_size: corpus/ is {megabytes:.1f} MB, over the {hard // (1024 * 1024)} MB hard ceiling; "
        "lower the per-bucket cap or move the full capture to a CI artifact",
        file=sys.stderr,
    )
    raise SystemExit(1)
if total > soft:
    print(
        f"::warning::corpus/ is {megabytes:.1f} MB, over the {soft // (1024 * 1024)} MB soft target",
        file=sys.stderr,
    )
print(f"OK: {megabytes:.1f} MB < {soft // (1024 * 1024)} MB target")
PYEOF
