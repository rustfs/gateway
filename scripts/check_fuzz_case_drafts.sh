#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# WHAT THIS CHECKS
#   No fuzz-found case draft is committed as if it were a case
#   (rustfs/backlog#1762, a-df-0020): no `.toml` file lies under
#   conformance/cases/_from_fuzz/, and no file under conformance/ still holds
#   the FUZZ-DRAFT marker `fuzz-to-case` writes where a person must write.
#
# WHY
#   A draft asserts what the gateway answered, not what is right. Merged
#   unreviewed, it would pin whichever stack happened to be wrong, with a
#   rationale nobody wrote. The draft becomes a case by review, in the domain
#   directory its behaviour belongs to.
#
# HOW TO EXEMPT
#   There is no exemption. Finish the draft (conformance/cases/_from_fuzz/README.md).
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_fuzz_case_drafts: %s\n' "$*" >&2
    exit 1
}

[[ -d "${ROOT_DIR}/conformance/cases" ]] || fail 'rule input is missing: conformance/cases'

python3 - "$ROOT_DIR" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
conformance = root / "conformance"
MARKER = "FUZZ-DRAFT"
problems = []
drafts = conformance / "cases" / "_from_fuzz"
if drafts.is_dir():
    problems += [f"{path.relative_to(root)}: a draft is not a case (move it to its domain once reviewed)" for path in sorted(drafts.rglob("*.toml"))]
for path in sorted(conformance.rglob("*")):
    if not path.is_file() or path == drafts / "README.md":
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        continue
    if MARKER in text:
        problems.append(f"{path.relative_to(root)}: still holds {MARKER} where a person must write")
if problems:
    for problem in problems:
        print(problem, file=sys.stderr)
    print("check_fuzz_case_drafts: finish each draft: conformance/cases/_from_fuzz/README.md", file=sys.stderr)
    raise SystemExit(1)
print("check_fuzz_case_drafts: no fuzz-found draft is committed")
PY
