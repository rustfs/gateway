#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# WHAT THIS CHECKS
#   Every conformance case carries at least one evidence entry, and every entry
#   is an HTTPS URL (or repository-local URN) plus a non-empty original summary
#   of at most 200 chars.
#
# WHY
#   P8-01 requires traceability without copying upstream issue prose. The
#   length ceiling makes a pasted issue body structurally invalid.
#
# HOW TO EXEMPT
#   There is no exemption. A case without compact source evidence is invalid.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

python3 - "$REPO_DIR" <<'PYEOF'
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
case_root = root / "conformance/cases"
if not case_root.is_dir():
    print(f"check_evidence_shape: no case directory at {case_root}", file=sys.stderr)
    raise SystemExit(1)

failures = []
cases = sorted(case_root.rglob("*.toml"))
if not cases:
    failures.append("no case files found")

for path in cases:
    relative = path.relative_to(root)
    try:
        document = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        failures.append(f"{relative}: {error}")
        continue
    evidence = document.get("case", {}).get("evidence")
    if not isinstance(evidence, list) or not evidence:
        failures.append(f"{relative}: case.evidence must contain at least one entry")
        continue
    for index, item in enumerate(evidence):
        prefix = f"{relative}: case.evidence[{index}]"
        if not isinstance(item, dict):
            failures.append(f"{prefix} must be a table")
            continue
        url = item.get("url")
        summary = item.get("summary")
        if not isinstance(url, str) or not url.startswith(("https://", "urn:")):
            failures.append(f"{prefix}.url must be HTTPS or a repository-local URN")
        if not isinstance(summary, str) or not summary.strip():
            failures.append(f"{prefix}.summary must be non-empty")
        elif len(summary) > 200:
            failures.append(f"{prefix}.summary is {len(summary)} chars; maximum is 200")

if failures:
    for failure in failures:
        print(f"check_evidence_shape: {failure}", file=sys.stderr)
    raise SystemExit(1)

print(f"OK: {len(cases)} cases, evidence is url+summary only")
PYEOF
