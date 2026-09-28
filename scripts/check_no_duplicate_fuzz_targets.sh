#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_duplicate_fuzz_targets.sh
#
# WHAT THIS CHECKS
#   No two fuzz targets fuzz the same thing (rustfs/backlog#1766 a-pf-0022):
#
#     1. No two files in fuzz/fuzz_targets/ have the same body once comments and
#        whitespace are removed.
#     2. Exactly one target drives `SigV4Authorization::parse`, the signature
#        header the P2-07 target (`credential_header_parse`) already owns.
#
# WHY
#   A duplicate target doubles the nightly budget for no new coverage, and two
#   copies of one property drift apart: a fix lands in one and the other keeps
#   fuzzing the old contract. The signature parser is named because the original
#   plan called out re-implementing its target as the likely duplicate.
#
# HOW TO EXEMPT
#   There is no exemption. Extend the existing target or its property module.
# =============================================================================

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

python3 - "$ROOT" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
directory = root / "fuzz/fuzz_targets"
targets = sorted(directory.glob("*.rs")) if directory.is_dir() else []
if not targets:
    print("check_no_duplicate_fuzz_targets: required input is missing: fuzz/fuzz_targets/*.rs", file=sys.stderr)
    raise SystemExit(1)

failures = []
bodies = {}
signature_parsers = []
for path in targets:
    text = path.read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", text)
    normalized = re.sub(r"\s+", "", code)
    if normalized in bodies:
        failures.append(f"{path.name} is the same target as {bodies[normalized]}")
    bodies.setdefault(normalized, path.name)
    if re.search(r"\bSigV4Authorization::parse\b", code):
        signature_parsers.append(path.name)

if signature_parsers != ["credential_header_parse.rs"]:
    failures.append(
        "SigV4Authorization::parse must be fuzzed by credential_header_parse.rs alone, found "
        + (", ".join(signature_parsers) or "no target")
    )

if failures:
    for message in failures:
        print(f"check_no_duplicate_fuzz_targets: {message}", file=sys.stderr)
    raise SystemExit(1)
print(f"OK: {len(targets)} fuzz targets, no duplicates")
PY
