#!/usr/bin/env bash
set -euo pipefail

# WHAT: Forbids date or timestamp parsing conveniences on OpaqueString.
# WHY: rustfs/backlog#1706 c-ts-n002 requires Expires-like values to round-trip without interpretation.
# HOW TO EXEMPT: There is no exemption; callers may parse as an explicit, visible operation.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SOURCE="${ROOT}/crates/types/src/scalar/opaque_string.rs"

[[ -f "$SOURCE" ]] || {
    printf 'check_opaque_string: required input is missing: %s\n' "$SOURCE" >&2
    exit 1
}

python3 - "$SOURCE" <<'PYEOF'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text()
text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
text = re.sub(r"//.*", "", text)
methods = re.findall(r"\b(?:pub\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)", text)
for method in methods:
    lowered = method.lower()
    if lowered.startswith("parse_") or "date" in lowered or "timestamp" in lowered:
        print(f"check_opaque_string: forbidden interpreting method on OpaqueString: {method}", file=sys.stderr)
        raise SystemExit(1)
PYEOF

printf 'OK: c-ts-n002 exposes no OpaqueString date parser\n'
