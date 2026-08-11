#!/usr/bin/env bash
set -euo pipefail

# WHAT: Records the external crc-fast unsafe boundary while refusing every local unsafe token.
# WHY: rustfs/backlog#1706 requires a reviewed reason for the SIMD dependency; AGENTS.md forbids
# local unsafe without an ADR and allowance process.
# HOW TO EXEMPT: Additions require an ADR first, then one reasoned line in the allowance file.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ALLOWANCE="${ROOT}/scripts/allowances/unsafe-code-allowances.txt"

[[ -f "$ALLOWANCE" ]] || {
    printf 'check_unsafe_code_allowances: required allowance file is missing\n' >&2
    exit 1
}

expected='crc-fast|external SIMD implementation; remove when crc-fast is removed|https://crates.io/crates/crc-fast'
grep -Fqx "$expected" "$ALLOWANCE" || {
    printf 'check_unsafe_code_allowances: crc-fast has no reviewed external-unsafe record\n' >&2
    exit 1
}

python3 - "$ROOT" <<'PYEOF'
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
tracked = set()
for args in (["ls-files", "*.rs"], ["ls-files", "--others", "--exclude-standard", "*.rs"]):
    tracked.update(
        subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
    )

for relative in sorted(tracked):
    parts = pathlib.PurePosixPath(relative).parts
    if "generated" in parts:
        continue
    text = (root / relative).read_text()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    text = re.sub(r'r(?P<marks>#+)".*?"(?P=marks)', '""', text, flags=re.S)
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text, flags=re.S)
    if re.search(r"\bunsafe\b", text):
        print(f"check_unsafe_code_allowances: local unsafe token is forbidden: {relative}", file=sys.stderr)
        raise SystemExit(1)
PYEOF

printf 'OK: crc-fast external unsafe is recorded and local Rust remains unsafe-free\n'
