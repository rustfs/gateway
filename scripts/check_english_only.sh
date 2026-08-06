#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_english_only.sh
#
# WHAT THIS CHECKS
#   That no tracked file in this repository contains CJK characters.
#
# WHY
#   Everything that lands here is English — source, docs, templates, scripts.
#   Across the rustfs organisation, `rustfs/backlog` is the single exception,
#   where planning discussion may be Chinese; every other repository, this one
#   included, is English-only.
#
#   The rule is not about preference. Anything written once is read by everyone
#   who touches it afterwards, including contributors who do not read Chinese
#   and the greps that go looking for it. A Chinese sentence in a comment is a
#   dead end for half the people who hit it.
#
#   This guard covers the source tree. It cannot see the GitHub surface —
#   issues, comments, PR descriptions — which is governed by the same rule in
#   AGENTS.md and enforced by review.
#
# HOW TO EXEMPT
#   Add a path to `scripts/allowances/english-only-allowances.txt`, one per
#   line, with a comment giving the reason. A conformance case asserting how a
#   non-ASCII object key round-trips is a legitimate reason; a comment nobody
#   got round to translating is not.
#
# USAGE
#   scripts/check_english_only.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_english_only.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ALLOWANCE_FILE="${SCRIPT_DIR}/allowances/english-only-allowances.txt"
cd "$ROOT_DIR"

status=0

ALLOWANCES=""
if [[ -f "$ALLOWANCE_FILE" ]]; then
    while IFS= read -r line; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | tr -d ' \t')"
        [[ -z "$line" ]] && continue
        ALLOWANCES="${ALLOWANCES}${line}
"
    done <"$ALLOWANCE_FILE"
fi

is_allowed() {
    [[ -z "$ALLOWANCES" ]] && return 1
    printf '%s' "$ALLOWANCES" | grep -qxF "$1"
}

# Codepoint ranges, checked in Python rather than with a grep bracket expression.
# A bracket range spelled with two CJK endpoints looks right and is not: it is resolved
# through the locale's collation order rather than through codepoints, so on macOS it
# matched an em dash and a middle dot. The first version of this guard reported every
# English file in the tree — including this one.
python3 - "$ALLOWANCE_FILE" <<'PYEOF' || status=1
import pathlib
import subprocess
import sys

RANGES = [
    (0x3040, 0x30FF),    # Hiragana, Katakana
    (0x3400, 0x4DBF),    # CJK Extension A
    (0x4E00, 0x9FFF),    # CJK Unified Ideographs
    (0xAC00, 0xD7AF),    # Hangul syllables
    (0xF900, 0xFAFF),    # CJK compatibility ideographs
    (0xFF01, 0xFF60),    # Fullwidth forms
    (0x20000, 0x2FA1F),  # CJK Extensions B and beyond
]
SKIP = {"model/s3.json", "model/sts.json"}


def is_cjk(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in RANGES)


allowances = set()
allowance_file = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else None
if allowance_file and allowance_file.is_file():
    for line in allowance_file.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            allowances.add(line)

tracked = subprocess.run(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard"], capture_output=True, text=True, check=False
).stdout.splitlines()

bad = False
for name in tracked:
    if name in SKIP or name.endswith(".sha256") or name in allowances:
        continue
    path = pathlib.Path(name)
    if not path.is_file():
        continue
    try:
        text = path.read_text()
    except (UnicodeDecodeError, OSError):
        continue
    hits = [
        (n, line)
        for n, line in enumerate(text.splitlines(), 1)
        if any(is_cjk(ch) for ch in line)
    ]
    if hits:
        bad = True
        print(
            f"{name}: contains CJK text; everything that lands here is English "
            f"(AGENTS.md, Language Requirements)",
            file=sys.stderr,
        )
        for n, line in hits[:3]:
            print(f"    {n}: {line.strip()[:90]}", file=sys.stderr)

sys.exit(1 if bad else 0)
PYEOF

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Translate before it lands. `rustfs/backlog` is the one repository in the
organisation where Chinese is allowed; this is not that repository.
EOF
fi

# `--cached --others --exclude-standard` rather than a bare `git ls-files`: the bare form
# lists only *tracked* files, so a brand-new file is invisible to this guard right up until
# the moment `git add -A` commits it. That is exactly how CJK text reached commit 343f044
# past a guard that had just reported success. Ignored files stay out.
exit "$status"
