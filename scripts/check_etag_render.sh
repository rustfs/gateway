#!/usr/bin/env bash
set -euo pipefail

# WHAT: Keeps ETag rendering behind the explicit EtagRender context and forbids default string traits.
# WHY: rustfs/backlog#1706 c-etag-n009 makes missing quote context a compile-time/API-shape error.
# HOW TO EXEMPT: There is no exemption; add a new EtagRender variant instead of a default rendering.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SOURCE="${ROOT}/crates/types/src/scalar/etag.rs"

[[ -f "$SOURCE" ]] || {
    printf 'check_etag_render: required input is missing: %s\n' "$SOURCE" >&2
    exit 1
}

python3 - "$SOURCE" <<'PYEOF'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
text = re.sub(r"//.*", "", text)

forbidden = {
    "Display for ETag": r"\bimpl(?:\s*<[^>]*>)?\s+(?:(?:std::)?fmt::)?Display\s+for\s+ETag\b",
    "From<ETag> for String": r"\bimpl(?:\s*<[^>]*>)?\s+(?:std::convert::)?From\s*<\s*ETag\s*>\s+for\s+(?:std::string::)?String\b",
    "Into<String> for ETag": r"\bimpl(?:\s*<[^>]*>)?\s+(?:std::convert::)?Into\s*<\s*(?:std::string::)?String\s*>\s+for\s+ETag\b",
}
for label, pattern in forbidden.items():
    if re.search(pattern, text, flags=re.S):
        print(f"check_etag_render: forbidden default rendering trait: {label}", file=sys.stderr)
        raise SystemExit(1)

entries = re.findall(r"\bpub\s+fn\s+render\s*\(\s*&self\s*,\s*ctx\s*:\s*EtagRender\b", text, flags=re.S)
if len(entries) != 1:
    print(f"check_etag_render: expected one render(&self, ctx: EtagRender) entry, found {len(entries)}", file=sys.stderr)
    raise SystemExit(1)
PYEOF

printf 'OK: c-etag-n009 has one contextual render entry and no default string trait\n'
