#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SOURCE_ROOT="${ROOT_DIR}/crates/core/src"
SUBJECT="${SOURCE_ROOT}/error.rs"

if [[ ! -f "$SUBJECT" ]]; then
    printf 'PreAuthError subject is missing; static-message check cannot run\n' >&2
    exit 1
fi

python3 - "$SUBJECT" "$SOURCE_ROOT" <<'PY'
import pathlib
import re
import sys

subject = pathlib.Path(sys.argv[1])
source_root = pathlib.Path(sys.argv[2])
text = subject.read_text()

match = re.search(r"pub struct PreAuthError\s*\{(?P<body>.*?)\n\}", text, re.S)
if match is None:
    print("PreAuthError struct is missing; static-message check cannot run", file=sys.stderr)
    raise SystemExit(1)

body = match.group("body")
if len(re.findall(r"\bmessage\s*:", body)) != 1 or re.search(
    r"\bmessage\s*:\s*&\s*'static\s+str\s*,", body
) is None:
    print("PreAuthError message must remain exactly &'static str", file=sys.stderr)
    raise SystemExit(1)

for number, line in enumerate(text.splitlines(), 1):
    stripped = line.strip()
    if stripped.startswith("//"):
        continue
    if "format!(" in stripped:
        print(f"{subject}:{number}: PreAuthError must not format a message", file=sys.stderr)
        raise SystemExit(1)

for path in sorted(source_root.rglob("*.rs")):
    for number, line in enumerate(path.read_text().splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        if ".leak(" in stripped or "Box::leak" in stripped:
            print(f"{path}:{number}: a runtime string must not be laundered into a static message", file=sys.stderr)
            raise SystemExit(1)

print("OK: PreAuthError messages remain compile-time strings with no laundering path")
PY
