#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SUBJECT="${ROOT_DIR}/crates/gateway/src/ext/credentials.rs"

if [[ ! -f "$SUBJECT" ]]; then
    printf 'credential provider subject is missing; pre-auth error check cannot run\n' >&2
    exit 1
fi

python3 - "$SUBJECT" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
match = re.search(r"pub enum ProviderError\s*\{(?P<body>.*?)\n\}", text, re.S)
if match is None:
    print("ProviderError enum is missing; pre-auth error check cannot run", file=sys.stderr)
    raise SystemExit(1)

body = "\n".join(line for line in match.group("body").splitlines() if not line.lstrip().startswith("///"))
for line in body.splitlines():
    stripped = line.strip().rstrip(",")
    if not stripped:
        continue
    if not re.fullmatch(r"[A-Z][A-Za-z0-9_]*", stripped):
        print(f"ProviderError variant carries data: {stripped}", file=sys.stderr)
        raise SystemExit(1)

print("OK: ProviderError variants are request-data-free")
PY
