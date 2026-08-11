#!/usr/bin/env bash
set -euo pipefail

# The stream crate sits below protocol types. Protocol vocabulary in code or
# comments is evidence that the dependency cycle is returning in another form.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if ! command -v python3 >/dev/null 2>&1; then
    printf 'check_stream_vocabulary: required command is missing: python3\n' >&2
    exit 1
fi

python3 - "$ROOT_DIR" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
source = root / "crates/stream/src"
if not source.is_dir():
    print("check_stream_vocabulary: required input is missing: crates/stream/src", file=sys.stderr)
    raise SystemExit(1)

pattern = re.compile(r"\b(?:etag|checksum|bucket|multipart|object[-_ ]?key)\b", re.IGNORECASE)
violations = []
files = sorted(source.rglob("*.rs"))
if not files:
    print("check_stream_vocabulary: no Rust sources found", file=sys.stderr)
    raise SystemExit(1)
for path in files:
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if pattern.search(line):
            violations.append(f"{path.relative_to(root)}:{number}: protocol vocabulary in stream kernel")

if violations:
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)
PY
