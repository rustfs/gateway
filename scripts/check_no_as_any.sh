#!/usr/bin/env bash
set -euo pipefail

# Payload negotiation is a named enum contract. Runtime downcasts can bypass
# wrappers and silently turn a missing fast path into an unobserved fallback.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if ! command -v python3 >/dev/null 2>&1; then
    printf 'check_no_as_any: required command is missing: python3\n' >&2
    exit 1
fi

python3 - "$ROOT_DIR" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
source = root / "crates/stream/src"
if not source.is_dir():
    print("check_no_as_any: required input is missing: crates/stream/src", file=sys.stderr)
    raise SystemExit(1)

pattern = re.compile(r"\bfn\s+as_any\b|\bdowncast(?:_ref|_mut)?\b")
violations = []
files = sorted(source.rglob("*.rs"))
if not files:
    print("check_no_as_any: no Rust sources found", file=sys.stderr)
    raise SystemExit(1)
for path in files:
    text = path.read_text()
    code = re.sub(r"/\*.*?\*/", lambda match: "\n" * match.group().count("\n"), text, flags=re.S)
    code = re.sub(r"//[^\n]*", "", code)
    for match in pattern.finditer(code):
        line = code.count("\n", 0, match.start()) + 1
        violations.append(f"{path.relative_to(root)}:{line}: runtime downcast escape hatch")

if violations:
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)
PY
