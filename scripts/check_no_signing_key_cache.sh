#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

cd "$ROOT_DIR"

python3 - <<'PY'
import pathlib
import re

paths = []
for root in (pathlib.Path("crates/sig/src"), pathlib.Path("crates/gateway/src")):
    if not root.is_dir():
        print(f"{root} is missing; signing-key cache check cannot run")
        raise SystemExit(1)
    paths.extend(root.rglob("*.rs"))

# The client-side signer deliberately caches its own derivation within one signer object. The
# prohibition is the server verification path retaining a key across requests.
paths = [path for path in paths if "signer" not in path.parts and path.name != "signer.rs"]

for path in paths:
    lines = []
    for line in path.read_text().splitlines():
        lines.append("" if line.lstrip().startswith("//") else line)
    code = "\n".join(lines)
    forbidden = [
        r"(?:HashMap|BTreeMap|Cache|Mutex|RwLock)[^;\n]{0,200}SigningKey",
        r"signing_key_cache",
        r"cached_signing_key",
    ]
    if any(re.search(pattern, code, re.I) for pattern in forbidden):
        print(f"{path}: derived signing-key cache detected")
        raise SystemExit(1)

print("OK: no derived signing-key cache")
PY
