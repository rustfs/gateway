#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="${BASH_SOURCE[0]%/*}"

# WHAT: Pins crc-fast to the reduced feature posture and keeps types on the workspace declaration.
# WHY: rustfs/backlog#1706 c-cks-n009 forbids crc-fast's ffi and panic-handler default features.
# HOW TO EXEMPT: There is no exemption; changing the checksum backend needs a dependency decision.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ROOT_MANIFEST="${ROOT}/Cargo.toml"
TYPES_MANIFEST="${ROOT}/crates/types/Cargo.toml"

for input in "$ROOT_MANIFEST" "$TYPES_MANIFEST"; do
    [[ -f "$input" ]] || {
        printf 'check_checksum_dependencies: required input is missing: %s\n' "$input" >&2
        exit 1
    }
done

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_checksum_dependencies)" || exit 1
"$PYTHON" - "$ROOT_MANIFEST" "$TYPES_MANIFEST" <<'PYEOF'
import pathlib
import sys
import tomllib

root = tomllib.loads(pathlib.Path(sys.argv[1]).read_text())
types = tomllib.loads(pathlib.Path(sys.argv[2]).read_text())
dependency = root.get("workspace", {}).get("dependencies", {}).get("crc-fast")
expected = {"version": "1.10", "default-features": False, "features": ["std"]}
if dependency != expected:
    print("check_checksum_dependencies: crc-fast must disable defaults and enable only std in Cargo.toml", file=sys.stderr)
    raise SystemExit(1)
if types.get("dependencies", {}).get("crc-fast") != {"workspace": True}:
    print("check_checksum_dependencies: crates/types must inherit the reviewed crc-fast declaration", file=sys.stderr)
    raise SystemExit(1)
PYEOF

printf 'OK: c-cks-n009 keeps crc-fast default-features=false with std only\n'
