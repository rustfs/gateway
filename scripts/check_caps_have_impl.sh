#!/usr/bin/env bash
# P7-03: every kernel-transfer capability advertised by the response planner has an implementation.
set -euo pipefail

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PLAN="${ROOT_DIR}/crates/gateway/src/conn/body_plan.rs"
SERVER_LIB="${ROOT_DIR}/crates/server/src/lib.rs"
SENDFILE="${ROOT_DIR}/crates/server/src/sendfile.rs"

fail() {
    printf 'check_caps_have_impl: %s\n' "$1" >&2
    exit 1
}

[[ -f "$PLAN" ]] || fail 'response body planner is missing'
[[ -f "$SERVER_LIB" ]] || fail 'server module root is missing'
[[ -f "$SENDFILE" ]] || fail 'sendfile implementation is missing'

python3 - "$PLAN" "$SERVER_LIB" "$SENDFILE" <<'PYEOF'
import re
import sys
from pathlib import Path

plan = Path(sys.argv[1]).read_text()
server = Path(sys.argv[2]).read_text()
sendfile = Path(sys.argv[3]).read_text()

declaration = re.search(
    r"const SUPPORTED_KERNEL_TRANSFER_CAPS: TransportCaps = TransportCaps::([A-Z_]+);",
    plan,
)
if declaration is None:
    raise SystemExit("check_caps_have_impl: response planner has no explicit supported capability census")

advertised = declaration.group(1)
if advertised != "SENDFILE":
    raise SystemExit(f"check_caps_have_impl: advertised capability {advertised} has no reviewed implementation mapping")
if "try_into_file_region_for(SUPPORTED_KERNEL_TRANSFER_CAPS)" not in plan:
    raise SystemExit("check_caps_have_impl: response planning bypasses the supported capability census")
if "mod sendfile;" not in server:
    raise SystemExit("check_caps_have_impl: the server does not compile the sendfile backend")
if sendfile.count("nix::sys::sendfile::sendfile") != 2:
    raise SystemExit("check_caps_have_impl: a Linux or Apple sendfile implementation is missing")
PYEOF

printf 'OK: every advertised response kernel-transfer capability has a production implementation\n'
