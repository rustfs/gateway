#!/usr/bin/env bash
set -euo pipefail

# ADR-0002 keeps extension traits dyn compatible: only the exact core `Operation` and `Handler`
# authorities may use AFIT/RPITIT. Every other trait must spell asynchronous work as BoxFuture.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
SCANNER="${SCRIPT_DIR}/trait_policy_scan.py"

fail() {
    printf 'check_dyn_policy: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
[[ -f "$SCANNER" ]] || fail 'required scanner is missing: scripts/trait_policy_scan.py'
python3 "$SCANNER" "$ROOT_DIR" dyn-policy
