#!/usr/bin/env bash
set -euo pipefail

# Reject compile-time Handler bundles. Missing-operation completeness belongs to the registry's
# one-line runtime `require(OperationSet)` diagnostic; a supertrait reports one bound error per
# operation and is not dyn compatible.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
SCANNER="${SCRIPT_DIR}/trait_policy_scan.py"

fail() {
    printf 'check_no_bundle_trait: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
[[ -f "$SCANNER" ]] || fail 'required scanner is missing: scripts/trait_policy_scan.py'
python3 "$SCANNER" "$ROOT_DIR" no-bundle
