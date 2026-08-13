#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_dto_non_exhaustive.sh
#
# WHAT THIS CHECKS
#   That no generated dto struct carries `#[non_exhaustive]`.
#
# WHY
#   The intuitive answer — "mark them non_exhaustive so adding a field is not a
#   breaking change" — is wrong here, and measurably so. `#[non_exhaustive]`
#   forbids functional update syntax as well as full literals:
#
#       error[E0639]: cannot create non-exhaustive struct using struct expression
#
#   so `Foo { a, ..Default::default() }` stops compiling. rustfs has 4619 such
#   sites. Meanwhile a plain struct with `#[derive(Default)]` is *already*
#   immune to a new `Option` field, because FRU fills it in. The attribute buys
#   nothing and costs every construction site.
#
#   Real enums are the opposite case: downstream matches on them rather than
#   constructing them, so `#[non_exhaustive]` there is correct and this guard
#   deliberately does not look at them.
#
#   See ADR-0004 rules P1 and P5.
#
# HOW TO EXEMPT
#   There is no exemption. A dto that needs `#[non_exhaustive]` is a dto that
#   should not be a struct; take it to an ADR.
#
# USAGE
#   scripts/check_no_dto_non_exhaustive.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_no_dto_non_exhaustive.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
HELPER="${SCRIPT_DIR}/lib/rust_semver_surface.py"

fail() {
    printf 'check_no_dto_non_exhaustive: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
[[ -f "$HELPER" ]] || fail 'required parser is missing: scripts/lib/rust_semver_surface.py'

python3 "$HELPER" non-exhaustive "$ROOT_DIR"
