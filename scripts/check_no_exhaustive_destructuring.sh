#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_exhaustive_destructuring.sh
#
# WHAT THIS CHECKS
#   That no hand-written code destructures a generated dto without a trailing
#   `..` — that is, `let Foo { a, b } = x;` rather than `let Foo { a, b, .. } = x;`.
#
# WHY
#   Exhaustive destructuring is the one pattern that a new field breaks, and it
#   is the reason dto structs cannot simply grow. AWS adds fields to the S3 model
#   every quarter; each one would turn into a compile error at every such site,
#   for no benefit, since these sites want two fields out of forty.
#
#   This is the counterpart to check_no_dto_non_exhaustive.sh. That guard keeps
#   construction additive; this one keeps consumption additive. Together they are
#   what makes "a new optional field is a minor change" true rather than aspirational.
#
#   See ADR-0004 rule P3.
#
# HOW TO EXEMPT
#   There is no allowance. Supersede ADR-0004 and change this guard in the same
#   reviewed change; a path-and-line text file must not silently weaken P3.
#
# USAGE
#   scripts/check_no_exhaustive_destructuring.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_no_exhaustive_destructuring.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
HELPER="${SCRIPT_DIR}/lib/rust_semver_surface.py"

fail() {
    printf 'check_no_exhaustive_destructuring: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
[[ -f "$HELPER" ]] || fail 'required parser is missing: scripts/lib/rust_semver_surface.py'

python3 "$HELPER" destructuring "$ROOT_DIR"
