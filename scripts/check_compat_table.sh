#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_compat_table.sh
#
# WHAT THIS CHECKS
#   The compatibility table in README.md is exactly what `scripts/gen_compat_table.sh` renders from
#   `compat/matrix.json`.
#
# WHY
#   The table is the compatibility promise a reader actually sees. A hand-edited or stale table
#   claims coverage the manifest does not record, and nothing else in the repository would notice.
#   rustfs/backlog#1765 §4.4.
#
# HOW TO EXEMPT
#   There is no exemption. Run `scripts/gen_compat_table.sh` and commit the result.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/gen_compat_table.sh" --check
