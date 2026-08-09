#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_scaffold_on_main.sh
#
# WHAT THIS CHECKS
#   No file produced by `cargo xtask new-op` still carries the exact scaffold
#   marker. Both tracked and untracked files are inspected.
#
# WHY
#   rustfs/backlog#1743. A new operation is intentionally generated with a
#   `todo!()` and a red conformance case. The marker is the deterministic merge
#   fence that prevents that deliberately incomplete state from reaching main.
#
# HOW TO EXEMPT
#   Not applicable. Implement the operation and remove every scaffold artefact
#   before merging; an allowance would turn an intentionally red state green.
#
# USAGE
#   scripts/check_no_scaffold_on_main.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_no_scaffold_on_main.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

cd "$ROOT_DIR"

required='crates/core/src/ops/mod.rs'
if [[ ! -f "$required" ]]; then
    printf 'check_no_scaffold_on_main.sh: required input is missing: %s\n' "$required" >&2
    exit 1
fi

marker='SCAFFOLD: implement before merge'
status=0
files=0

while IFS= read -r file; do
    [[ -n "$file" && -f "$file" ]] || continue
    files=$((files + 1))
    while IFS= read -r hit; do
        [[ -n "$hit" ]] || continue
        printf 'check_no_scaffold_on_main.sh: %s:%s still contains the new-op scaffold marker\n' \
            "$file" "${hit%%:*}" >&2
        status=1
    done < <(grep -nF "$marker" "$file" 2>/dev/null || true)
done < <(git ls-files --cached --others --exclude-standard -- \
    'crates/core/src/ops/mod.rs' \
    'crates/core/src/ops/*.rs' \
    'crates/core/tests/scaffold_*.rs' \
    'conformance/cases/scaffold/*.toml' \
    'xtask/scaffolds/*.toml' 2>/dev/null || true)

if [[ "$files" -eq 0 ]]; then
    printf 'check_no_scaffold_on_main.sh: no guarded files found; refusing to skip a missing input\n' >&2
    exit 1
fi

if [[ "$status" -ne 0 ]]; then
    printf 'check_no_scaffold_on_main.sh: implement the scaffold and remove all marker-bearing artefacts before merge\n' >&2
    exit "$status"
fi

printf 'OK: no new-op scaffold markers remain\n'
