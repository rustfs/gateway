#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   A scoped AGENTS.md cannot appear before it has five crate-only rules and the duplicate checker
#   required by the root governance file.
# WHY
#   rustfs/backlog#1742 records the failure mode where agents read only the nearest rule file.
# HOW TO EXEMPT
#   Meet the documented trigger: at least five bullet rules and scripts/check_agents_no_dup.sh.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
failures=0

while IFS= read -r file; do
    rules=$(grep -Ec '^[[:space:]]*-[[:space:]]+' "$file" || true)
    if (( rules < 5 )) || [[ ! -x "$ROOT/scripts/check_agents_no_dup.sh" ]]; then
        printf 'check_agents_layering: %s appears before the five-rule layering trigger\n' "${file#"$ROOT"/}" >&2
        failures=$((failures + 1))
    fi
done < <(find "$ROOT" \
    -path "$ROOT/.git" -prune -o \
    -path "$ROOT/target" -prune -o \
    -path "$ROOT/generated" -prune -o \
    -type f -name AGENTS.md ! -path "$ROOT/AGENTS.md" -print)

if (( failures > 0 )); then
    exit 1
fi
printf 'OK: AGENTS.md remains unlayered until the documented trigger\n'
