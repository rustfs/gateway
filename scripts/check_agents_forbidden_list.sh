#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   Each context-budget prohibition in AGENTS.md has both a reason and a safe alternative.
# WHY
#   rustfs/backlog#1742 requires usable routing guidance, not unexplained prohibitions.
# HOW TO EXEMPT
#   There is no exemption. Preserve all three rows and fill both explanatory columns.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
agents="$ROOT/AGENTS.md"
failures=0
count=0

for subject in 'generated/**' 'model/s3.json' 'Cargo.lock'; do
    line=$(awk -F '|' -v subject="\`$subject\`" 'NF >= 5 && index($2, subject) { print; exit }' "$agents")
    if [[ -z "$line" ]]; then
        printf 'check_agents_forbidden_list: missing %s\n' "$subject" >&2
        failures=$((failures + 1))
        continue
    fi
    IFS='|' read -r _ path reason alternative _ <<<"$line"
    reason=${reason//[[:space:]]/}
    alternative=${alternative//[[:space:]]/}
    if [[ -z "$reason" || -z "$alternative" || "$alternative" == "none" ]]; then
        printf 'check_agents_forbidden_list: %s needs a reason and alternative\n' "$subject" >&2
        failures=$((failures + 1))
    else
        count=$((count + 1))
    fi
done

if (( failures > 0 )); then
    exit 1
fi
printf 'OK: %s/3 forbidden entries have a reason and alternative\n' "$count"
