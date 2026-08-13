#!/usr/bin/env bash
set -euo pipefail

# WHAT: Keep the root AGENTS task-start budget at no more than 8 files and 40k tokens.
# WHY:  rustfs/backlog#1714 makes bounded context a condition for starting a task.
# HOW TO EXEMPT: There are no exemptions; split a task whose required inputs exceed the budget.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
AGENTS="$REPO_ROOT/AGENTS.md"

if [[ ! -f "$AGENTS" ]]; then
    printf 'check_agents_context_contract: required input is missing: AGENTS.md\n' >&2
    exit 1
fi

if ! grep -Fq '**≤8 files / ≤40k tokens**' "$AGENTS"; then
    printf 'check_agents_context_contract: AGENTS.md lost the ≤8 files / ≤40k tokens task-start budget\n' >&2
    exit 1
fi

printf 'OK: AGENTS.md keeps the ≤8 files / ≤40k tokens task-start budget\n'
