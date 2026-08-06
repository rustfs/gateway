#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_planning_docs.sh
#
# WHAT THIS CHECKS
#   That no planning-type document is TRACKED by git. Two detectors:
#
#     1. Directory detector — anything under docs/notes/, docs/plans/,
#        docs/planning/, docs/superpowers/, docs/reports/, docs/analysis/,
#        docs/scratch/ or .agent-notes/.
#     2. Filename detector — Markdown files whose name reads like an agent
#        working note: PLAN.md, NOTES.md, TODO.md, ANALYSIS.md, REPORT.md,
#        SUMMARY.md, PROGRESS.md, STATUS.md, CHECKLIST.md, HANDOFF.md,
#        WORKLOG.md, SCRATCH.md, and the `<something>-plan.md` /
#        `<something>_NOTES.md` family. Matching is case-insensitive.
#
#   Durable documentation is unaffected: README.md, AGENTS.md, CHANGELOG.md,
#   docs/adr/**, docs/msrv.md and any other named, reviewed document pass.
#
# WHY
#   One-shot implementation plans, migration ledgers and agent-generated
#   working notes belong in the issue tracker — the GitHub issue is the single
#   source of truth for this project (rustfs/backlog#1723, and the same rule in
#   the rustfs/rustfs main repository under AGENTS.md "Sources of Truth").
#
#   .gitignore alone is not enough: `git add -f` walks straight through it.
#   This guard closes that hole — it inspects the git INDEX, so a file fails
#   the check no matter how it got there.
#
#   The reason this matters more than it looks: agent-written reports that can
#   land on disk accumulate. Six months later the repository holds a dozen
#   stale analyses that no one dares delete and every future agent reads as if
#   they were current. That is a correctness hazard, not just clutter.
#
# HOW TO EXEMPT
#   Add the exact repository-relative path to
#   `scripts/allowances/planning-doc-allowances.txt` (create it if absent):
#
#       docs/plans/example.md    # <why this one is durable, and who owns it>
#
#   Prefer renaming the document into a durable form (an ADR, a section of an
#   existing doc) over adding an allowance.
#
# USAGE
#   scripts/check_no_planning_docs.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_no_planning_docs.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ALLOWANCE_FILE="${SCRIPT_DIR}/allowances/planning-doc-allowances.txt"

cd "$ROOT_DIR"

PLANNING_DIRS=(
    'docs/notes/*'
    'docs/plans/*'
    'docs/planning/*'
    'docs/superpowers/*'
    'docs/reports/*'
    'docs/analysis/*'
    'docs/scratch/*'
    '.agent-notes/*'
)

# Case-insensitive basename patterns. Anchored, so `codegen-plan.md` matches
# but `deployment.md` does not.
PLANNING_NAME_RE='^(plan|plans|notes|todo|analysis|report|summary|progress|status|checklist|handoff|scratch|worklog|implementation[-_]plan|migration[-_]plan|.+[-_](plan|plans|notes|analysis|report|summary|progress|worklog|handoff))\.md$'

status=0

ALLOWANCES=""
if [[ -f "$ALLOWANCE_FILE" ]]; then
    while IFS= read -r line; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | tr -d ' \t')"
        [[ -z "$line" ]] && continue
        ALLOWANCES="${ALLOWANCES}${line}
"
    done <"$ALLOWANCE_FILE"
fi

is_allowed() {
    [[ -z "$ALLOWANCES" ]] && return 1
    printf '%s' "$ALLOWANCES" | grep -qxF "$1"
}

report() {
    local file="$1" reason="$2"
    if is_allowed "$file"; then
        return 0
    fi
    printf '%s: %s — planning-type documents must not be committed; keep it in the GitHub issue or a local worktree\n' \
        "$file" "$reason" >&2
    status=1
}

# Detector 1: whole directories reserved for throwaway material.
while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    report "$file" "lives in a planning/notes directory"
# `--cached --others --exclude-standard` rather than a bare `git ls-files`: the bare form lists
# only *tracked* files, so a brand-new file stays invisible to this guard right up until the
# moment `git add -A` commits it. That is how CJK text reached commit 343f044 past a guard run
# that had just reported success. `--exclude-standard` keeps ignored files out.
done < <(git ls-files --cached --others --exclude-standard -- "${PLANNING_DIRS[@]}" 2>/dev/null || true)

# Detector 2: filenames that read like an agent working note.
while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    base="$(basename "$file" | tr '[:upper:]' '[:lower:]')"
    if printf '%s' "$base" | grep -Eq "$PLANNING_NAME_RE"; then
        report "$file" "filename reads like a working note"
    fi
done < <(git ls-files --cached --others --exclude-standard -- ':(icase)*.md' 2>/dev/null || true)

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Remove the file(s) above with `git rm --cached` (or `git rm`).
The GitHub issue is the single source of truth for plans and analyses; only
durable, reviewed documentation belongs in the repository (README, AGENTS.md,
docs/adr/**). See rustfs/backlog#1723.
EOF
fi

exit "$status"
