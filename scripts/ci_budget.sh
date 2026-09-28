#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS DOES
#   Runs one CI command under its wall-clock budget, and reports the margin left over
#   every single time it runs — not only when it fails.
# WHY
#   rustfs/gateway#188 and #217 are the same failure twice. A suite grows with every
#   merge (AGENTS.md requires a mutation per new assertion, so case counts only ever go
#   up), the job's runtime creeps toward its hard `timeout`, and one day it crosses.
#   What CI then prints is `Process completed with exit code 124` after every case has
#   said `ok`. There is no failing assertion to read and nothing names the clock, so the
#   failure is attributed to whichever branch happened to be next through the gate:
#   #188 cost four pull requests a full cycle each and one author concluded their own
#   work was broken; #217 sat red on main across three merges while three separate
#   worktrees independently started fixing it.
#
#   The margin was shrinking for weeks before each cliff. Nobody saw it, because nothing
#   reported it. So the fix is not a bigger number, it is making the number visible:
#   every timed job says how much of its budget it used, warns while there is still room
#   to act, and an overrun says what actually happened instead of dying at 124.
# HOW TO USE
#   scripts/ci_budget.sh <seconds> <label> <command> [args...]
#
#   Always prints:  "<label> completed in <n>s of its <b>s budget (<p>%)"
#   At >= 80%:      a GitHub `::warning::` annotation, which surfaces on the pull-request
#                   checks UI rather than only in the fold of a log nobody opens.
#   On timeout:     a GitHub `::error::` annotation plus an explicit OUT OF TIME
#                   diagnosis naming the budget, and exit 124 is preserved.
#
#   A suite may ALSO watch its own clock and stop early with a per-case diagnosis, the
#   way scripts/test_guard_scripts.sh does. That is strictly better where it is possible,
#   because it names the case in flight. This wrapper is the outer layer: it costs one
#   line per job and it works for `cargo test` and other commands that will never
#   instrument themselves.
# HOW TO EXEMPT
#   There are no exemptions. scripts/check_ci_test_split.sh requires every timed command
#   in the jobs behind the `Test` aggregate to run through this wrapper, so a new job
#   cannot be added without a reported margin.

# Warn once the job has eaten this share of its budget. Deliberately well short of the
# cliff: the point is to be loud while the margin can still be recovered cheaply, not to
# confirm the crash after it happens.
CI_BUDGET_WARN_PERCENT="${GATEWAY_CI_BUDGET_WARN_PERCENT:-80}"

# ci_budget_verdict <elapsed> <budget> <warn-percent>
# Pure: the whole budget policy in one testable place, mirroring guard_budget_verdict in
# scripts/test_guard_scripts.sh. Kept separate from the reporting so the thresholds can be
# asserted without running a command or burning wall-clock in the self-test.
ci_budget_verdict() {
    local elapsed="$1" budget="$2" warn_percent="$3"
    if ((elapsed >= budget)); then
        printf 'over\n'
    elif ((elapsed * 100 >= budget * warn_percent)); then
        printf 'warn\n'
    else
        printf 'ok\n'
    fi
}

# Sourcing the script gets the pure helpers without running anything, which is what the
# self-test does. Executing it runs a command under budget.
if [[ "${BASH_SOURCE[0]:-}" != "${0:-}" ]]; then
    return 0
fi

if [[ "$#" -lt 3 ]]; then
    printf 'usage: ci_budget.sh <seconds> <label> <command> [args...]\n' >&2
    exit 2
fi

BUDGET_SECONDS="$1"
LABEL="$2"
shift 2

if [[ ! "$BUDGET_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
    printf 'ci_budget: budget must be a positive integer number of seconds, got %s\n' \
        "$BUDGET_SECONDS" >&2
    exit 2
fi
if [[ -z "$LABEL" ]]; then
    printf 'ci_budget: label must not be empty, or an overrun cannot name the job it came from\n' >&2
    exit 2
fi

# `timeout` is GNU coreutils. CI runners are Ubuntu, and scripts/ci_install_host_tools.sh
# installs coreutils when the image does not already have it. macOS, where these
# guards are also run by hand, generally does not. Degrading quietly to "no enforcement"
# would turn every budget into a check that cannot fail, so the degradation is allowed
# only off CI and it is announced. On CI a missing enforcer is a hard error.
TIMEOUT_COMMAND=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_COMMAND="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_COMMAND="gtimeout"
elif [[ -n "${CI:-}" ]]; then
    printf 'ci_budget: no timeout(1) available, so no budget could be enforced for %s.\n' \
        "$LABEL" >&2
    printf '  Refusing to report a margin this run did not actually measure.\n' >&2
    exit 2
else
    printf 'ci_budget: timeout(1) is unavailable, so %ss is measured but NOT enforced here.\n' \
        "$BUDGET_SECONDS" >&2
    printf '  Install coreutils for local enforcement; CI always enforces.\n' >&2
fi

started="$(date +%s)"
status=0
if [[ -n "$TIMEOUT_COMMAND" ]]; then
    "$TIMEOUT_COMMAND" "${BUDGET_SECONDS}s" "$@" || status=$?
else
    "$@" || status=$?
fi
elapsed="$(($(date +%s) - started))"
percent=$((elapsed * 100 / BUDGET_SECONDS))
verdict="$(ci_budget_verdict "$elapsed" "$BUDGET_SECONDS" "$CI_BUDGET_WARN_PERCENT")"

# `timeout` reports 124 when it had to kill the command. That is the opaque failure this
# whole script exists to explain, so it is answered before the ordinary reporting.
if [[ "$status" -eq 124 ]]; then
    printf '::error title=CI budget exhausted::%s ran out of time: %ss of a %ss budget. No assertion failed — the job no longer fits its CI slice.\n' \
        "$LABEL" "$elapsed" "$BUDGET_SECONDS"
    printf '\n' >&2
    printf 'ci_budget: OUT OF TIME — no assertion in this job failed.\n' >&2
    printf '  %s reached %ss of its %ss budget and was stopped.\n' \
        "$LABEL" "$elapsed" "$BUDGET_SECONDS" >&2
    printf '  This is almost certainly NOT a defect in the change under test. Check whether\n' >&2
    printf '  this job is red on main before assuming your branch caused it.\n' >&2
    printf '  Fix it by making the work faster or by splitting it across runners, never by\n' >&2
    printf '  deleting, skipping or sampling checks to fit the clock. scripts/check_ci_time_gate.sh\n' >&2
    printf '  caps every dependency path at ten minutes, so raising the number is usually not\n' >&2
    printf '  even available. See scripts/ci_budget.sh and rustfs/gateway#217.\n' >&2
    exit 124
fi

printf '%s completed in %ss of its %ss budget (%s%%)\n' \
    "$LABEL" "$elapsed" "$BUDGET_SECONDS" "$percent"

if [[ "$verdict" == warn ]]; then
    printf '::warning title=CI budget margin::%s used %s%% of its %ss budget (%ss, %ss left). It is on course to start failing at exit 124 on an unrelated branch. See scripts/ci_budget.sh.\n' \
        "$LABEL" "$percent" "$BUDGET_SECONDS" "$elapsed" "$((BUDGET_SECONDS - elapsed))"
    printf 'WARNING: %s has only %ss of its %ss CI budget left. The next cases added to it\n' \
        "$LABEL" "$((BUDGET_SECONDS - elapsed))" "$BUDGET_SECONDS" >&2
    printf '  are the ones that will tip it into an opaque exit 124 on somebody else'"'"'s branch.\n' >&2
fi

exit "$status"
