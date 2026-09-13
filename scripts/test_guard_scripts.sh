#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# test_guard_scripts.sh
#
# WHAT THIS CHECKS
#   That every guard in `scripts/check_*.sh` (a) passes on the repository as it
#   stands, and (b) actually FAILS when the violation it exists to catch is
#   introduced. Each negative case is run against a throwaway copy of the
#   repository in a temporary directory via `GATEWAY_CHECK_ROOT`; the working
#   tree is never modified.
#
# WHY
#   A guard that cannot fail is worse than no guard: it produces a green check
#   mark that everyone trusts. Every one of these scripts is a few dozen lines
#   of shell and awk, and a typo in a regex turns it into a no-op silently.
#   The negative cases are the only evidence that the guards do anything.
#
# HOW TO EXEMPT
#   Not applicable — this is the test, not a policy guard.
#
# USAGE
#   scripts/test_guard_scripts.sh
#
#   GATEWAY_GUARD_JOBS=<n>              run this group's cases across n worker
#                                       processes (default: the core count, capped
#                                       at 8)
#   GATEWAY_GUARD_SHARD_GROUPS=<n>      how many CI runners the suite is split over
#   GATEWAY_GUARD_SHARD_GROUP=<i>       which of them this run is (0-based)
#   GATEWAY_GUARD_BUDGET_SECONDS=<n>    wall-clock budget; the suite stops itself with
#                                       a diagnosis 30s before it, rather than being
#                                       killed by the CI `timeout` wrapper. The reserve
#                                       is flat, so anything under 120s is refused
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

failures=0
cases=0
QUIRK_LEDGER_ONLY="${GATEWAY_GUARD_QUIRK_LEDGER_ONLY:-0}"
if [[ "$QUIRK_LEDGER_ONLY" != 0 && "$QUIRK_LEDGER_ONLY" != 1 ]]; then
    printf 'test_guard_scripts: GATEWAY_GUARD_QUIRK_LEDGER_ONLY must be 0 or 1\n' >&2
    exit 1
fi
DTO_COMPILER_ONLY="${GATEWAY_GUARD_DTO_COMPILER_ONLY:-0}"
if [[ "$DTO_COMPILER_ONLY" != 0 && "$DTO_COMPILER_ONLY" != 1 ]]; then
    printf 'test_guard_scripts: GATEWAY_GUARD_DTO_COMPILER_ONLY must be 0 or 1\n' >&2
    exit 1
fi
BUILD_GUARDS_ONLY="${GATEWAY_GUARD_BUILD_GUARDS_ONLY:-0}"
if [[ "$BUILD_GUARDS_ONLY" != 0 && "$BUILD_GUARDS_ONLY" != 1 ]]; then
    printf 'test_guard_scripts: GATEWAY_GUARD_BUILD_GUARDS_ONLY must be 0 or 1\n' >&2
    exit 1
fi
ERROR_STATUS_ONLY="${GATEWAY_GUARD_ERROR_STATUS_ONLY:-0}"
if [[ "$ERROR_STATUS_ONLY" != 0 && "$ERROR_STATUS_ONLY" != 1 ]]; then
    printf 'test_guard_scripts: GATEWAY_GUARD_ERROR_STATUS_ONLY must be 0 or 1\n' >&2
    exit 1
fi
if [[ $((QUIRK_LEDGER_ONLY + DTO_COMPILER_ONLY + BUILD_GUARDS_ONLY + ERROR_STATUS_ONLY)) -gt 1 ]]; then
    printf 'test_guard_scripts: mutation-only modes are mutually exclusive\n' >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# Wall-clock budget
#
# CI runs each guard shard under `timeout 300s` and hands it the same number in
# GATEWAY_GUARD_BUDGET_SECONDS (.github/workflows/ci.yml, pinned by
# scripts/check_ci_test_split.sh, which also fails if the two ever disagree, and now
# fails for every mode rather than only the sharded ones: the DTO-compiler and
# error-status jobs escaped that check for months and ran with no declared budget at
# all, defending 480s while CI enforced 90s and 60s). The
# 300s and the jobs' `timeout-minutes: 6` sit inside the ten-minute whole-gate
# budget in AGENTS.md: a guard runner plus the one-minute Test aggregate is the
# longest path at seven minutes, and the runner keeps the rest for checkout and
# toolchain setup. The default below is for running the suite by hand.
#
# The first time the suite outgrew its slice, the only symptom was
# `Process completed with exit code 124` after every printed case had said `ok`.
# Three separate pull requests were read as broken by their own authors before
# anyone noticed the suite had simply run out of time. An opaque kill is the
# worst possible failure for a self-test, so the suite now watches its own clock
# and stops with an explicit diagnosis before `timeout` can reach it.
# -----------------------------------------------------------------------------
GUARD_BUDGET_SECONDS="${GATEWAY_GUARD_BUDGET_SECONDS:-480}"
if [[ ! "$GUARD_BUDGET_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
    printf 'test_guard_scripts: GATEWAY_GUARD_BUDGET_SECONDS must be a positive integer\n' >&2
    exit 1
fi
# Stop with thirty seconds to spare: enough for the case in flight to finish and
# for the diagnosis to reach the log before `timeout` sends its signal.
GUARD_BUDGET_RESERVE_SECONDS=30
# The reserve is a flat number of seconds, not a fraction of the budget, so a small budget spends
# most of its clock on it: at the 60s the quirk-ledger shards used to be given, the suite had 30s
# of working time and stopped itself in runs 33641327259 and 33646920592 with every case still
# printing ok. Sharding cannot fix that — the reserve does not shrink when the shards do — so a
# budget that small is refused here instead of being quietly halved. Four times the reserve is the
# floor: below it the diagnosis costs more than a quarter of what the job was given.
GUARD_BUDGET_FLOOR=$((GUARD_BUDGET_RESERVE_SECONDS * 4))
if ((GUARD_BUDGET_SECONDS < GUARD_BUDGET_FLOOR)); then
    printf 'test_guard_scripts: a %ss budget keeps only %ss of working time, because the stop\n' \
        "$GUARD_BUDGET_SECONDS" "$((GUARD_BUDGET_SECONDS - GUARD_BUDGET_RESERVE_SECONDS))" >&2
    printf '  reserve is a flat %ss. Give it at least %ss, or the suite spends more than a quarter\n' \
        "$GUARD_BUDGET_RESERVE_SECONDS" "$GUARD_BUDGET_FLOOR" >&2
    printf '  of its clock on the reserve and stops itself while every case is still printing ok.\n' >&2
    exit 1
fi
GUARD_BUDGET_STOP=$((GUARD_BUDGET_SECONDS - GUARD_BUDGET_RESERVE_SECONDS))
# Say so out loud well before that, so an overrun is visible one pull request
# early rather than on the pull request that crosses the line.
GUARD_BUDGET_WARN=$((GUARD_BUDGET_SECONDS * 4 / 5))

# Reset SECONDS to measure elapsed time from this point, not from when the
# parent shell started. Without this, inheriting SECONDS from the environment
# (e.g., SECONDS=582) causes guard_case_owned to immediately report OUT OF TIME.
SECONDS=0

# guard_budget_verdict <elapsed> <stop> <warn>
# Pure: the whole budget policy in one testable place.
guard_budget_verdict() {
    local elapsed="$1" stop="$2" warn="$3"
    if ((elapsed >= stop)); then
        printf 'stop\n'
    elif ((elapsed >= warn)); then
        printf 'warn\n'
    else
        printf 'ok\n'
    fi
}

# -----------------------------------------------------------------------------
# Case shards
#
# The suite grows with every merge — that is AGENTS.md's mutation rule working as
# intended — and each case is a short burst of forks (git, grep, python3, ruby)
# against a sandbox. So it parallelises across processes far better than it can be
# micro-optimised case by case, and it is split twice:
#
#   * across CI runners, by GATEWAY_GUARD_SHARD_GROUPS / GATEWAY_GUARD_SHARD_GROUP.
#     .github/workflows/ci.yml runs one `Guard self-test <i>/<n>` job per group.
#   * across processes inside one runner, by GATEWAY_GUARD_JOBS. The parent process
#     runs no cases at all: it re-executes this script once per worker.
#
# A case ordinal is assigned to exactly one (group, worker) pair by arithmetic on
# the ordinal alone, so the two levels compose without a scheduler and without any
# shared state between runners.
#
# Two things the previous authors optimised must survive that, and both do
# because a shard is a *process*, not a thread:
#
#   * One sandbox, reused, mutated by one mutator at a time. Every shard makes
#     its own sandbox under its own private TMPDIR, so the single-mutator
#     assumption inside `make_sandbox` / `stage_sandbox_changes` /
#     `reset_sandbox_changes` holds exactly as it did when the suite was serial.
#     `shard_sandbox_isolation_contract` proves it in both directions.
#   * One shared CARGO_TARGET_DIR. It stays shared, because giving each shard its
#     own would cold-compile the workspace per shard, which is the cost the
#     sharing was introduced to remove. That is sound inside one runner because
#     cargo takes an exclusive lock on the target directory for the duration of a
#     build, so concurrent invocations serialise rather than interleave. The
#     build-backed mode stays single-process per runner, but may stride its cases
#     over isolated CI runners through GATEWAY_GUARD_SHARD_GROUPS. Other
#     mode-scoped runs stay single-process on one runner. `guard_shard_plan` and
#     its cases pin the process-level scoping.
#
# Coverage is not taken on trust, and it survives being split over runners that
# never see each other. Every worker counts every case it *considers*, whether or
# not it owns it, and records the ordinal of every case it *executes*. Each group's
# parent then proves that its workers executed **exactly** the ordinal set the
# arithmetic assigns to that group — no hole, no duplicate, nothing outside it —
# against a case total every worker agreed on. The groups partition 1..total by
# construction, so the whole suite is covered when every group's job is green, and
# the `test` aggregate requires all of them. A worker that died early leaves a
# hole; a case site that never learned about the gate leaves a duplicate; a group
# that drifted out of step reports a different total. All three fail loudly, so the
# split suite cannot quietly run fewer cases than the serial one did.
# -----------------------------------------------------------------------------
GUARD_SELF="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"
GUARD_SHARD_INDEX="${GATEWAY_GUARD_SHARD_INDEX:-}"
GUARD_SHARD_COUNT="${GATEWAY_GUARD_SHARD_COUNT:-}"
GUARD_SHARD_GROUPS="${GATEWAY_GUARD_SHARD_GROUPS:-1}"
GUARD_SHARD_GROUP="${GATEWAY_GUARD_SHARD_GROUP:-0}"
if [[ ! "$GUARD_SHARD_GROUPS" =~ ^[1-9][0-9]*$ ]]; then
    printf 'test_guard_scripts: GATEWAY_GUARD_SHARD_GROUPS must be a positive integer\n' >&2
    exit 1
fi
if [[ ! "$GUARD_SHARD_GROUP" =~ ^(0|[1-9][0-9]*)$ ]] ||
    ((GUARD_SHARD_GROUP >= GUARD_SHARD_GROUPS)); then
    printf 'test_guard_scripts: GATEWAY_GUARD_SHARD_GROUP must be in 0..%s\n' \
        "$((GUARD_SHARD_GROUPS - 1))" >&2
    exit 1
fi
GUARD_SHARD_LEDGER="${GATEWAY_GUARD_SHARD_LEDGER:-}"
GUARD_SHARD_SUMMARY="${GATEWAY_GUARD_SHARD_SUMMARY:-}"
GUARD_EXECUTED=0

guard_budget_stop() {
    local ordinal="$1" where='this run'
    [[ -z "$GUARD_SHARD_COUNT" ]] ||
        where="group $((GUARD_SHARD_GROUP + 1))/${GUARD_SHARD_GROUPS} worker $((GUARD_SHARD_INDEX + 1))/${GUARD_SHARD_COUNT}"
    printf '\n' >&2
    printf 'test_guard_scripts: OUT OF TIME — no assertion in this suite failed.\n' >&2
    printf '  %s reached %ss of its %ss budget at case %s and stopped itself.\n' \
        "$where" "$SECONDS" "$GUARD_BUDGET_SECONDS" "$ordinal" >&2
    printf '  This is not a defect in the change under test. The suite no longer fits\n' >&2
    printf '  the CI slice it is given, which is a gate failing for a reason having\n' >&2
    printf '  nothing to do with what it checks.\n' >&2
    printf '  Fix it by making cases faster or by raising GATEWAY_GUARD_JOBS, never by\n' >&2
    printf '  deleting, skipping or sampling cases. See the budget note at the top of\n' >&2
    printf '  scripts/test_guard_scripts.sh.\n' >&2
    exit 2
}

# guard_group_of <ordinal> <groups>
# Pure: which CI runner owns a case. Runners take every groups-th ordinal rather
# than a contiguous block, because the cases for one guard are written consecutively
# and the costs are very uneven — one guard is 30% of the whole suite. Blocking
# would drop that guard on one or two runners and make them the slow ones; striding
# spreads every guard evenly. Measured: blocked, the four runners came in at 100s,
# 95s, 160s and 180s for the same 240 cases each.
guard_group_of() {
    printf '%s\n' "$((($1 - 1) % $2))"
}

# json_string <text>
# Encodes text as a single-line JSON string, which is what `toJSON()` puts in
# GATEWAY_PR_BODY_JSON in .github/workflows/ci.yml. The pull-request body is exported
# encoded so that no line of it can start a CI log line and be read as a workflow command
# (rustfs/gateway#224), and the guards that consume it decode it and reject anything that
# still carries a raw newline. The suite therefore has to hand them the shape CI does.
json_string() {
    local text="$1"
    text="${text//\\/\\\\}"
    text="${text//\"/\\\"}"
    text="${text//$'\r'/\\r}"
    text="${text//$'\t'/\\t}"
    text="${text//$'\n'/\\n}"
    printf '"%s"' "$text"
}

# guard_worker_of <ordinal> <groups> <workers>
# Pure: which worker process inside the owning runner runs the case, striding for
# the same reason. Both are functions of the ordinal alone, which is what lets
# runners that never talk to each other partition the suite exactly.
guard_worker_of() {
    printf '%s\n' "$(((($1 - 1) / $2) % $3))"
}

# guard_case_owned <ordinal>
# Called once per case, immediately after the case counter is advanced. Returns
# non-zero when another shard owns the case, so the caller skips it; every worker
# still counts it, which is what makes the group's coverage proof possible.
guard_case_owned() {
    local ordinal="$1"
    if ((SECONDS >= GUARD_BUDGET_STOP)); then
        guard_budget_stop "$ordinal"
    fi
    if [[ -n "$GUARD_SHARD_COUNT" ]]; then
        if (($(guard_group_of "$ordinal" "$GUARD_SHARD_GROUPS") != GUARD_SHARD_GROUP)); then
            return 1
        fi
        if (($(guard_worker_of "$ordinal" "$GUARD_SHARD_GROUPS" "$GUARD_SHARD_COUNT") !=
            GUARD_SHARD_INDEX)); then
            return 1
        fi
    fi
    GUARD_EXECUTED=$((GUARD_EXECUTED + 1))
    if [[ -n "$GUARD_SHARD_LEDGER" ]]; then
        printf '%s\n' "$ordinal" >>"$GUARD_SHARD_LEDGER"
    fi
    return 0
}

# guard_shard_plan <requested> <quirk-only> <dto-only> <build-only> <error-status-only>
# Pure: how many worker processes a run gets. The mode-scoped runs are already
# minutes-scale, and the build-guard mode is the one whose cases compile, so it
# must keep one CARGO_TARGET_DIR per runner. All four stay single-process; CI may
# still partition a mode across isolated runners with the group variables.
guard_shard_plan() {
    local requested="$1" quirk="$2" dto="$3" build="$4" error_status="${5:-0}"
    if ((quirk + dto + build + error_status > 0)); then
        printf '1\n'
        return 0
    fi
    ((requested >= 1)) || requested=1
    printf '%s\n' "$requested"
}

guard_detect_jobs() {
    local cores=""
    if command -v nproc >/dev/null 2>&1; then
        cores="$(nproc 2>/dev/null || true)"
    elif command -v sysctl >/dev/null 2>&1; then
        cores="$(sysctl -n hw.ncpu 2>/dev/null || true)"
    fi
    [[ "$cores" =~ ^[1-9][0-9]*$ ]] || cores=1
    # One worker per core, not more. Each worker builds its own sandbox — a copy of
    # the whole tree plus a fresh Git index — which on a two-core hosted runner is
    # tens of seconds, so an extra worker beyond the core count adds more setup than
    # the cases it takes away. GATEWAY_GUARD_JOBS overrides it, and every run prints
    # its elapsed time, so the choice stays reviewable against real numbers.
    local jobs="$cores"
    ((jobs <= 8)) || jobs=8
    printf '%s\n' "$jobs"
}

# guard_shard_ledger_report <considered> <groups> <group> <ledger>...
# The coverage proof for one group. Prints one line per defect and returns non-zero
# unless this group's workers together executed exactly the ordinals the shard
# arithmetic assigns to this group — every one of them, once each, and nothing
# else. Every group asserting that about the same total is what makes the union
# over groups exactly 1..considered.
guard_shard_ledger_report() {
    local considered="$1" groups="$2" group="$3"
    shift 3
    python3 - "$considered" "$groups" "$group" "$@" <<'PYEOF'
import sys
from pathlib import Path

considered = int(sys.argv[1])
groups = int(sys.argv[2])
group = int(sys.argv[3])
seen: dict[int, int] = {}
for name in sys.argv[4:]:
    path = Path(name)
    if not path.exists():
        print(f"shard ledger is missing: {name}")
        raise SystemExit(1)
    for token in path.read_text().split():
        ordinal = int(token)
        seen[ordinal] = seen.get(ordinal, 0) + 1

expected = {n for n in range(1, considered + 1) if (n - 1) % groups == group}
missing = sorted(expected - set(seen))
duplicated = sorted(n for n, count in seen.items() if count > 1)
unknown = sorted(n for n in seen if n not in expected)


def sample(values: list[int]) -> str:
    head = ", ".join(str(value) for value in values[:10])
    return head + (f", ... ({len(values)} total)" if len(values) > 10 else "")


status = 0
if missing:
    print(
        f"group {group + 1}/{groups} coverage is incomplete: {len(missing)} of its "
        f"{len(expected)} case(s) ran in no worker: {sample(missing)}"
    )
    status = 1
if duplicated:
    print(
        f"group {group + 1}/{groups} coverage overlaps: {len(duplicated)} case(s) ran in "
        f"more than one worker, so a case site is missing its guard_case_owned gate: "
        f"{sample(duplicated)}"
    )
    status = 1
if unknown:
    print(
        f"group {group + 1}/{groups} ran {len(unknown)} case(s) that belong to another "
        f"group or to no case at all: {sample(unknown)}"
    )
    status = 1
if status == 0:
    print(
        f"group {group + 1}/{groups} coverage complete: {len(expected)} of {considered} "
        f"case(s), each executed exactly once"
    )
raise SystemExit(status)
PYEOF
}

guard_print_elapsed() {
    local verdict remaining
    verdict="$(guard_budget_verdict "$SECONDS" "$GUARD_BUDGET_STOP" "$GUARD_BUDGET_WARN")"
    printf '%ss elapsed of the %ss CI budget\n' "$SECONDS" "$GUARD_BUDGET_SECONDS"
    if [[ "$verdict" != ok ]]; then
        remaining=$((GUARD_BUDGET_SECONDS - SECONDS))
        printf 'WARNING: the guard self-test has %ss of its CI budget left. The next cases added to\n' \
            "$remaining" >&2
        printf 'WARNING: it will turn the guard-self-test job red for a reason having nothing to do\n' >&2
        printf 'WARNING: with what it checks. Make cases faster or raise GATEWAY_GUARD_JOBS.\n' >&2
    fi
}

run_guard_shards() {
    local jobs="$1"
    local workdir index rc status=0 considered="" summary recorded=0
    local total_failures=0 total_executed=0
    local pids=() codes=()
    local shard_considered shard_executed shard_failures
    workdir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-shards.XXXXXX")"
    printf 'Guard self-test: group %s/%s, %s worker(s), %ss budget\n' \
        "$((GUARD_SHARD_GROUP + 1))" "$GUARD_SHARD_GROUPS" "$jobs" "$GUARD_BUDGET_SECONDS"
    for ((index = 0; index < jobs; index++)); do
        mkdir -p "${workdir}/tmp-${index}"
        : >"${workdir}/ledger-${index}"
        env \
            GATEWAY_GUARD_SHARD_INDEX="$index" \
            GATEWAY_GUARD_SHARD_COUNT="$jobs" \
            GATEWAY_GUARD_SHARD_GROUPS="$GUARD_SHARD_GROUPS" \
            GATEWAY_GUARD_SHARD_GROUP="$GUARD_SHARD_GROUP" \
            GATEWAY_GUARD_SHARD_LEDGER="${workdir}/ledger-${index}" \
            GATEWAY_GUARD_SHARD_SUMMARY="${workdir}/summary-${index}" \
            GATEWAY_GUARD_BUDGET_SECONDS="$GUARD_BUDGET_SECONDS" \
            TMPDIR="${workdir}/tmp-${index}" \
            bash "$GUARD_SELF" >"${workdir}/out-${index}" 2>&1 &
        pids[index]=$!
    done
    for ((index = 0; index < jobs; index++)); do
        rc=0
        wait "${pids[index]}" || rc=$?
        codes[index]=$rc
    done
    for ((index = 0; index < jobs; index++)); do
        printf '\n===== group %s/%s worker %s/%s (exit %s) =====\n' \
            "$((GUARD_SHARD_GROUP + 1))" "$GUARD_SHARD_GROUPS" "$((index + 1))" "$jobs" "${codes[index]}"
        cat "${workdir}/out-${index}"
        summary="${workdir}/summary-${index}"
        if [[ ! -f "$summary" ]]; then
            printf 'test_guard_scripts: worker %s/%s ended without a summary, so its cases did not all run\n' \
                "$((index + 1))" "$jobs" >&2
            status=1
            continue
        fi
        read -r shard_considered shard_executed shard_failures <"$summary"
        if [[ -z "$considered" ]]; then
            considered="$shard_considered"
        elif [[ "$shard_considered" != "$considered" ]]; then
            printf 'test_guard_scripts: workers disagree on the case list (%s vs %s); the suite is not deterministic\n' \
                "$considered" "$shard_considered" >&2
            status=1
        fi
        total_executed=$((total_executed + shard_executed))
        total_failures=$((total_failures + shard_failures))
        ((codes[index] <= 1)) || status=1
    done
    printf '\n'
    if [[ -n "$considered" ]]; then
        guard_shard_ledger_report "$considered" "$GUARD_SHARD_GROUPS" "$GUARD_SHARD_GROUP" \
            "${workdir}"/ledger-* || status=1
        # Independent of the ledger contents: what the workers counted themselves must
        # equal what they recorded, so a worker cannot report cases it never wrote down.
        recorded="$(cat "${workdir}"/ledger-* | wc -l | tr -d ' ')"
        if ((total_executed != recorded)); then
            printf 'test_guard_scripts: workers counted %s executed case(s) but recorded %s\n' \
                "$total_executed" "$recorded" >&2
            status=1
        fi
    else
        printf 'test_guard_scripts: no worker reported a case list\n' >&2
        status=1
    fi
    printf '\n%s of %s case(s) in group %s/%s, %s failure(s)\n' \
        "$total_executed" "${considered:-0}" "$((GUARD_SHARD_GROUP + 1))" "$GUARD_SHARD_GROUPS" \
        "$total_failures"
    guard_print_elapsed
    rm -rf "$workdir" || true
    ((total_failures == 0)) || status=1
    return "$status"
}

guard_finish() {
    if [[ -n "$GUARD_SHARD_SUMMARY" ]]; then
        printf '%s %s %s\n' "$cases" "$GUARD_EXECUTED" "$failures" >"$GUARD_SHARD_SUMMARY"
        printf '\n%s of %s case(s) in this worker, %s failure(s)\n' \
            "$GUARD_EXECUTED" "$cases" "$failures"
    else
        printf '\n%s case(s), %s failure(s)\n' "$cases" "$failures"
        guard_print_elapsed
    fi
    [[ "$failures" -eq 0 ]]
}

if [[ -z "$GUARD_SHARD_COUNT" ]]; then
    GUARD_JOBS="${GATEWAY_GUARD_JOBS:-$(guard_detect_jobs)}"
    if [[ ! "$GUARD_JOBS" =~ ^[1-9][0-9]*$ ]]; then
        printf 'test_guard_scripts: GATEWAY_GUARD_JOBS must be a positive integer\n' >&2
        exit 1
    fi
    GUARD_JOBS="$(guard_shard_plan \
        "$GUARD_JOBS" "$QUIRK_LEDGER_ONLY" "$DTO_COMPILER_ONLY" "$BUILD_GUARDS_ONLY" \
        "$ERROR_STATUS_ONLY")"
    # One worker is still a shard when the suite is split over runners: the group
    # filter and the coverage proof both live in run_guard_shards, so a single-worker
    # group must go through it rather than quietly running every other group's cases.
    if ((GUARD_JOBS > 1 || GUARD_SHARD_GROUPS > 1)); then
        GUARD_SHARDS_RC=0
        run_guard_shards "$GUARD_JOBS" || GUARD_SHARDS_RC=$?
        exit "$GUARD_SHARDS_RC"
    fi
fi

pass_msg() { printf '  ok   %s\n' "$*"; }
fail_msg() {
    printf '  FAIL %s\n' "$*" >&2
    failures=$((failures + 1))
}

# One sandbox, reused. Each negative case mutates it, the guard runs, and only the paths
# changed by that case are checked out before untracked files are cleaned. Checking out
# the whole tree for every case made the reset cost grow with the repository rather than
# with the mutation and pushed the suite past the ten-minute CI budget.
SANDBOX=""
SANDBOX_RESET_TRACKED=""
SANDBOX_RESET_UNTRACKED=""
SANDBOX_RESET_READY=0
QUIRK_LEDGER_PARSE_CACHE=""
CT_EQ_SANDBOX=""
SEMVER_SANDBOX=""
SANDBOX_BASE=""

literalize_nul_paths() {
    local input="$1" output="$2" path
    : >"$output"
    while IFS= read -r -d '' path; do
        printf ':(literal)%s\0' "$path" >>"$output"
    done <"$input"
}

reset_sandbox_changes() {
    local sandbox="$1" changed changed_literal untracked path
    if [[ "$sandbox" == "$SANDBOX" && "$SANDBOX_RESET_READY" -eq 1 ]]; then
        # Consume before touching Git so an interrupted or failed reset can never leak paths into
        # the next case. The cache contains only literal NUL entries published after staging.
        SANDBOX_RESET_READY=0
        local rc=0
        (
            cd "$sandbox"
            if [[ -s "$SANDBOX_RESET_TRACKED" ]]; then
                git reset -q HEAD --pathspec-from-file="$SANDBOX_RESET_TRACKED" \
                    --pathspec-file-nul >/dev/null 2>&1 || exit $?
            fi
            if [[ -s "$SANDBOX_RESET_UNTRACKED" ]]; then
                git reset -q HEAD --pathspec-from-file="$SANDBOX_RESET_UNTRACKED" \
                    --pathspec-file-nul >/dev/null 2>&1 || exit $?
                while IFS= read -r -d '' path; do
                    git clean -fdq -- "$path" >/dev/null 2>&1 || exit $?
                done <"$SANDBOX_RESET_UNTRACKED"
            fi
            if [[ -s "$SANDBOX_RESET_TRACKED" ]]; then
                git checkout -f HEAD --pathspec-from-file="$SANDBOX_RESET_TRACKED" \
                    --pathspec-file-nul >/dev/null 2>&1 || exit $?
            fi
        ) || rc=$?
        : >"$SANDBOX_RESET_TRACKED"
        : >"$SANDBOX_RESET_UNTRACKED"
        return "$rc"
    fi

    # Special probes that deliberately bypass staging have no cache. Scan once for those callers;
    # ordinary negative cases always arrive through stage_sandbox_changes and avoid this path.
    changed="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-changed.XXXXXX")"
    changed_literal="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-changed-literal.XXXXXX")"
    untracked="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-untracked.XXXXXX")"
    local rc=0
    (
        cd "$sandbox"
        git diff --name-only -z HEAD -- >"$changed" || exit $?
        if [[ -s "$changed" ]]; then
            literalize_nul_paths "$changed" "$changed_literal"
            git reset -q HEAD --pathspec-from-file="$changed_literal" \
                --pathspec-file-nul >/dev/null 2>&1 || exit $?
        fi
        git ls-files --others --exclude-standard -z >"$untracked" || exit $?
        while IFS= read -r -d '' path; do
            git clean -fdq -- ":(literal)${path}" >/dev/null 2>&1 || exit $?
        done <"$untracked"
        git diff --name-only -z HEAD -- >"$changed" || exit $?
        if [[ -s "$changed" ]]; then
            literalize_nul_paths "$changed" "$changed_literal"
            git checkout -f HEAD --pathspec-from-file="$changed_literal" \
                --pathspec-file-nul >/dev/null 2>&1 || exit $?
        fi
    ) || rc=$?
    rm -f "$changed" "$changed_literal" "$untracked"
    return "$rc"
}
# Reuse the caller's build directory. A guard that declares REQUIRES-BUILD compiles
# the workspace, and a separate target/ recompiles it after `cargo test --workspace`.
# CI measured that duplication past this suite's wall-clock budget (declared at the top of
# this file: 480s, its slice of the ten-minute whole-gate budget). Sandbox mutations still
# rebuild affected workspace crates because Cargo fingerprints their different source
# root, while registry dependencies and the positive control remain reusable.
#
# Sharing is sound because a sandbox differs from the tree only in the one file a case
# mutates: every dependency is already built, and cargo rebuilds the workspace crates
# alone. It is not a correctness shortcut — the guards still read the sandbox, and
# CARGO_TARGET_DIR changes where objects land, not what is compiled.
GUARD_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
export CARGO_TARGET_DIR="$GUARD_TARGET_DIR"

make_sandbox() {
    if [[ -n "$SANDBOX" ]]; then
        # History-sensitive mutations may add commits. Restore the disposable branch before the
        # literal-path reset consumes the current mutation journal.
        if [[ "$(git -C "$SANDBOX" rev-parse HEAD)" != "$SANDBOX_BASE" ]]; then
            git -C "$SANDBOX" reset -q --hard "$SANDBOX_BASE"
            git -C "$SANDBOX" clean -fdq
            SANDBOX_RESET_READY=0
            : >"$SANDBOX_RESET_TRACKED"
            : >"$SANDBOX_RESET_UNTRACKED"
        else
            reset_sandbox_changes "$SANDBOX"
        fi
        git -C "$SANDBOX" update-ref refs/remotes/origin/main "$SANDBOX_BASE"
        return
    fi

    local dir list archive
    dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-test.XXXXXX")"
    # `tar --null -T -` is GNU-only; BSD tar (macOS) rejects it, and letting the failing
    # call write to the pipe before the fallback produces a spurious "tar: Write error"
    # that would mask a real one. A list file is understood by both.
    #
    # The pinned model JSON used to be excluded here as 3.2 MB no guard read.
    # check_route_coverage.sh reads it, and the exclusion made that guard skip
    # its own self-test while reporting success — so the sandbox now carries the
    # whole tree. One sandbox is built per run and reset between cases, so the
    # 3.2 MB is paid once.
    list="${dir}.files"
    archive="${dir}.tar"
    # Include new, unignored files: a guard introduced in the same change must be able to test its
    # own inputs before the author stages them.
    if ! (
        cd "$REPO_ROOT" &&
            git ls-files >"$list" &&
            git ls-files --others --exclude-standard >>"$list" &&
            sort -u -o "$list" "$list"
    ); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$REPO_ROOT" && tar -cf "$archive" -T "$list"); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$dir" && tar -xf "$archive"); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! rm -f "$list" "$archive"; then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$dir" && git init -q .); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$dir" && git add -A >/dev/null 2>&1); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$dir" && git -c user.name=t -c user.email=t@t commit -qm base >/dev/null 2>&1); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    SANDBOX="$dir"
    SANDBOX_RESET_TRACKED="${dir}.reset-tracked"
    SANDBOX_RESET_UNTRACKED="${dir}.reset-untracked"
    : >"$SANDBOX_RESET_TRACKED"
    : >"$SANDBOX_RESET_UNTRACKED"
    SANDBOX_RESET_READY=0
    SANDBOX_BASE="$(git -C "$dir" rev-parse HEAD)"
    git -C "$dir" update-ref refs/remotes/origin/main "$SANDBOX_BASE"
}

# Stage only paths changed by the current mutation. A repository-wide `git add -A` rescans every
# workspace file for every negative case; the guard reads the same index when the exact tracked and
# untracked paths are staged explicitly.
stage_sandbox_changes() {
    local sandbox="$1" tracked untracked paths
    tracked="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-stage-tracked.XXXXXX")"
    untracked="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-stage-untracked.XXXXXX")"
    paths="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-stage-paths.XXXXXX")"
    if [[ "$sandbox" == "$SANDBOX" ]]; then
        SANDBOX_RESET_READY=0
        : >"$SANDBOX_RESET_TRACKED"
        : >"$SANDBOX_RESET_UNTRACKED"
    fi
    if ! (
        cd "$sandbox"
        git diff --name-only -z HEAD -- >"$tracked" &&
            git ls-files --others --exclude-standard -z >"$untracked"
    ); then
        rm -f "$tracked" "$untracked" "$paths" "$paths.tracked" "$paths.untracked"
        return 1
    fi
    literalize_nul_paths "$tracked" "$paths.tracked"
    literalize_nul_paths "$untracked" "$paths.untracked"
    cat "$paths.tracked" "$paths.untracked" >"$paths"
    if [[ -s "$paths" ]] && ! (
        cd "$sandbox"
        git add -A --pathspec-from-file="$paths" --pathspec-file-nul
    ); then
        rm -f "$tracked" "$untracked" "$paths" "$paths.tracked" "$paths.untracked"
        return 1
    fi
    if [[ "$sandbox" == "$SANDBOX" ]]; then
        cp "$paths.tracked" "$SANDBOX_RESET_TRACKED"
        cp "$paths.untracked" "$SANDBOX_RESET_UNTRACKED"
        SANDBOX_RESET_READY=1
    fi
    rm -f "$tracked" "$untracked" "$paths" "$paths.tracked" "$paths.untracked"
}

cleanup_sandbox() {
    # Must return 0: an EXIT trap's status becomes the script's status, so a bare
    # `[[ -n "$SANDBOX" ]] && rm -rf` reports failure whenever no sandbox was made,
    # and the suite would exit 1 while printing "0 failures".
    #
    # Every removal is `|| true` for the same reason, one step further along. Under `set -e` a
    # failing `rm -rf` aborts this function before its `return 0`, and the run exits 1 having just
    # printed "0 failure(s)" — which is what happened on rustfs/gateway#232, where a sandbox's
    # `.git` was still being written to when the trap fired: `rm: cannot remove '.git': Directory
    # not empty`, thirteen green cases, exit 1. A temporary directory that outlives the run is
    # litter on a throwaway runner; a green run reported red is a defect nobody can distinguish
    # from a real one.
    if [[ -n "$SANDBOX" ]]; then
        rm -rf "$SANDBOX" || true
    fi
    rm -f "$SANDBOX_RESET_TRACKED" "$SANDBOX_RESET_UNTRACKED" || true
    if [[ -n "$QUIRK_LEDGER_PARSE_CACHE" ]]; then
        rm -f "$QUIRK_LEDGER_PARSE_CACHE" || true
    fi
    if [[ -n "$CT_EQ_SANDBOX" ]]; then
        rm -rf "$CT_EQ_SANDBOX" || true
    fi
    if [[ -n "$SEMVER_SANDBOX" ]]; then
        rm -rf "$SEMVER_SANDBOX" || true
    fi
    return 0
}

make_semver_sandbox() {
    if [[ -n "$SEMVER_SANDBOX" ]]; then
        (
            cd "$SEMVER_SANDBOX"
            git reset --hard -q HEAD
            git clean -fdq
        )
        return
    fi

    SEMVER_SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/gateway-semver-test.XXXXXX")"
    mkdir -p \
        "$SEMVER_SANDBOX/crates/types/src" \
        "$SEMVER_SANDBOX/docs/adr" \
        "$SEMVER_SANDBOX/generated/dto/ops" \
        "$SEMVER_SANDBOX/scripts/allowances" \
        "$SEMVER_SANDBOX/scripts/lib"
    cp "$REPO_ROOT/crates/types/src/lib.rs" "$SEMVER_SANDBOX/crates/types/src/lib.rs"
    cp "$REPO_ROOT/generated/dto/ops/get_bucket_location.rs" \
        "$SEMVER_SANDBOX/generated/dto/ops/get_bucket_location.rs"
    cp "$REPO_ROOT/docs/adr/0004-semver-policy.md" "$SEMVER_SANDBOX/docs/adr/"
    cp "$REPO_ROOT/scripts/check_no_dto_non_exhaustive.sh" \
        "$REPO_ROOT/scripts/check_no_exhaustive_destructuring.sh" \
        "$SEMVER_SANDBOX/scripts/"
    cp "$REPO_ROOT/scripts/lib/rust_semver_surface.py" "$SEMVER_SANDBOX/scripts/lib/"
    cat >"$SEMVER_SANDBOX/generated/dto/semver_names.rs" <<'RS'
pub struct Nested {}
pub struct ObjectLockConfiguration {}
RS
    (
        cd "$SEMVER_SANDBOX"
        git init -q .
        git add -A
        git -c user.name=t -c user.email=t@t commit -qm base
    )
    if ! GATEWAY_CHECK_ROOT="$SEMVER_SANDBOX" \
        "$SEMVER_SANDBOX/scripts/check_no_dto_non_exhaustive.sh" >/dev/null 2>&1 ||
        ! GATEWAY_CHECK_ROOT="$SEMVER_SANDBOX" \
            "$SEMVER_SANDBOX/scripts/check_no_exhaustive_destructuring.sh" >/dev/null 2>&1; then
        fail_msg 'ADR-0004 guards reject their minimal unmodified fixture'
        return 1
    fi
}

expect_semver_fail() {
    local guard="$1" desc="$2" mutate="$3" output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_semver_sandbox
    (cd "$SEMVER_SANDBOX" && "$mutate" >/dev/null)
    output="$(GATEWAY_CHECK_ROOT="$SEMVER_SANDBOX" \
        "$SEMVER_SANDBOX/scripts/$guard" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 &&
        ( "$output" == *'rule: docs/adr/0004-semver-policy.md'* ||
            "$output" == *'ADR-0004 guard:'* ||
            "$output" == *'required parser is missing:'* ) ]]; then
        pass_msg "${guard} catches: ${desc}"
    elif [[ "$rc" -ne 0 ]]; then
        fail_msg "${guard} failed without its policy diagnostic: ${desc}"
    else
        fail_msg "${guard} did NOT catch: ${desc}"
    fi
}
trap cleanup_sandbox EXIT

make_ct_eq_sandbox() {
    if [[ -n "$CT_EQ_SANDBOX" ]]; then
        (
            cd "$CT_EQ_SANDBOX"
            git reset --hard -q HEAD
            git clean -fdq
        )
        return
    fi

    CT_EQ_SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/gateway-ct-eq-test.XXXXXX")"
    mkdir -p "$CT_EQ_SANDBOX/crates" "$CT_EQ_SANDBOX/scripts/allowances"
    cp -R "$REPO_ROOT/crates/sig" "$CT_EQ_SANDBOX/crates/sig"
    if [[ -f "$REPO_ROOT/scripts/allowances/ct-eq-allowances.txt" ]]; then
        cp "$REPO_ROOT/scripts/allowances/ct-eq-allowances.txt" \
            "$CT_EQ_SANDBOX/scripts/allowances/ct-eq-allowances.txt"
    fi
    (
        cd "$CT_EQ_SANDBOX"
        git init -q .
        git add -A
        git -c user.name=t -c user.email=t@t commit -qm base
    )
    if ! GATEWAY_CHECK_ROOT="$CT_EQ_SANDBOX" "${SCRIPT_DIR}/check_ct_eq.sh" >/dev/null 2>&1; then
        fail_msg 'check_ct_eq.sh rejects its minimal unmodified sig fixture'
        return 1
    fi
}

expect_ct_eq_fail() {
    local desc="$1" mutate="$2" output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_ct_eq_sandbox
    (cd "$CT_EQ_SANDBOX" && "$mutate" >/dev/null)
    (cd "$CT_EQ_SANDBOX" && git add -A >/dev/null 2>&1)
    output="$(GATEWAY_CHECK_ROOT="$CT_EQ_SANDBOX" "${SCRIPT_DIR}/check_ct_eq.sh" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 && "$output" == *'Constant-time rule violated.'* ]]; then
        pass_msg "check_ct_eq.sh catches: ${desc}"
    elif [[ "$rc" -ne 0 ]]; then
        fail_msg "check_ct_eq.sh failed without its policy diagnostic: ${desc}"
    else
        fail_msg "check_ct_eq.sh did NOT catch: ${desc}"
    fi
}

# expect_fail_unstaged <guard> <description> <mutation-fn>
# Same as expect_fail, but deliberately does NOT `git add` the mutation. This is what
# distinguishes a guard that reads the working tree from one that only reads the index.
expect_fail_unstaged() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    if [[ ! -x "${SCRIPT_DIR}/${guard}" ]]; then
        fail_msg "${guard} is missing or not executable; cannot test: ${desc}"
        return
    fi
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        pass_msg "${guard} catches (unstaged): ${desc}"
    else
        fail_msg "${guard} did NOT catch (unstaged): ${desc}"
    fi
}

# expect_english_fail_minimal <description> <mutation-fn> <path> <tracked|untracked>
# The English-only guard needs Git metadata but not the workspace. Keeping these controls in tiny,
# independent repositories preserves the tracked/untracked contract without copying the full tree.
expect_english_fail_minimal() {
    local desc="$1" mutate="$2" path="$3" mode="$4"
    local sandbox output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    sandbox="$(mktemp -d "${TMPDIR:-/tmp}/gateway-english-test.XXXXXX")"
    mkdir -p "$sandbox/$(dirname "$path")" "$sandbox/scripts/allowances"
    printf 'Visible English — middle · dot.\n' >"$sandbox/visible-control.txt"
    if [[ "$mode" == tracked ]]; then
        printf 'Visible English — middle · dot.\n' >"$sandbox/$path"
    elif [[ "$mode" != untracked ]]; then
        rm -rf "$sandbox"
        fail_msg "check_english_only.sh has an unsupported minimal-test mode: ${mode}"
        return
    fi
    (
        cd "$sandbox"
        git init -q .
        git add -A
        git -c user.name=t -c user.email=t@t commit -qm base
    )
    if ! GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_english_only.sh" >/dev/null 2>&1; then
        rm -rf "$sandbox"
        fail_msg "check_english_only.sh rejects its visible English, em-dash, or middle-dot control: ${desc}"
        return
    fi
    (cd "$sandbox" && "$mutate" >/dev/null)
    if [[ "$mode" == tracked ]]; then
        (cd "$sandbox" && git add -A >/dev/null 2>&1)
    fi
    output="$(GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_english_only.sh" 2>&1)" || rc=$?
    rm -rf "$sandbox"
    if [[ "$rc" -ne 0 && "$output" == *"${path}: contains CJK text"* ]]; then
        if [[ "$mode" == tracked ]]; then
            pass_msg "check_english_only.sh catches: ${desc}"
        else
            pass_msg "check_english_only.sh catches (unstaged): ${desc}"
        fi
    else
        fail_msg "check_english_only.sh did not reject the CJK mutation at ${path}: ${desc}"
    fi
}

# expect_fail <guard> <description> <mutation-fn> [expected-diagnostic]
# Runs the mutation inside a sandbox, then asserts the guard exits non-zero.
expect_fail() {
    local guard="$1" desc="$2" mutate="$3"
    local expected_diagnostic="${4:-}" require_diagnostic=0 sandbox output rc=0
    [[ "$#" -ge 4 ]] && require_diagnostic=1
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    if [[ ! -x "${SCRIPT_DIR}/${guard}" ]]; then
        fail_msg "${guard} is missing or not executable; cannot test: ${desc}"
        return
    fi
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    output="$(GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
    local diagnostic_helper diagnostic_fragment
    if [[ "$guard" == check_quirk_ledger.sh ]]; then
        require_diagnostic=1
        expected_diagnostic=""
        while IFS=$'\t' read -r diagnostic_helper diagnostic_fragment; do
            if [[ "$diagnostic_helper" == "$mutate" ]]; then
                expected_diagnostic="$diagnostic_fragment"
                break
            fi
        done <<<"$QUIRK_LEDGER_DIAGNOSTICS"
    fi
    if [[ "$rc" -ne 0 && ( "$require_diagnostic" -eq 0 || ( -n "$expected_diagnostic" && "$output" == *"$expected_diagnostic"* ) ) ]]; then
        pass_msg "${guard} catches: ${desc}"
    elif [[ "$rc" -ne 0 ]]; then
        fail_msg "${guard} failed without its policy diagnostic: ${desc}"
    else
        fail_msg "${guard} did NOT catch: ${desc}"
    fi
}

# Planning-directory fixtures must use `git add -f` because the repository deliberately ignores
# those paths. Keep them in a disposable sandbox so a staged file absent from HEAD never enters the
# shared selective-reset cache.
expect_fail_forced_staged() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    output="$(GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
    rm -rf "$sandbox"
    rm -f "$SANDBOX_RESET_TRACKED" "$SANDBOX_RESET_UNTRACKED"
    SANDBOX=""
    SANDBOX_RESET_TRACKED=""
    SANDBOX_RESET_UNTRACKED=""
    SANDBOX_RESET_READY=0
    if [[ "$rc" -ne 0 ]]; then
        pass_msg "${guard} catches: ${desc}"
    else
        fail_msg "${guard} did NOT catch: ${desc}"
    fi
}

# expect_guard_pass <guard> <description> <mutation-fn>
# Proves token decoys stay ignored while the same syntax in active Rust is rejected separately.
expect_guard_pass() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg "${guard} accepts: ${desc}"
    else
        fail_msg "${guard} rejected its positive control: ${desc}"
    fi
}

# expect_fail_self_mutation <guard> <description> <mutation-fn>
# Runs the sandbox's copy of a guard when the mutation changes the guard policy itself. Calling
# SCRIPT_DIR here would exercise the unmodified source-tree copy and make every such mutation a
# false green.
expect_fail_self_mutation() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    GATEWAY_CHECK_ROOT="$sandbox" "$sandbox/scripts/$guard" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        pass_msg "${guard} catches its own mutation: ${desc}"
    else
        fail_msg "${guard} did NOT catch its own mutation: ${desc}"
    fi
}

# expect_fail_with_diagnostic <guard> <description> <diagnostic> <mutation-fn>
# Runs the mutation and also proves the guard failed for the policy reason under test.
expect_fail_with_diagnostic() {
    local guard="$1" desc="$2" diagnostic="$3" mutate="$4"
    local sandbox output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    if [[ ! -x "${SCRIPT_DIR}/${guard}" ]]; then
        fail_msg "${guard} is missing or not executable; cannot test: ${desc}"
        return
    fi
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    output="$(GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 && "$output" == *"$diagnostic"* ]]; then
        pass_msg "${guard} catches: ${desc}"
    else
        fail_msg "${guard} did not catch with its expected diagnostic: ${desc}"
    fi
}

# expect_cargo_test_fail_with_diagnostic <package> <target> <test> <diagnostic> <mutation-fn>
# Proves a compiler-backed policy test rejects the mutation for the intended reason.
expect_cargo_test_fail_with_diagnostic() {
    local package="$1" target="$2" test_name="$3" diagnostic="$4" mutate="$5"
    local sandbox output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    output="$(
        cd "$sandbox" &&
            cargo test -p "$package" --test "$target" "$test_name" -- --exact 2>&1
    )" || rc=$?
    if [[ "$rc" -ne 0 && "$output" == *"$diagnostic"* ]]; then
        pass_msg "${package}/${target} catches: ${test_name}"
    else
        fail_msg "${package}/${target} did not catch ${test_name} with its expected diagnostic"
    fi
}

# expect_rustc_test_fail_with_diagnostic <source> <test> <diagnostic> <mutation-fn>
# Runs a std-only compiler probe without starting an unrelated crate dependency graph.
expect_rustc_test_fail_with_diagnostic() {
    local source="$1" test_name="$2" diagnostic="$3" mutate="$4"
    local sandbox output binary rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    binary="$(mktemp "${TMPDIR:-/tmp}/gateway-rustc-test.XXXXXX")"
    if ! rustc --edition=2024 --test "$sandbox/$source" -o "$binary" >/dev/null 2>&1 ||
        ! "$binary" "$test_name" --exact >/dev/null 2>&1; then
        rm -f "$binary"
        fail_msg "${source} rejects its unmodified compiler control: ${test_name}"
        return
    fi
    (cd "$sandbox" && "$mutate" >/dev/null)
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    output="$({
        rustc --edition=2024 --test "$sandbox/$source" -o "$binary" &&
            "$binary" "$test_name" --exact --nocapture
    } 2>&1)" || rc=$?
    rm -f "$binary"
    if [[ "$rc" -ne 0 && "$output" == *"$diagnostic"* && "$output" == *"test result: FAILED"* ]]; then
        pass_msg "${source} catches: ${test_name}"
    else
        fail_msg "${source} did not catch ${test_name} with its expected diagnostic"
    fi
}

# expect_fail_and_missing_grep <guard> <description> <mutation-fn>
# Proves both the policy mutation and the dependency-missing path while keeping them one guard case.
expect_fail_and_missing_grep() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox mutation_rc=0 missing_rc=0 missing_output tool_path clean=1
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    if [[ ! -x "${SCRIPT_DIR}/${guard}" ]]; then
        fail_msg "${guard} is missing or not executable; cannot test: ${desc}"
        return
    fi
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" >/dev/null 2>&1 || mutation_rc=$?

    make_sandbox
    sandbox="$SANDBOX"
    if ! (
        cd "$sandbox"
        git diff --quiet HEAD -- &&
            git diff --cached --quiet HEAD -- &&
            [[ -z "$(git ls-files --others --exclude-standard)" ]]
    ); then
        clean=0
    fi
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    missing_output="$(GATEWAY_CHECK_ROOT="$sandbox" PATH="$tool_path" /bin/bash "${SCRIPT_DIR}/${guard}" 2>&1)" || missing_rc=$?
    rm -rf "$tool_path"

    if [[ "$mutation_rc" -ne 0 && "$clean" -eq 1 && "$missing_rc" -ne 0 && "$missing_output" == *'required command is missing: grep'* ]]; then
        pass_msg "${guard} catches: ${desc}; missing grep also fails closed"
    else
        fail_msg "${guard} did not catch its mutation or reported green without grep: ${desc}"
    fi
}

# check_monomorphic_dispatch reads compiler output rather than repository source. Feed it a tiny
# LLVM mutation directly so the negative control proves that an indirect handler call is rejected
# without paying for a second release build.
expect_monomorphic_ir_fail() {
    local desc="$1" mutate="$2"
    local sandbox ir rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    ir="$sandbox/scripts/monomorphic-indirect.ll"
    GATEWAY_CHECK_ROOT="$sandbox" GATEWAY_MONOMORPHIC_IR="$ir" \
        "${SCRIPT_DIR}/check_monomorphic_dispatch.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        pass_msg "check_monomorphic_dispatch.sh catches: ${desc}"
    else
        fail_msg "check_monomorphic_dispatch.sh did NOT catch: ${desc}"
    fi
}

# expect_fail_and_missing_cargo <guard> <description> <mutation-fn>
# Proves the Rust-aware guard catches its policy mutation and fails closed without its parser.
expect_fail_and_missing_cargo() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox mutation_rc=0 missing_rc=0 missing_output tool_path clean=1
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    if [[ ! -x "${SCRIPT_DIR}/${guard}" ]]; then
        fail_msg "${guard} is missing or not executable; cannot test: ${desc}"
        return
    fi
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" >/dev/null 2>&1 || mutation_rc=$?

    make_sandbox
    sandbox="$SANDBOX"
    if ! (
        cd "$sandbox"
        git diff --quiet HEAD -- &&
            git diff --cached --quiet HEAD -- &&
            [[ -z "$(git ls-files --others --exclude-standard)" ]]
    ); then
        clean=0
    fi
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    missing_output="$(GATEWAY_CHECK_ROOT="$sandbox" PATH="$tool_path" /bin/bash "${SCRIPT_DIR}/${guard}" 2>&1)" || missing_rc=$?
    rm -rf "$tool_path"

    if [[ "$mutation_rc" -ne 0 && "$clean" -eq 1 && "$missing_rc" -ne 0 && "$missing_output" == *'required command is missing: cargo'* ]]; then
        pass_msg "${guard} catches: ${desc}; missing cargo also fails closed"
    else
        fail_msg "${guard} did not catch its mutation or reported green without cargo: ${desc}"
    fi
}

# -----------------------------------------------------------------------------
# Positive control: the repository as it stands must be clean.
# -----------------------------------------------------------------------------
if [[ "$BUILD_GUARDS_ONLY" == 1 ]]; then
printf 'Build-backed controls\n'
for guard in \
    check_case_keys_honoured.sh \
    check_macro_governance.sh \
    check_monomorphic_dispatch.sh \
    check_verify_map_generated.sh; do
    cases=$((cases + 1))
    guard_case_owned "$cases" || continue
    positive_control_output=""
    if positive_control_output="$("${SCRIPT_DIR}/${guard}" 2>&1)"; then
        pass_msg "$guard"
    else
        fail_msg "$guard fails on the current tree"
        printf '%s\n' "$positive_control_output" | sed 's/^/       /' >&2
    fi
done
mut_build_monomorphic_handler_is_indirect() {
    python3 - <<'PYEOF'
from pathlib import Path
Path("scripts/monomorphic-indirect.ll").write_text("""\
define internal void @_RNCINvMNtXstatic_dispatchXStaticOperationXintegration7support4PingE21dispatch_with_handlerX7Backend() {
  call void @_Rstatic()
}
define internal void @_RNCINvNtNtXrustfs_gateway_core8registry8handlers21dispatch_with_contextXintegration7support4PingX7Backend() {
; <integration::support::Backend as rustfs_gateway_core::handler::Handler<integration::support::Ping>>::call_with_context
  %result = call ptr %handler()
}
define internal void @_Rdecode() {
; <integration::support::Ping as rustfs_gateway_core::codec::OperationCodec>::decode
  call void @_Rcodec()
}
""")
PYEOF
}
expect_monomorphic_ir_fail \
    'the concrete Handler<Ping> call becoming indirect' mut_build_monomorphic_handler_is_indirect
mut_build_unread_schema_key() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
schema["$defs"]["expect"]["properties"]["nothing_reads_this"] = {"type": "boolean"}
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_case_keys_honoured.sh \
    'a schema key the harness never reads' mut_build_unread_schema_key
mut_build_dropped_schema_field() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["evidence"]["properties"]["kind"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_case_keys_honoured.sh \
    'a DECLARED entry naming a field the schema dropped' mut_build_dropped_schema_field
mut_build_verify_map_edited() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/verify-map.toml")
text = path.read_text()
old = 'name = "AbortMultipartUpload"'
if text.count(old) != 1:
    raise SystemExit("verify-map mutation anchor is not unique")
path.write_text(text.replace(old, 'name = "AbortMultipartUploadEdited"'))
PYEOF
}
expect_fail check_verify_map_generated.sh \
    'a manual edit to the generated operation verification map' mut_build_verify_map_edited
mut_build_verify_map_deleted() { rm -f xtask/verify-map.toml; }
expect_fail check_verify_map_generated.sh \
    'the generated operation verification map being absent' mut_build_verify_map_deleted
mut_build_macro_operation_names_edited() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/macros/src/op_names.rs")
text = path.read_text()
old = '    "AbortMultipartUpload",'
if text.count(old) != 1:
    raise SystemExit("macro operation-name mutation anchor is not unique")
path.write_text(text.replace(old, '    "AbortMultipartUploadEdited",', 1))
PYEOF
}
expect_fail check_verify_map_generated.sh \
    'a manual edit to the generated macro operation-name table' mut_build_macro_operation_names_edited \
    'crates/macros/src/op_names.rs'
mut_build_macro_operation_names_marker_removed() {
    perl -0pi -e 's#// \@generated by `cargo xtask codegen`\. Do not edit\.#// hand maintained#' \
        crates/macros/src/op_names.rs
}
expect_fail check_verify_map_generated.sh \
    'the macro operation-name table losing its codegen marker' mut_build_macro_operation_names_marker_removed \
    'has no exact codegen ownership marker'
mut_build_macro_operation_names_deleted() { rm -f crates/macros/src/op_names.rs; }
expect_fail check_verify_map_generated.sh \
    'the generated macro operation-name table being absent' mut_build_macro_operation_names_deleted \
    'required generated input is missing'
mut_build_macro_operation_names_emission_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/codegen/src/lib.rs")
text = path.read_text()
old = '''    files.push((
        out.macro_operation_names(),
        emit::rust_files::macro_operation_names(&lowered.operations, &lowered.route_only),
    ));
'''
if text.count(old) != 1:
    raise SystemExit("macro operation-name emission anchor is not unique")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_verify_map_generated.sh \
    'the code generator no longer emitting the macro operation-name table' \
    mut_build_macro_operation_names_emission_removed \
    'required codegen artefact was not emitted'
mut_build_macro_mints_public_type() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/macros/src/expand.rs")
text = path.read_text()
old = "    quote! {\n        #block\n"
if text.count(old) != 1:
    raise SystemExit("macro public-type mutation anchor is not unique")
path.write_text(text.replace(old, old + "        pub struct GeneratedRegistry;\n", 1))
PYEOF
}
expect_fail check_macro_governance.sh \
    'the handler macro minting a public type name' \
    mut_build_macro_mints_public_type \
    'tests::the_expansion_mints_no_public_type_name'
mut_build_macro_rewrites_body() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/macros/src/expand.rs")
text = path.read_text()
old = "    quote! {\n        #block\n"
if text.count(old) != 1:
    raise SystemExit("macro body-rewrite mutation anchor is not unique")
path.write_text(text.replace(old, "    quote! {\n", 1))
PYEOF
}
expect_fail check_macro_governance.sh \
    'the handler macro dropping the source impl and its bodies' \
    mut_build_macro_rewrites_body \
    'tests::the_expansion_rewrites_no_function_body'
mut_build_macro_docs_pair_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/macros/src/lib.rs")
text = path.read_text()
old = "//! # The hand-written equivalent, which always works"
if text.count(old) != 1:
    raise SystemExit("macro documentation-pair mutation anchor is not unique")
path.write_text(text.replace(old, "//! # Registration example", 1))
PYEOF
}
expect_fail check_macro_governance.sh \
    'the public macro docs losing the adjacent macro-free form' \
    mut_build_macro_docs_pair_removed \
    'macro-free documentation pair is missing'
mut_build_macro_manual_equivalence_broken() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/macros/tests/equivalence.rs")
text = path.read_text()
old = '''\
    async fn list_objects_v2(&self, request: Req<ListObjectsV2>) -> HandlerResult<ListObjectsV2> {
        let _ = request.input();
        Ok(Resp::new(ListObjectsV2Output {
            key_count: 0,
            ..ListObjectsV2Output::default()
        }))
    }

'''
if text.count(old) != 2:
    raise SystemExit("macro/manual equivalence mutation anchors are not exact")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_macro_governance.sh \
    'the macro fixture dropping a registration kept by the hand-written form' \
    mut_build_macro_manual_equivalence_broken \
    'macro_and_manual_registration_are_equivalent'
mut_build_macro_link_magic_added() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/macros/Cargo.toml")
text = path.read_text()
old = "[dependencies]\n"
if text.count(old) != 1:
    raise SystemExit("macro dependency mutation anchor is not unique")
path.write_text(text.replace(old, old + 'inventory = "0.3"\n', 1))
PYEOF
}
expect_fail check_macro_governance.sh \
    'the macro crate adding link-time registration magic' \
    mut_build_macro_link_magic_added \
    'crates/macros/Cargo.toml'
fi

if [[ "$QUIRK_LEDGER_ONLY" == 0 && "$DTO_COMPILER_ONLY" == 0 && "$BUILD_GUARDS_ONLY" == 0 && "$ERROR_STATUS_ONLY" == 0 ]]; then
printf 'Positive control (repository must be clean)\n'
for guard in "${SCRIPT_DIR}"/check_*.sh; do
    grep -q '^# REQUIRES-PR$' "$guard" && continue
    grep -q '^# REQUIRES-BUILD$' "$guard" && continue
    cases=$((cases + 1))
    guard_case_owned "$cases" || continue
    if grep -q '^# REQUIRES-PR$' "$guard"; then
        pass_msg "$(basename "$guard") deferred to its PR-context probes"
        continue
    fi
    positive_control_output=""
    if positive_control_output="$("$guard" 2>&1)"; then
        pass_msg "$(basename "$guard")"
    else
        # Print what the guard said. A positive control that swallows its own diagnosis
        # reports "fails on the current tree" and nothing else, which is a whole CI cycle
        # spent rediscovering a message the runner already had.
        fail_msg "$(basename "$guard") fails on the current tree"
        printf '%s\n' "$positive_control_output" | sed 's/^/       /' >&2
    fi
done
fi

# -----------------------------------------------------------------------------
# Negative cases
# -----------------------------------------------------------------------------
if [[ "$ERROR_STATUS_ONLY" == 0 ]]; then
printf '\nNegative cases (guards must fail)\n'
fi

if [[ "$QUIRK_LEDGER_ONLY" == 0 && "$DTO_COMPILER_ONLY" == 0 && "$BUILD_GUARDS_ONLY" == 0 && "$ERROR_STATUS_ONLY" == 0 ]]; then

replace_template_text() {
    python3 - "$1" "$2" "$3" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
old, new = sys.argv[2:]
text = path.read_text()
if old not in text:
    raise SystemExit(f"missing template mutation subject in {path}: {old}")
path.write_text(text.replace(old, new, 1))
PYEOF
}

mut_template_pr_checklist_drift() {
    replace_template_text .github/pull_request_template.md \
        '- [ ] Every new assertion was mutated — the implementation was broken on purpose and the assertion
      went red. The PR description names which ones
' ''
}
expect_fail check_template_contract.sh \
    'the PR checklist dropping the mutation evidence item from AGENTS.md' mut_template_pr_checklist_drift

mut_template_task_heading_hidden_in_comment() {
    replace_template_text .github/ISSUE_TEMPLATE/task.md \
        '## 7. Full case list (exhaustive, negatives included)' \
        '<!-- ## 7. Full case list (exhaustive, negatives included) -->'
}
expect_fail check_template_contract.sh \
    'a task section heading surviving only inside an HTML comment' mut_template_task_heading_hidden_in_comment

mut_template_task_heading_hidden_in_fence() {
    replace_template_text .github/ISSUE_TEMPLATE/task.md \
        '## 7. Full case list (exhaustive, negatives included)' \
        '```markdown
## 7. Full case list (exhaustive, negatives included)
```'
}
expect_fail check_template_contract.sh \
    'a task section heading surviving only inside a fenced block' mut_template_task_heading_hidden_in_fence

mut_template_task_forbidden_input_comment_decoy() {
    replace_template_text .github/ISSUE_TEMPLATE/task.md \
        '- `Cargo.lock`' \
        '<!-- `Cargo.lock` -->'
}
expect_fail check_template_contract.sh \
    'a forbidden input surviving only inside an HTML comment' mut_template_task_forbidden_input_comment_decoy

mut_template_task_parent_removed() {
    replace_template_text .github/ISSUE_TEMPLATE/task.md \
        '> Epic: rustfs/backlog#1677' '> Epic: unspecified'
}
expect_fail check_template_contract.sh \
    'the implementation template losing Parent #1677' mut_template_task_parent_removed

mut_template_task_negative_requirement_removed() {
    replace_template_text .github/ISSUE_TEMPLATE/task.md \
        'the number of negative cases MUST be >= the number of positive cases' \
        'include representative cases'
}
expect_fail check_template_contract.sh \
    'the task template losing its negative-case ratio' mut_template_task_negative_requirement_removed

mut_template_task_handoff_comment_decoy() {
    replace_template_text .github/ISSUE_TEMPLATE/task.md \
        '    - Gotcha: ...' \
        '    <!-- - Gotcha: ... -->'
}
expect_fail check_template_contract.sh \
    'a Handoff field surviving only inside an HTML comment' mut_template_task_handoff_comment_decoy

mut_template_task_front_matter_label_changed() {
    replace_template_text .github/ISSUE_TEMPLATE/task.md 'labels: task' 'labels: enhancement'
}
expect_fail check_template_contract.sh \
    'the implementation template losing its intended live label' mut_template_task_front_matter_label_changed

mut_template_blank_issues_enabled() {
    replace_template_text .github/ISSUE_TEMPLATE/config.yml \
        'blank_issues_enabled: false' 'blank_issues_enabled: true'
}
expect_fail check_template_contract.sh \
    'the web blank-issue entry being re-enabled' mut_template_blank_issues_enabled

mut_template_disabled_discussion_link_returns() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path(".github/ISSUE_TEMPLATE/config.yml")
path.write_text(path.read_text() + """\
  - name: Question / discussion
    url: https://github.com/rustfs/gateway/discussions
    about: Ask questions here instead of opening an issue.
""")
PYEOF
}
expect_fail check_template_contract.sh \
    'a contact link returning before Discussions is enabled' mut_template_disabled_discussion_link_returns

mut_template_security_contact_changed() {
    replace_template_text .github/ISSUE_TEMPLATE/config.yml \
        'https://github.com/rustfs/gateway/security/advisories/new' \
        'https://github.com/rustfs/gateway/issues/new'
}
expect_fail check_template_contract.sh \
    'the private security contact being redirected to public issues' mut_template_security_contact_changed

mut_template_protocol_wire_heading_comment_decoy() {
    replace_template_text .github/ISSUE_TEMPLATE/protocol-mismatch.md \
        '## 3. Wire evidence (MANDATORY — provide at least one, both is better)' \
        '<!-- ## 3. Wire evidence (MANDATORY — provide at least one, both is better) -->'
}
expect_fail check_template_contract.sh \
    'the mandatory wire-evidence section becoming a comment decoy' mut_template_protocol_wire_heading_comment_decoy

mut_template_protocol_redaction_removed() {
    replace_template_text .github/ISSUE_TEMPLATE/protocol-mismatch.md \
        'REDACTION IS MANDATORY BEFORE PASTING.' \
        'CAPTURE DETAILS FOLLOW.'
}
expect_fail check_template_contract.sh \
    'the protocol report losing its redaction requirement' mut_template_protocol_redaction_removed

mut_template_protocol_close_rule_removed() {
    replace_template_text .github/ISSUE_TEMPLATE/protocol-mismatch.md \
        'will be closed immediately' 'may need follow-up'
}
expect_fail check_template_contract.sh \
    'the protocol template losing its no-evidence close rule' mut_template_protocol_close_rule_removed

mut_template_protocol_debug_capture_removed() {
    replace_template_text .github/ISSUE_TEMPLATE/protocol-mismatch.md \
        'aws --debug' 'aws --no-debug'
}
expect_fail check_template_contract.sh \
    'the protocol template losing one real debug capture instruction' mut_template_protocol_debug_capture_removed

mut_template_bug_security_route_removed() {
    replace_template_text .github/ISSUE_TEMPLATE/bug.md ' — see `SECURITY.md`.' '.'
}
expect_fail check_template_contract.sh \
    'the bug template losing its private security route' mut_template_bug_security_route_removed

mut_template_bug_rustc_version_removed() {
    replace_template_text .github/ISSUE_TEMPLATE/bug.md \
        '- `rustc -vV` output:' '- compiler version:'
}
expect_fail check_template_contract.sh \
    'the bug template losing its compiler-version field' mut_template_bug_rustc_version_removed

mut_template_operation_shares_contract_removed() {
    replace_template_text .github/ISSUE_TEMPLATE/new-operation.md \
        'is declared with a `//! Shares:` header.' \
        'is declared in prose.'
}
expect_fail check_template_contract.sh \
    'the new-operation template losing its shared-surface declaration' mut_template_operation_shares_contract_removed

mut_template_operation_official_url_removed() {
    replace_template_text .github/ISSUE_TEMPLATE/new-operation.md \
        '- **AWS API documentation URL**:' '- **Documentation**:'
}
expect_fail check_template_contract.sh \
    'the new-operation template losing its official API URL field' mut_template_operation_official_url_removed

mut_template_pr_role_heading_comment_decoy() {
    replace_template_text .github/pull_request_template.md \
        '## Role Verdicts' '<!-- ## Role Verdicts -->'
}
expect_fail check_template_contract.sh \
    'the PR role-verdict anchor surviving only inside a comment' mut_template_pr_role_heading_comment_decoy

mut_template_pr_role_row_comment_decoy() {
    replace_template_text .github/pull_request_template.md \
        '- simplicity-adversary:' '<!-- - simplicity-adversary: -->'
}
expect_fail check_template_contract.sh \
    'the PR role-verdict row surviving only inside a comment' mut_template_pr_role_row_comment_decoy

mut_template_pr_closes_field_removed() {
    replace_template_text .github/pull_request_template.md 'Closes #' 'Related issue:'
}
expect_fail check_template_contract.sh \
    'the PR template losing its issue-closing field' mut_template_pr_closes_field_removed

mut_template_pr_verification_command_weakened() {
    replace_template_text .github/pull_request_template.md \
        '$ cargo clippy --workspace --all-targets -- -D warnings' \
        '$ cargo clippy --workspace'
}
expect_fail check_template_contract.sh \
    'the PR template weakening one four-command gate instruction' mut_template_pr_verification_command_weakened

mut_template_pr_breaking_checkbox_comment_decoy() {
    replace_template_text .github/pull_request_template.md \
        '- [ ] BREAKING — this PR touches a protected file or changes a public contract.' \
        '<!-- - [ ] BREAKING — this PR touches a protected file or changes a public contract. -->'
}
expect_fail check_template_contract.sh \
    'the PR BREAKING checkbox surviving only inside a comment' mut_template_pr_breaking_checkbox_comment_decoy

mut_template_pr_migration_prompt_removed() {
    replace_template_text .github/pull_request_template.md \
        'describe the migration path here' 'describe the change here'
}
expect_fail check_template_contract.sh \
    'the PR template losing its protected-file migration prompt' mut_template_pr_migration_prompt_removed

mut_template_file_deleted() {
    rm -f .github/ISSUE_TEMPLATE/new-operation.md
}
expect_fail check_template_contract.sh \
    "one of the guard's six template inputs deleted, which must fail rather than skip" mut_template_file_deleted

probe_template_guard_missing_ruby() {
    local output rc=0 sandbox
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    output="$(GATEWAY_CHECK_ROOT="$sandbox" PATH=/nonexistent /bin/bash \
        "${SCRIPT_DIR}/check_template_contract.sh" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: ruby'* ]]; then
        pass_msg 'check_template_contract.sh fails closed without ruby'
    else
        fail_msg 'check_template_contract.sh reported green without ruby'
    fi
}
probe_template_guard_missing_ruby

# The codegen feedback loop must not rebuild product crates before generation starts.
mut_xtask_codegen_alias_bypasses_launcher() {
    perl -0pi -e 's#run --quiet --package xtask-launcher --#run --quiet --package xtask --no-default-features --#' .cargo/config.toml
}
expect_fail check_xtask_codegen_surface.sh \
    'the cargo xtask alias bypassing the budget-aware launcher' \
    mut_xtask_codegen_alias_bypasses_launcher

mut_xtask_crate_runner_returns_to_light_graph() {
    perl -0pi -e 's/const FULL_RUNNER: &\[&str\] = &\["--features", "full"\];/const FULL_RUNNER: \&[\&str] = \&["--no-default-features"];/' \
        xtask-launcher/src/main.rs
}
expect_fail check_xtask_codegen_surface.sh \
    'non-facade crate verification rebuilding the light runner after the workspace gate' \
    mut_xtask_crate_runner_returns_to_light_graph

mut_xtask_operation_runner_uses_full_graph() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask-launcher/src/main.rs")
text = path.read_text()
old = '        return OPERATION_RUNNER;'
new = '        return FULL_RUNNER;'
if text.count(old) != 1:
    raise SystemExit("the operation runner selection is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'operation verification returning to the production server graph' \
    mut_xtask_operation_runner_uses_full_graph

mut_xtask_facade_runner_returns_to_full_graph() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask-launcher/src/main.rs")
text = path.read_text()
old = 'Some("rustfs-gateway" | "s3gate" | "rustfs-gateway-conformance" | "s3gate-conformance" | "conformance")'
new = 'Some("rustfs-gateway-conformance" | "s3gate-conformance" | "conformance")'
if text.count(old) != 1:
    raise SystemExit("the light facade and conformance selection is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'facade verification re-entering the full dependency graph' \
    mut_xtask_facade_runner_returns_to_full_graph

mut_xtask_conformance_runner_returns_to_full_graph() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask-launcher/src/main.rs")
text = path.read_text()
old = 'Some("rustfs-gateway" | "s3gate" | "rustfs-gateway-conformance" | "s3gate-conformance" | "conformance")'
new = 'Some("rustfs-gateway" | "s3gate")'
if text.count(old) != 1:
    raise SystemExit("the light facade and conformance selection is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'conformance verification re-entering the full dependency graph' \
    mut_xtask_conformance_runner_returns_to_full_graph

mut_xtask_selection_module_becomes_full_only() {
    python3 - <<'PYEOF'
from pathlib import Path

verify = Path("xtask/src/verify.rs")
selection = Path("xtask/src/verify/selection.rs")
text = verify.read_text()
if not selection.exists():
    start = text.index("fn crate_steps")
    body = text.index("{", start)
    depth = 0
    end = None
    for index in range(body, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break
    if end is None:
        raise SystemExit("crate_steps body is unbalanced")
    selection.write_text("pub(super) " + text[start:end] + "\n")
    text = text[:start] + text[end:]
    text = text.replace("mod process;", "mod process;\n#[cfg(feature = \"full\")]\nmod selection;", 1)
    text = text.replace("use launcher::launcher_started;", "use launcher::launcher_started;\nuse selection::crate_steps;", 1)
else:
    text = text.replace("mod selection;", '#[cfg(feature = "full")]\nmod selection;', 1)
verify.write_text(text)
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the extracted crate-step selection becoming full-only' \
    mut_xtask_selection_module_becomes_full_only

mut_xtask_launcher_timestamp_removed() {
    perl -0pi -e 's/started\.as_nanos\(\)\.to_string\(\)/"0".to_owned()/' xtask-launcher/src/main.rs
}
expect_fail check_xtask_codegen_surface.sh \
    'the launcher no longer recording command startup' mut_xtask_launcher_timestamp_removed

mut_xtask_verify_ignores_launcher_time() {
    perl -0pi -e 's/        started: started\.and_then\(\|started\| started\.checked_add\(build\.elapsed\)\),\n/        started: None,\n/' xtask/src/verify.rs
}
expect_fail check_xtask_codegen_surface.sh \
    'crate verification ignoring launcher time' mut_xtask_verify_ignores_launcher_time

mut_xtask_codegen_gateway_becomes_nonoptional() {
    perl -0pi -e 's/rustfs-gateway = \{ workspace = true, optional = true \}/rustfs-gateway = { workspace = true }/' \
        xtask/Cargo.toml
}
expect_fail check_xtask_codegen_surface.sh \
    'the light codegen runner regaining the facade dependency' \
    mut_xtask_codegen_gateway_becomes_nonoptional

mut_xtask_full_forgets_conformance() {
    perl -0pi -e 's/    "dep:rustfs-gateway-conformance",\n//' xtask/Cargo.toml
}
expect_fail check_xtask_codegen_surface.sh \
    'the full xtask feature dropping a full-only dependency edge' \
    mut_xtask_full_forgets_conformance

mut_xtask_codegen_reexecutes_full_runner() {
    perl -0pi -e 's/Some\("codegen"\) => codegen::codegen\(&rest\)/Some("codegen") => run_full(first.clone(), \&rest)/g' \
        xtask/src/main.rs
}
expect_fail check_xtask_codegen_surface.sh \
    'the codegen command re-entering the full dependency surface' \
    mut_xtask_codegen_reexecutes_full_runner

mut_xtask_codegen_comment_decoy_reexec() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = 'Some("codegen") => codegen::codegen(&rest),'
positions = [index for index in range(len(text)) if text.startswith(old, index)]
if len(positions) != 2:
    raise SystemExit("expected exactly two codegen dispatch arms")
index = positions[1]
new = 'Some("codegen") => run_full(first.clone(), &rest), // Some("codegen") => codegen::codegen(&rest),'
path.write_text(text[:index] + new + text[index + len(old):])
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'a comment decoy hiding light codegen re-execution' \
    mut_xtask_codegen_comment_decoy_reexec

mut_xtask_codegen_target_dependency() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/Cargo.toml")
text = path.read_text()
text += '''
[target.'cfg(unix)'.dependencies]
hidden_gateway = { package = "rustfs-gateway", path = "../crates/gateway" }
'''
path.write_text(text)
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'a target-specific dependency restoring the facade on the light runner' \
    mut_xtask_codegen_target_dependency

mut_xtask_full_runner_drops_rest() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = "    command.args(rest);"
new = "    let _ = rest; // command.args(rest);"
if text.count(old) != 1:
    raise SystemExit("full runner rest forwarding is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the full runner dropping the remaining arguments' \
    mut_xtask_full_runner_drops_rest

mut_xtask_nonunix_runner_hides_failure() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = "        Ok(status) => std::process::exit(status.code().unwrap_or(1)),"
new = "        Ok(_) => std::process::exit(0),"
if text.count(old) != 1:
    raise SystemExit("non-Unix i32 status propagation is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the non-Unix bridge reporting a failing child as success' \
    mut_xtask_nonunix_runner_hides_failure

mut_xtask_codegen_string_token_changes() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = 'Some("codegen") => codegen::codegen(&rest),'
positions = [index for index in range(len(text)) if text.startswith(old, index)]
if len(positions) != 2:
    raise SystemExit("expected exactly two codegen dispatch arms")
index = positions[1]
new = 'Some("code gen") => codegen::codegen(&rest),'
path.write_text(text[:index] + new + text[index + len(old):])
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'whitespace changing the light codegen command token' \
    mut_xtask_codegen_string_token_changes

mut_xtask_full_feature_string_token_changes() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = 'command.args(["run", "--quiet", "--package", "xtask", "--features", "full", "--"]);'
new = 'command.args(["run", "--quiet", "--package", "xtask", "--features", "f ull", "--"]);'
if text.count(old) != 1:
    raise SystemExit("full feature runner arguments are missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'whitespace changing the full-runner feature token' \
    mut_xtask_full_feature_string_token_changes

mut_xtask_light_builds_full_catalog_helper() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/catalog.rs")
text = path.read_text()
old = '#[cfg(feature = "operation")]\npub(crate) fn nearest'
if text.count(old) != 1:
    raise SystemExit("operation-only catalog helper is missing")
path.write_text(text.replace(old, "pub(crate) fn nearest", 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the light runner compiling an operation-only catalog helper' \
    mut_xtask_light_builds_full_catalog_helper

mut_xtask_light_builds_full_usage() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = '#[cfg(feature = "full")]\nconst USAGE: &str'
if text.count(old) != 1:
    raise SystemExit("full-only usage declaration is missing")
path.write_text(text.replace(old, "const USAGE: &str", 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the light runner compiling the full-only usage text' \
    mut_xtask_light_builds_full_usage

mut_xtask_crate_verify_reexecutes_full_runner() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = 'Some("verify") if verify::is_available_request(&rest) => verify::verify(&rest),'
new = 'Some("verify") if verify::is_available_request(&rest) => run_full(first, &rest),'
if text.count(old) != 1:
    raise SystemExit("expected exactly one light crate-verification dispatch arm")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'exact crate verification re-entering the full runner' \
    mut_xtask_crate_verify_reexecutes_full_runner

mut_xtask_crate_verify_drops_arguments() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = 'Some("verify") if verify::is_available_request(&rest) => verify::verify(&rest),'
new = 'Some("verify") if verify::is_available_request(&rest) => verify::verify(&[]),'
if text.count(old) != 1:
    raise SystemExit("expected exactly one light crate-verification dispatch arm")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the light crate-verification runner dropping its arguments' \
    mut_xtask_crate_verify_drops_arguments

mut_xtask_process_supervisor_becomes_full_only() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/Cargo.toml")
text = path.read_text()
old = "command-group.workspace = true"
new = "command-group = { workspace = true, optional = true }"
if text.count(old) != 1:
    raise SystemExit("light process-supervisor dependency is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the crate-verification process supervisor becoming full-only' \
    mut_xtask_process_supervisor_becomes_full_only

mut_xtask_full_gate_leaks_into_light_surface() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '#[cfg(feature = "full")]\nmod full_gate;'
if text.count(old) != 1:
    raise SystemExit("full-only gate stage runner module is missing")
path.write_text(text.replace(old, "mod full_gate;", 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the full-gate stage runner leaking into the light crate surface' \
    mut_xtask_full_gate_leaks_into_light_surface

mut_xtask_verify_operation_loses_operation_gate() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '#[cfg(feature = "operation")]\nfn verify_operation'
new = 'fn verify_operation'
if text.count(old) != 1:
    raise SystemExit("operation-only verifier is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'an operation-only verifier leaking into the light crate surface' \
    mut_xtask_verify_operation_loses_operation_gate

mut_xtask_operation_conformance_runner_leaks_into_light_surface() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '#[cfg(feature = "operation")]\nfn run_representative_case'
new = 'fn run_representative_case'
if text.count(old) != 1:
    raise SystemExit("full-only operation conformance runner is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the operation conformance runner leaking into the light crate surface' \
    mut_xtask_operation_conformance_runner_leaks_into_light_surface

mut_xtask_full_verify_uses_unstable_slice_conversion() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = "fn verify_full(args: &[String], json: bool) -> ExitCode {\n    match args {"
new = "fn verify_full(args: &[String], json: bool) -> ExitCode {\n    match args.as_slice() {"
if text.count(old) != 1:
    raise SystemExit("borrowed full-verification slice match is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'full verification calling unstable as_slice on an existing slice' \
    mut_xtask_full_verify_uses_unstable_slice_conversion

mut_xtask_core_fast_scope_loses_compile_fail_skip() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify/selection.rs")
if not path.exists():
    path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '''                "--".to_owned(),
                "--skip".to_owned(),
                "compile_fail::compile_time_contracts_are_not_openable".to_owned(),
'''
new = '''
'''
if text.count(old) != 1:
    raise SystemExit("core compile-fail fast-scope skip is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the core fast scope losing its compile-fail skip' \
    mut_xtask_core_fast_scope_loses_compile_fail_skip

mut_xtask_core_fast_scope_drops_library_tests() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify/selection.rs")
if not path.exists():
    path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '''                package.to_owned(),
                "--lib".to_owned(),
                "--test".to_owned(),
'''
new = '''                package.to_owned(),
                "--test".to_owned(),
'''
if text.count(old) != 1:
    raise SystemExit("core library runtime step is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the core fast scope dropping its library tests' \
    mut_xtask_core_fast_scope_drops_library_tests

mut_xtask_core_fast_scope_drops_integration_tests() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify/selection.rs")
if not path.exists():
    path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '''                "--lib".to_owned(),
                "--test".to_owned(),
                "integration".to_owned(),
'''
new = '''                "--lib".to_owned(),
'''
if text.count(old) != 1:
    raise SystemExit("core integration runtime step is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the core fast scope dropping its integration tests' \
    mut_xtask_core_fast_scope_drops_integration_tests

mut_xtask_gateway_fast_scope_loses_compile_fail_skip() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify/selection.rs")
if not path.exists():
    path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '''        test_step.extend([
            "--".to_owned(),
            "--skip".to_owned(),
            "compile_fail::gateway_compile_fail_contracts_are_enforced".to_owned(),
        ]);
'''
new = ''''''
if text.count(old) != 1:
    raise SystemExit("gateway compile-fail fast-scope skip is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the gateway fast scope losing its compile-fail skip' \
    mut_xtask_gateway_fast_scope_loses_compile_fail_skip

mut_xtask_gateway_fast_scope_drops_library_tests() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify/selection.rs")
if not path.exists():
    path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '        test_step.extend(["--lib".to_owned(), "--test".to_owned(), "integration".to_owned()]);'
new = '        test_step.extend(["--test".to_owned(), "integration".to_owned()]);'
if text.count(old) != 1:
    raise SystemExit("gateway bounded runtime target list is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the gateway fast scope dropping its library tests' \
    mut_xtask_gateway_fast_scope_drops_library_tests

mut_xtask_gateway_fast_scope_drops_integration_tests() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify/selection.rs")
if not path.exists():
    path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '        test_step.extend(["--lib".to_owned(), "--test".to_owned(), "integration".to_owned()]);'
new = '        test_step.push("--lib".to_owned());'
if text.count(old) != 1:
    raise SystemExit("gateway bounded runtime target list is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the gateway fast scope dropping its integration tests' \
    mut_xtask_gateway_fast_scope_drops_integration_tests

mut_xtask_gateway_fast_scope_drops_its_conformance_case() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/conformance/src/cli.rs")
text = path.read_text()
old = "    fn feedback_case_c_object_0001() {"
new = "    fn feedback_case_c_object_0001_removed() {"
if text.count(old) != 1:
    raise SystemExit("workspace-only gateway conformance case is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the workspace gate dropping the gateway representative conformance case' \
    mut_xtask_gateway_fast_scope_drops_its_conformance_case

mut_xtask_gateway_fast_scope_runs_rss_stress() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '    test.extend(["--skip".to_owned(), GATEWAY_RSS_TEST.to_owned()]);'
new = ""
if text.count(old) != 1:
    raise SystemExit("gateway RSS fast-scope exclusion is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the gateway fast scope rerunning its million-key workspace stress contract' \
    mut_xtask_gateway_fast_scope_runs_rss_stress

mut_xtask_server_fast_scope_runs_c_lim_0006() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
subject = '            "c_lim_0006_a_srv_0008_one_thousand_connections_stay_inside_the_rss_budget".to_owned(),\n'
if text.count(subject) != 1:
    raise SystemExit("server c-lim-0006 fast-scope exclusion is not unique")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the server fast scope rerunning the c-lim-0006 thousand-connection load contract' \
    mut_xtask_server_fast_scope_runs_c_lim_0006

mut_xtask_server_fast_scope_runs_c_lim_0061() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
subject = '            "c_lim_0061_a_srv_0026_one_thousand_slow_readers_close_without_starving_healthy_traffic".to_owned(),\n'
if text.count(subject) != 1:
    raise SystemExit("server c-lim-0061 fast-scope exclusion is not unique")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the server fast scope rerunning the c-lim-0061 thousand-reader load contract' \
    mut_xtask_server_fast_scope_runs_c_lim_0061

mut_xtask_gateway_conformance_runs_twice() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '(package != "rustfs-gateway").then(|| crate_case(package)).flatten()'
new = 'crate_case(package)'
if text.count(old) != 1:
    raise SystemExit("gateway standalone conformance suppression is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the representative conformance case rejoining the gateway fast scope' \
    mut_xtask_gateway_conformance_runs_twice

mut_xtask_gateway_rss_contract_disappears() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/cors_runtime.rs")
text = path.read_text()
old = "fn a_million_unique_keys_keep_rss_within_the_entry_budget() {"
new = "fn a_million_unique_keys_keep_rss_within_the_entry_budget_removed() {"
if text.count(old) != 1:
    raise SystemExit("workspace-only gateway RSS contract is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the workspace gate dropping the gateway million-key RSS contract' \
    mut_xtask_gateway_rss_contract_disappears

mut_xtask_sig_fast_scope_loses_exact_matching() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify/selection.rs")
text = path.read_text()
old = '                "--exact",\n'
if text.count(old) != 1:
    raise SystemExit("signature fast-scope exact selector is missing")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the signature fast scope broadening its statistical timing skips' \
    mut_xtask_sig_fast_scope_loses_exact_matching

mut_xtask_core_fast_scope_renames_compile_fail_skip() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify/selection.rs")
if not path.exists():
    path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '"compile_fail::compile_time_contracts_are_not_openable".to_owned(),'
new = '"compile_fail::renamed_contract".to_owned(),'
if text.count(old) != 1:
    raise SystemExit("core compile-fail skip name is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the core fast scope naming a nonexistent skipped test' \
    mut_xtask_core_fast_scope_renames_compile_fail_skip

mut_xtask_compile_fail_skip_applies_to_every_crate() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify/selection.rs")
if not path.exists():
    path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '    if package == "rustfs-gateway-core" {'
new = '    if !package.is_empty() {'
if text.count(old) != 1:
    raise SystemExit("core-only skip condition is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the core compile-fail skip leaking into another crate scope' \
    mut_xtask_compile_fail_skip_applies_to_every_crate

mut_xtask_conformance_fast_scope_loses_library_limit() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify/selection.rs")
if not path.exists():
    path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '''    } else if package == "rustfs-gateway-conformance" {
        test_step.push("--lib".to_owned());
'''
new = '''    } else if package == "rustfs-gateway-conformance" {
'''
if text.count(old) != 1:
    raise SystemExit("conformance library fast-scope limit is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the conformance fast scope losing its library-only test limit' \
    mut_xtask_conformance_fast_scope_loses_library_limit

mut_xtask_conformance_scope_restores_all_target_clippy() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify/selection.rs")
if not path.exists():
    path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '            "rustfs-gateway-conformance" => "--lib",'
new = '            "rustfs-gateway-conformance-disabled" => "--lib",'
if text.count(old) != 1:
    raise SystemExit("conformance library-only clippy scope is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the conformance fast scope restoring all-target clippy' \
    mut_xtask_conformance_scope_restores_all_target_clippy

mut_xtask_workspace_target_reuse_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify/selection.rs")
if not path.exists():
    path = Path("xtask/src/verify.rs")
text = path.read_text()
old = 'let target_scope = ["--workspace", "--bin", "xtask", "--test", "xtask-integration"];'
new = 'let target_scope = ["--bin", "xtask", "--test", "xtask-integration"];'
if text.count(old) != 1:
    raise SystemExit("xtask workspace target scope is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'xtask verification losing workspace feature reuse' \
    mut_xtask_workspace_target_reuse_removed

mut_xtask_clippy_omits_the_integration_target() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify/selection.rs")
if not path.exists():
    path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '''            std::iter::once("clippy")
                .chain(target_scope)
                .chain(["--", "-D", "warnings"])
'''
new = '''            std::iter::once("clippy")
                .chain(["--", "-D", "warnings"])
'''
if text.count(old) != 1:
    raise SystemExit("xtask clippy target scope is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'xtask clippy omitting the integration target' \
    mut_xtask_clippy_omits_the_integration_target

mut_xtask_crate_classifier_leaks_into_full_build() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '#[cfg(not(feature = "full"))]\npub(crate) fn is_available_request'
new = 'pub(crate) fn is_available_request'
if text.count(old) != 1:
    raise SystemExit("light-only crate classifier is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the light crate classifier leaking as dead code into full builds' \
    mut_xtask_crate_classifier_leaks_into_full_build

mut_xtask_light_gate_result_becomes_full_only() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = "type GateResult = (String, std::io::Result<Output>);"
new = '#[cfg(feature = "full")]\n' + old
if text.count(old) != 1:
    raise SystemExit("light gate-result carrier is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the gate-result carrier becoming unavailable to light crate verification' \
    mut_xtask_light_gate_result_becomes_full_only

mut_xtask_light_gate_command_becomes_full_only() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = "type GateCommand = (String, Vec<String>, String);"
new = '#[cfg(feature = "full")]\n' + old
if text.count(old) != 1:
    raise SystemExit("light gate-command carrier is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the gate-command carrier becoming unavailable to light crate verification' \
    mut_xtask_light_gate_command_becomes_full_only

mut_xtask_light_output_import_becomes_full_only() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = "use std::process::{Command, ExitCode, Output};"
new = '#[cfg(feature = "full")]\n' + old
if text.count(old) != 1:
    raise SystemExit("light process-output import is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the process-output import becoming unavailable to light crate verification' \
    mut_xtask_light_output_import_becomes_full_only

mut_xtask_full_forwards_dangerous_dependency_feature() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/Cargo.toml")
text = path.read_text()
old = '    "dep:rustfs-gateway",'
new = old + '\n    "rustfs-gateway/dangerous-allow-all-authorizer",'
if text.count(old) != 1:
    raise SystemExit("full facade dependency feature is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the full feature forwarding a dangerous facade feature' \
    mut_xtask_full_forwards_dangerous_dependency_feature

mut_xtask_facade_dependency_enables_dangerous_feature() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/Cargo.toml")
text = path.read_text()
old = "rustfs-gateway = { workspace = true, optional = true }"
new = 'rustfs-gateway = { workspace = true, optional = true, features = ["dangerous-allow-all-authorizer"] }'
if text.count(old) != 1:
    raise SystemExit("optional facade dependency is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the local facade dependency enabling its dangerous authorizer feature' \
    mut_xtask_facade_dependency_enables_dangerous_feature

mut_xtask_local_dependency_changes_default_features() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/Cargo.toml")
text = path.read_text()
old = "signal-hook.workspace = true"
new = "signal-hook = { workspace = true, default-features = false }"
if text.count(old) != 1:
    raise SystemExit("light signal-hook dependency is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'a local dependency overriding inherited default features' \
    mut_xtask_local_dependency_changes_default_features

mut_xtask_inherits_dangerous_facade_feature() {
    python3 - <<'PYEOF'
import re
from pathlib import Path

# The version is matched rather than spelled out. It used to be literal, and a facade version
# bump then made this control fail as "anchor is missing" — a control that reports a defect it
# was not testing for is one nobody trusts the next time.
path = Path("Cargo.toml")
text = path.read_text()
pattern = re.compile(r'^rustfs-gateway = \{ path = "crates/gateway", version = "[0-9]+\.[0-9]+\.[0-9]+", default-features = false \}$', re.M)
found = pattern.findall(text)
if len(found) != 1:
    raise SystemExit("workspace facade dependency is missing")
replacement = found[0][: -len(" }")] + ', features = ["dangerous-allow-all-authorizer"] }'
path.write_text(pattern.sub(lambda _: replacement, text, count=1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the workspace facade dependency injecting its dangerous authorizer feature' \
    mut_xtask_inherits_dangerous_facade_feature

mut_xtask_operation_restores_server_default() {
    perl -0pi -e 's/, default-features = false//' Cargo.toml
}
expect_fail check_xtask_codegen_surface.sh \
    'operation verification restoring the facade server default' \
    mut_xtask_operation_restores_server_default

mut_xtask_operation_restores_conformance_default() {
    python3 - <<'PYEOF'
import re
from pathlib import Path

path = Path("Cargo.toml")
text = path.read_text()
pattern = re.compile(r'^(rustfs-gateway-conformance = \{ path = "crates/conformance", version = "[0-9]+\.[0-9]+\.[0-9]+"), default-features = false \}$', re.M)
if len(pattern.findall(text)) != 1:
    raise SystemExit("workspace conformance dependency policy is missing")
path.write_text(pattern.sub(r'\1 }', text, count=1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'operation verification restoring the production transport compile graph' \
    mut_xtask_operation_restores_conformance_default

mut_conformance_production_transport_feature_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/conformance/Cargo.toml")
text = path.read_text()
old = 'production-transports = ["rustfs-gateway/server"]'
if text.count(old) != 1:
    raise SystemExit("production transport feature is missing")
path.write_text(text.replace(old, 'production-transports = []', 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the production transport feature losing the real server graph' \
    mut_conformance_production_transport_feature_removed

mut_case_key_audit_restores_production_transport_graph() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/check_case_keys_honoured.sh")
text = path.read_text()
old = "cargo run -q -p rustfs-gateway-conformance --no-default-features --bin rustfs-gateway-conformance -- audit-keys"
new = "cargo run -q -p rustfs-gateway-conformance --bin rustfs-gateway-conformance -- audit-keys"
if text.count(old) != 1:
    raise SystemExit("light case-key audit command is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the case-key audit restoring the production transport compile graph' \
    mut_case_key_audit_restores_production_transport_graph

mut_xtask_inherits_jsonschema_default_features() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("Cargo.toml")
text = path.read_text()
old = 'jsonschema = { version = "0.48.2", default-features = false }'
new = 'jsonschema = { version = "0.48.2", default-features = true }'
if text.count(old) != 1:
    raise SystemExit("workspace jsonschema dependency policy is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the workspace jsonschema dependency restoring default features' \
    mut_xtask_inherits_jsonschema_default_features

mut_xtask_nonunix_runner_truncates_large_status() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = "        Ok(status) => std::process::exit(status.code().unwrap_or(1)),"
new = "        Ok(status) => return ExitCode::from(status.code().unwrap_or(1) as u8),"
if text.count(old) != 1:
    raise SystemExit("non-Unix i32 status propagation is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the non-Unix bridge truncating a child status above 255' \
    mut_xtask_nonunix_runner_truncates_large_status

mut_scalar_duplicate_acceptance_id() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/check_scalar_case_coverage.sh")
text = path.read_text()
old = "for n in 001 002 003 004 005 006 007 008 009 010; do"
new = "for n in 001 002 003 004 005 006 007 008 009 009; do"
if old not in text:
    raise SystemExit("scalar acceptance id loop is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail_self_mutation check_scalar_case_coverage.sh \
    'one acceptance id replacing another while the total stays 71' mut_scalar_duplicate_acceptance_id

mut_scalar_test_replaced_by_comment_and_string() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/tests/name_tests.rs")
text = path.read_text()
old = "#[test]\nfn c_name_n009_a_dotted_bucket_is_legal_but_not_vhost_safe()"
new = '''// #[test]
// fn c_name_n009_a_dotted_bucket_is_legal_but_not_vhost_safe() {}
const DECOY: &str = "fn c_name_n009_a_";
#[test]
fn removed_name_n009_a_dotted_bucket_is_legal_but_not_vhost_safe()'''
if old not in text:
    raise SystemExit("scalar test mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_scalar_case_coverage.sh \
    'comments and strings replacing a mapped scalar test' mut_scalar_test_replaced_by_comment_and_string

mut_scalar_objectlock_case_does_not_replace_ts_n006() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/tests/timestamp_tests.rs")
text = path.read_text()
old = "#[test]\nfn c_ts_n006_the_object_lock_header_only_accepts_iso8601()"
new = "#[test]\nfn removed_ts_n006_the_object_lock_header_only_accepts_iso8601()"
if text.count(old) != 1:
    raise SystemExit("c-ts-n006 scalar acceptance test is not unique")
if text.count("fn c_objectlock_0001_the_object_lock_header_only_accepts_iso8601()") != 1:
    raise SystemExit("c-objectlock-0001 quirk case must remain independently registered")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_scalar_case_coverage.sh \
    'the object-lock quirk case replacing the independent c-ts-n006 acceptance id' \
    mut_scalar_objectlock_case_does_not_replace_ts_n006

mut_scalar_id_maps_to_two_active_tests() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/tests/name_tests.rs")
text = path.read_text()
text += "\n#[test]\nfn c_name_n009_duplicate_atomic_evidence() {}\n"
path.write_text(text)
PYEOF
}
expect_fail check_scalar_case_coverage.sh \
    'one scalar id mapping to two active tests' mut_scalar_id_maps_to_two_active_tests

mut_scalar_test_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/tests/timestamp_corpus_tests.rs")
text = path.read_text()
old = "#[test]\nfn c_ts_0001_complete_smithy_timestamp_corpus_matches_gateway_codec()"
new = "#[cfg(any())]\n#[test]\nfn c_ts_0001_complete_smithy_timestamp_corpus_matches_gateway_codec()"
if old not in text:
    raise SystemExit("timestamp corpus test mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_scalar_case_coverage.sh \
    'a cfg-disabled scalar test being counted as executable evidence' mut_scalar_test_disabled_by_cfg

mut_scalar_test_module_unwired() {
    perl -0pi -e 's/^mod timestamp_corpus_tests;\n//m' crates/types/src/scalar/tests/mod.rs
}
expect_fail check_scalar_case_coverage.sh \
    'a scalar test file no longer wired into its parent module' mut_scalar_test_module_unwired

mut_scalar_test_file_disabled_by_cfg() {
    perl -0pi -e 's/^(\/\/ Copyright 2026 RustFS Team)/#![cfg(any())]\n$1/' \
        crates/types/src/scalar/tests/timestamp_corpus_tests.rs
}
expect_fail check_scalar_case_coverage.sh \
    'a file-level cfg disabling mapped scalar tests' mut_scalar_test_file_disabled_by_cfg

mut_scalar_test_file_disabled_by_cfg_attr() {
    perl -0pi -e 's/^(\/\/ Copyright 2026 RustFS Team)/#![cfg_attr(all(), cfg(any()))]\n$1/' \
        crates/types/src/scalar/tests/timestamp_corpus_tests.rs
}
expect_fail check_scalar_case_coverage.sh \
    'a file-level cfg_attr disabling mapped scalar tests' mut_scalar_test_file_disabled_by_cfg_attr

mut_scalar_test_replaced_by_macro_body() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/tests/range_tests.rs")
text = path.read_text()
old = "#[test]\nfn c_rng_0001_a_closed_range_resolves_to_itself()"
new = '''macro_rules! decoy_scalar_test {
    () => {
        #[test]
        fn c_rng_0001_a_closed_range_resolves_to_itself() {}
    };
}
#[test]
fn removed_rng_0001_a_closed_range_resolves_to_itself()'''
if old not in text:
    raise SystemExit("range test mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_scalar_case_coverage.sh \
    'a test name surviving only inside an unexpanded macro body' mut_scalar_test_replaced_by_macro_body

mut_scalar_case_id_replaced_by_comment() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("conformance/cases/range/c-range-0015.toml")
text = path.read_text()
old = 'id = "c-range-0015"'
new = '# id = "c-range-0015"\nid = "removed-range-0015"'
if old not in text:
    raise SystemExit("range case id mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_scalar_case_coverage.sh \
    'a commented TOML id replacing the active conformance case id' mut_scalar_case_id_replaced_by_comment

# -- check_object_semantics_ledger.sh -------------------------------------------------------------
#
# The ledger owes three separable deaths, one per mutation class its header names. They are written
# out rather than looped because each one has to fail for its *own* diagnostic: a roll-call failure
# and an arithmetic failure read identically in a green/red summary, and the whole point of the
# split is that they are different mistakes.

mut_object_ledger_row_id_duplicated() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/check_object_semantics_ledger.sh")
text = path.read_text()
old = "    'c-obj-0019|positive|bound|"
new = "    'c-obj-0018|positive|bound|"
if text.count(old) != 1:
    raise SystemExit("object ledger row mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
# Mutation 1: one mapping stops existing. The polarity arithmetic is deliberately left intact by
# renaming rather than deleting, so this case can only be caught by the roll call.
expect_fail_self_mutation check_object_semantics_ledger.sh \
    'a §7 rule losing its mapping while the polarity totals still add up' \
    mut_object_ledger_row_id_duplicated

mut_object_ledger_row_polarity_flipped() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/check_object_semantics_ledger.sh")
text = path.read_text()
old = "    'c-obj-0019|positive|bound|"
new = "    'c-obj-0019|negative|bound|"
if text.count(old) != 1:
    raise SystemExit("object ledger polarity mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
# Mutation 3, first half: a rule relabelled to the other kind of evidence.
expect_fail_self_mutation check_object_semantics_ledger.sh \
    "a §7 rule's polarity flipped in the ledger" \
    mut_object_ledger_row_polarity_flipped

mut_object_ledger_assertion_deleted() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("conformance/cases/object/c-object-0006.toml")
text = path.read_text()
old = '"expires" = "not-a-date-at-all"\n'
if text.count(old) != 1:
    raise SystemExit("opaque-expires assertion mutation subject is not unique")
path.write_text(text.replace(old, "", 1))
PYEOF
}
# Mutation 2: the case keeps its id, its title and its rationale, and quietly stops asserting the
# rule the ledger says it settles. This is the shape that made two audits disagree.
expect_fail_with_diagnostic check_object_semantics_ledger.sh \
    'a mapped case dropping the assertion the ledger names' \
    'no longer carries an assertion at /exchanges/1/expect/headers_present/expires' \
    mut_object_ledger_assertion_deleted

mut_object_ledger_assertion_value_changed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("conformance/cases/object/c-object-0017.toml")
text = path.read_text()
old = '"content-type" = "binary/octet-stream"'
new = '"content-type" = "application/octet-stream"'
if text.count(old) != 1:
    raise SystemExit("default media type mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
# The assertion survives and answers a different rule. The IANA spelling is the exact substitution
# q-content-0008 exists to refuse, so a ledger that only checked the pointer would stay green here.
expect_fail_with_diagnostic check_object_semantics_ledger.sh \
    'a mapped assertion keeping its shape and changing its value' \
    "the ledger records 'binary/octet-stream'" \
    mut_object_ledger_assertion_value_changed

mut_object_ledger_case_polarity_flipped() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("conformance/cases/object/c-object-0024.toml")
text = path.read_text()
old = 'polarity = "positive"'
if text.count(old) != 1:
    raise SystemExit("case polarity mutation subject is not unique")
path.write_text(text.replace(old, 'polarity = "negative"', 1))
PYEOF
}
# Mutation 3, second half, and the independent one: the corpus's own label. `negative >= positive`
# is counted from these, so relabelling a case is how a suite buys headroom without writing a case.
expect_fail_with_diagnostic check_object_semantics_ledger.sh \
    "a mapped case's own polarity relabelled" \
    'the case declares' \
    mut_object_ledger_case_polarity_flipped

mut_object_ledger_blocked_row_without_owner() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/check_object_semantics_ledger.sh")
text = path.read_text()
old = "    'c-obj-0044|negative|bound|"
new = "    'c-obj-0044|negative|blocked|someone-will-do-it::"
if text.count(old) != 1:
    raise SystemExit("blocked-row owner mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
# A block with no owner is a gap nobody is carrying, which is the state the ledger exists to end.
expect_fail_self_mutation check_object_semantics_ledger.sh \
    'a blocked rule with no owning issue' \
    mut_object_ledger_blocked_row_without_owner

probe_object_ledger_guard_missing_python() {
    local output rc=0 tool_path
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-object-ledger-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_object_semantics_ledger.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: python3'* ]]; then
        pass_msg 'check_object_semantics_ledger.sh fails closed without python3'
    else
        fail_msg 'check_object_semantics_ledger.sh reported green without python3'
    fi
}
probe_object_ledger_guard_missing_python

# -- scripts/lib/python.sh ------------------------------------------------------------------------
#
# Three guards died in the middle of their inline programs on the macOS system interpreter
# (3.9.6): two on `import tomllib`, one on a PEP 604 union evaluated at runtime
# (rustfs/gateway#503, #583, #623). The interpreter is now resolved in one place against one
# floor, so the controls are: a below-floor interpreter is refused *by version*, with a line
# naming the floor and no traceback, before any program runs; an interpreter at the floor is
# accepted and the guard then passes on the clean tree; the resolver names the floor when only
# an old interpreter is on PATH and keeps the `required command is missing: python3` line when
# there is none; and lowering the floor makes the refusal disappear, which is what proves the
# refusal is the floor's doing.

python_floor_shim() {
    local shim
    shim="$(mktemp -d "${TMPDIR:-/tmp}/gateway-python-floor.XXXXXX")"
    printf '#!/bin/bash\ncase "$1" in -c) printf 3.9.6 ;; esac\n' >"${shim}/python3"
    chmod +x "${shim}/python3"
    printf '%s\n' "$shim"
}

probe_python_floor_refuses_a_below_floor_interpreter() {
    local guard shim output rc all_ok=1
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    shim="$(python_floor_shim)"
    for guard in check_ring_boundaries.sh check_object_semantics_ledger.sh check_op_file_shape.sh; do
        rc=0
        output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" GATEWAY_PYTHON="${shim}/python3" \
            bash "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
        if [[ "$rc" -eq 0 || "$output" != *'which is Python 3.9.6; the repository floor is 3.11'* || "$output" == *'Traceback'* ]]; then
            all_ok=0
            fail_msg "${guard} did not refuse a Python 3.9.6 interpreter by version: rc=${rc}: ${output}"
        fi
    done
    rm -rf "$shim"
    if [[ "$all_ok" -eq 1 ]]; then
        pass_msg 'the three floor-dependent guards refuse a Python 3.9.6 interpreter before running any program'
    fi
}
probe_python_floor_refuses_a_below_floor_interpreter

probe_python_floor_accepts_an_interpreter_at_the_floor() {
    local guard real output rc all_ok=1
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    real="$(bash -c 'source "$1/lib/python.sh"; gateway_python probe' _ "$SCRIPT_DIR")" || {
        fail_msg 'no interpreter at the repository floor is available to run the positive control'
        return
    }
    for guard in check_ring_boundaries.sh check_object_semantics_ledger.sh check_op_file_shape.sh; do
        rc=0
        output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" GATEWAY_PYTHON="$real" bash "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
        if [[ "$rc" -ne 0 ]]; then
            all_ok=0
            fail_msg "${guard} failed with an interpreter at the floor (${real}): ${output}"
        fi
    done
    if [[ "$all_ok" -eq 1 ]]; then
        pass_msg "the three floor-dependent guards pass with an interpreter at the floor (${real})"
    fi
}
probe_python_floor_accepts_an_interpreter_at_the_floor

probe_python_floor_resolver_names_the_floor_or_the_missing_tool() {
    local shim old_output old_rc=0 none_output none_rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    shim="$(python_floor_shim)"
    old_output="$(PATH="$shim" /bin/bash -c 'source "$1/lib/python.sh"; gateway_python probe' _ "$SCRIPT_DIR" 2>&1)" || old_rc=$?
    none_output="$(PATH="/nonexistent" /bin/bash -c 'source "$1/lib/python.sh"; gateway_python probe' _ "$SCRIPT_DIR" 2>&1)" || none_rc=$?
    rm -rf "$shim"
    if [[ "$old_rc" -ne 0 && "$old_output" == *"python3 is 3.9.6 at ${shim}/python3; the repository floor is Python 3.11"* &&
        "$none_rc" -ne 0 && "$none_output" == *'required command is missing: python3'* ]]; then
        pass_msg 'lib/python.sh names the floor for an old PATH interpreter and the missing tool for none'
    else
        fail_msg "lib/python.sh diagnostics drifted: old=${old_rc}:${old_output} none=${none_rc}:${none_output}"
    fi
}
probe_python_floor_resolver_names_the_floor_or_the_missing_tool

probe_python_floor_lowering_the_floor_admits_the_old_interpreter() {
    local shim lowered output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    shim="$(python_floor_shim)"
    lowered="$(mktemp "${TMPDIR:-/tmp}/gateway-python-lowered.XXXXXX")"
    sed 's/^GATEWAY_PYTHON_FLOOR_MINOR=11$/GATEWAY_PYTHON_FLOOR_MINOR=9/' "${SCRIPT_DIR}/lib/python.sh" >"$lowered"
    if ! grep -q '^GATEWAY_PYTHON_FLOOR_MINOR=9$' "$lowered"; then
        fail_msg 'the floor mutation changed nothing; lib/python.sh no longer spells the floor the way this case expects'
        rm -rf "$shim" "$lowered"
        return
    fi
    output="$(GATEWAY_PYTHON="${shim}/python3" bash -c 'source "$1"; gateway_python probe' _ "$lowered" 2>&1)" || rc=$?
    rm -rf "$shim" "$lowered"
    if [[ "$rc" -eq 0 && "$output" == *"/python3" ]]; then
        pass_msg 'lowering the floor admits the 3.9.6 shim, so the refusal above is the floor and not the shim'
    else
        fail_msg "lowering the floor did not admit the shim: rc=${rc}: ${output}"
    fi
}
probe_python_floor_lowering_the_floor_admits_the_old_interpreter

# -- check_response_encoding_ledger.sh -----------------------------------------------------------

mut_response_encoding_ledger_row_deleted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_response_encoding_ledger.sh")
text = path.read_text()
line = "    'c-enc-0008|positive|bound|conformance/cases/copy/c-copy-0038.toml::/expect/status=200;conformance/cases/copy/c-copy-0038.toml::/expect/error/code=NoSuchKey;conformance/cases/copy/c-copy-0038.toml::/expect/headers_absent/3=trailer'\n"
if text.count(line) != 1:
    raise SystemExit("response-encoding row mutation subject is not unique")
path.write_text(text.replace(line, "", 1))
PYEOF
}
expect_fail_self_mutation check_response_encoding_ledger.sh \
    'one of the 39 response-encoding mappings being deleted' \
    mut_response_encoding_ledger_row_deleted

mut_response_encoding_ledger_function_misspelled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_response_encoding_ledger.sh")
text = path.read_text()
old = "test fn a_head_keeps_the_headers_a_get_would_have_carried"
if text.count(old) != 1:
    raise SystemExit("response-encoding function mutation subject is not unique")
path.write_text(text.replace(old, "test fn a_head_keeps_only_a_decoy", 1))
PYEOF
}
expect_fail_self_mutation check_response_encoding_ledger.sh \
    'a mapped Rust test naming a nonexistent function' \
    mut_response_encoding_ledger_function_misspelled

mut_response_encoding_evidence_only_in_comment_and_string() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/codec/tests/metadata_and_url.rs")
text = path.read_text()
name = "metadata_encoded_words_are_decoded_for_storage_and_encoded_again_on_return"
old = f"fn {name}("
if text.count(old) != 1:
    raise SystemExit("response-encoding decoy mutation subject is not unique")
text = text.replace(old, f"fn removed_{name}(", 1)
text += f'\n// #[test] fn {name}() {{}}\nconst RESPONSE_ENCODING_DECOY: &str = "#[test] fn {name}() {{}}";\n'
path.write_text(text)
PYEOF
}
expect_fail check_response_encoding_ledger.sh \
    'a mapped test name surviving only in a comment and string' \
    mut_response_encoding_evidence_only_in_comment_and_string

mut_response_encoding_test_cfg_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/pipeline.rs")
text = path.read_text()
old = "#[tokio::test]\nasync fn a_not_modified_refusal_carries_neither_content_nor_a_framing_header()"
new = "#[cfg(any())]\n#[tokio::test]\nasync fn a_not_modified_refusal_carries_neither_content_nor_a_framing_header()"
if text.count(old) != 1:
    raise SystemExit("response-encoding cfg mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_response_encoding_ledger.sh \
    'a mapped response test being cfg-disabled' \
    mut_response_encoding_test_cfg_disabled

mut_response_encoding_raw_writer_exported() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/lib.rs")
text = path.read_text()
text += "\npub struct ResponseWriter;\nimpl ResponseWriter { pub fn write_raw(&self, _bytes: &[u8]) {} }\n"
path.write_text(text)
PYEOF
}
expect_fail check_response_encoding_ledger.sh \
    'a public raw response-writer escape hatch' \
    mut_response_encoding_raw_writer_exported

mut_response_encoding_trybuild_glob_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail.rs")
text = path.read_text()
old = '    cases.compile_fail("tests/compile_fail/committed_*.rs");'
if text.count(old) != 1:
    raise SystemExit("response-encoding trybuild mutation subject is not unique")
path.write_text(text.replace(old, '    cases.compile_fail("tests/compile_fail/removed_*.rs");', 1))
PYEOF
}
expect_fail check_response_encoding_ledger.sh \
    'the deferred-operation trybuild fixture leaving the harness' \
    mut_response_encoding_trybuild_glob_removed

mut_response_encoding_zero_window_evidence_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/committed_progress.rs")
text = path.read_text()
old = "fn c_enc_0060_complete_multipart_upload_finishes_behind_a_zero_window("
if text.count(old) != 1:
    raise SystemExit("response-encoding zero-window mutation subject is not unique")
path.write_text(text.replace(old, "fn removed_c_enc_0060_complete_multipart_upload_finishes_behind_a_zero_window(", 1))
PYEOF
}
expect_fail check_response_encoding_ledger.sh \
    'the CompleteMultipartUpload zero-window evidence disappearing' \
    mut_response_encoding_zero_window_evidence_removed

mut_response_encoding_commit_load_evidence_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/commit.rs")
text = path.read_text()
old = "fn c_enc_0065_five_hundred_twelve_commits_have_linear_timer_wakes("
if text.count(old) != 1:
    raise SystemExit("response-encoding commit-load mutation subject is not unique")
path.write_text(text.replace(old, "fn removed_c_enc_0065_five_hundred_twelve_commits_have_linear_timer_wakes(", 1))
PYEOF
}
expect_fail check_response_encoding_ledger.sh \
    'the 512-way committed timer evidence disappearing' \
    mut_response_encoding_commit_load_evidence_removed

mut_response_encoding_redirect_authority_bypassed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/service.rs")
text = path.read_text()
old = "crate::invariants::validate(&response, &self.inner.temporary_redirect_targets)"
if text.count(old) != 1:
    raise SystemExit("response-encoding redirect authority mutation subject is not unique")
path.write_text(text.replace(old, "crate::invariants::validate(&response, &[])", 1))
PYEOF
}
expect_fail check_response_encoding_ledger.sh \
    'the final response seam bypassing configured redirect authority' \
    mut_response_encoding_redirect_authority_bypassed

probe_scalar_case_guard_missing_python() {
    local output rc=0 tool_path
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scalar-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_scalar_case_coverage.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: python3'* ]]; then
        pass_msg 'check_scalar_case_coverage.sh fails closed without python3'
    else
        fail_msg 'check_scalar_case_coverage.sh reported green without python3'
    fi
}
probe_scalar_case_guard_missing_python

mut_etag_display_added() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/etag.rs")
path.write_text(path.read_text() + "\nimpl std::fmt::Display for ETag { fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) } }\n")
PYEOF
}
expect_fail check_etag_render.sh \
    'ETag acquiring a default Display rendering' mut_etag_display_added

mut_etag_into_string_added() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/etag.rs")
path.write_text(path.read_text() + "\nimpl From<ETag> for String { fn from(_: ETag) -> Self { String::new() } }\n")
PYEOF
}
expect_fail check_etag_render.sh \
    'ETag acquiring a default String conversion' mut_etag_into_string_added

mut_etag_contextual_render_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/etag.rs")
text = path.read_text()
path.write_text(text.replace("pub fn render(&self, ctx: EtagRender)", "pub fn render_default(&self, ctx: EtagRender)", 1))
PYEOF
}
expect_fail check_etag_render.sh \
    'the sole contextual ETag render entry being removed' mut_etag_contextual_render_removed

mut_opaque_date_parser_added() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/opaque_string.rs")
text = path.read_text()
path.write_text(text.replace("impl OpaqueString {", "impl OpaqueString {\n    pub fn parse_as_date(&self) {}", 1))
PYEOF
}
expect_fail check_opaque_string.sh \
    'OpaqueString acquiring a date parser' mut_opaque_date_parser_added

mut_checksum_default_features_enabled() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("Cargo.toml")
text = path.read_text()
path.write_text(text.replace("default-features = false, features = [\"std\"]", "default-features = true, features = [\"std\"]", 1))
PYEOF
}
expect_fail check_checksum_dependencies.sh \
    'crc-fast default features being enabled' mut_checksum_default_features_enabled

mut_checksum_workspace_inheritance_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("crc-fast = { workspace = true }", "crc-fast = { version = \"1.10\" }", 1))
PYEOF
}
expect_fail check_checksum_dependencies.sh \
    'the types crate bypassing the reviewed crc-fast declaration' mut_checksum_workspace_inheritance_removed

mut_crc_fast_unsafe_record_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/allowances/unsafe-code-allowances.txt")
text = path.read_text()
path.write_text("\n".join(line for line in text.splitlines() if not line.startswith("crc-fast|")) + "\n")
PYEOF
}
expect_fail check_unsafe_code_allowances.sh \
    'the crc-fast external unsafe record being removed' mut_crc_fast_unsafe_record_removed

mut_local_unsafe_added() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("fuzz/fuzz_targets/etag_parse.rs")
path.write_text(path.read_text() + "\nunsafe fn mutation_only() {}\n")
PYEOF
}
expect_fail check_unsafe_code_allowances.sh \
    'a local Rust file acquiring unsafe code' mut_local_unsafe_added

mut_second_s3_error_bridge() {
    printf '\nimpl From<rustfs_gateway_core::HandlerError> for S3Error {\n    fn from(_: rustfs_gateway_core::HandlerError) -> Self { todo!() }\n}\n' \
        >>crates/gateway/src/render.rs
}
expect_fail check_error_resolution_surface.sh \
    'a second public bridge constructing S3Error before resolution' mut_second_s3_error_bridge

mut_multiline_nested_s3_error_bridge() {
    printf '\nimpl\n    From<Option<ErrorResolution>> for S3Error\n{\n    fn from(_: Option<ErrorResolution>) -> Self { todo!() }\n}\n' \
        >>crates/gateway/src/render.rs
}
expect_fail check_error_resolution_surface.sh \
    'a multiline nested-generic From bridge constructing S3Error' mut_multiline_nested_s3_error_bridge

mut_s3_error_bridge_takes_handler() {
    perl -0pi -e 's/impl From<ErrorResolution> for S3Error/impl From<HandlerError> for S3Error/' \
        crates/gateway/src/render.rs
}
expect_fail check_error_resolution_surface.sh \
    'the sole S3Error bridge accepting an unresolved HandlerError' mut_s3_error_bridge_takes_handler

mut_s3_error_resource_writer() {
    perl -0pi -e 's/impl S3Error \{/impl S3Error {\n    pub fn about_resource(self, _: String) -> Self { self }/' \
        crates/gateway/src/render.rs
}
expect_fail check_error_resolution_surface.sh \
    'S3Error regaining a post-resolution resource writer' mut_s3_error_resource_writer

mut_handler_status_authority() {
    perl -0pi -e 's/impl HandlerError \{/impl HandlerError {\n    pub fn status(\&self) -> StatusCode { StatusCode::BAD_REQUEST }/' \
        crates/core/src/handler.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerError regaining a status authority before resolution' mut_handler_status_authority

mut_stage_filter_resolves_error() {
    perl -0pi -e 's/(fn on_wire\([^\n]+Result<\(\), )HandlerError>/$1S3Error>/' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_error_resolution_surface.sh \
    'a StageFilter seam returning an already-resolved S3Error' mut_stage_filter_resolves_error

mut_stage_filter_seam_removed() {
    perl -0pi -e 's/    fn on_response\([^\n]+\n        Ok\(\(\)\)\n    \}\n//' crates/gateway/src/ext/filter.rs
}
expect_fail check_error_resolution_surface.sh \
    'the closed StageFilter seam set losing its response seam' mut_stage_filter_seam_removed

mut_typed_writer_made_public() {
    perl -0pi -e 's/pub\(crate\) fn from_wire_reject/pub fn from_wire_reject/' crates/gateway/src/render.rs
}
expect_fail check_error_resolution_surface.sh \
    'a typed S3Error converter becoming public' mut_typed_writer_made_public

mut_context_carrier_bridge_removed() {
    perl -0pi -e 's/impl From<HandlerErrorContext> for HandlerError/impl From<ErrorContext> for HandlerError/' \
        crates/core/src/handler.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerError regaining an arbitrary ErrorContext carrier bridge' mut_context_carrier_bridge_removed

mut_handler_context_field_public() {
    perl -0pi -e 's/pub struct HandlerErrorContext\(ErrorContext\);/pub struct HandlerErrorContext(pub ErrorContext);/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext exposing its arbitrary ErrorContext field' mut_handler_context_field_public

mut_handler_context_generic_factory() {
    perl -0pi -e 's/impl HandlerErrorContext \{/impl HandlerErrorContext {\n    pub fn new(context: ErrorContext) -> Self { Self(context) }/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining a generic ErrorContext factory' mut_handler_context_generic_factory

mut_handler_context_missing_visibility_widened() {
    perl -0pi -e 's/pub\(crate\) fn hide_missing_object/pub fn hide_missing_object/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext exposing its missing-object narrowing seam publicly' \
    mut_handler_context_missing_visibility_widened

mut_handler_context_async_factory() {
    perl -0pi -e 's/impl HandlerErrorContext \{/impl HandlerErrorContext {\n    pub async fn new(context: ErrorContext) -> Self { Self(context) }/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining an async generic ErrorContext factory' mut_handler_context_async_factory

mut_handler_context_auth_factory() {
    perl -0pi -e 's/impl HandlerErrorContext \{/impl HandlerErrorContext {\n    pub fn authorization_scope_malformed() -> Self { Self(ErrorContext::authorization_scope_malformed()) }/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining an authorization-scope factory' mut_handler_context_auth_factory

mut_handler_context_multiline_from_impl() {
    printf '\nimpl\n    From<ErrorContext> for HandlerErrorContext {\n    fn from(context: ErrorContext) -> Self { Self(context) }\n}\n' \
        >>crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining a multiline From<ErrorContext> bridge' mut_handler_context_multiline_from_impl

mut_handler_context_macro_generated_from_impl() {
    printf '\nmacro_rules! reopen {\n    () => {\n        impl From<ErrorContext> for HandlerErrorContext {\n            fn from(context: ErrorContext) -> Self { Self(context) }\n        }\n    };\n}\nreopen!();\n' \
        >>crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining a macro-generated From<ErrorContext> bridge' mut_handler_context_macro_generated_from_impl

mut_handler_context_paren_macro_generated_from_impl() {
    printf '\nmacro_rules! reopen (\n    () => {\n        impl From<ErrorContext> for HandlerErrorContext {\n            fn from(context: ErrorContext) -> Self { Self(context) }\n        }\n    };\n);\nreopen!();\n' \
        >>crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining a parenthesized macro-generated From bridge' mut_handler_context_paren_macro_generated_from_impl

mut_handler_context_bracket_macro_generated_from_impl() {
    printf '\nmacro_rules! reopen [\n    () => {\n        impl From<ErrorContext> for HandlerErrorContext {\n            fn from(context: ErrorContext) -> Self { Self(context) }\n        }\n    };\n];\nreopen!();\n' \
        >>crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining a bracketed macro-generated From bridge' mut_handler_context_bracket_macro_generated_from_impl

mut_resolver_entry_renamed() {
    perl -0pi -e 's/pub fn resolve\(context: ErrorContext, response: ResponseKind\)/pub fn resolve_unchecked(context: ErrorContext, response: ResponseKind)/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'core losing the sole public resolution entry' mut_resolver_entry_renamed

mut_resolution_source_removed() {
    rm -f crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'the required resolution source disappearing' mut_resolution_source_removed

mut_owned_bucket_context_takes_a_region() {
    perl -0pi -e 's/pub const fn owned_bucket_recreation\(\) -> Self/pub fn owned_bucket_recreation(_: RegionLabel) -> Self/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'the owned-bucket refusal context regaining a region-selected success path' mut_owned_bucket_context_takes_a_region

mut_owned_bucket_success_enters_the_resolver() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/error_resolution.rs")
text = path.read_text()
old = '''        ErrorCase::OwnedBucketRecreation => ordinary_parts(
            ErrorCode::BUCKET_ALREADY_OWNED_BY_YOU,
            Cow::Borrowed("Your previous request to create the named bucket succeeded and you already own it."),
            Vec::new(),
            Vec::new(),
            None,
        ),'''
new = "        ErrorCase::OwnedBucketRecreation => success(StatusCode::OK),"
if old not in text:
    raise SystemExit("owned-bucket conflict arm is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the us-east-1 owned-bucket success entering ErrorContext' mut_owned_bucket_success_enters_the_resolver

mut_core_error_trybuild_harness_disabled() {
    perl -0pi -e 's/^(\/\/ Copyright 2026 RustFS Team)/#![cfg_attr(all(), cfg(any()))]\n$1/' \
        crates/core/tests/compile_fail.rs
}
expect_fail check_error_resolution_surface.sh \
    'the core error-resolution trybuild harness disabled by file-level cfg_attr' mut_core_error_trybuild_harness_disabled

mut_gateway_error_trybuild_harness_disabled() {
    perl -0pi -e 's/^(\/\/ Copyright 2026 RustFS Team)/#![cfg(any())]\n$1/' \
        crates/gateway/tests/compile_fail.rs
}
expect_fail check_error_resolution_surface.sh \
    'the gateway error-resolution trybuild harness disabled by file-level cfg' mut_gateway_error_trybuild_harness_disabled

mut_gateway_consolidated_harness_disabled() {
    perl -0pi -e 's/^(\/\/ Copyright 2026 RustFS Team)/#![cfg_attr(all(), cfg(any()))]\n$1/' \
        crates/gateway/tests/integration.rs
}
expect_fail check_error_resolution_surface.sh \
    'the consolidated gateway harness disabled by file-level cfg_attr' mut_gateway_consolidated_harness_disabled

mut_gateway_consolidated_registration_decoys() {
    cat >>crates/gateway/tests/integration.rs <<'RSEOF'

// #[path = "compile_fail.rs"]
// mod compile_fail;
const COMPILE_FAIL_REGISTRATION_DECOY: &str = r#"#[path = "compile_fail.rs"]
mod compile_fail;"#;
RSEOF
}

probe_gateway_consolidated_registration_decoys() {
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && mut_gateway_consolidated_registration_decoys >/dev/null)
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_error_resolution_surface.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_error_resolution_surface.sh ignores consolidated registration comment and raw-string decoys'
    else
        fail_msg 'check_error_resolution_surface.sh rejected consolidated registration comment or raw-string decoys'
    fi
}
probe_gateway_consolidated_registration_decoys

mut_gateway_trybuild_harness_split() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/compile_fail.rs")
text = path.read_text()
call = '    cases.compile_fail("tests/trybuild/credential/*.rs");\n'
if text.count(call) != 1:
    raise SystemExit("gateway credential trybuild call is missing")
path.write_text(text.replace(call, "", 1))
Path("crates/gateway/tests/trybuild_credential.rs").write_text(
    "#[test]\n"
    "fn credential_contract() {\n"
    "    let cases = trybuild::TestCases::new();\n"
    f"{call}"
    "}\n"
)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the gateway trybuild fixtures being split across synthetic projects' mut_gateway_trybuild_harness_split

mut_gateway_extra_trybuild_harness_added() {
    python3 - <<'PYEOF'
from pathlib import Path

Path("crates/gateway/tests/extra_compile.rs").write_text(
    "#[test]\n"
    "fn extra_compile_fail_contract() {\n"
    "    let cases = trybuild::TestCases::new();\n"
    "    cases.compile_fail(\"tests/compile_fail/azc_*.rs\");\n"
    "}\n"
)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'an extra gateway trybuild entry point creating a second synthetic project' mut_gateway_extra_trybuild_harness_added

mut_gateway_trybuild_harness_reused_by_path() {
    python3 - <<'PYEOF'
from pathlib import Path

Path("crates/gateway/tests/extra_compile.rs").write_text(
    '#[path = "compile_fail.rs"]\nmod duplicate;\n'
)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'a second integration target reusing the unified trybuild harness by path' mut_gateway_trybuild_harness_reused_by_path

mut_gateway_trybuild_harness_reused_by_cfg_attr_path() {
    python3 - <<'PYEOF'
from pathlib import Path

Path("crates/gateway/tests/extra_compile.rs").write_text(
    '#[cfg_attr(all(), path = "compile_fail.rs")]\nmod duplicate;\n'
)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'a second integration target reusing the unified trybuild harness through cfg_attr' mut_gateway_trybuild_harness_reused_by_cfg_attr_path

mut_gateway_lib_reuses_trybuild_harness() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/lib.rs")
text = path.read_text()
text += '''
#[cfg(test)]
#[path = "../tests/compile_fail.rs"]
mod duplicate_compile_fail;
'''
path.write_text(text)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the gateway library test target reusing the unified trybuild harness' mut_gateway_lib_reuses_trybuild_harness

mut_gateway_manifest_reuses_trybuild_harness() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/Cargo.toml")
text = path.read_text()
text += '''
[[example]]
name = "duplicate-compile-fail"
path = "tests/compile_fail.rs"
test = true
'''
path.write_text(text)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'a testable Cargo example reusing the unified trybuild harness' mut_gateway_manifest_reuses_trybuild_harness

mut_gateway_consolidated_harness_omits_trybuild_module() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/integration.rs")
text = path.read_text()
entry = '#[path = "compile_fail.rs"]\nmod compile_fail;\n'
if text.count(entry) != 1:
    raise SystemExit("gateway compile-fail module registration is missing")
path.write_text(text.replace(entry, "", 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the consolidated gateway target omitting its unified trybuild module' mut_gateway_consolidated_harness_omits_trybuild_module

mut_gateway_manifest_disables_consolidated_target() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/Cargo.toml")
text = path.read_text()
anchor = 'path = "tests/integration.rs"\n'
if text.count(anchor) != 1:
    raise SystemExit("gateway integration target is missing")
path.write_text(text.replace(anchor, anchor + "test = false\n", 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the consolidated gateway target disabling its test harness' mut_gateway_manifest_disables_consolidated_target

mut_gateway_manifest_gates_consolidated_target() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/Cargo.toml")
text = path.read_text()
anchor = 'path = "tests/integration.rs"\n'
if text.count(anchor) != 1:
    raise SystemExit("gateway integration target is missing")
path.write_text(text.replace(anchor, anchor + 'required-features = ["compat-s3s"]\n', 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the consolidated gateway target requiring a non-default feature' mut_gateway_manifest_gates_consolidated_target

mut_gateway_manifest_duplicates_consolidated_target() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/Cargo.toml")
text = path.read_text()
text += '''
[[test]]
name = "duplicate_integration"
path = "tests/integration.rs"
'''
path.write_text(text)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'a second Cargo target duplicating the consolidated gateway harness' mut_gateway_manifest_duplicates_consolidated_target

mut_gateway_manifest_redirects_consolidated_target() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/Cargo.toml")
text = path.read_text()
old = 'path = "tests/integration.rs"'
if text.count(old) != 1:
    raise SystemExit("gateway integration target is missing")
path.write_text(text.replace(old, 'path = "tests/facade_probe.rs"', 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the consolidated gateway target being redirected to another path' mut_gateway_manifest_redirects_consolidated_target

mut_gateway_trybuild_receiver_shadowed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/compile_fail.rs")
text = path.read_text()
old = "    let cases = trybuild::TestCases::new();\n"
new = old + "    let cases = FakeCases::new();\n"
if text.count(old) != 1:
    raise SystemExit("gateway trybuild constructor is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the gateway trybuild receiver being shadowed after construction' mut_gateway_trybuild_receiver_shadowed

mut_gateway_credential_fixture_pair_removed() {
    rm crates/gateway/tests/trybuild/credential/provider_returns_secret.rs
    rm crates/gateway/tests/trybuild/credential/provider_returns_secret.stderr
}
expect_fail check_error_resolution_surface.sh \
    'a gateway credential source and golden being removed together' mut_gateway_credential_fixture_pair_removed

mut_core_error_trybuild_call_replaced_by_string() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/tests/compile_fail.rs")
text = path.read_text()
old = '    cases.compile_fail("tests/compile_fail/error_resolution_*.rs");'
new = '    let _ = r#"cases.compile_fail(\\"tests/compile_fail/error_resolution_*.rs\\");"#;'
if old not in text:
    raise SystemExit("core error-resolution trybuild call is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the core error-resolution trybuild call replaced by a string decoy' mut_core_error_trybuild_call_replaced_by_string

mut_gateway_error_trybuild_call_replaced_by_comment() {
    perl -0pi -e 's/    cases\.compile_fail\("tests\/compile_fail\/error_resolution_\*\.rs"\);/    \/\/ cases.compile_fail("tests\/compile_fail\/error_resolution_*.rs");/' \
        crates/gateway/tests/compile_fail.rs
}
expect_fail check_error_resolution_surface.sh \
    'the gateway error-resolution trybuild call replaced by a comment decoy' mut_gateway_error_trybuild_call_replaced_by_comment

mut_error_trybuild_fixture_disabled() {
    perl -0pi -e 's/^(\/\/ Copyright 2026 RustFS Team)/#![cfg_attr(all(), cfg(any()))]\n$1/' \
        crates/core/tests/compile_fail/error_resolution_context_fields.rs
}
expect_fail check_error_resolution_surface.sh \
    'an error-resolution compile-fail fixture disabled by cfg_attr' mut_error_trybuild_fixture_disabled

mut_error_trybuild_fixture_replaced_by_string() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/tests/compile_fail/error_resolution_context_fields.rs")
text = path.read_text()
old = "    let ErrorContext(_case) = context;"
new = '    let _ = "let ErrorContext(_case) = context;";'
if old not in text:
    raise SystemExit("error-resolution fixture evidence is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'an error-resolution compile-fail expression replaced by a string decoy' mut_error_trybuild_fixture_replaced_by_string

mut_error_trybuild_golden_removed() {
    rm crates/core/tests/compile_fail/error_resolution_context_fields.stderr
}
expect_fail check_error_resolution_surface.sh \
    'an error-resolution compile-fail golden removed' mut_error_trybuild_golden_removed

mut_error_trybuild_golden_loses_diagnostic() {
    perl -0pi -e 's/cannot match against a tuple struct which contains private fields/forged generic diagnostic/' \
        crates/core/tests/compile_fail/error_resolution_context_fields.stderr
}
expect_fail check_error_resolution_surface.sh \
    'an error-resolution compile-fail golden losing its case-specific diagnostic' mut_error_trybuild_golden_loses_diagnostic

mut_scope_region_opened() {
    perl -0pi -e 's/pub struct ScopeRegion\(Box<str>\);/pub struct ScopeRegion(pub Box<str>);/' crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'ScopeRegion gaining a public field' mut_scope_region_opened

mut_scope_rejection_opened() {
    perl -0pi -e 's/pub struct ScopeRejection\(Option<ScopeRegion>\);/pub struct ScopeRejection(pub Option<ScopeRegion>);/' \
        crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'ScopeRejection gaining a public field' mut_scope_rejection_opened

mut_scope_return_erased() {
    perl -0pi -e 's/Result<VerifiedScope, ScopeRejection>/Result<VerifiedScope, AuthError>/' crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'enforce_scope erasing the typed rejection' mut_scope_return_erased

mut_scope_date_carries_region() {
    perl -0pi -e 's/return Err\(ScopeRejection\(None\)\);/return Err(ScopeRejection(expected.regions().regions.first().cloned()));/' \
        crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'a date mismatch carrying a remediation region' mut_scope_date_carries_region

mut_scope_region_loses_remediation() {
    perl -0pi -e 's/ScopeRejection\(expected\.regions\(\)\.regions\.first\(\)\.cloned\(\)\)/ScopeRejection(None)/' \
        crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'a region mismatch losing its configured remediation' mut_scope_region_loses_remediation

mut_scope_sort_removed() {
    perl -0pi -e 's/regions\.sort_by\(/regions.sort_by_key(/' crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'configured remediation order no longer using the canonical byte sort' mut_scope_sort_removed

mut_scope_dedup_removed() {
    perl -0pi -e 's/regions\.dedup\(\);/\/\/ mutation removed deduplication/' crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'configured regions no longer being deduplicated' mut_scope_dedup_removed

mut_scope_alphabet_widened() {
    perl -0pi -e 's/byte\.is_ascii_lowercase\(\)/byte.is_ascii_alphabetic()/' crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'configured regions accepting uppercase request text' mut_scope_alphabet_widened

mut_authentication_outcome_field_public() {
    perl -0pi -e 's/    scope_rejection: Option<ScopeRejection>,/    pub scope_rejection: Option<ScopeRejection>,/' \
        crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'the facade carrier exposing its scope proof field' mut_authentication_outcome_field_public

mut_scope_rejection_trait_bridge() {
    printf '\nimpl From<ScopeRejection> for AuthenticationOutcome {\n    fn from(rejection: ScopeRejection) -> Self { Self::scope_rejected(rejection) }\n}\n' \
        >>crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'ScopeRejection gaining a public trait bridge into AuthenticationOutcome' mut_scope_rejection_trait_bridge

mut_ordinary_outcome_gets_proof() {
    perl -0pi -e 's/scope_rejection: None,/scope_rejection: Some(todo!()),/' crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'an ordinary custom-authenticator outcome receiving contextual proof' mut_ordinary_outcome_gets_proof

# ADR-0022 admits exactly one field beyond ADR-0009's two: the optional caller secret.
mut_authentication_outcome_fourth_field() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/ext/authenticator.rs")
text = path.read_text()
old = "    caller_secret: Option<rustfs_gateway_sig::SecretBytes>,\n}\n"
if text.count(old) != 1:
    raise SystemExit("missing mutation subject: the AuthenticationOutcome field list")
path.write_text(text.replace(old, "    caller_secret: Option<rustfs_gateway_sig::SecretBytes>,\n    session_hint: Option<Box<str>>,\n}\n", 1))
PYEOF
}
expect_fail check_scope_rejection_surface.sh \
    'AuthenticationOutcome gaining a fourth field beyond the ADR-0022 caller secret' \
    mut_authentication_outcome_fourth_field

mut_authentication_outcome_secret_public() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/ext/authenticator.rs")
text = path.read_text()
old = "    caller_secret: Option<rustfs_gateway_sig::SecretBytes>,\n}\n"
if text.count(old) != 1:
    raise SystemExit("missing mutation subject: the AuthenticationOutcome field list")
path.write_text(text.replace(old, "    pub caller_secret: Option<rustfs_gateway_sig::SecretBytes>,\n}\n", 1))
PYEOF
}
expect_fail check_scope_rejection_surface.sh \
    'the ADR-0022 caller secret becoming a public field' mut_authentication_outcome_secret_public

mut_verdict_accessor_rewrites() {
    perl -0pi -e 's/        &self\.verdict\n/        todo!()\n/' crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'the public verdict accessor no longer borrowing the stored verdict' mut_verdict_accessor_rewrites

mut_scope_verdict_replaced() {
    perl -0pi -e 's/verdict: Verdict::reject\(AuthError::AuthorizationHeaderMalformed\)/verdict: Verdict::reject(AuthError::AccessDenied)/' \
        crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'the private scope carrier replacing the fixed public verdict' mut_scope_verdict_replaced

mut_scope_split_public() {
    perl -0pi -e 's/pub\(crate\) fn into_parts/pub fn into_parts/' crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'the contextual carrier gaining a public consuming split' mut_scope_split_public

mut_authenticator_returns_bare_verdict() {
    perl -0pi -e 's/Result<AuthenticationOutcome, Unavailable>/Result<Verdict, Unavailable>/' \
        crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'Authenticator returning the old bare verdict' mut_authenticator_returns_bare_verdict

mut_service_drops_scope_proof() {
    perl -0pi -e 's/scope_rejection\.and_then\(\|rejection\| rejection\.expected_region\(\)\.cloned\(\)\)/None/' \
        crates/gateway/src/service.rs
}
expect_fail check_scope_rejection_surface.sh \
    'the service dropping the trusted scope proof' mut_service_drops_scope_proof

mut_service_region_context_swapped() {
    perl -0pi -e 's/ErrorContext::authorization_region_mismatch\(region\)/ErrorContext::authorization_scope_malformed()/' \
        crates/gateway/src/service.rs
}
expect_fail check_scope_rejection_surface.sh \
    'a trusted region mismatch losing its Region detail' mut_service_region_context_swapped

mut_service_no_detail_context_swapped() {
    perl -0pi -e 's/None => ErrorContext::authorization_scope_malformed\(\)/None => ErrorContext::authorization_region_mismatch(todo!())/' \
        crates/gateway/src/service.rs
}
expect_fail check_scope_rejection_surface.sh \
    'a date or service mismatch gaining a Region detail' mut_service_no_detail_context_swapped

mut_core_scope_context_removed() {
    perl -0pi -e 's/pub const fn authorization_scope_malformed/pub const fn removed_scope_malformed/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_scope_rejection_surface.sh \
    'core losing the closed no-detail scope context' mut_core_scope_context_removed

mut_scope_source_removed() {
    rm -f crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'the required typed scope source disappearing' mut_scope_source_removed

probe_error_scope_guards_without_rg() {
    local guard output rc tool_path
    local guards=(check_error_resolution_surface.sh check_scope_rejection_surface.sh)

    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-error-scope-guard-path.XXXXXX")"
    ln -s "$(command -v python3)" "${tool_path}/python3"
    ln -s "$(command -v grep)" "${tool_path}/grep"
    ln -s "$(command -v awk)" "${tool_path}/awk"
    for guard in "${guards[@]}"; do
        cases=$((cases + 1))
        guard_case_owned "$cases" || continue
        rc=0
        output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
        if [[ "$rc" -eq 0 ]]; then
            pass_msg "${guard} runs without ripgrep"
        else
            fail_msg "${guard} requires ripgrep: ${output}"
        fi
    done
    rm -rf "$tool_path"
}
probe_error_scope_guards_without_rg

probe_error_scope_guards_missing_python() {
    local guard output rc tool_path
    local guards=(check_error_resolution_surface.sh check_scope_rejection_surface.sh)

    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-error-scope-guard-path.XXXXXX")"
    ln -s "$(command -v grep)" "${tool_path}/grep"
    ln -s "$(command -v awk)" "${tool_path}/awk"
    for guard in "${guards[@]}"; do
        cases=$((cases + 1))
        guard_case_owned "$cases" || continue
        rc=0
        output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
        if [[ "$rc" -ne 0 && "$output" == *'required command is missing: python3'* ]]; then
            pass_msg "${guard} fails closed without python3"
        else
            fail_msg "${guard} reported green without python3"
        fi
    done
    rm -rf "$tool_path"
}
probe_error_scope_guards_missing_python

replace_adr_text() {
    python3 - "$1" "$2" "$3" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
old, new = sys.argv[2:]
text = path.read_text()
if old not in text:
    raise SystemExit(f"missing ADR mutation subject in {path}: {old}")
path.write_text(text.replace(old, new, 1))
PYEOF
}

mut_adr_second_legacy_filename() {
    cp docs/adr/0008-closed-error-resolution.md docs/adr/ADR-0010-second-legacy.md
}
expect_fail check_adr_contract.sh \
    'a second uppercase ADR filename expanding the one historical exception' mut_adr_second_legacy_filename

mut_adr_number_gap() {
    mv docs/adr/0008-closed-error-resolution.md docs/adr/0010-closed-error-resolution.md
}
expect_fail check_adr_contract.sh \
    'the numbered ADR record gaining a gap' mut_adr_number_gap

mut_adr_duplicate_number() {
    cp docs/adr/0008-closed-error-resolution.md docs/adr/0008-duplicate-number.md
}
expect_fail check_adr_contract.sh \
    'two ADR files claiming the same number' mut_adr_duplicate_number

mut_adr_h1_number_mismatch() {
    replace_adr_text docs/adr/0008-closed-error-resolution.md \
        '# ADR-0008:' '# ADR-0010:'
}
expect_fail check_adr_contract.sh \
    'an ADR H1 disagreeing with its file number' mut_adr_h1_number_mismatch

mut_adr_placeholder_title() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("docs/adr/0008-closed-error-resolution.md")
lines = path.read_text().splitlines()
lines[0] = "# ADR-0008: <Title>"
path.write_text("\n".join(lines) + "\n")
PYEOF
}
expect_fail check_adr_contract.sh \
    'an accepted ADR retaining the template title' mut_adr_placeholder_title

mut_adr_duplicate_status_metadata() {
    replace_adr_text docs/adr/0008-closed-error-resolution.md \
        '- Status: Accepted' '- Status: Accepted
- Status: Accepted'
}
expect_fail check_adr_contract.sh \
    'an ADR carrying two active status rows' mut_adr_duplicate_status_metadata

mut_adr_invalid_status() {
    replace_adr_text docs/adr/0008-closed-error-resolution.md \
        '- Status: Accepted' '- Status: Proposed'
}
expect_fail check_adr_contract.sh \
    'an ADR restoring the forbidden Proposed state' mut_adr_invalid_status

mut_adr_invalid_date() {
    replace_adr_text docs/adr/0008-closed-error-resolution.md \
        '- Date: 2026-08-11' '- Date: someday'
}
expect_fail check_adr_contract.sh \
    'an ADR losing its exact decision date' mut_adr_invalid_date

mut_adr_impossible_calendar_date() {
    replace_adr_text docs/adr/0008-closed-error-resolution.md \
        '- Date: 2026-08-11' '- Date: 2026-02-31'
}
expect_fail check_adr_contract.sh \
    'an ADR using a shaped but impossible calendar date' mut_adr_impossible_calendar_date

mut_adr_metadata_fence_decoy() {
    replace_adr_text docs/adr/0008-closed-error-resolution.md \
        '- Status: Accepted' '```markdown
- Status: Accepted
```'
}
expect_fail check_adr_contract.sh \
    'an ADR status surviving only inside a fenced block' mut_adr_metadata_fence_decoy

mut_adr_merged_body_drift() {
    replace_adr_text docs/adr/0008-closed-error-resolution.md \
        'The `204` case is the proof that this cannot remain only an error-code mapping' \
        'The `204` case merely suggests that this should not remain only an error-code mapping'
}
expect_fail check_adr_contract.sh \
    'an already merged ADR body changing outside lifecycle metadata' mut_adr_merged_body_drift

mut_adr_body_status_prefix_drift() {
    cat >>docs/adr/0008-closed-error-resolution.md <<'EOF'

- Status: this is Decision prose, not lifecycle metadata
EOF
}
expect_fail check_adr_contract.sh \
    'ADR body prose sharing the Status prefix, which remains immutable' \
    mut_adr_body_status_prefix_drift

probe_adr_committed_self_base_rejected() {
    local holder sandbox implicit_output explicit_output implicit_rc=0 explicit_rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    holder="$(mktemp -d "${TMPDIR:-/tmp}/gateway-adr-self-base.XXXXXX")"
    git clone -q "$SANDBOX" "$holder/repository"
    sandbox="$holder/repository"
    git -C "$sandbox" remote remove origin
    (
        cd "$sandbox"
        replace_adr_text docs/adr/0008-closed-error-resolution.md \
            'The `204` case is the proof that this cannot remain only an error-code mapping' \
            'The committed drift tries to become its own baseline'
        git add docs/adr/0008-closed-error-resolution.md
        git -c user.name=t -c user.email=t@t commit -qm 'mutate ADR body'
    )
    implicit_output="$(GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_adr_contract.sh" 2>&1)" || implicit_rc=$?
    explicit_output="$(GATEWAY_CHECK_ROOT="$sandbox" GATEWAY_ADR_BASE=HEAD \
        "${SCRIPT_DIR}/check_adr_contract.sh" 2>&1)" || explicit_rc=$?
    rm -rf "$holder"
    if [[ "$implicit_rc" -ne 0 && "$implicit_output" == *'cannot resolve a trusted ADR base'* &&
        "$explicit_rc" -ne 0 && "$explicit_output" == *'must not resolve to HEAD'* ]]; then
        pass_msg 'check_adr_contract.sh rejects committed drift with an implicit or explicit self-base'
    else
        fail_msg 'check_adr_contract.sh accepted a committed ADR as its own baseline'
    fi
}
probe_adr_committed_self_base_rejected

probe_adr_origin_main_self_base_rejected() {
    local holder sandbox output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    holder="$(mktemp -d "${TMPDIR:-/tmp}/gateway-adr-origin-self.XXXXXX")"
    git clone -q "$SANDBOX" "$holder/repository"
    sandbox="$holder/repository"
    git -C "$sandbox" remote remove origin
    (
        cd "$sandbox"
        replace_adr_text docs/adr/0008-closed-error-resolution.md \
            'The `204` case is the proof that this cannot remain only an error-code mapping' \
            'The committed drift advances the local origin/main ref too'
        git add docs/adr/0008-closed-error-resolution.md
        git -c user.name=t -c user.email=t@t commit -qm 'mutate ADR body and main'
        git update-ref refs/remotes/origin/main HEAD
    )
    output="$(GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_adr_contract.sh" 2>&1)" || rc=$?
    rm -rf "$holder"
    if [[ "$rc" -ne 0 && "$output" == *'merged body changed outside lifecycle metadata'* ]]; then
        pass_msg 'check_adr_contract.sh compares origin/main HEAD with its prior independent state'
    else
        fail_msg 'check_adr_contract.sh accepted origin/main HEAD as its own ADR baseline'
    fi
}
probe_adr_origin_main_self_base_rejected

probe_adr_pull_request_merge_uses_first_parent() {
    local sandbox
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    local rc=0
    (
        cd "$sandbox"
        base="$(git rev-parse HEAD)"
        replace_adr_text docs/adr/0008-closed-error-resolution.md \
            'The `204` case is the proof that this cannot remain only an error-code mapping' \
            'The `204` case merely suggests that this should not remain only an error-code mapping'
        git add docs/adr/0008-closed-error-resolution.md
        tree="$(git write-tree)"
        mutation="$(printf 'mutate ADR body\n' | git commit-tree "$tree" -p "$base")"
        merge="$(printf 'merge mutation\n' | git commit-tree "$tree" -p "$base" -p "$mutation")"
        git reset -q --hard "$merge"
    ) || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        GATEWAY_CHECK_ROOT="$sandbox" GITHUB_ACTIONS=true GITHUB_EVENT_NAME=pull_request \
            "${SCRIPT_DIR}/check_adr_contract.sh" >/dev/null 2>&1 || rc=$?
    fi
    if [[ "$rc" -ne 0 ]]; then
        pass_msg 'check_adr_contract.sh compares a pull-request merge checkout with its first parent'
    else
        fail_msg 'check_adr_contract.sh accepted pull-request ADR drift from a merge result'
    fi
}
probe_adr_pull_request_merge_uses_first_parent

mut_adr_mixed_fence_marker() {
    cat >>docs/adr/0008-closed-error-resolution.md <<'EOF'

```~
## Mixed fence decoy
```~
EOF
}
expect_fail check_adr_contract.sh \
    'a mixed backtick/tilde run hiding an extra ADR section' mut_adr_mixed_fence_marker

mut_adr_invalid_fence_close() {
    replace_adr_text docs/adr/0008-closed-error-resolution.md \
        '## Evidence' '```markdown
``` trailing text
## Evidence
```
```'
}
expect_fail check_adr_contract.sh \
    'a fenced block closing with non-whitespace trailing text' mut_adr_invalid_fence_close

mut_adr_placeholder_trigger() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("docs/adr/0008-closed-error-resolution.md")
text = path.read_text()
start = text.index("- Trigger: ")
end = text.index("\n", start)
path.write_text(text[:start] + "- Trigger: <axiom>" + text[end:])
PYEOF
}
expect_fail check_adr_contract.sh \
    'an accepted ADR retaining a placeholder trigger' mut_adr_placeholder_trigger

mut_adr_missing_relation_target() {
    replace_adr_text docs/adr/0008-closed-error-resolution.md \
        '- Supersedes / Superseded by: none' \
        '- Supersedes / Superseded by: ADR-9999'
}
expect_fail check_adr_contract.sh \
    'supersession metadata naming a missing ADR' mut_adr_missing_relation_target

mut_adr_one_way_supersession() {
    replace_adr_text docs/adr/0008-closed-error-resolution.md \
        '- Status: Accepted' '- Status: Superseded by ADR-0009'
    replace_adr_text docs/adr/0008-closed-error-resolution.md \
        '- Supersedes / Superseded by: none' \
        '- Supersedes / Superseded by: ADR-0009'
}
expect_fail check_adr_contract.sh \
    'a supersession recorded on only one side' mut_adr_one_way_supersession

probe_adr_paired_supersession_allowed() {
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    (
        cd "$sandbox"
        python3 - <<'PYEOF'
import re
from pathlib import Path

adr_dir = Path("docs/adr")
numbers = [
    int(match.group(1))
    for path in adr_dir.iterdir()
    if (match := re.match(r"^(\d{4})-", path.name)) is not None
]
next_number = max(numbers) + 1
next_digits = f"{next_number:04d}"
next_adr = f"ADR-{next_digits}"

prior = adr_dir / "0008-closed-error-resolution.md"
prior_text = prior.read_text()
status = "- Status: Accepted"
relation = "- Supersedes / Superseded by: none"
if prior_text.count(status) != 1 or prior_text.count(relation) != 1:
    raise SystemExit("ADR supersession fixture is not unique")
prior_text = prior_text.replace(status, f"- Status: Superseded by {next_adr}", 1)
prior_text = prior_text.replace(relation, f"- Supersedes / Superseded by: {next_adr}", 1)
prior.write_text(prior_text)

(adr_dir / f"{next_digits}-supersede-closed-error-resolution.md").write_text(f"""# {next_adr}: Supersede closed error resolution

- Status: Accepted
- Date: 2026-08-12
- Trigger: axiom A2 changed through a new reviewed decision
- Supersedes / Superseded by: ADR-0008

## Context

The previous decision needs a replacement.

## Decision

The replacement is recorded in a new ADR.

## Evidence

The reciprocal metadata names the prior record.

## Rejected alternatives

Editing the merged body would erase history.

## Consequences

Readers can follow both directions.
""")

path = Path("docs/adr/README.md")
text = path.read_text()
old_row = "| 0008 | Closed error resolution across the types, signature, core and facade boundary | Accepted |"
new_row = f"| 0008 | Closed error resolution across the types, signature, core and facade boundary | Superseded by {next_adr} |"
rows = list(re.finditer(r"^\| (\d{4}) \|.*\|$", text, flags=re.MULTILINE))
if text.count(old_row) != 1 or not rows:
    raise SystemExit("ADR index supersession fixture is not unique")
text = text.replace(old_row, new_row, 1)
last_row = rows[-1].group(0)
text = text.replace(last_row, last_row + f"\n| {next_digits} | Supersede closed error resolution | Accepted |", 1)
path.write_text(text)
PYEOF
    )
    git -C "$sandbox" update-ref -d refs/remotes/origin/main
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_adr_contract.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_adr_contract.sh allows paired supersession through a new ADR'
    else
        fail_msg 'check_adr_contract.sh rejected a paired new superseding ADR'
    fi
}
probe_adr_paired_supersession_allowed

mut_adr_relation_without_superseded_side() {
    replace_adr_text docs/adr/0008-closed-error-resolution.md \
        '- Supersedes / Superseded by: none' \
        '- Supersedes / Superseded by: ADR-0009'
    replace_adr_text docs/adr/0009-typed-scope-region-rejection.md \
        '- Supersedes / Superseded by: none' \
        '- Supersedes / Superseded by: ADR-0008'
}
expect_fail check_adr_contract.sh \
    'two accepted ADRs claiming a relation with no superseded side' mut_adr_relation_without_superseded_side

mut_adr_section_heading_comment_decoy() {
    replace_adr_text docs/adr/0008-closed-error-resolution.md \
        '## Evidence' '<!-- ## Evidence -->'
}
expect_fail check_adr_contract.sh \
    'an ADR section heading surviving only inside a comment' mut_adr_section_heading_comment_decoy

mut_adr_empty_evidence_comment_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("docs/adr/0008-closed-error-resolution.md")
text = path.read_text()
start = text.index("## Evidence\n")
end = text.index("## Rejected alternatives\n", start)
path.write_text(text[:start] + "## Evidence\n\n<!-- measured facts removed -->\n\n" + text[end:])
PYEOF
}
expect_fail check_adr_contract.sh \
    'an Evidence section containing only a comment' mut_adr_empty_evidence_comment_decoy

mut_adr_empty_rejected_alternatives() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("docs/adr/0008-closed-error-resolution.md")
text = path.read_text()
start = text.index("## Rejected alternatives\n")
end = text.index("## Consequences\n", start)
path.write_text(text[:start] + "## Rejected alternatives\n\n" + text[end:])
PYEOF
}
expect_fail check_adr_contract.sh \
    'an ADR losing every rejected alternative' mut_adr_empty_rejected_alternatives

mut_adr_template_heading_fence_decoy() {
    replace_adr_text docs/adr/0000-template.md \
        '## Evidence' '```markdown
## Evidence
```'
}
expect_fail check_adr_contract.sh \
    'the template Evidence heading surviving only inside a fence' mut_adr_template_heading_fence_decoy

mut_adr_template_metadata_changed() {
    replace_adr_text docs/adr/0000-template.md \
        '- Status: Accepted' '- Status: Proposed'
}
expect_fail check_adr_contract.sh \
    'the ADR template restoring a Proposed lifecycle' mut_adr_template_metadata_changed

mut_adr_readme_trigger_removed() {
    replace_adr_text docs/adr/README.md \
        '3. Changing the licensing or dependency policy.' \
        '<!-- 3. Changing the licensing or dependency policy. -->'
}
expect_fail check_adr_contract.sh \
    'one ADR trigger surviving only inside a comment' mut_adr_readme_trigger_removed

mut_adr_readme_fourth_trigger() {
    replace_adr_text docs/adr/README.md \
        'If your change is not one of these three, do NOT write an ADR.' \
        '4. Changing a local implementation detail.

If your change is not one of these three, do NOT write an ADR.'
}
expect_fail check_adr_contract.sh \
    'a fourth ADR trigger widening the mechanism' mut_adr_readme_fourth_trigger

mut_adr_readme_exclusion_removed() {
    replace_adr_text docs/adr/README.md \
        'do NOT write an ADR' 'consider an ADR'
}
expect_fail check_adr_contract.sh \
    'the ADR README losing its non-trigger exclusion' mut_adr_readme_exclusion_removed

mut_adr_readme_exclusion_comment_decoy() {
    replace_adr_text docs/adr/README.md \
        'do NOT write an ADR' 'consider an ADR<!-- do NOT write an ADR -->'
}
expect_fail check_adr_contract.sh \
    'the non-trigger exclusion surviving only inside a comment' mut_adr_readme_exclusion_comment_decoy

mut_adr_readme_filename_rule_changed() {
    replace_adr_text docs/adr/README.md \
        'NNNN-kebab-case-title.md' 'ADR-NNNN-any-title.md'
}
expect_fail check_adr_contract.sh \
    'the documented ADR filename rule drifting' mut_adr_readme_filename_rule_changed

mut_adr_readme_rule_comment_decoy() {
    replace_adr_text docs/adr/README.md \
        'There is no `Proposed` state' \
        'The lifecycle is flexible<!-- There is no `Proposed` state -->'
}
expect_fail check_adr_contract.sh \
    'a required ADR rule surviving only inside a comment' mut_adr_readme_rule_comment_decoy

mut_adr_index_title_changed() {
    replace_adr_text docs/adr/README.md \
        '| 0008 | Closed error resolution across the types, signature, core and facade boundary | Accepted |' \
        '| 0008 | Error handling notes | Accepted |'
}
expect_fail check_adr_contract.sh \
    'the ADR index title disagreeing with the record H1' mut_adr_index_title_changed

mut_adr_index_row_comment_decoy() {
    replace_adr_text docs/adr/README.md \
        '| 0008 | Closed error resolution across the types, signature, core and facade boundary | Accepted |' \
        '<!-- | 0008 | Closed error resolution across the types, signature, core and facade boundary | Accepted | -->'
}
expect_fail check_adr_contract.sh \
    'an ADR index row surviving only inside a comment' mut_adr_index_row_comment_decoy

mut_adr_duplicate_index_row() {
    replace_adr_text docs/adr/README.md \
        '| 0008 | Closed error resolution across the types, signature, core and facade boundary | Accepted |' \
        '| 0008 | Closed error resolution across the types, signature, core and facade boundary | Accepted |
| 0008 | Closed error resolution across the types, signature, core and facade boundary | Accepted |'
}
expect_fail check_adr_contract.sh \
    'the hand-maintained index duplicating one ADR number' mut_adr_duplicate_index_row

mut_adr_record_symlink() {
    rm -f docs/adr/0009-typed-scope-region-rejection.md
    ln -s 0008-closed-error-resolution.md docs/adr/0009-typed-scope-region-rejection.md
}
expect_fail check_adr_contract.sh \
    'an ADR record replaced by a symlink' mut_adr_record_symlink

mut_adr_readme_deleted() {
    rm -f docs/adr/README.md
}
expect_fail check_adr_contract.sh \
    "the guard's README input deleted, which must fail rather than skip" mut_adr_readme_deleted

probe_adr_guard_missing_ruby() {
    local output rc=0 sandbox
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    output="$(GATEWAY_CHECK_ROOT="$sandbox" PATH=/nonexistent /bin/bash \
        "${SCRIPT_DIR}/check_adr_contract.sh" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: ruby'* ]]; then
        pass_msg 'check_adr_contract.sh fails closed without ruby'
    else
        fail_msg 'check_adr_contract.sh reported green without ruby'
    fi
}
probe_adr_guard_missing_ruby

mut_assembly_case_id_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("scripts/check_monomorphic_dispatch.sh")
path.write_text(path.read_text().replace("a-asm-0007", "removed-asm-0007", 1))
PYEOF
}
expect_fail check_assembly_case_coverage.sh \
    'the static-dispatch case losing its LLVM guard mapping' mut_assembly_case_id_deleted

mut_monomorphic_handler_is_indirect() {
    python3 - <<'PYEOF'
from pathlib import Path

Path("scripts/monomorphic-indirect.ll").write_text("""\
define internal void @_RNCINvMNtCstatic_dispatchStaticOperationintegration7support4Ping8dispatch7Backend() {
; <integration::support::Backend as rustfs_gateway_core::handler::Handler<integration::support::Ping>>::call
  %result = call ptr %handler()
}
; rustfs_gateway_core::static_dispatch::decode::<integration::support::Ping>
define internal void @_Rdecode() {
; <integration::support::Ping as rustfs_gateway_core::codec::OperationCodec>::decode
  call void @_Rcodec()
}
""")
PYEOF
}
# Executed by the build-guard worker above.



# ── check_minimal_assembly_lines.sh (P7-01) ───────────────────────────────────

mut_minimal_assembly_exceeds_twenty_lines() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/examples/minimal.rs")
text = path.read_text()
extra = "".join(f"    let _extra_{index} = {index};\n" for index in range(21))
path.write_text(text.replace("    // END MINIMAL ASSEMBLY", extra + "    // END MINIMAL ASSEMBLY", 1))
PY
}
expect_fail check_minimal_assembly_lines.sh \
    'the minimal ServiceBuilder assembly grows beyond twenty effective lines' mut_minimal_assembly_exceeds_twenty_lines

mut_minimal_assembly_marker_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/examples/minimal.rs")
path.write_text(path.read_text().replace("    // BEGIN MINIMAL ASSEMBLY\n", "", 1))
PY
}
expect_fail check_minimal_assembly_lines.sh \
    'the assembly measurement loses its opening marker' mut_minimal_assembly_marker_removed

mut_minimal_listener_exceeds_ratchet() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/examples/minimal.rs")
text = path.read_text()
extra = "".join(f"let _listener_extra_{index} = {index};\n" for index in range(47))
path.write_text(text.replace("// END MINIMAL LISTENER", extra + "// END MINIMAL LISTENER", 1))
PY
}
expect_fail check_minimal_assembly_lines.sh \
    'the runnable listener path grows beyond its measured ratchet' mut_minimal_listener_exceeds_ratchet

mut_minimal_listener_marker_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/examples/minimal.rs")
path.write_text(path.read_text().replace("// BEGIN MINIMAL LISTENER\n", "", 1))
PY
}
expect_fail check_minimal_assembly_lines.sh \
    'the listener measurement loses its opening marker' mut_minimal_listener_marker_removed

# ── check_example_contracts.sh (P7-04) ───────────────────────────────────────

mut_example_target_becomes_implicit() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/Cargo.toml")
section = '\n[[example]]\nname = "custom_credential_provider"\n'
path.write_text(path.read_text().replace(section, "", 1))
PY
}
expect_fail check_example_contracts.sh \
    'a Rust example target becomes implicit Cargo discovery' mut_example_target_becomes_implicit

mut_example_teaches_panic_handling() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/examples/minimal.rs")
path.write_text(path.read_text() + '\nfn panic_shaped_example() { Some(()).expect("copied into production"); }\n')
PY
}
expect_fail check_example_contracts.sh \
    'a Rust example teaches consumers to panic on recoverable input' mut_example_teaches_panic_handling

mut_example_teaches_ufcs_panic_handling() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/examples/minimal.rs")
path.write_text(path.read_text() + '\nfn ufcs_panic_example() { Option::expect(Some(()), "copied into production"); }\n')
PY
}
expect_fail check_example_contracts.sh \
    'a Rust example hides panic handling behind UFCS syntax' mut_example_teaches_ufcs_panic_handling

# Exercise selective staging in a tiny repository so the control measures only index semantics.
# The Git shim records every invocation and rejects a regression to repository-wide `git add -A`.
stage_helper_contract() {
    local helper="$1" repo shim log expected real_git output rc=0
    repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-stage-helper.XXXXXX")"
    shim="$(mktemp -d "${TMPDIR:-/tmp}/gateway-stage-git.XXXXXX")"
    log="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-log.XXXXXX")"
    expected="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-expected.XXXXXX")"
    real_git="$(command -v git)"
    write_stage_contract_pathspec "$expected"
    (
        cd "$repo"
        "$real_git" init -q .
        printf 'keep\n' >modified.txt
        printf 'delete\n' >deleted.txt
        printf 'magic\n' >':(glob)decoy'
        printf 'bracket\n' >'tracked[one].txt'
        printf 'unchanged\n' >unchanged.txt
        "$real_git" add modified.txt deleted.txt unchanged.txt -- \
            ':(literal):(glob)decoy' ':(literal)tracked[one].txt'
        "$real_git" -c user.name=t -c user.email=t@t commit -qm base
        printf 'changed\n' >>modified.txt
        rm deleted.txt
        printf 'changed\n' >>':(glob)decoy'
        rm 'tracked[one].txt'
        printf 'new\n' >untracked.txt
        printf 'new magic\n' >':(glob)untracked'
        printf 'new bracket\n' >'untracked[two].txt'
    )
    printf '%s\n' \
        '#!/bin/sh' \
        'printf "CALL\0" >>"$GATEWAY_STAGE_GIT_LOG"' \
        'printf "%s\0" "$@" >>"$GATEWAY_STAGE_GIT_LOG"' \
        'printf "END\0" >>"$GATEWAY_STAGE_GIT_LOG"' \
        'case "${1-}" in' \
        '    add)' \
        '        [ "$#" -eq 4 ] && [ "${2-}" = -A ] && [ "${4-}" = --pathspec-file-nul ] || exit 97' \
        '        case "${3-}" in --pathspec-from-file=*) pathspec=${3#*=} ;; *) exit 97 ;; esac' \
        '        [ -n "$pathspec" ] && [ "$pathspec" != - ] || exit 97' \
        '        "$GATEWAY_STAGE_VALIDATE" "$GATEWAY_STAGE_EXPECTED" "$pathspec" || exit 97' \
        '        ;;' \
        '    diff)' \
        '        [ "$#" -eq 5 ] && [ "${2-}" = --name-only ] && [ "${3-}" = -z ] &&' \
        '            [ "${4-}" = HEAD ] && [ "${5-}" = -- ] || exit 97' \
        '        ;;' \
        '    ls-files)' \
        '        [ "$#" -eq 4 ] && [ "${2-}" = --others ] &&' \
        '            [ "${3-}" = --exclude-standard ] && [ "${4-}" = -z ] || exit 97' \
        '        ;;' \
        '    *) exit 97 ;;' \
        'esac' \
        'exec "$GATEWAY_STAGE_REAL_GIT" "$@"' >"$shim/git"
    printf '%s\n' \
        '#!/usr/bin/env python3' \
        'import pathlib' \
        'import sys' \
        '' \
        'def entries(path):' \
        '    data = pathlib.Path(path).read_bytes()' \
        '    if not data or not data.endswith(b"\0"):' \
        '        raise SystemExit(1)' \
        '    values = data[:-1].split(b"\0")' \
        '    if any(not value for value in values):' \
        '        raise SystemExit(1)' \
        '    return values' \
        '' \
        'expected = entries(sys.argv[1])' \
        'actual = entries(sys.argv[2])' \
        'if len(actual) != len(set(actual)):' \
        '    raise SystemExit(1)' \
        'if any(not value.startswith(b":(literal)") for value in actual):' \
        '    raise SystemExit(1)' \
        'if set(actual) != set(expected):' \
        '    raise SystemExit(1)' >"$shim/validate"
    chmod +x "$shim/git"
    chmod +x "$shim/validate"
    PATH="$shim:$PATH" GATEWAY_STAGE_GIT_LOG="$log" GATEWAY_STAGE_EXPECTED="$expected" \
        GATEWAY_STAGE_VALIDATE="$shim/validate" GATEWAY_STAGE_REAL_GIT="$real_git" \
        "$helper" "$repo" || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        output="$(cd "$repo" && "$real_git" diff --cached --name-only -z | python3 -c 'import sys; print("\n".join(sorted(part.decode() for part in sys.stdin.buffer.read().split(b"\0") if part)))')"
        if [[ "$output" != $':(glob)decoy\n:(glob)untracked\ndeleted.txt\nmodified.txt\ntracked[one].txt\nuntracked.txt\nuntracked[two].txt' ]] ||
            ! (cd "$repo" && "$real_git" diff --quiet) ||
            [[ -n "$(cd "$repo" && "$real_git" ls-files --others --exclude-standard)" ]]; then
            rc=1
        fi
    fi
    if [[ "$rc" -eq 0 ]] && python3 - "$log" <<'PYEOF'
import pathlib
import sys

records = pathlib.Path(sys.argv[1]).read_bytes().split(b"\0")
calls = []
current = None
for record in records:
    if record == b"CALL":
        if current is not None:
            raise SystemExit(1)
        current = []
    elif record == b"END":
        if current is None:
            raise SystemExit(1)
        calls.append(current)
        current = None
    elif record and current is not None:
        current.append(record)
if current is not None or not calls:
    raise SystemExit(1)
for call in calls:
    allowed_query = call in (
        [b"diff", b"--name-only", b"-z", b"HEAD", b"--"],
        [b"ls-files", b"--others", b"--exclude-standard", b"-z"],
    )
    allowed_add = (
        len(call) == 4
        and call[0] == b"add"
        and call[1] == b"-A"
        and call[2].startswith(b"--pathspec-from-file=")
        and call[3] == b"--pathspec-file-nul"
    )
    if not (allowed_query or allowed_add):
        raise SystemExit(1)
PYEOF
    then
        (cd "$repo" && "$real_git" reset -q --hard HEAD && "$real_git" clean -fdq)
        PATH="$shim:$PATH" GATEWAY_STAGE_GIT_LOG="$log" GATEWAY_STAGE_EXPECTED="$expected" \
            GATEWAY_STAGE_VALIDATE="$shim/validate" GATEWAY_STAGE_REAL_GIT="$real_git" \
            "$helper" "$repo" || rc=$?
        if [[ "$rc" -eq 0 ]] && ! (cd "$repo" && "$real_git" status --porcelain | grep . >/dev/null); then
            rc=0
        else
            rc=1
        fi
    else
        rc=1
    fi
    rm -rf "$repo" "$shim"
    rm -f "$log" "$expected"
    return "$rc"
}

write_stage_contract_pathspec() {
    printf '%s\0' \
        ':(literal):(glob)decoy' \
        ':(literal):(glob)untracked' \
        ':(literal)deleted.txt' \
        ':(literal)modified.txt' \
        ':(literal)tracked[one].txt' \
        ':(literal)untracked.txt' \
        ':(literal)untracked[two].txt' >"$1"
}

stage_mutant_adds_whole_tree() {
    (cd "$1" && git add -A)
}

stage_mutant_adds_dot() {
    (cd "$1" && git add .)
}

stage_mutant_adds_dot_with_global_directory() {
    git -C "$1" add .
}

stage_mutant_adds_whole_tree_then_targeted() {
    (cd "$1" && git add -A) || return
    stage_sandbox_changes "$1"
}

stage_mutant_adds_whole_tree_via_file() {
    local pathspec rc=0
    pathspec="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-mutant.XXXXXX")"
    printf '.\0' >"$pathspec"
    (cd "$1" && git add -A --pathspec-from-file="$pathspec" --pathspec-file-nul) || rc=$?
    rm -f "$pathspec"
    return "$rc"
}

stage_mutant_uses_glob_via_file() {
    local pathspec rc=0
    pathspec="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-mutant.XXXXXX")"
    printf ':(glob)*\0' >"$pathspec"
    (cd "$1" && git add -A --pathspec-from-file="$pathspec" --pathspec-file-nul) || rc=$?
    rm -f "$pathspec"
    return "$rc"
}

stage_mutant_duplicates_pathspec() {
    local pathspec rc=0
    pathspec="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-mutant.XXXXXX")"
    write_stage_contract_pathspec "$pathspec"
    printf ':(literal)modified.txt\0' >>"$pathspec"
    (cd "$1" && git add -A --pathspec-from-file="$pathspec" --pathspec-file-nul) || rc=$?
    rm -f "$pathspec"
    return "$rc"
}

stage_mutant_adds_extra_pathspec() {
    local pathspec rc=0
    pathspec="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-mutant.XXXXXX")"
    write_stage_contract_pathspec "$pathspec"
    printf ':(literal)unchanged.txt\0' >>"$pathspec"
    (cd "$1" && git add -A --pathspec-from-file="$pathspec" --pathspec-file-nul) || rc=$?
    rm -f "$pathspec"
    return "$rc"
}

stage_mutant_misses_tracked() {
    local list paths
    list="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-mutant.XXXXXX")"
    paths="${list}.paths"
    (cd "$1" && git ls-files --others --exclude-standard -z >"$list")
    literalize_nul_paths "$list" "$paths"
    [[ ! -s "$paths" ]] ||
        (cd "$1" && git add -A --pathspec-from-file="$paths" --pathspec-file-nul)
    rm -f "$list" "$paths"
}

stage_mutant_misses_untracked() {
    local list paths
    list="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-mutant.XXXXXX")"
    paths="${list}.paths"
    (cd "$1" && git diff --name-only -z HEAD -- >"$list")
    literalize_nul_paths "$list" "$paths"
    [[ ! -s "$paths" ]] ||
        (cd "$1" && git add -A --pathspec-from-file="$paths" --pathspec-file-nul)
    rm -f "$list" "$paths"
}

stage_mutant_rejects_empty() {
    stage_sandbox_changes "$1"
    [[ -n "$(cd "$1" && git status --porcelain)" ]]
}

probe_selective_staging() {
    local mutant desc
    cases=$((cases + 1))
    if guard_case_owned "$cases"; then
        if stage_helper_contract stage_sandbox_changes; then
            pass_msg 'selective staging covers modified, deleted, untracked and empty mutations'
        else
            fail_msg 'selective staging lost a changed path or scanned the whole repository'
        fi
    fi
    while IFS='|' read -r mutant desc; do
        cases=$((cases + 1))
        guard_case_owned "$cases" || continue
        if stage_helper_contract "$mutant"; then
            fail_msg "selective staging accepted its mutation: ${desc}"
        else
            pass_msg "selective staging catches its own mutation: ${desc}"
        fi
    done <<'EOF'
stage_mutant_adds_whole_tree|repository-wide git add restored
stage_mutant_adds_dot|repository-wide git add dot restored
stage_mutant_adds_dot_with_global_directory|repository-wide git add dot hidden after a global directory argument
stage_mutant_adds_whole_tree_then_targeted|repository-wide git add hidden before targeted staging
stage_mutant_adds_whole_tree_via_file|repository-wide dot path hidden in a pathspec file
stage_mutant_uses_glob_via_file|repository-wide glob hidden in a pathspec file
stage_mutant_duplicates_pathspec|a duplicate literal path hidden in a pathspec file
stage_mutant_adds_extra_pathspec|an unchanged extra path hidden in a pathspec file
stage_mutant_misses_tracked|tracked modifications and deletions omitted
stage_mutant_misses_untracked|untracked additions omitted
stage_mutant_rejects_empty|an empty mutation reported as failure
EOF
}
probe_selective_staging

reset_helper_contract() {
    local helper="$1" repo real_git rc=0
    repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-reset-helper.XXXXXX")"
    real_git="$(command -v git)"
    (
        cd "$repo"
        "$real_git" init -q .
        printf 'magic baseline\n' >':(glob)decoy'
        printf 'bracket baseline\n' >'tracked[one].txt'
        "$real_git" add -- ':(literal):(glob)decoy' ':(literal)tracked[one].txt'
        "$real_git" -c user.name=t -c user.email=t@t commit -qm base
        printf 'changed\n' >>':(glob)decoy'
        rm 'tracked[one].txt'
        printf 'untracked magic\n' >':(glob)untracked'
        printf 'untracked bracket\n' >'untracked[two].txt'
        "$real_git" add -- ':(literal):(glob)decoy' ':(literal)untracked[two].txt'
    )
    "$helper" "$repo" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]] &&
        [[ "$(cd "$repo" && "$real_git" status --porcelain)" == "" ]] &&
        [[ "$(<"$repo/:(glob)decoy")" == 'magic baseline' ]] &&
        [[ "$(<"$repo/tracked[one].txt")" == 'bracket baseline' ]] &&
        [[ ! -e "$repo/:(glob)untracked" ]] &&
        [[ ! -e "$repo/untracked[two].txt" ]]; then
        rc=0
    else
        rc=1
    fi
    rm -rf "$repo"
    return "$rc"
}

reset_mutant_uses_raw_pathspecs() {
    local repo="$1" changed untracked
    changed="$(mktemp "${TMPDIR:-/tmp}/gateway-reset-mutant.XXXXXX")"
    untracked="${changed}.untracked"
    (
        cd "$repo"
        git diff --name-only -z HEAD -- >"$changed"
        [[ ! -s "$changed" ]] || xargs -0 git reset -q HEAD -- <"$changed"
        git ls-files --others --exclude-standard -z >"$untracked"
        [[ ! -s "$untracked" ]] || xargs -0 git clean -fdq -- <"$untracked"
        git diff --name-only -z HEAD -- >"$changed"
        [[ ! -s "$changed" ]] || xargs -0 git checkout -f HEAD -- <"$changed"
    )
    local rc=$?
    rm -f "$changed" "$untracked"
    return "$rc"
}

probe_literal_reset_paths() {
    cases=$((cases + 1))
    if guard_case_owned "$cases"; then
        if reset_helper_contract reset_sandbox_changes; then
            pass_msg 'selective reset treats glob-like and bracket paths literally'
        else
            fail_msg 'selective reset lost a literal tracked or untracked path'
        fi
    fi
    cases=$((cases + 1))
    if guard_case_owned "$cases"; then
        if reset_helper_contract reset_mutant_uses_raw_pathspecs; then
            fail_msg 'selective reset accepted raw Git pathspec magic'
        else
            pass_msg 'selective reset catches its own mutation: raw Git pathspec magic restored'
        fi
    fi
}
probe_literal_reset_paths

# Prove that a successful stage publishes the exact literal path sets for one reset, that the
# reset consumes them without rescanning the repository, and that failure/empty/fallback paths do
# not leak state into the next case.
probe_cached_sandbox_reset() {
    local repo shim log real_git rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-reset-cache.XXXXXX")"
    shim="$(mktemp -d "${TMPDIR:-/tmp}/gateway-reset-cache-git.XXXXXX")"
    log="$(mktemp "${TMPDIR:-/tmp}/gateway-reset-cache-log.XXXXXX")"
    real_git="$(command -v git)"
    SANDBOX="$repo"
    SANDBOX_RESET_TRACKED="${repo}.tracked"
    SANDBOX_RESET_UNTRACKED="${repo}.untracked"
    SANDBOX_RESET_READY=0
    (
        cd "$repo"
        "$real_git" init -q .
        printf 'modified baseline\n' >modified.txt
        printf 'deleted baseline\n' >deleted.txt
        printf 'magic baseline\n' >':(glob)tracked'
        printf 'fallback baseline\n' >fallback.txt
        "$real_git" add -- modified.txt deleted.txt fallback.txt ':(literal):(glob)tracked'
        "$real_git" -c user.name=t -c user.email=t@t commit -qm base
    )
    printf '%s\n' \
        '#!/bin/sh' \
        'printf "%s\n" "${1-}" >>"$GATEWAY_RESET_CACHE_LOG"' \
        'if [ "${GATEWAY_RESET_FAIL_ADD-0}" -eq 1 ] && [ "${1-}" = add ]; then exit 71; fi' \
        'exec "$GATEWAY_RESET_REAL_GIT" "$@"' >"$shim/git"
    chmod +x "$shim/git"

    (
        cd "$repo"
        printf 'changed\n' >>modified.txt
        rm deleted.txt
        printf 'changed\n' >>':(glob)tracked'
        printf 'untracked magic\n' >':(glob)untracked'
        printf 'untracked bracket\n' >'untracked[one].txt'
    )
    PATH="$shim:$PATH" GATEWAY_RESET_CACHE_LOG="$log" GATEWAY_RESET_REAL_GIT="$real_git" \
        stage_sandbox_changes "$repo" || rc=$?
    : >"$log"
    if [[ "$rc" -eq 0 ]]; then
        PATH="$shim:$PATH" GATEWAY_RESET_CACHE_LOG="$log" GATEWAY_RESET_REAL_GIT="$real_git" \
            reset_sandbox_changes "$repo" || rc=$?
    fi
    if [[ "$rc" -eq 0 ]] &&
        grep -Eq '^(diff|ls-files)$' "$log"; then
        rc=1
    fi
    if [[ "$rc" -eq 0 ]] && ! (
        cd "$repo"
        [[ -z "$("$real_git" status --porcelain)" ]] &&
            [[ "$(<modified.txt)" == 'modified baseline' ]] &&
            [[ "$(<deleted.txt)" == 'deleted baseline' ]] &&
            [[ "$(<':(glob)tracked')" == 'magic baseline' ]] &&
            [[ ! -e ':(glob)untracked' ]] &&
            [[ ! -e 'untracked[one].txt' ]]
    ); then
        rc=1
    fi
    if [[ "$rc" -eq 0 && "$SANDBOX_RESET_READY" -ne 0 ]]; then
        rc=1
    fi

    # An unstaged special probe has no cache and must take the explicit scan fallback once.
    if [[ "$rc" -eq 0 ]]; then
        printf 'fallback change\n' >>"$repo/fallback.txt"
        printf 'fallback untracked\n' >"$repo/fallback-new.txt"
        : >"$log"
        PATH="$shim:$PATH" GATEWAY_RESET_CACHE_LOG="$log" GATEWAY_RESET_REAL_GIT="$real_git" \
            reset_sandbox_changes "$repo" || rc=$?
        if ! grep -qx diff "$log" || ! grep -qx ls-files "$log" ||
            [[ -n "$(cd "$repo" && "$real_git" status --porcelain)" ]]; then
            rc=1
        fi
    fi

    # Empty staging still publishes a consumable empty set, avoiding a scan on the next reset.
    if [[ "$rc" -eq 0 ]]; then
        : >"$log"
        PATH="$shim:$PATH" GATEWAY_RESET_CACHE_LOG="$log" GATEWAY_RESET_REAL_GIT="$real_git" \
            stage_sandbox_changes "$repo" || rc=$?
        : >"$log"
        PATH="$shim:$PATH" GATEWAY_RESET_CACHE_LOG="$log" GATEWAY_RESET_REAL_GIT="$real_git" \
            reset_sandbox_changes "$repo" || rc=$?
        if grep -Eq '^(diff|ls-files)$' "$log"; then
            rc=1
        fi
    fi

    # A failed stage must not publish a cache for a later case.
    if [[ "$rc" -eq 0 ]]; then
        printf 'failed stage\n' >>"$repo/modified.txt"
        GATEWAY_RESET_FAIL_ADD=1 PATH="$shim:$PATH" GATEWAY_RESET_CACHE_LOG="$log" \
            GATEWAY_RESET_REAL_GIT="$real_git" stage_sandbox_changes "$repo" >/dev/null 2>&1 && rc=1
        if [[ "$SANDBOX_RESET_READY" -ne 0 ]]; then
            rc=1
        fi
        (cd "$repo" && "$real_git" reset -q --hard HEAD && "$real_git" clean -fdq)
    fi

    rm -rf "$repo" "$shim"
    rm -f "$log" "$SANDBOX_RESET_TRACKED" "$SANDBOX_RESET_UNTRACKED"
    SANDBOX=""
    SANDBOX_RESET_TRACKED=""
    SANDBOX_RESET_UNTRACKED=""
    SANDBOX_RESET_READY=0
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'cached sandbox reset consumes exact literal paths once and keeps fallback isolated'
    else
        fail_msg 'cached sandbox reset rescanned, leaked, or lost a modified/deleted/untracked path'
    fi
}
probe_cached_sandbox_reset

probe_cached_reset_failures() {
    local command repo shim marker real_git helper_rc
    for command in reset clean checkout; do
        cases=$((cases + 1))
        guard_case_owned "$cases" || continue
        repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-reset-failure.XXXXXX")"
        shim="$(mktemp -d "${TMPDIR:-/tmp}/gateway-reset-failure-git.XXXXXX")"
        marker="${repo}.failed"
        real_git="$(command -v git)"
        SANDBOX="$repo"
        SANDBOX_RESET_TRACKED="${repo}.tracked"
        SANDBOX_RESET_UNTRACKED="${repo}.untracked"
        SANDBOX_RESET_READY=0
        (
            cd "$repo"
            "$real_git" init -q .
            printf 'baseline\n' >tracked.txt
            "$real_git" add tracked.txt
            "$real_git" -c user.name=t -c user.email=t@t commit -qm base
            printf 'changed\n' >>tracked.txt
            printf 'untracked\n' >untracked.txt
        )
        printf '%s\n' \
            '#!/bin/sh' \
            'if [ "${1-}" = "$GATEWAY_RESET_FAIL_COMMAND" ] && [ ! -e "$GATEWAY_RESET_FAIL_MARKER" ]; then' \
            '    : >"$GATEWAY_RESET_FAIL_MARKER"' \
            '    exit 72' \
            'fi' \
            'exec "$GATEWAY_RESET_REAL_GIT" "$@"' >"$shim/git"
        chmod +x "$shim/git"
        stage_sandbox_changes "$repo"
        helper_rc=0
        GATEWAY_RESET_FAIL_COMMAND="$command" GATEWAY_RESET_FAIL_MARKER="$marker" \
            GATEWAY_RESET_REAL_GIT="$real_git" PATH="$shim:$PATH" \
            reset_sandbox_changes "$repo" >/dev/null 2>&1 || helper_rc=$?
        if [[ "$helper_rc" -ne 0 && "$SANDBOX_RESET_READY" -eq 0 &&
            ! -s "$SANDBOX_RESET_TRACKED" && ! -s "$SANDBOX_RESET_UNTRACKED" ]]; then
            pass_msg "cached sandbox reset fails closed when git ${command} fails"
        else
            fail_msg "cached sandbox reset swallowed a git ${command} failure or leaked its cache"
        fi
        (cd "$repo" && "$real_git" reset -q --hard HEAD && "$real_git" clean -fdq)
        rm -rf "$repo" "$shim"
        rm -f "$marker" "$SANDBOX_RESET_TRACKED" "$SANDBOX_RESET_UNTRACKED"
    done
    SANDBOX=""
    SANDBOX_RESET_TRACKED=""
    SANDBOX_RESET_UNTRACKED=""
    SANDBOX_RESET_READY=0
}
probe_cached_reset_failures

# Prove the selective reset itself before relying on it for the remaining cases. The probe dirties
# the index, a tracked file and an untracked file, then asks the next sandbox acquisition for the
# same clean baseline every guard case expects.
probe_selective_reset() {
    local sandbox
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    (
        cd "$sandbox"
        printf '\n# reset probe\n' >>Cargo.toml
        printf 'probe\n' >reset-probe.txt
    )
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    make_sandbox
    if (
        cd "$sandbox"
        git diff --quiet HEAD -- &&
            git diff --cached --quiet HEAD -- &&
            [[ -z "$(git ls-files --others --exclude-standard)" ]]
    ); then
        pass_msg 'selective sandbox reset restores the tracked, staged and untracked baseline'
    else
        fail_msg 'selective sandbox reset left state from the preceding mutation'
    fi
}
probe_selective_reset

# History-sensitive mutations may commit more than one revision. The next case must restore the
# original sandbox commit, including tracked paths introduced only by that temporary history.
probe_history_sensitive_reset() {
    local sandbox
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    (
        cd "$sandbox"
        printf 'history-only\n' >history-reset-probe.txt
        git add history-reset-probe.txt
        git -c user.name=t -c user.email=t@t commit -qm 'history reset probe'
        git -c user.name=t -c user.email=t@t commit --allow-empty -qm 'history reset follow-up'
    )
    make_sandbox
    if [[ "$(git -C "$sandbox" rev-parse HEAD)" == "$SANDBOX_BASE" &&
        ! -e "$sandbox/history-reset-probe.txt" &&
        -z "$(git -C "$sandbox" status --porcelain)" ]]; then
        pass_msg 'history-sensitive sandbox reset restores its original commit and paths'
    else
        fail_msg 'history-sensitive sandbox reset leaked a temporary commit or tracked path'
    fi
}
probe_history_sensitive_reset

mut_reverse_edge() {
    printf 'rustfs-gateway-types = { workspace = true }\n' >>crates/xml/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'reverse edge rustfs-gateway-xml -> rustfs-gateway-types' mut_reverse_edge

mut_reverse_edge_renamed() {
    printf 'types-bridge = { package = "rustfs-gateway-types", path = "../types" }\n' >>crates/xml/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'a renamed reverse internal dependency' mut_reverse_edge_renamed

mut_reverse_edge_target_specific() {
    printf '\n[target.'"'"'cfg(any())'"'"'.dependencies]\ntypes-target = { package = "rustfs-gateway-types", path = "../types" }\n' \
        >>crates/xml/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'a target-specific reverse internal dependency' mut_reverse_edge_target_specific

mut_reverse_edge_workspace_inherited() {
    python3 - <<'PYEOF'
from pathlib import Path
root = Path("Cargo.toml")
text = root.read_text()
marker = "[workspace.dependencies]\n"
if text.count(marker) != 1:
    raise SystemExit("workspace dependency table is not unique")
root.write_text(text.replace(marker, marker + 'types-workspace-alias = { package = "rustfs-gateway-types", path = "crates/types" }\n', 1))
with Path("crates/xml/Cargo.toml").open("a") as output:
    output.write('types-workspace-alias = { workspace = true }\n')
PYEOF
}
expect_fail check_layer_dependencies.sh \
    'a workspace-inherited renamed reverse internal dependency' \
    mut_reverse_edge_workspace_inherited

# Adds one dependency line to `crates/conformance/Cargo.toml`'s `[dependencies]` table.
#
# Not `>>` onto the end of the file. An append lands in whichever table happens to be last, and a
# `[dev-dependencies]` section there turns every mutation below into a dev-dependency — which the
# guards are right to permit, so the cases stop proving anything. That is not hypothetical: it is
# how three cases in this file went dark at once. The manifest keeps `[dependencies]` last and says
# why, and this function does not rely on it.
add_conformance_dependency() {
    GATEWAY_MUTATION_DEPENDENCY="$1" python3 - <<'PYEOF'
import os
from pathlib import Path

manifest = Path("crates/conformance/Cargo.toml")
text = manifest.read_text()
marker = "[dependencies]\n"
if text.count(marker) != 1:
    raise SystemExit("crates/conformance/Cargo.toml has no unique [dependencies] table to mutate")
line = os.environ["GATEWAY_MUTATION_DEPENDENCY"] + "\n"
manifest.write_text(text.replace(marker, marker + line, 1))
PYEOF
}

mut_conformance_internal() {
    add_conformance_dependency 'rustfs-gateway-core = { workspace = true }'
}
expect_fail check_layer_dependencies.sh \
    'conformance reaching past the facade into rustfs-gateway-core' mut_conformance_internal

mut_unregistered_crate() {
    mkdir -p crates/newthing
    printf '[package]\nname = "rustfs-gateway-newthing"\n\n[dependencies]\n' >crates/newthing/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'a new crate that is not registered in the allow matrix' mut_unregistered_crate

mut_gateway_macro_layer_edge_deleted() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/check_layer_dependencies.sh")
text = path.read_text()
old = '''            "rustfs-gateway-http",
            "rustfs-gateway-macros",
            "rustfs-gateway-server",
            "rustfs-gateway-types",'''
new = '''            "rustfs-gateway-http",
            "rustfs-gateway-server",
            "rustfs-gateway-types",'''
if text.count(old) != 1:
    raise SystemExit("the gateway macro edge is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail_self_mutation check_layer_dependencies.sh \
    'the public facade macro edge disappearing from the executable layer matrix' \
    mut_gateway_macro_layer_edge_deleted

mut_gateway_server_layer_edge_deleted() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/check_layer_dependencies.sh")
text = path.read_text()
old = '''            "rustfs-gateway-macros",
            "rustfs-gateway-server",
            "rustfs-gateway-types",'''
new = '''            "rustfs-gateway-macros",
            "rustfs-gateway-types",'''
if text.count(old) != 1:
    raise SystemExit("the gateway server edge is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail_self_mutation check_layer_dependencies.sh \
    'the self-held server edge disappearing from the executable layer matrix' \
    mut_gateway_server_layer_edge_deleted

mut_gateway_macro_agents_edge_deleted() {
    sed '/rustfs-gateway.*rustfs-gateway-macros.*public facade re-export/d' AGENTS.md >AGENTS.md.mut
    mv AGENTS.md.mut AGENTS.md
}
expect_fail check_layer_dependencies.sh \
    'the public facade macro edge disappearing from the AGENTS dependency graph' \
    mut_gateway_macro_agents_edge_deleted

mut_gateway_server_agents_edge_deleted() {
    sed '/rustfs-gateway.*rustfs-gateway-server.*optional self-held listener assembly/d' AGENTS.md >AGENTS.md.mut
    mv AGENTS.md.mut AGENTS.md
}
expect_fail check_layer_dependencies.sh \
    'the self-held server edge disappearing from the AGENTS dependency graph' \
    mut_gateway_server_agents_edge_deleted

mut_handlers_facade_expansion_reaches_core() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/macros/src/expand.rs")
text = path.read_text()
old = "impl #impl_generics ::rustfs_gateway::Handler<#operations> for #self_ty #where_clause {"
new = "impl #impl_generics ::rustfs_gateway_core::handler::Handler<#operations> for #self_ty #where_clause {"
if text.count(old) != 1:
    raise SystemExit("the facade Handler expansion path is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_layer_dependencies.sh \
    'generated handler impls reaching through the facade into rustfs-gateway-core' \
    mut_handlers_facade_expansion_reaches_core \
    'macro expansion reaches past the public facade into rustfs_gateway_core'

mut_xtask_dispatch_layer_registration_deleted() {
    sed '/^dispatcher_name = "rustfs-gateway-xtask-dispatch"$/d' scripts/check_layer_dependencies.sh \
        >scripts/check_layer_dependencies.sh.mut
    mv scripts/check_layer_dependencies.sh.mut scripts/check_layer_dependencies.sh
}
expect_fail_self_mutation check_layer_dependencies.sh \
    'the std-only xtask dispatcher losing its pre-registered layer row' \
    mut_xtask_dispatch_layer_registration_deleted

mut_xtask_dispatch_layer_allows_dependency() {
    perl -0pi -e 's/dispatcher_allowed_dependencies: set\[str\] = set\(\)/dispatcher_allowed_dependencies: set[str] = {"rustfs-gateway-model"}/' \
        scripts/check_layer_dependencies.sh
}
expect_fail_self_mutation check_layer_dependencies.sh \
    'the std-only xtask dispatcher layer row allowing a dependency' \
    mut_xtask_dispatch_layer_allows_dependency

mut_xtask_dispatch_audit_exits_without_output() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/check_layer_dependencies.sh")
text = path.read_text()
old = "    return dispatcher_audit_sentinel\n"
if text.count(old) != 1:
    raise SystemExit("dispatcher audit exit mutation subject is not exact")
path.write_text(text.replace(old, "    return \"\"\n", 1))
PYEOF
}
expect_fail_self_mutation check_layer_dependencies.sh \
    'the structured dispatcher audit failing without diagnostic output' \
    mut_xtask_dispatch_audit_exits_without_output

mut_xtask_dispatch_agents_registration_deleted() {
    sed '/rustfs-gateway-xtask-dispatch.*std-only cargo xtask process selection/d' AGENTS.md >AGENTS.md.mut
    mv AGENTS.md.mut AGENTS.md
}
expect_fail check_layer_dependencies.sh \
    'the std-only xtask dispatcher leaving the AGENTS dependency graph' \
    mut_xtask_dispatch_agents_registration_deleted

write_future_xtask_dispatch_manifest() {
    mkdir -p crates/xtask-dispatch
    cat >crates/xtask-dispatch/Cargo.toml <<'TOMLEOF'
[package]
name = "rustfs-gateway-xtask-dispatch"
version = "0.1.1"
edition = "2024"

[package.metadata.gateway]
ring = 0
TOMLEOF
}

probe_xtask_dispatch_manifest_without_dependencies() {
    local sandbox layer_rc=0 ring_rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && write_future_xtask_dispatch_manifest)
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_layer_dependencies.sh" >/dev/null 2>&1 || layer_rc=$?
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_ring_boundaries.sh" >/dev/null 2>&1 || ring_rc=$?
    if [[ "$layer_rc" -eq 0 && "$ring_rc" -eq 0 ]]; then
        pass_msg 'layer and ring guards accept the canonical std-only dispatcher manifest'
    else
        fail_msg 'a dependency guard rejected the canonical std-only dispatcher manifest'
    fi
}
probe_xtask_dispatch_manifest_without_dependencies

probe_xtask_dispatch_guard_missing_python() {
    local output rc=0 tool_path
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-dispatch-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_layer_dependencies.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: python3'* ]]; then
        pass_msg 'check_layer_dependencies.sh fails closed without python3'
    else
        fail_msg 'check_layer_dependencies.sh reported green without python3'
    fi
}
probe_xtask_dispatch_guard_missing_python

mut_xtask_dispatch_normal_dependency() {
    write_future_xtask_dispatch_manifest
    printf '\n[dependencies]\nserde = "1"\n' >>crates/xtask-dispatch/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'the std-only dispatcher declaring a normal dependency' \
    mut_xtask_dispatch_normal_dependency

mut_xtask_dispatch_target_dependency() {
    write_future_xtask_dispatch_manifest
    printf '\n[target.'\''cfg(unix)'\''.dependencies]\nserde = "1"\n' \
        >>crates/xtask-dispatch/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'the std-only dispatcher declaring a target dependency' \
    mut_xtask_dispatch_target_dependency

mut_xtask_dispatch_dev_dependency() {
    write_future_xtask_dispatch_manifest
    printf '\n[dev-dependencies]\nserde = "1"\n' >>crates/xtask-dispatch/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'the std-only dispatcher declaring a dev dependency' \
    mut_xtask_dispatch_dev_dependency

mut_xtask_dispatch_build_dependency() {
    write_future_xtask_dispatch_manifest
    printf '\n[build-dependencies]\nserde = "1"\n' >>crates/xtask-dispatch/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'the std-only dispatcher declaring a build dependency' \
    mut_xtask_dispatch_build_dependency

mut_xtask_dispatch_wrong_manifest_path() {
    mkdir -p tools/dispatcher-shadow
    cat >tools/dispatcher-shadow/Cargo.toml <<'TOMLEOF'
[package]
name = "rustfs-gateway-xtask-dispatch"
version = "0.1.1"
edition = "2024"
TOMLEOF
}
expect_fail check_layer_dependencies.sh \
    'the dispatcher package appearing outside its canonical manifest path' \
    mut_xtask_dispatch_wrong_manifest_path

mut_xtask_dispatch_indented_dependency() {
    write_future_xtask_dispatch_manifest
    printf '\n[dependencies]\n    serde = "1"\n' >>crates/xtask-dispatch/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'the dispatcher hiding an indented normal dependency' \
    mut_xtask_dispatch_indented_dependency

mut_xtask_dispatch_indented_wrong_manifest_name() {
    mkdir -p tools/dispatcher-shadow
    cat >tools/dispatcher-shadow/Cargo.toml <<'TOMLEOF'
[package]
    name = "rustfs-gateway-xtask-dispatch"
version = "0.1.1"
edition = "2024"
TOMLEOF
}
expect_fail check_layer_dependencies.sh \
    'the dispatcher hiding an indented package name outside its canonical path' \
    mut_xtask_dispatch_indented_wrong_manifest_name

mut_stream_unapproved_external_dependency() {
    printf '\nserde = "1"\n' >>crates/stream/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'the stream kernel adding an external dependency outside its whitelist' \
    mut_stream_unapproved_external_dependency

mut_xtask_extra_internal_dependency() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/Cargo.toml")
text = path.read_text()
marker = "[dependencies]\n"
if text.count(marker) != 1:
    raise SystemExit("xtask dependency table is not unique")
path.write_text(text.replace(marker, marker + "rustfs-gateway-http = { workspace = true }\n", 1))
PYEOF
}
expect_fail check_layer_dependencies.sh \
    'xtask gaining an internal dependency outside its five-package tooling row' \
    mut_xtask_extra_internal_dependency

mut_xtask_extra_internal_dev_dependency() {
    printf '\n[dev-dependencies]\nrustfs-gateway-http = { workspace = true }\n' >>xtask/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'xtask gaining a dev-only internal dependency outside its five-package tooling row' \
    mut_xtask_extra_internal_dev_dependency

mut_agents_dependency_matrix_drift() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("AGENTS.md")
text = path.read_text()
old = "xtask ──▶ gateway + conformance + core + codegen + model"
if text.count(old) != 1:
    raise SystemExit("xtask matrix row is not unique")
path.write_text(text.replace(old, "xtask ──▶ gateway + core + codegen + model", 1))
PYEOF
}
expect_fail check_layer_dependencies.sh \
    'the AGENTS dependency matrix drifting from the executable xtask row' \
    mut_agents_dependency_matrix_drift

probe_layer_dev_dependency_is_allowed() {
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    printf '\n[dev-dependencies]\nrustfs-gateway-types = { workspace = true }\n' \
        >>"$sandbox/crates/xml/Cargo.toml"
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_layer_dependencies.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_layer_dependencies.sh allows internal dev-only edges'
    else
        fail_msg 'check_layer_dependencies.sh rejected an internal dev-only edge'
    fi
}
probe_layer_dev_dependency_is_allowed

mut_stream_shared_trailer_slot() {
    printf '\nstruct SharedTrailers(std::sync::Mutex<Option<crate::TrailingHeaders>>);\n' \
        >>crates/stream/src/trailers.rs
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning to a shared mutable slot' mut_stream_shared_trailer_slot
expect_fail check_no_trailer_mutex.sh \
    'the P3-04 trailer mutex alias rejecting a shared slot' mut_stream_shared_trailer_slot

mut_checksum_ledger_missing_row() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/check_checksum_case_coverage.sh")
text = path.read_text()
needle = "    'c-ck-0041|negative|test:crates/gateway/src/request_body_tests.rs::c_ck_0041_a_matching_checksum_never_substitutes_for_the_payload_hash'\n"
if text.count(needle) != 1:
    raise SystemExit("checksum ledger row mutation anchor is not unique")
path.write_text(text.replace(needle, "", 1))
PYEOF
}
expect_fail_self_mutation check_checksum_case_coverage.sh \
    'the checksum ledger losing one of its thirty-eight rows' mut_checksum_ledger_missing_row

mut_checksum_ledger_comment_only_test() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/http/tests/checksum_arbitration.rs")
text = path.read_text()
old = "fn c_ck_0001_a_matching_checksum_header_verifies_and_reports_what_it_verified() {"
new = "fn renamed_matching_checksum_header_verifies_and_reports_what_it_verified() {"
if text.count(old) != 1:
    raise SystemExit("checksum evidence mutation anchor is not unique")
text = text.replace(old, new, 1)
text += f"\n// {old} assert!(true); }}\n"
path.write_text(text)
PYEOF
}
expect_fail check_checksum_case_coverage.sh \
    'the checksum ledger accepting a deleted test name left only in a comment' \
    mut_checksum_ledger_comment_only_test

mut_checksum_ledger_trybuild_unbound() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/compile_fail.rs")
text = path.read_text()
needle = '    cases.compile_fail("tests/compile_fail/c_ck_0020_*.rs");\n'
if text.count(needle) != 1:
    raise SystemExit("checksum trybuild mutation anchor is not unique")
path.write_text(text.replace(needle, "", 1))
PYEOF
}
expect_fail check_checksum_case_coverage.sh \
    'the checksum timing fixture no longer being run by trybuild' mut_checksum_ledger_trybuild_unbound

mut_checksum_ledger_range_backlink_weakened() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("conformance/cases/range/c-range-0016.toml")
text = path.read_text()
needle = '"x-amz-checksum-crc32" = "*"'
if text.count(needle) != 1:
    raise SystemExit("range checksum backlink mutation anchor is not unique")
path.write_text(text.replace(needle, '"x-amz-request-id" = "*"', 1))
PYEOF
}
expect_fail check_checksum_case_coverage.sh \
    'the checksum range backlink losing its full-object positive control' \
    mut_checksum_ledger_range_backlink_weakened

mut_stream_rwlock_trailer_slot() {
    printf '\nstruct SharedTrailers(std::sync::RwLock<Option<crate::TrailingHeaders>>);\n' \
        >>crates/stream/src/trailers.rs
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning to a shared rwlock slot' mut_stream_rwlock_trailer_slot

mut_stream_once_cell_trailers() {
    printf '\nstruct SharedTrailers(std::cell::OnceCell<crate::TrailingHeaders>);\n' \
        >>crates/stream/src/trailers.rs
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning to a once-cell slot' mut_stream_once_cell_trailers

mut_stream_once_lock_trailers() {
    printf '\nstruct SharedTrailers(std::sync::OnceLock<crate::TrailingHeaders>);\n' \
        >>crates/stream/src/trailers.rs
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning to a once-lock slot' mut_stream_once_lock_trailers

mut_stream_aliased_shared_trailer_slot() {
    cat >>crates/stream/src/trailers.rs <<'RUST'

type SharedTrailerSlot = Option<crate::TrailingHeaders>;
struct SharedTrailers(std::sync::Mutex<SharedTrailerSlot>);
RUST
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning to a shared slot hidden behind an alias' \
    mut_stream_aliased_shared_trailer_slot

mut_stream_transitively_aliased_once_lock() {
    cat >>crates/stream/src/trailers.rs <<'RUST'

type TrailerMap = crate::TrailingHeaders;
type TrailerMapAlias = TrailerMap;
struct SharedTrailers(std::sync::OnceLock<TrailerMapAlias>);
RUST
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning to a once-lock hidden behind transitive aliases' \
    mut_stream_transitively_aliased_once_lock

mut_stream_generic_wrapper_alias() {
    cat >>crates/stream/src/trailers.rs <<'RUST'

type Lock<T> = std::sync::Mutex<T>;
type SharedTrailerSlot = Option<crate::TrailingHeaders>;
struct SharedTrailers(Lock<SharedTrailerSlot>);
RUST
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning through a generic lock alias' \
    mut_stream_generic_wrapper_alias

mut_stream_defaulted_generic_wrapper_alias() {
    cat >>crates/stream/src/trailers.rs <<'RUST'

type Lock<T = ()> = std::sync::Mutex<T>;
type SharedTrailerSlot = Option<crate::TrailingHeaders>;
struct SharedTrailers(Lock<SharedTrailerSlot>);
RUST
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning through a defaulted generic lock alias' \
    mut_stream_defaulted_generic_wrapper_alias

mut_stream_extra_defaulted_wrapper_parameter() {
    cat >>crates/stream/src/trailers.rs <<'RUST'

type Lock<T, Marker = ()> = std::sync::Mutex<T>;
struct SharedTrailers(Lock<Option<crate::TrailingHeaders>>);
RUST
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning through a lock alias with an extra defaulted parameter' \
    mut_stream_extra_defaulted_wrapper_parameter

mut_stream_imported_wrapper_alias() {
    cat >>crates/stream/src/trailers.rs <<'RUST'

use std::sync::Mutex as Lock;
type SharedTrailerSlot = Option<crate::TrailingHeaders>;
struct SharedTrailers(Lock<SharedTrailerSlot>);
RUST
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning through an imported lock alias' \
    mut_stream_imported_wrapper_alias

mut_stream_as_any_escape_hatch() {
    printf '\ntrait EscapeHatch { fn as_any(&self) -> &dyn std::any::Any; }\n' \
        >>crates/stream/src/payload.rs
}
expect_fail check_no_as_any.sh \
    'stream payload exposing an as_any escape hatch' mut_stream_as_any_escape_hatch

mut_stream_downcast_ref_escape_hatch() {
    printf '\nfn escape(value: &dyn std::any::Any) { let _ = value.downcast_ref::<u8>(); }\n' \
        >>crates/stream/src/payload.rs
}
expect_fail check_no_as_any.sh \
    'stream payload using downcast_ref for negotiation' mut_stream_downcast_ref_escape_hatch

mut_stream_downcast_mut_escape_hatch() {
    printf '\nfn escape(value: &mut dyn std::any::Any) { let _ = value.downcast_mut::<u8>(); }\n' \
        >>crates/stream/src/payload.rs
}
expect_fail check_no_as_any.sh \
    'stream payload using downcast_mut for negotiation' mut_stream_downcast_mut_escape_hatch

mut_stream_generic_downcast_escape_hatch() {
    printf '\nfn escape(value: Box<dyn std::any::Any>) { let _ = value.downcast::<u8>(); }\n' \
        >>crates/stream/src/payload.rs
}
expect_fail check_no_as_any.sh \
    'stream payload using owned Any downcast for negotiation' mut_stream_generic_downcast_escape_hatch

# The four cases above plant into `crates/stream/src`, which the guard already read
# before P3-02. The eight below are the widening: an escape hatch in the wire layer or in
# the facade, and an allowlist that could be used to switch the rule off from the outside.

mut_wire_as_any_escape_hatch() {
    printf '\ntrait EscapeHatch { fn as_any(&self) -> &dyn std::any::Any; }\n' \
        >>crates/http/src/wire.rs
}
expect_fail check_no_as_any.sh \
    'the wire layer exposing an as_any escape hatch' mut_wire_as_any_escape_hatch

mut_facade_as_any_escape_hatch() {
    printf '\ntrait EscapeHatch { fn as_any(&self) -> &dyn std::any::Any; }\n' \
        >>crates/gateway/src/dispatch.rs
}
expect_fail check_no_as_any.sh \
    'the facade exposing an as_any escape hatch' mut_facade_as_any_escape_hatch

# A call site with no declaration anywhere: the transport half of the bypass, which is what
# arrives first when the trait is defined in a downstream crate.
mut_core_as_any_call_site() {
    printf '\nfn escape(value: &u8) { let _ = value.as_any(); }\n' >>crates/core/src/lib.rs
}
expect_fail check_no_as_any.sh \
    'an as_any call site with no declaration in the repository' mut_core_as_any_call_site

mut_wire_downcast_ref_escape_hatch() {
    printf '\nfn escape(value: &dyn std::any::Any) { let _ = value.downcast_ref::<u8>(); }\n' \
        >>crates/http/src/wire.rs
}
expect_fail check_no_as_any.sh \
    'the wire layer using downcast_ref, which the allowlist cannot reach' \
    mut_wire_downcast_ref_escape_hatch

mut_core_unregistered_downcast() {
    printf '\nfn escape(value: &dyn std::any::Any) { let _ = value.downcast_ref::<u8>(); }\n' \
        >>crates/core/src/lib.rs
}
expect_fail check_no_as_any.sh \
    'a downcast outside the payload data plane that nobody registered' \
    mut_core_unregistered_downcast

mut_as_any_allowance_inside_data_plane() {
    printf 'crates/stream/src/payload.rs:1    # convenient\n' \
        >>scripts/allowances/as-any-allowances.txt
}
expect_fail check_no_as_any.sh \
    'an allowlist entry reaching into the payload data plane' \
    mut_as_any_allowance_inside_data_plane

mut_as_any_allowance_without_reason() {
    printf 'crates/core/src/lib.rs:1\n' >>scripts/allowances/as-any-allowances.txt
}
expect_fail check_no_as_any.sh \
    'an allowlist entry with no reason written next to it' \
    mut_as_any_allowance_without_reason

# An exemption that outlives the code it was written for silently covers whatever moves
# onto that line next, which is the shape every stale suppression takes.
mut_as_any_allowance_stale() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/allowances/as-any-allowances.txt")
text = path.read_text()
if "codecs.rs:217" not in text:
    raise SystemExit("expected allowlist entry is missing")
path.write_text(text.replace("codecs.rs:217", "codecs.rs:218", 1))
PYEOF
}
expect_fail check_no_as_any.sh \
    'an allowlist entry whose line no longer holds a downcast' mut_as_any_allowance_stale

# The data plane is what a file implements, not only where it sits. Without these three cases
# the sealed set is two directory names, and a crate that grows a payload producer of its own
# could take an allowlist entry for the downcast sitting beside it.

mut_implementor_registers_a_downcast() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/lib.rs")
text = path.read_text()
planted = (
    "\nstruct PlantedProducer;\n"
    "impl crate::PayloadStream for PlantedProducer {}\n"
    "fn planted(value: &dyn std::any::Any) { let _ = value.downcast_ref::<u8>(); }\n"
)
path.write_text(text + planted)
line = len((text + planted).splitlines())
Path("scripts/allowances/as-any-allowances.txt").open("a").write(
    f"crates/core/src/lib.rs:{line}    # planted, and argued for exactly as a real entry would be\n"
)
PYEOF
}
expect_fail check_no_as_any.sh \
    'an allowlist entry for a file that implements a payload producer' \
    mut_implementor_registers_a_downcast

mut_implementor_reaches_for_any() {
    printf '\nstruct PlantedConsumer;\nimpl crate::AsyncPayloadRead for PlantedConsumer {}\nfn planted(value: &dyn std::any::Any) -> bool { value.is::<u8>() }\n' \
        >>crates/core/src/lib.rs
}
expect_fail check_no_as_any.sh \
    'a payload consumer outside the two directories reaching for Any' \
    mut_implementor_reaches_for_any

# Fail closed. If the traits that define the content half of the data plane are renamed away,
# the rule silently narrows back to two directory names, which is the one failure a green line
# would never show.
mut_payload_contract_renamed_away() {
    python3 - <<'PYEOF'
from pathlib import Path

changed = 0
for directory in (Path("crates"), Path("spikes"), Path("xtask")):
    if not directory.is_dir():
        continue
    for path in directory.rglob("*.rs"):
        text = path.read_text()
        if "PayloadStream" not in text and "AsyncPayloadRead" not in text:
            continue
        path.write_text(text.replace("PayloadStream", "PushHalf").replace("AsyncPayloadRead", "PullHalf"))
        changed += 1
if changed == 0:
    raise SystemExit("expected the payload contract to be implemented somewhere")
PYEOF
}
expect_fail check_no_as_any.sh \
    'the payload contract renamed away, leaving the content half of the data plane empty' \
    mut_payload_contract_renamed_away

# The positive half of the rule. "There is no as_any()" is only an argument while the named
# accessors it points at still exist; without this case the guard would keep reporting green
# over a Payload with no negotiation surface left.
mut_payload_accessor_renamed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/stream/src/payload.rs")
text = path.read_text()
if "pub fn try_as_vectored" not in text:
    raise SystemExit("expected payload accessor is missing")
path.write_text(text.replace("pub fn try_as_vectored", "pub fn vectored_slice", 1))
PYEOF
}
expect_fail check_no_as_any.sh \
    'the named accessor as_any was banned in favour of, renamed away' \
    mut_payload_accessor_renamed

# --- check_no_spawn_in_stream.sh ------------------------------------------------------
#
# Back-pressure in the push model is the absence of a read-ahead task, so every one of
# these plants a producer that would keep running after its consumer stopped.

mut_stream_spawn_read_ahead() {
    printf '\nfn prefetch() { let _ = tokio::spawn(async {}); }\n' >>crates/stream/src/adapt.rs
}
expect_fail check_no_spawn_in_stream.sh \
    'a read-ahead task inside the payload crate' mut_stream_spawn_read_ahead

# The case that scoping the rule to `crates/stream` alone would miss: the producer that
# reads from a socket lives in the wire layer, not in the payload crate.
mut_ingest_spawn_read_ahead() {
    printf '\nfn prefetch() { let _ = tokio::spawn(async {}); }\n' \
        >>crates/http/src/ingest/pipeline.rs
}
expect_fail check_no_spawn_in_stream.sh \
    'a read-ahead task inside a wire-layer AsyncPayloadRead impl' mut_ingest_spawn_read_ahead

mut_stream_join_set_read_ahead() {
    printf '\nfn prefetch(set: &mut tokio::task::JoinSet<()>) { let _ = set; }\n' \
        >>crates/stream/src/byte_stream.rs
}
expect_fail check_no_spawn_in_stream.sh \
    'a JoinSet holding the handle a spawn returned' mut_stream_join_set_read_ahead

mut_stream_thread_spawn_read_ahead() {
    printf '\nfn prefetch() { let _ = std::thread::spawn(|| {}); }\n' >>crates/stream/src/stream.rs
}
expect_fail check_no_spawn_in_stream.sh \
    'a read-ahead thread rather than a task' mut_stream_thread_spawn_read_ahead

# The structural half: with no runtime in the dependency tree, a read-ahead task is not
# merely forbidden in this crate, it is unwritable.
mut_stream_declares_runtime() {
    printf 'tokio = { workspace = true }\n' >>crates/stream/Cargo.toml
}
expect_fail check_no_spawn_in_stream.sh \
    'the payload crate declaring an async runtime' mut_stream_declares_runtime

mut_payload_traits_renamed() {
    python3 - <<'PYEOF'
from pathlib import Path

for path in Path("crates").rglob("*.rs"):
    text = path.read_text()
    if "PayloadStream" in text or "AsyncPayloadRead" in text:
        path.write_text(
            text.replace("PayloadStream", "Renamed1").replace("AsyncPayloadRead", "Renamed2")
        )
PYEOF
}
expect_fail check_no_spawn_in_stream.sh \
    'both data-plane traits renamed, leaving the guard with no subject' \
    mut_payload_traits_renamed

# A workspace member outside `crates/`. It compiles under `--workspace`, so an escape hatch
# written there is shipped code, and scoping the scan to `crates/` alone would miss it.
mut_spike_as_any_escape_hatch() {
    printf '\ntrait EscapeHatch { fn as_any(&self) -> &dyn std::any::Any; }\n' \
        >>spikes/ext-field/src/policy.rs
}
expect_fail check_no_as_any.sh \
    'a workspace member outside crates/ exposing an as_any escape hatch' \
    mut_spike_as_any_escape_hatch

# A spawning helper one module away from the impl that calls it. A file-scoped rule reads the
# impl as clean and the back-pressure is gone all the same.
mut_wire_neighbour_spawn() {
    printf '\nfn prefetch() { let _ = tokio::spawn(async {}); }\n' >>crates/http/src/limits.rs
}
expect_fail check_no_spawn_in_stream.sh \
    'a spawning helper in a wire-layer module that carries no impl' mut_wire_neighbour_spawn

mut_wire_declares_runtime() {
    printf 'tokio = { workspace = true }\n' >>crates/http/Cargo.toml
}
expect_fail check_no_spawn_in_stream.sh \
    'the wire layer declaring an async runtime' mut_wire_declares_runtime

mut_wire_plane_removed() {
    rm -rf crates/http/src
}
expect_fail check_no_spawn_in_stream.sh \
    'the wire half of the data plane removed, leaving half a rule' mut_wire_plane_removed

mut_stream_protocol_vocabulary() {
    printf '\n// Checksum belongs above the stream kernel.\n' >>crates/stream/src/stream.rs
}
expect_fail check_stream_vocabulary.sh \
    'protocol vocabulary entering the stream kernel' mut_stream_protocol_vocabulary

mut_stream_etag_vocabulary() {
    printf '\n// ETag belongs above the stream kernel.\n' >>crates/stream/src/stream.rs
}
expect_fail check_stream_vocabulary.sh \
    'ETag vocabulary entering the stream kernel' mut_stream_etag_vocabulary

mut_stream_bucket_vocabulary() {
    printf '\n// Bucket belongs above the stream kernel.\n' >>crates/stream/src/stream.rs
}
expect_fail check_stream_vocabulary.sh \
    'bucket vocabulary entering the stream kernel' mut_stream_bucket_vocabulary

mut_stream_multipart_vocabulary() {
    printf '\n// Multipart belongs above the stream kernel.\n' >>crates/stream/src/stream.rs
}
expect_fail check_stream_vocabulary.sh \
    'multipart vocabulary entering the stream kernel' mut_stream_multipart_vocabulary

mut_stream_object_key_vocabulary() {
    printf '\n// ObjectKey belongs above the stream kernel.\n' >>crates/stream/src/stream.rs
}
expect_fail check_stream_vocabulary.sh \
    'object-key vocabulary entering the stream kernel' mut_stream_object_key_vocabulary

mut_stream_hyphenated_object_key_vocabulary() {
    printf '\n// Object-key belongs above the stream kernel.\n' >>crates/stream/src/stream.rs
}
expect_fail check_stream_vocabulary.sh \
    'hyphenated object-key vocabulary entering the stream kernel' mut_stream_hyphenated_object_key_vocabulary

probe_stream_vocabulary_allows_plain_object() {
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    printf '\n// A trait object is ordinary stream-kernel vocabulary.\n' >>"${sandbox}/crates/stream/src/stream.rs"
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_stream_vocabulary.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_stream_vocabulary.sh permits ordinary object vocabulary'
    else
        fail_msg 'check_stream_vocabulary.sh overfits ordinary object vocabulary'
    fi
}
probe_stream_vocabulary_allows_plain_object

probe_pipeline_borrowed_view_allowed() {
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    cat >>"${sandbox}/crates/stream/src/read.rs" <<'RUST'

pub struct BorrowedView<'a>(&'a [u8]);
RUST
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_pipeline_stage_shape.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_pipeline_stage_shape.sh permits a non-stage borrowed view'
    else
        fail_msg 'check_pipeline_stage_shape.sh rejects a non-stage borrowed view'
    fi
}
probe_pipeline_borrowed_view_allowed

mut_pipeline_new_stage_has_lifetime() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
path.write_text(path.read_text() + """
pub(crate) struct BorrowedStage<'a>(&'a [u8]);
impl RequestConfig<Authorized> {
    pub(crate) fn borrowed<'a>(self) -> RequestConfig<BorrowedStage<'a>> { self.advance() }
}
""")
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'a newly added real request stage carrying a lifetime' mut_pipeline_new_stage_has_lifetime

mut_pipeline_non_unit_stage() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text().replace(
    "pub(crate) struct Entered;",
    "pub(crate) struct Entered { marker: core::marker::PhantomData<()> }",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'a request stage carrying data outside the owned carrier' mut_pipeline_non_unit_stage

mut_pipeline_multiple_roots() {
    cat >>crates/gateway/src/request_config.rs <<'RUST'

pub(crate) struct Alternative;
impl RequestConfig<Alternative> {
    pub(crate) fn authorized(self) -> RequestConfig<Authorized> { self.advance() }
}
RUST
}
expect_fail check_pipeline_stage_shape.sh \
    'an alternative root entering the request transition closure' mut_pipeline_multiple_roots

mut_pipeline_predecode_stage_is_generic() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text().replace(
    "pub(crate) struct Routed;",
    "pub(crate) struct Routed<O>(core::marker::PhantomData<fn() -> O>);",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'a pre-decode request stage carrying an operation generic' \
    mut_pipeline_predecode_stage_is_generic

mut_pipeline_service_skips_targeted() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let config = config.targeted();",
    "let config = config;",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'the production service skipping host targeting' mut_pipeline_service_skips_targeted

mut_pipeline_service_drops_missing_visibility() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
text = text.replace(
    "let config = config.with_missing_object_visibility(visibility).authorized();",
    "let config = config.authorized();",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'the production service dropping its missing-object visibility transition' \
    mut_pipeline_service_drops_missing_visibility

mut_pipeline_dynamic_decode_moves_after_authorization() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/operation_mode.rs")
text = path.read_text().replace(
    "let decoded = entry.decode(meta, body).map_err(StaticDispatchError::Codec)?;",
    "let decoded = entry.decode_after_authorization(meta, body).map_err(StaticDispatchError::Codec)?;",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'the erased decoder moving outside its guarded boundary' \
    mut_pipeline_dynamic_decode_moves_after_authorization

mut_pipeline_stage_borrows_request() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text().replace(
    "pub(crate) struct RequestConfig<S> {",
    "pub(crate) struct RequestConfig<'a, S> {\n    wire: &'a rustfs_gateway_http::OwnedWireRequest,",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'the request stage carrier borrowing its wire request' mut_pipeline_stage_borrows_request

mut_pipeline_stage_uses_borrowed_alias() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text().replace(
    "pub(crate) struct RequestConfig<S> {",
    "type BorrowedWire<'a> = &'a rustfs_gateway_http::OwnedWireRequest;\n"
    "pub(crate) struct RequestConfig<S> {\n    wire: BorrowedWire<'static>,",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'the request stage carrier hiding a borrowed wire behind a type alias' \
    mut_pipeline_stage_uses_borrowed_alias

mut_pipeline_stage_uses_borrowed_newtype() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text().replace(
    "pub(crate) struct RequestConfig<S> {",
    "struct BorrowedWire(&'static rustfs_gateway_http::OwnedWireRequest);\n"
    "pub(crate) struct RequestConfig<S> {\n    wire: BorrowedWire,",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'the request stage carrier hiding a borrowed wire behind a newtype' \
    mut_pipeline_stage_uses_borrowed_newtype

mut_pipeline_stage_uses_borrowed_enum() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text().replace(
    "pub(crate) struct RequestConfig<S> {",
    "enum BorrowedWire { Value(&'static rustfs_gateway_http::OwnedWireRequest) }\n"
    "pub(crate) struct RequestConfig<S> {\n    wire: BorrowedWire,",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'the request stage carrier hiding a borrowed wire behind an enum variant' \
    mut_pipeline_stage_uses_borrowed_enum

mut_pipeline_stage_marker_has_lifetime() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text().replace(
    "pub(crate) struct Entered;",
    "pub(crate) struct Entered<'a>;",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'a request stage marker carrying a lifetime' mut_pipeline_stage_marker_has_lifetime

probe_stream_guards_fail_closed() {
    local guard output rc tool_path empty_root
    local guards=(
        check_no_shared_trailers.sh
        check_no_trailer_mutex.sh
        check_no_as_any.sh
        check_no_spawn_in_stream.sh
        check_stream_vocabulary.sh
        check_pipeline_stage_shape.sh
    )

    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-stream-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    for guard in "${guards[@]}"; do
        cases=$((cases + 1))
        guard_case_owned "$cases" || continue
        rc=0
        output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash \
            "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
        if [[ "$rc" -ne 0 && "$output" == *'required command is missing: python3'* ]]; then
            pass_msg "${guard} fails closed without python3"
        else
            fail_msg "${guard} reported green without python3"
        fi
    done
    rm -rf "$tool_path"

    empty_root="$(mktemp -d "${TMPDIR:-/tmp}/gateway-stream-guard-empty.XXXXXX")"
    for guard in "${guards[@]}"; do
        cases=$((cases + 1))
        guard_case_owned "$cases" || continue
        rc=0
        GATEWAY_CHECK_ROOT="$empty_root" "${SCRIPT_DIR}/${guard}" >/dev/null 2>&1 || rc=$?
        if [[ "$rc" -ne 0 ]]; then
            pass_msg "${guard} fails closed without its required source"
        else
            fail_msg "${guard} reported green without its required source"
        fi
    done
    rm -rf "$empty_root"
}
probe_stream_guards_fail_closed
mut_smithy_timestamp_digest_byte() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/types/tests/data/date_time_format_test_suite.json")
text = path.read_text()
old = '"smithy_format_value": "0001-01-25T11:23:19.123456Z"'
new = '"smithy_format_value": "0001-01-25T11:23:19.123457Z"'
if old not in text:
    raise SystemExit("expected Smithy timestamp vector is missing")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_smithy_timestamp_corpus.sh \
    'one vendored corpus byte changing its pinned digest' mut_smithy_timestamp_digest_byte

mut_smithy_timestamp_case_count() {
    python3 - <<'PY'
import hashlib
import json
from pathlib import Path

corpus_path = Path("crates/types/tests/data/date_time_format_test_suite.json")
suite = json.loads(corpus_path.read_text())
suite["parse_http_date"].pop()
corpus_path.write_text(json.dumps(suite, indent=2) + "\n")
corpus = corpus_path.read_bytes()

guard_path = Path("scripts/check_smithy_timestamp_corpus.sh")
guard = guard_path.read_text()
guard = guard.replace("expected_bytes = 152_448", f"expected_bytes = {len(corpus)}", 1)
guard = guard.replace(
    'expected_sha256 = "95adad86782f37c5eff4601cccaeb76b5ef827121ad7b2f7030224d231a746bd"',
    f'expected_sha256 = "{hashlib.sha256(corpus).hexdigest()}"',
    1,
)
guard_path.write_text(guard)
PY
}
expect_fail check_smithy_timestamp_corpus.sh \
    'one section dropping a vector even after refreshing the byte pin' mut_smithy_timestamp_case_count

mut_smithy_timestamp_notice_commit() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
path.write_text(text.replace("2744eb413935073aa43800e58e36268cd90b3a83", "0" * 40, 1))
PY
}
expect_fail check_smithy_timestamp_corpus.sh \
    'the legal notice losing the pinned source commit' mut_smithy_timestamp_notice_commit

mut_smithy_timestamp_mapping() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/types/tests/data/README.md")
text = path.read_text()
date_time = "| `date-time` | `TimestampFormat::Iso8601` |"
epoch_seconds = "| `epoch-seconds` | `TimestampFormat::EpochSeconds` |"
if date_time not in text or epoch_seconds not in text:
    raise SystemExit("expected timestamp mapping rows are missing")
text = text.replace(date_time, "__DATE_TIME_ROW__", 1)
text = text.replace(epoch_seconds, "| `epoch-seconds` | `TimestampFormat::Iso8601` |", 1)
path.write_text(text.replace("__DATE_TIME_ROW__", "| `date-time` | `TimestampFormat::EpochSeconds` |", 1))
PY
}
expect_fail check_smithy_timestamp_corpus.sh \
    'the upstream-to-gateway format mapping changing' mut_smithy_timestamp_mapping

mut_smithy_timestamp_third_party_license() {
    python3 - <<'PY'
from pathlib import Path

path = Path("THIRD-PARTY-NOTICES.md")
text = path.read_text()
old = "Apache License 2.0. The exact source revision and digest"
if old not in text:
    raise SystemExit("expected Smithy third-party license attribution is missing")
path.write_text(text.replace(old, "the upstream license. The exact source revision and digest", 1))
PY
}
expect_fail check_smithy_timestamp_corpus.sh \
    'the third-party summary losing the Smithy license' mut_smithy_timestamp_third_party_license

probe_smithy_timestamp_guard_missing_python() {
    local output rc=0 tool_path
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-smithy-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_smithy_timestamp_corpus.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: python3'* ]]; then
        pass_msg 'check_smithy_timestamp_corpus.sh fails closed without python3'
    else
        fail_msg 'check_smithy_timestamp_corpus.sh reported green without python3'
    fi
}
probe_smithy_timestamp_guard_missing_python

mut_has_operation_mapping_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/core/src/ops/get_object.rs")
text = path.read_text()
old = """impl HasOperation for GetObjectInput {
    type Op = GetObject;
}
"""
if old not in text:
    raise SystemExit("expected GetObject reverse mapping is missing")
path.write_text(text.replace(old, "", 1))
PY
}
expect_fail check_has_operation_coverage.sh \
    'a standard operation losing its reverse mapping' mut_has_operation_mapping_removed

mut_has_operation_target_changed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/core/src/ops/get_object.rs")
text = path.read_text()
old = "type Op = GetObject;"
if old not in text:
    raise SystemExit("expected GetObject reverse target is missing")
path.write_text(text.replace(old, "type Op = HeadObject;", 1))
PY
}
expect_fail check_has_operation_coverage.sh \
    'a reverse mapping naming another operation' mut_has_operation_target_changed

mut_has_operation_input_codrift() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/core/src/ops/get_object.rs")
text = path.read_text()
old_input = "type Input = GetObjectInput;"
old_reverse = "impl HasOperation for GetObjectInput"
if old_input not in text or old_reverse not in text:
    raise SystemExit("expected GetObject input mapping is missing")
text = text.replace(old_input, "type Input = HeadObjectInput;", 1)
path.write_text(text.replace(old_reverse, "impl HasOperation for HeadObjectInput", 1))
PY
}
expect_fail check_has_operation_coverage.sh \
    'an Operation and reverse mapping drifting together from the codegen name' \
    mut_has_operation_input_codrift

mut_has_operation_manual_authority_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("model/overlays/ops/post-object.toml")
text = path.read_text()
old = '[[manual]]\nreason = "Browser POST is an S3 REST operation absent from the Smithy service model; its DTO and codec are hand-authored while this overlay remains the route authority."\noperations = ["PostObject"]\n\n'
if old not in text:
    raise SystemExit("expected PostObject manual-operation authority is missing")
path.write_text(text.replace(old, "", 1))
PY
}
expect_fail check_has_operation_coverage.sh \
    'a manual standard operation losing its reviewed overlay authority' \
    mut_has_operation_manual_authority_removed

probe_has_operation_guard_missing_python() {
    local output rc=0 tool_path
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-has-operation-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_has_operation_coverage.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: python3'* ]]; then
        pass_msg 'check_has_operation_coverage.sh fails closed without python3'
    else
        fail_msg 'check_has_operation_coverage.sh reported green without python3'
    fi
}
probe_has_operation_guard_missing_python

mut_rust_toolchain_moving_channel() {
    python3 - <<'PY'
from pathlib import Path

path = Path("rust-toolchain.toml")
path.write_text(path.read_text().replace('channel = "1.97.1"', 'channel = "stable"', 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the development compiler becoming a moving stable channel' mut_rust_toolchain_moving_channel

mut_rust_toolchain_cargo_floor_drift() {
    python3 - <<'PY'
from pathlib import Path

path = Path("Cargo.toml")
path.write_text(path.read_text().replace('rust-version = "1.97.1"', 'rust-version = "1.97.2"', 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the Cargo compiler floor drifting from the pinned toolchain' mut_rust_toolchain_cargo_floor_drift

mut_rust_toolchain_component_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("rust-toolchain.toml")
path.write_text(path.read_text().replace(', "rust-analyzer"', '', 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'one required development component disappearing' mut_rust_toolchain_component_removed

mut_rust_toolchain_readme_drift() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
path.write_text(path.read_text().replace('**Development toolchain: 1.97.1**', '**Development toolchain: stable**', 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the README claiming a different development compiler' mut_rust_toolchain_readme_drift

mut_rust_toolchain_msrv_doc_drift() {
    python3 - <<'PY'
from pathlib import Path

path = Path("docs/msrv.md")
path.write_text(path.read_text().replace('**MSRV = 1.97.1**', '**MSRV = 1.97.0**', 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the MSRV policy naming a different compiler floor' mut_rust_toolchain_msrv_doc_drift

mut_rust_toolchain_ci_version_drift() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  msrv:")
end = text.index("\n  clippy:", start)
block = text[start:end]
if block.count("toolchain: 1.97.1") != 1:
    raise SystemExit("MSRV job toolchain pin is missing or ambiguous")
block = block.replace("toolchain: 1.97.1", "toolchain: stable", 1)
path.write_text(text[:start] + block + text[end:])
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the MSRV CI job installing a moving compiler' mut_rust_toolchain_ci_version_drift

mut_rust_toolchain_ci_bootstrap_components_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  bootstrap:")
end = text.index("\n  feedback-loop:", start)
block = text[start:end]
old = "          components: rustfmt, clippy, rust-src, rust-analyzer\n"
if block.count(old) != 1:
    raise SystemExit("the bootstrap component materialization is missing or ambiguous")
block = block.replace(old, "", 1)
path.write_text(text[:start] + block + text[end:])
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the cold bootstrap charging development-component downloads to its measured command' \
    mut_rust_toolchain_ci_bootstrap_components_removed

# This is the exact shape main carried on 2026-08-20: no `with:`, so
# dtolnay/rust-toolchain installs its own `stable` default and makes it the rustup
# default, whatever stable happens to be that day. It must not read green again.
mut_rust_toolchain_ci_step_takes_stable_default() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
old = """      - uses: dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30 # pinned action revision
        with:
          toolchain: 1.97.1
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
      - run: cargo clippy --workspace --all-targets -- -D warnings
"""
new = """      - uses: dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30 # stable
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
      - run: cargo clippy --workspace --all-targets -- -D warnings
"""
if text.count(old) != 1:
    raise SystemExit("the clippy toolchain step is missing or ambiguous")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'a CI job falling back to the action default stable toolchain' \
    mut_rust_toolchain_ci_step_takes_stable_default

# The compiler floor moves and one repeated CI pin is left behind. The workflow repeats the
# number per job -- a workflow env var under a CARGO/RUST prefix would move the rust-cache
# restore key -- so a partial bump is the drift this guard has to catch.
mut_rust_toolchain_ci_pin_left_behind() {
    python3 - <<'PY'
from pathlib import Path

for name, old, new in (
    ("Cargo.toml", 'rust-version = "1.97.1"', 'rust-version = "1.97.2"'),
    ("rust-toolchain.toml", 'channel = "1.97.1"', 'channel = "1.97.2"'),
    ("README.md", "MSRV-1.97.1", "MSRV-1.97.2"),
    ("README.md", "**MSRV: 1.97.1.**", "**MSRV: 1.97.2.**"),
    ("README.md", "**Development toolchain: 1.97.1**", "**Development toolchain: 1.97.2**"),
    ("docs/msrv.md", "**MSRV = 1.97.1**", "**MSRV = 1.97.2**"),
    ("docs/msrv.md", "The workspace pins Rust 1.97.1 for development",
     "The workspace pins Rust 1.97.2 for development"),
):
    path = Path(name)
    text = path.read_text()
    if old not in text:
        raise SystemExit(f"missing mutation subject in {name}: {old}")
    path.write_text(text.replace(old, new, 1))

path = Path(".github/workflows/ci.yml")
text = path.read_text()
if text.count("toolchain: 1.97.1") < 2:
    raise SystemExit("the workflow no longer repeats its toolchain pin")
# Bump every CI pin except one, so only the straggler is wrong.
path.write_text(text.replace("toolchain: 1.97.1", "toolchain: 1.97.2").replace(
    "toolchain: 1.97.2", "toolchain: 1.97.1", 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'one CI job left behind on the previous compiler after an MSRV bump' \
    mut_rust_toolchain_ci_pin_left_behind

mut_rust_toolchain_ci_step_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
old = """      - uses: dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30 # pinned action revision
        with:
          toolchain: 1.97.1
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
      - name: Workspace tests 1/3 (maximum 8 minutes after setup)
"""
new = """      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
      - name: Workspace tests 1/3 (maximum 8 minutes after setup)
"""
if text.count(old) != 1:
    raise SystemExit("the workspace-tests toolchain step is missing or ambiguous")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'a cargo job running with no declared compiler at all' mut_rust_toolchain_ci_step_removed

mut_rust_toolchain_ci_nightly_undated() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
old = "          toolchain: nightly-2026-06-18\n"
if text.count(old) != 1:
    raise SystemExit("the TSAN nightly pin is missing or ambiguous")
path.write_text(text.replace(old, "          toolchain: nightly\n", 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the sanitizer job trading its dated nightly for a moving one' \
    mut_rust_toolchain_ci_nightly_undated

mut_rust_toolchain_ci_workspace_check_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
path.write_text(path.read_text().replace("cargo check --workspace --all-targets", "cargo check -p xtask", 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the MSRV CI job no longer compiling the whole workspace' mut_rust_toolchain_ci_workspace_check_removed

mut_rust_toolchain_ci_job_disabled() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  msrv:")
end = text.index("\n  clippy:", start)
block = text[start:end]
anchor = "    runs-on: ubuntu-latest\n"
if block.count(anchor) != 1:
    raise SystemExit("MSRV job runner is missing or ambiguous")
block = block.replace(anchor, anchor + "    if: false\n", 1)
path.write_text(text[:start] + block + text[end:])
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the entire MSRV CI job being disabled with a boolean if' mut_rust_toolchain_ci_job_disabled

mut_rust_toolchain_ci_check_allowed_to_fail() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
old = "      - run: cargo check --workspace --all-targets\n"
new = old + '        continue-on-error: "true"\n'
if text.count(old) != 1:
    raise SystemExit("MSRV workspace check step is missing or ambiguous")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the MSRV workspace check being allowed to fail with a string boolean' mut_rust_toolchain_ci_check_allowed_to_fail

mut_rust_toolchain_ci_job_disabled_with_quoted_key() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  msrv:")
end = text.index("\n  clippy:", start)
block = text[start:end]
anchor = "    runs-on: ubuntu-latest\n"
if block.count(anchor) != 1:
    raise SystemExit("MSRV job runner is missing or ambiguous")
block = block.replace(anchor, anchor + '    "if": false\n', 1)
path.write_text(text[:start] + block + text[end:])
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'a double-quoted YAML key disabling the entire MSRV job' mut_rust_toolchain_ci_job_disabled_with_quoted_key

mut_rust_toolchain_ci_check_allowed_to_fail_with_quoted_key() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
old = "      - run: cargo check --workspace --all-targets\n"
new = old + "        'continue-on-error': true\n"
if text.count(old) != 1:
    raise SystemExit("MSRV workspace check step is missing or ambiguous")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'a single-quoted YAML key allowing the MSRV check to fail' mut_rust_toolchain_ci_check_allowed_to_fail_with_quoted_key

mut_governance_relationship_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
path.write_text(text.replace("repository is not a fork", "repository has a separate history", 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the README no longer saying this repository is not a fork' mut_governance_relationship_removed

mut_governance_relationship_hidden_in_comment() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
text = text.replace("repository is not a fork", "repository has a separate history", 1)
text = text.replace(
    "## Relationship to s3s\n",
    "## Relationship to s3s\n\n<!-- repository is not a fork -->",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the README relationship surviving only in an HTML comment' mut_governance_relationship_hidden_in_comment

mut_governance_relationship_hidden_in_fence() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
text = text.replace("repository is not a fork", "repository has a separate history", 1)
text = text.replace(
    "## Relationship to s3s\n",
    "## Relationship to s3s\n\n```text\nrepository is not a fork\n```",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the README relationship surviving only in a fenced block' mut_governance_relationship_hidden_in_fence

mut_governance_relationship_hidden_in_blockquote_fence() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
text = text.replace("repository is not a fork", "repository has a separate history", 1)
text = text.replace(
    "## Relationship to s3s\n",
    "## Relationship to s3s\n\n> ```text\n> repository is not a fork\n> ```",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the README relationship surviving only in a blockquote fenced block' mut_governance_relationship_hidden_in_blockquote_fence

mut_governance_relationship_hidden_in_list_fence() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
text = text.replace("repository is not a fork", "repository has a separate history", 1)
text = text.replace(
    "## Relationship to s3s\n",
    "## Relationship to s3s\n\n- ```text\n  repository is not a fork\n  ```",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the README relationship surviving only in a list fenced block' mut_governance_relationship_hidden_in_list_fence

mut_governance_relationship_hidden_in_space_indented_code() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
text = text.replace("repository is not a fork", "repository has a separate history", 1)
text = text.replace(
    "## Relationship to s3s\n",
    "## Relationship to s3s\n\n    repository is not a fork",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the README relationship surviving only in four-space indented code' mut_governance_relationship_hidden_in_space_indented_code

mut_governance_relationship_hidden_in_tab_indented_code() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
text = text.replace("repository is not a fork", "repository has a separate history", 1)
text = text.replace(
    "## Relationship to s3s\n",
    "## Relationship to s3s\n\n\trepository is not a fork",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the README relationship surviving only in tab-indented code' mut_governance_relationship_hidden_in_tab_indented_code

mut_governance_notice_revision_changed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
path.write_text(text.replace("2880e0785db4cf2ceb086cfeba86a4cbdeb14176", "0" * 40, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the aws-sigv4 NOTICE revision drifting from its source snapshot' mut_governance_notice_revision_changed

mut_governance_notice_commit_survives_only_in_notes() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
revision = "2880e0785db4cf2ceb086cfeba86a4cbdeb14176"
text = text.replace(f"   Commit:  {revision}", "   Commit:  " + "0" * 40, 1)
text = text.replace(
    "   Notes:   rustfs-gateway",
    f"   Notes:   Commit:  {revision}\n            rustfs-gateway",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the NOTICE commit surviving only inside Notes' mut_governance_notice_commit_survives_only_in_notes

mut_governance_notice_permalink_changed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
old = "   Permalink: https://github.com/smithy-lang/smithy-rs/blob/2880e0785db4cf2ceb086cfeba86a4cbdeb14176/aws/rust-runtime/aws-sigv4/src/sign/v4.rs"
new = "   Permalink: https://github.com/smithy-lang/smithy-rs/blob/" + "0" * 40 + "/aws/rust-runtime/aws-sigv4/src/sign/v4.rs"
if text.count(old) != 1:
    raise SystemExit("the NOTICE permalink anchor is not unique")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the NOTICE aws-sigv4 entry losing its revision-pinned permalink' mut_governance_notice_permalink_changed

mut_governance_notice_source_field_duplicated() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
source = "   Source:  https://github.com/smithy-lang/smithy-rs\n"
if text.count(source) < 2:
    raise SystemExit("smithy-rs NOTICE source fields are missing")
path.write_text(text.replace(source, source + source, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the NOTICE aws-sigv4 entry repeating a formal source field' mut_governance_notice_source_field_duplicated

mut_governance_registry_entry_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
path.write_text(text.replace("crates/sig/src/derive.rs", "crates/sig/src/missing.rs", 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the adapted source disappearing from the copied-code registry' mut_governance_registry_entry_removed

mut_governance_registry_revision_in_notes() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
old = "  Upstream revision: 2880e0785db4cf2ceb086cfeba86a4cbdeb14176"
new = "  Upstream revision: " + "0" * 40 + "\n  Notes:             2880e0785db4cf2ceb086cfeba86a4cbdeb14176"
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the registry revision surviving only in Notes' mut_governance_registry_revision_in_notes

mut_governance_registry_facts_split_across_entries() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
text = text.replace(
    "  Upstream revision: 2880e0785db4cf2ceb086cfeba86a4cbdeb14176",
    "  Upstream revision: " + "0" * 40,
    1,
)
text += """

  Local path:        crates/sig/src/other.rs
  Upstream project:  https://github.com/smithy-lang/smithy-rs
  Upstream revision: 2880e0785db4cf2ceb086cfeba86a4cbdeb14176
  Upstream path:     aws/rust-runtime/aws-sigv4/src/sign/v4.rs
  License:           Apache-2.0
"""
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the registry facts being split across different entries' mut_governance_registry_facts_split_across_entries

mut_governance_registry_path_changed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
old = "  Upstream path:     aws/rust-runtime/aws-sigv4/src/sign/v4.rs"
path.write_text(text.replace(old, "  Upstream path:     aws/rust-runtime/aws-sigv4/src/sign/other.rs", 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the copied-code registry losing the exact upstream path' mut_governance_registry_path_changed

mut_governance_registry_permalink_changed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
old = "  Upstream permalink: https://github.com/smithy-lang/smithy-rs/blob/2880e0785db4cf2ceb086cfeba86a4cbdeb14176/aws/rust-runtime/aws-sigv4/src/sign/v4.rs"
new = "  Upstream permalink: https://github.com/smithy-lang/smithy-rs/blob/" + "0" * 40 + "/aws/rust-runtime/aws-sigv4/src/sign/v4.rs"
if text.count(old) != 1:
    raise SystemExit("the registry permalink anchor is not unique")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the copied-code registry losing its revision-pinned permalink' mut_governance_registry_permalink_changed

mut_governance_registry_license_in_notes() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
old = "  License:           Apache-2.0"
new = "  License:           MIT\n  Notes:             Apache-2.0"
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the registry license surviving only in Notes' mut_governance_registry_license_in_notes

mut_governance_notice_copyright_changed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
old = "   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved."
new = "   Copyright attribution omitted."
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the aws-sigv4 NOTICE entry losing its copyright attribution' mut_governance_notice_copyright_changed

mut_governance_source_revision_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/sig/src/derive.rs")
text = path.read_text()
path.write_text(text.replace("2880e0785db4cf2ceb086cfeba86a4cbdeb14176", "revision omitted", 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the in-file attribution losing the reviewed upstream revision' mut_governance_source_revision_removed

mut_governance_source_permalink_changed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/sig/src/derive.rs")
text = path.read_text()
old = "//     Upstream permalink: https://github.com/smithy-lang/smithy-rs/blob/2880e0785db4cf2ceb086cfeba86a4cbdeb14176/aws/rust-runtime/aws-sigv4/src/sign/v4.rs"
new = "//     Upstream permalink: https://github.com/smithy-lang/smithy-rs/blob/" + "0" * 40 + "/aws/rust-runtime/aws-sigv4/src/sign/v4.rs"
if text.count(old) != 1:
    raise SystemExit("the source permalink anchor is not unique")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'derive.rs losing its revision-pinned upstream permalink' mut_governance_source_permalink_changed

mut_governance_source_revision_survives_only_outside_attribution() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/sig/src/derive.rs")
text = path.read_text()
revision = "2880e0785db4cf2ceb086cfeba86a4cbdeb14176"
old = f"//     Revision: {revision} (aws-sigv4 1.5.1)"
new = "//     Revision: " + "0" * 40 + " (aws-sigv4 1.5.1)"
text = text.replace(old, new, 1)
text = text.replace(
    "// ---------------------------------------------------------------------------\n\n//!",
    f"// ---------------------------------------------------------------------------\n// Decoy revision outside ATTRIBUTION: {revision}\n\n//!",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the source revision surviving only outside ATTRIBUTION' mut_governance_source_revision_survives_only_outside_attribution

mut_governance_source_attribution_block_duplicated() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/sig/src/derive.rs")
text = path.read_text()
divider = "// ---------------------------------------------------------------------------\n"
start = text.index(divider + "// ATTRIBUTION\n")
end = text.index(divider, start + len(divider)) + len(divider)
block = text[start:end]
path.write_text(text.replace("//! The SigV4", block + "\n//! The SigV4", 1))
PY
}
expect_fail check_governance_attribution.sh \
    'derive.rs containing more than one ATTRIBUTION block' mut_governance_source_attribution_block_duplicated

mut_governance_source_function_mapping_changed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/sig/src/derive.rs")
text = path.read_text()
old = "//     Function mapping: signing_key <- generate_signing_key"
new = "//     Function mapping: signing_key <- unrelated_function"
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'derive.rs changing a reviewed function mapping' mut_governance_source_function_mapping_changed

mut_rustfs_dep() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/Cargo.toml")
text = path.read_text()
anchor = "[dependencies]\n"
if text.count(anchor) != 1:
    raise SystemExit("core dependencies table is missing or ambiguous")
path.write_text(text.replace(anchor, anchor + 'rustfs-ecstore = "0.1"\n', 1))
PYEOF
}
expect_fail check_ring_boundaries.sh \
    'ring-0 crate depending on a rustfs crate' mut_rustfs_dep

mut_renamed_rustfs_dep() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/Cargo.toml")
text = path.read_text()
marker = "[dependencies]\n"
if text.count(marker) != 1:
    raise SystemExit("core dependency table is not unique")
path.write_text(text.replace(marker, marker + 'storage = { package = "rustfs-ecstore", version = "0.1" }\n', 1))
PYEOF
}
expect_fail check_ring_boundaries.sh 'a renamed RustFS business dependency' mut_renamed_rustfs_dep

mut_ring2_dep() {
    printf 'rustfs-gateway-admin = "0.1"\n' >>crates/http/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    'ring-0 crate depending on a ring-2 crate not declared in this workspace' mut_ring2_dep

mut_renamed_ring2_dep() { printf 'admin-adapter = { package = "rustfs-gateway-admin", version = "0.1" }\n' >>crates/http/Cargo.toml; }
expect_fail check_ring_boundaries.sh 'a renamed ring-2 dependency not declared in this workspace' mut_renamed_ring2_dep

# After the rename the crate name carries no ring information, so the declaration is
# the only thing the guard can read. A crate without one must fail rather than be
# silently treated as ring 0.
mut_missing_ring_decl() {
    grep -v '^ring = ' crates/http/Cargo.toml >/tmp/.rd.$$ && mv /tmp/.rd.$$ crates/http/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    'a crate with no [package.metadata.gateway] ring declaration' mut_missing_ring_decl

mut_bad_ring_value() {
    sed 's/^ring = 0$/ring = 2/' crates/http/Cargo.toml >/tmp/.rv.$$ && mv /tmp/.rv.$$ crates/http/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    'a crate declaring ring 2, which does not live in this repository' mut_bad_ring_value

mut_stray_s3s() {
    printf 's3s = "0.11"\n' >>crates/http/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    's3s dependency outside rustfs-gateway-types' mut_stray_s3s

mut_renamed_target_s3s() {
    printf '\n[target.'"'"'cfg(any())'"'"'.dev-dependencies]\nlegacy-s3 = { package = "s3s", version = "0.11" }\n' >>crates/http/Cargo.toml
}
expect_fail check_ring_boundaries.sh 'a renamed target-specific dev s3s dependency' mut_renamed_target_s3s

mut_workspace_inherited_rustfs_dep() {
    python3 - <<'PYEOF'
from pathlib import Path
root = Path("Cargo.toml")
text = root.read_text()
marker = "[workspace.dependencies]\n"
if text.count(marker) != 1:
    raise SystemExit("workspace dependency table is not unique")
root.write_text(text.replace(marker, marker + 'storage-workspace = { package = "rustfs-ecstore", version = "0.1" }\n', 1))
path = Path("crates/core/Cargo.toml")
text = path.read_text()
marker = "[dependencies]\n"
if text.count(marker) != 1:
    raise SystemExit("core dependency table is not unique")
path.write_text(text.replace(marker, marker + 'storage-workspace = { workspace = true }\n', 1))
PYEOF
}
expect_fail check_ring_boundaries.sh 'a workspace-inherited renamed RustFS dependency' mut_workspace_inherited_rustfs_dep

mut_drop_delete_by() {
    grep -v '# DELETE BY' crates/types/Cargo.toml >/tmp/.ct.$$ && mv /tmp/.ct.$$ crates/types/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    'compat-s3s losing its "# DELETE BY" expiry marker' mut_drop_delete_by

mut_floating_s3s_feature() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/types/Cargo.toml")
text = path.read_text()
for old in ('compat-s3s-f3e17541 = [', '"compat-s3s-f3e17541", '):
    if text.count(old) != 1:
        raise SystemExit(f"{old} is not unique")
path.write_text(text.replace('compat-s3s-f3e17541 = [', 'compat-s3s-prod = [').replace('"compat-s3s-f3e17541", ', '"compat-s3s-prod", '))
PYEOF
}
expect_fail check_ring_boundaries.sh \
    'an s3s feature not named after the revision it links' mut_floating_s3s_feature

mut_s3s_feature_outside_umbrella() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/types/Cargo.toml")
text = path.read_text()
old = '"compat-s3s-f3e17541", '
if text.count(old) != 1:
    raise SystemExit(f"{old} is not unique")
path.write_text(text.replace(old, ""))
PYEOF
}
expect_fail check_ring_boundaries.sh \
    'an s3s feature compat-s3s does not include' mut_s3s_feature_outside_umbrella

mut_server_unreviewed_dep() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/Cargo.toml")
text = path.read_text()
marker = "[dependencies]\n"
if text.count(marker) != 1:
    raise SystemExit("server dependency table is not unique")
path.write_text(text.replace(marker, marker + "rustfs-gateway-stream = { workspace = true }\n", 1))
PYEOF
}
expect_fail check_layer_dependencies.sh \
    'the dependency-free server gaining an internal runtime edge' mut_server_unreviewed_dep

mut_server_internal_dev_dependency() { printf 'rustfs-gateway-stream = { workspace = true }\n' >>crates/server/Cargo.toml; }
expect_fail check_layer_dependencies.sh 'the dependency-free server gaining an internal dev edge' mut_server_internal_dev_dependency

mut_server_host_write() {
    printf '\nfn normalize_host(request: &mut http::Request<()>) { request.headers_mut().insert(http::header::HOST, http::HeaderValue::from_static("x")); }\n' >>crates/server/src/conn.rs
}
expect_fail_and_missing_grep check_no_host_normalize.sh \
    'ring-1 server writing the Host header' mut_server_host_write

mut_server_handler_timeout() {
    printf '\nconst HANDLER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);\n' >>crates/server/src/config.rs
}
expect_fail_and_missing_grep check_timeout_layer_ownership.sh \
    'ring-1 server claiming the handler timeout layer' mut_server_handler_timeout

mut_server_first_body_byte_timeout() {
    printf '\nconst FIRST_BODY_BYTE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);\n' >>crates/server/src/config.rs
}
expect_fail check_timeout_layer_ownership.sh \
    'ring-1 server claiming the first-body-byte timeout layer' mut_server_first_body_byte_timeout

mut_server_body_read_idle_timeout() {
    printf '\nconst BODY_READ_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);\n' >>crates/server/src/config.rs
}
expect_fail check_timeout_layer_ownership.sh \
    'ring-1 server claiming the body-read idle timeout layer' mut_server_body_read_idle_timeout

mut_server_c_lim_0032_case_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/src/conn/deadline_test.rs")
text = path.read_text()
subject = "async fn c_lim_0032_a_srv_0010_one_byte_per_second_header_closes_at_ten_seconds() {"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0032 test name is not unique")
path.write_text(text.replace(subject, "async fn a_srv_0010_one_byte_per_second_header_closes_at_ten_seconds() {", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0032 losing its executable slow-header evidence' mut_server_c_lim_0032_case_removed

mut_server_c_lim_0032_deadline_changed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/src/conn/deadline_test.rs")
text = path.read_text()
subject = "        header_read_timeout: Duration::from_secs(10),\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0032 deadline setup is not unique")
path.write_text(text.replace(subject, "        header_read_timeout: Duration::from_secs(11),\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0032 drifting from the ten-second header deadline' mut_server_c_lim_0032_deadline_changed

mut_server_c_lim_0032_pacing_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/src/conn/deadline_test.rs")
text = path.read_text()
subject = '    for byte in b"ET / HTTP" {\n        tokio::time::advance(Duration::from_secs(1)).await;\n'
replacement = '    for byte in b"ET / HTTP" {\n        tokio::task::yield_now().await;\n'
if text.count(subject) != 1:
    raise SystemExit("c-lim-0032 pacing loop is not unique")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0032 losing its one-byte-per-second pacing' mut_server_c_lim_0032_pacing_removed

mut_server_c_lim_0037_case_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load/per_ip.rs")
text = path.read_text()
subject = "async fn c_lim_0037_ten_thousand_half_open_connections_preserve_other_ip_p99() {"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0037 test name is not unique")
path.write_text(text.replace(subject, "async fn ten_thousand_half_open_connections_preserve_other_ip_p99() {", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0037 losing its executable load evidence' mut_server_c_lim_0037_case_removed

mut_server_c_lim_0037_scale_reduced() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load/per_ip.rs")
text = path.read_text()
subject = "    const ATTEMPTS: usize = 10_000;\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0037 attempt count is not unique")
path.write_text(text.replace(subject, "    const ATTEMPTS: usize = 1_000;\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0037 shrinking below ten thousand connections' mut_server_c_lim_0037_scale_reduced

mut_server_c_lim_0037_per_ip_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load/per_ip.rs")
text = path.read_text()
subject = "    config.max_connections_per_ip = Some(HALF_OPEN_LIMIT);\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0037 per-IP setup is not unique")
path.write_text(text.replace(subject, "    config.max_connections_per_ip = None;\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0037 losing its per-IP ceiling' mut_server_c_lim_0037_per_ip_removed

mut_server_c_lim_0037_dual_stack_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load/per_ip.rs")
text = path.read_text()
subject = "    config.dual_stack = true;\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0037 dual-stack setup is not unique")
path.write_text(text.replace(subject, "    config.dual_stack = false;\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0037 losing the two-address-family listener' mut_server_c_lim_0037_dual_stack_removed

mut_server_c_lim_0037_global_capacity_confounds_per_ip() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load/per_ip.rs")
text = path.read_text()
subject = "    config.max_connections = ATTEMPTS + HALF_OPEN_LIMIT;\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0037 global capacity setup is not unique")
path.write_text(text.replace(subject, "    config.max_connections = HALF_OPEN_LIMIT;\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0037 letting the global ceiling hide per-IP rejection' mut_server_c_lim_0037_global_capacity_confounds_per_ip

mut_server_c_lim_0037_dedicated_runtime_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load/per_ip.rs")
text = path.read_text()
subject = "server_on_own_runtime(config.clone(), Bytes::new())"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0037 loaded runtime call is not unique")
path.write_text(text.replace(subject, "echo_server(config.clone())", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0037 sharing the loaded listener with the probe runtime' mut_server_c_lim_0037_dedicated_runtime_removed

mut_server_c_lim_0037_source_coalesced() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load/per_ip.rs")
text = path.read_text()
subject = "let loaded_v6 = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0037 healthy source family is not unique")
path.write_text(text.replace(subject, "let loaded_v6 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST)", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0037 coalescing attack and healthy source IPs' mut_server_c_lim_0037_source_coalesced

mut_server_c_lim_0037_attack_serialized() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load/per_ip.rs")
text = path.read_text()
subject = "    let attack = tokio::spawn(async move {\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0037 attack task is not unique")
path.write_text(text.replace(subject, "    let attack = async move {\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0037 serializing the attack after latency probes' mut_server_c_lim_0037_attack_serialized

mut_server_c_lim_0037_rejection_accounting_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load/per_ip.rs")
text = path.read_text()
subject = "loaded.metrics.per_ip_rejections() != ATTEMPTS - HALF_OPEN_LIMIT"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0037 rejection accounting is not unique")
path.write_text(text.replace(subject, "loaded.metrics.per_ip_rejections() != 0", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0037 losing exact rejection accounting' mut_server_c_lim_0037_rejection_accounting_removed

mut_server_c_lim_0037_control_gate_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load/per_ip.rs")
text = path.read_text()
subject = "    if control_probes.stalled > 0 {\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0037 control gate is not unique")
path.write_text(text.replace(subject, "    if false {\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0037 passing on a saturated latency control' mut_server_c_lim_0037_control_gate_removed

mut_server_c_lim_0037_p99_comparison_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load/per_ip.rs")
text = path.read_text()
subject = "            loaded_probes.p99 <= ceiling,\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0037 p99 comparison is not unique")
path.write_text(text.replace(subject, "            control_probes.p99 <= ceiling,\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0037 losing its loaded p99 comparison' mut_server_c_lim_0037_p99_comparison_removed

mut_server_c_lim_0062_case_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/tls_h2.rs")
text = path.read_text()
subject = "async fn c_lim_0062_a_srv_0015_per_ip_half_open_limit_and_header_deadline_recover() {"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0062 test name is not unique")
path.write_text(text.replace(subject, "async fn a_srv_0015_half_open_limit_and_header_deadline_recover() {", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0062 losing its executable TLS evidence' mut_server_c_lim_0062_case_removed

mut_server_c_lim_0062_cfg_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/tls_h2.rs")
text = path.read_text()
subject = "#[tokio::test]\nasync fn c_lim_0062_a_srv_0015_per_ip_half_open_limit_and_header_deadline_recover() {"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0062 active test entry is not unique")
path.write_text(text.replace(subject, "#[cfg(any())]\n" + subject, 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0062 being disabled by cfg' mut_server_c_lim_0062_cfg_disabled

mut_server_c_lim_0062_per_ip_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/tls_h2.rs")
text = path.read_text()
subject = "    server_config.max_connections_per_ip = Some(2);\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0062 per-IP setup is not unique")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0062 losing its per-IP rejection direction' mut_server_c_lim_0062_per_ip_removed

mut_server_c_lim_0062_header_deadline_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/tls_h2.rs")
text = path.read_text()
subject = (
    "    server_config.max_connections_per_ip = Some(2);\n"
    "    server_config.header_read_timeout = Duration::from_millis(50);\n"
)
if text.count(subject) != 1:
    raise SystemExit("c-lim-0062 header deadline setup is not unique")
replacement = (
    "    server_config.max_connections_per_ip = Some(2);\n"
    "    server_config.header_read_timeout = Duration::from_secs(5);\n"
)
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0062 losing its bounded header deadline' mut_server_c_lim_0062_header_deadline_removed

mut_server_c_lim_0062_recovery_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/tls_h2.rs")
text = path.read_text()
subject = '    assert!(request_keep_alive(&mut recovered).await.starts_with(b"HTTP/1.1 200"));\n'
if text.count(subject) != 1:
    raise SystemExit("c-lim-0062 healthy recovery assertion is not unique")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0062 losing its healthy recovery direction' mut_server_c_lim_0062_recovery_removed

mut_server_c_lim_0006_instrument_control_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = (
    '    eprintln!("c-lim-0006 instrument: ballast_bytes={BALLAST_BYTES} seen_bytes={ballast_seen}");\n'
    "    if ballast_seen < BALLAST_BYTES / BALLAST_SHARE_SEEN {\n"
)
if text.count(subject) != 1:
    raise SystemExit("c-lim-0006 instrument gate is not unique")
path.write_text(text.replace(subject, subject.replace("if ballast_seen < BALLAST_BYTES / BALLAST_SHARE_SEEN", "if false"), 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0006 asserting reuse on a host whose ps cannot see retained memory' \
    mut_server_c_lim_0006_instrument_control_removed

mut_server_c_lim_0006_single_tail_wave() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = "    let mut previous = loaded;\n    for _ in 1..WAVES {\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0006 wave loop is not unique")
path.write_text(text.replace(subject, "    let mut previous = loaded;\n    for _ in 1..2 {\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0006 collapsing its wave trend back to one later reading' \
    mut_server_c_lim_0006_single_tail_wave

mut_server_c_lim_0006_reuse_ceiling_hardcoded() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = (
    "        let reuse_ceiling = first_growth / TAIL_SHARE_OF_FIRST;\n"
    '        eprintln!("c-lim-0006 reuse: tail_mean={tail_mean} ceiling_bytes={reuse_ceiling}");\n'
)
if text.count(subject) != 1:
    raise SystemExit("c-lim-0006 derived reuse ceiling is not unique")
path.write_text(text.replace(subject, subject.replace("first_growth / TAIL_SHARE_OF_FIRST", "8 * 1024 * 1024"), 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0006 deriving its reuse ceiling from a constant instead of the first wave' \
    mut_server_c_lim_0006_reuse_ceiling_hardcoded

mut_server_c_lim_0006_reuse_assertion_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = (
    '        eprintln!("c-lim-0006 reuse: tail_mean={tail_mean} ceiling_bytes={reuse_ceiling}");\n'
    "        assert!(\n"
    "            tail_mean <= reuse_ceiling,\n"
)
if text.count(subject) != 1:
    raise SystemExit("c-lim-0006 reuse assertion is not unique")
path.write_text(text.replace(subject, subject.replace("tail_mean <= reuse_ceiling", "tail_mean <= usize::MAX"), 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0006 losing its multi-wave reuse direction' mut_server_c_lim_0006_reuse_assertion_removed

mut_server_c_lim_0061_case_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = "async fn c_lim_0061_a_srv_0026_one_thousand_slow_readers_close_without_starving_healthy_traffic() {"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0061 test name is not unique")
path.write_text(text.replace(subject, "async fn a_srv_0026_one_thousand_slow_readers_close() {", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0061 losing its executable load evidence' mut_server_c_lim_0061_case_removed

mut_server_c_lim_0061_cfg_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = (
    '#[tokio::test(flavor = "multi_thread", worker_threads = 4)]\n'
    "async fn c_lim_0061_a_srv_0026_one_thousand_slow_readers_close_without_starving_healthy_traffic() {"
)
if text.count(subject) != 1:
    raise SystemExit("c-lim-0061 active test entry is not unique")
path.write_text(text.replace(subject, "#[cfg(any())]\n" + subject, 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0061 being disabled by cfg' mut_server_c_lim_0061_cfg_disabled

mut_server_c_lim_0061_baseline_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = (
    "    let (control_probes, loaded_probes) = "
    "paired_probe_p99(control.local_addr, loaded.local_addr, PROBES, PROBE_CEILING).await;\n"
)
if text.count(subject) != 1:
    raise SystemExit("c-lim-0061 paired latency reading is not unique")
replacement = (
    "    let loaded_probes = probe_p99(loaded.local_addr, PROBES, PROBE_CEILING).await;\n"
    "    let control_probes = ProbeSet { p99: Duration::from_millis(500), stalled: 0 };\n"
)
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0061 replacing its concurrently sampled control with a constant' mut_server_c_lim_0061_baseline_removed

mut_server_c_lim_0061_stall_count_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = "            loaded_probes.stalled <= control_probes.stalled,\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0061 unanswered-probe direction is not unique")
path.write_text(text.replace(subject, "            loaded_probes.stalled <= usize::MAX,\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0061 letting unanswered probes hide in the tail its percentile discards' \
    mut_server_c_lim_0061_stall_count_removed

mut_server_c_lim_0061_saturation_skip_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = "    if control_probes.stalled > 0 {\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0061 saturation skip is not unique")
path.write_text(text.replace(subject, "    if false {\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0061 comparing two saturated percentiles instead of skipping with the reason' \
    mut_server_c_lim_0061_saturation_skip_removed

mut_server_c_lim_0061_control_shares_the_runtime() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = "    let runtime = tokio::runtime::Builder::new_multi_thread()\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0061 per-listener runtime is not unique")
path.write_text(text.replace(subject, "    let runtime = tokio::runtime::Builder::new_current_thread()\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0061 losing the worker pool that keeps its control off the loaded listener' \
    mut_server_c_lim_0061_control_shares_the_runtime

mut_server_c_lim_0061_reuse_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = (
    '        eprintln!("c-lim-0061 reuse: tail_mean={tail_mean} ceiling_bytes={reuse_ceiling}");\n'
    "        assert!(\n"
    "            tail_mean <= reuse_ceiling,\n"
)
if text.count(subject) != 1:
    raise SystemExit("c-lim-0061 multi-wave reuse assertion is not unique")
path.write_text(text.replace(subject, subject.replace("tail_mean <= reuse_ceiling", "tail_mean <= usize::MAX"), 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0061 losing its multi-wave reuse direction' mut_server_c_lim_0061_reuse_removed

mut_server_c_lim_0061_reuse_ceiling_hardcoded() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = (
    "        let reuse_ceiling = first_growth / TAIL_SHARE_OF_FIRST;\n"
    '        eprintln!("c-lim-0061 reuse: tail_mean={tail_mean} ceiling_bytes={reuse_ceiling}");\n'
)
if text.count(subject) != 1:
    raise SystemExit("c-lim-0061 derived reuse ceiling is not unique")
path.write_text(text.replace(subject, subject.replace("first_growth / TAIL_SHARE_OF_FIRST", "8 * 1024 * 1024"), 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0061 deriving its reuse ceiling from a constant instead of the first wave' \
    mut_server_c_lim_0061_reuse_ceiling_hardcoded

mut_server_c_lim_0061_early_retirement_unbounded() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = "        retired_early <= requested / EARLY_RETIREMENT_SHARE,\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0061 early-retirement bound is not unique")
path.write_text(text.replace(subject, "        retired_early <= usize::MAX,\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0061 timing a wave whose windows the deadline closed before they opened' \
    mut_server_c_lim_0061_early_retirement_unbounded

mut_server_c_lim_0061_sequential_first_bytes() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = "        tasks.push(tokio::spawn(async move {\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0061 per-reader task is not unique")
path.write_text(text.replace(subject, "        tasks.push(std::future::ready(async move {\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0061 waiting for a thousand first bytes one behind another' \
    mut_server_c_lim_0061_sequential_first_bytes

mut_server_c_lim_0061_instrument_control_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = (
    '    eprintln!("c-lim-0061 instrument: ballast_bytes={BALLAST_BYTES} seen_bytes={ballast_seen}");\n\n'
    "    if ballast_seen < BALLAST_BYTES / BALLAST_SHARE_SEEN {\n"
)
if text.count(subject) != 1:
    raise SystemExit("c-lim-0061 instrument gate is not unique")
path.write_text(text.replace(subject, subject.replace("if ballast_seen < BALLAST_BYTES / BALLAST_SHARE_SEEN", "if false"), 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0061 asserting reuse on a host whose ps cannot see retained memory' \
    mut_server_c_lim_0061_instrument_control_removed

mut_server_c_lim_0061_single_tail_wave() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = "    let mut previous = after_first;\n    for _ in 1..WAVES {\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0061 wave loop is not unique")
path.write_text(text.replace(subject, "    let mut previous = after_first;\n    for _ in 1..2 {\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0061 collapsing its wave trend back to a single second reading' \
    mut_server_c_lim_0061_single_tail_wave

mut_server_c_lim_0061_keep_alive_pulled_in() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/tests/server_load.rs")
text = path.read_text()
subject = "    config.keep_alive_idle = Duration::from_secs(60);\n"
if text.count(subject) != 1:
    raise SystemExit("c-lim-0061 distant keep-alive gap is not unique")
path.write_text(text.replace(subject, "    config.keep_alive_idle = Duration::from_secs(1);\n", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'c-lim-0061 letting the keep-alive gap retire the readers instead' mut_server_c_lim_0061_keep_alive_pulled_in

mut_server_connection_lifetime_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/src/config.rs")
text = path.read_text()
needle = "    pub connection_lifetime: Option<Duration>,\n"
if text.count(needle) != 1:
    raise SystemExit("connection-lifetime field is not unique")
path.write_text(text.replace(needle, "", 1))
PYEOF
}
expect_fail check_timeout_layer_ownership.sh \
    'the extra connection-lifetime safety valve being removed' mut_server_connection_lifetime_removed

mut_server_tuning_doc() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/server/src/config.rs")
text = path.read_text().replace(
    "/// Global open-connection ceiling. Increasing raises capacity and memory; decreasing applies earlier backpressure.\n",
    "/// Global open-connection ceiling.\n",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_tuning_doc.sh \
    'a server tuning field losing both tradeoff directions' mut_server_tuning_doc

mut_planning_dir() {
    mkdir -p docs/plans
    printf '# scratch\n' >docs/plans/codegen-rollout.md
    git add -f docs/plans/codegen-rollout.md
}
expect_fail_forced_staged check_no_planning_docs.sh \
    'a document committed under docs/plans/' mut_planning_dir

mut_planning_name() {
    printf '# scratch\n' >MIGRATION_PLAN.md
}
expect_fail check_no_planning_docs.sh \
    'a root-level MIGRATION_PLAN.md' mut_planning_name

mut_planning_allowance_bypass() {
    mkdir -p docs/plans scripts/allowances
    printf '# scratch\n' >docs/plans/allowed-rollout.md
    printf 'docs/plans/allowed-rollout.md # stale policy must not exempt a plan\n' >scripts/allowances/planning-doc-allowances.txt
    git add -f docs/plans/allowed-rollout.md scripts/allowances/planning-doc-allowances.txt
}
expect_fail_forced_staged check_no_planning_docs.sh \
    'a stale allowance attempting to exempt a tracked planning document' mut_planning_allowance_bypass

probe_planning_guard_missing_git_input() {
    local empty output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    empty="$(mktemp -d "${TMPDIR:-/tmp}/gateway-planning-empty.XXXXXX")"
    output="$(GATEWAY_CHECK_ROOT="$empty" "${SCRIPT_DIR}/check_no_planning_docs.sh" 2>&1)" || rc=$?
    rmdir "$empty"
    if [[ "$rc" -ne 0 && "$output" == *'cannot enumerate planning-directory inputs'* ]]; then
        pass_msg 'check_no_planning_docs.sh fails closed when git inputs are unavailable'
    else
        fail_msg 'check_no_planning_docs.sh reported green without git inputs'
    fi
}
probe_planning_guard_missing_git_input

expect_protected_fail() {
    local desc="$1" mutate="$2" sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    [[ -x "${SCRIPT_DIR}/check_protected_files.sh" ]] || { fail_msg "check_protected_files.sh is missing or not executable; cannot test: ${desc}"; return; }
    make_sandbox; sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null && git add -A && git -c user.name=t -c user.email=t@t commit -qm mutation)
    GATEWAY_CHECK_ROOT="$sandbox" GATEWAY_PROTECTED_BASE=HEAD^ GATEWAY_PROTECTED_HEAD=HEAD GATEWAY_PR_BODY_JSON='""' \
        "${SCRIPT_DIR}/check_protected_files.sh" >/dev/null 2>&1 || rc=$?
    [[ "$rc" -ne 0 ]] && pass_msg "check_protected_files.sh catches: ${desc}" || fail_msg "check_protected_files.sh did NOT catch: ${desc}"
}

expect_protected_pass() {
    local desc="$1" mutate="$2" body="${3:-}" sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null && git add -A && git -c user.name=t -c user.email=t@t commit -qm mutation)
    GATEWAY_CHECK_ROOT="$sandbox" GATEWAY_PROTECTED_BASE=HEAD^ GATEWAY_PROTECTED_HEAD=HEAD GATEWAY_PR_BODY_JSON="$(json_string "$body")" \
        "${SCRIPT_DIR}/check_protected_files.sh" >/dev/null 2>&1 || rc=$?
    [[ "$rc" -eq 0 ]] && pass_msg "check_protected_files.sh allows: ${desc}" || fail_msg "check_protected_files.sh rejected: ${desc}"
}

mut_protected_existing_adr() { printf '\nA changed accepted decision.\n' >>docs/adr/0003-no-global-registry-crates.md; }
expect_protected_fail 'an existing ADR modified without a BREAKING declaration' mut_protected_existing_adr
mut_protected_with_breaking() { printf '\nContract note.\n' >>NOTICE; }
expect_protected_pass 'a protected change carrying the literal BREAKING declaration' mut_protected_with_breaking 'BREAKING: downstream users must adopt the new contract.'
mut_new_adr() { printf '# New decision\n' >docs/adr/9999-new-decision.md; }
expect_protected_pass 'a newly added ADR' mut_new_adr

add_next_indexed_adr() {
    python3 - "$1" "$2" <<'PYEOF'
import re
import sys
from pathlib import Path

path = Path("docs/adr/README.md")
text = path.read_text()
rows = list(re.finditer(r"^\| ([0-9]{4}) \|[^\n]*$", text, re.MULTILINE))
if not rows:
    raise SystemExit("missing ADR index rows")
number = int(rows[-1].group(1), 10) + 1
if number > 9999:
    raise SystemExit("ADR test number exceeds four digits")
title, slug = sys.argv[1:]
record = Path(f"docs/adr/{number:04d}-{slug}.md")
if record.exists():
    raise SystemExit(f"ADR test path already exists: {record}")
record.write_text(f"# ADR-{number:04d}: {title}\n\n- Status: Accepted\n")
insert_at = rows[-1].end()
row = f"\n| {number:04d} | {title} | Accepted |"
path.write_text(text[:insert_at] + row + text[insert_at:])
PYEOF
}

mut_new_adr_with_required_index_row() {
    add_next_indexed_adr 'New indexed decision' 'new-indexed-decision'
}
expect_protected_pass 'a newly added ADR with its required matching index row' mut_new_adr_with_required_index_row

mut_new_adr_after_existing_next_number() {
    add_next_indexed_adr 'Existing indexed decision' 'existing-indexed-decision'
    mut_new_adr_with_required_index_row
}
expect_protected_pass 'a newly added ADR after the previous next number was accepted' mut_new_adr_after_existing_next_number

mut_new_adr_with_mismatched_index_row() {
    mut_new_adr_with_required_index_row
    sed -i.bak 's/New indexed decision/Wrong indexed decision/' docs/adr/README.md
    rm docs/adr/README.md.bak
}
expect_protected_fail 'a new ADR whose index title does not match' mut_new_adr_with_mismatched_index_row

mut_new_adr_with_index_and_readme_drift() {
    mut_new_adr_with_required_index_row
    printf '\nUnrelated policy drift.\n' >>docs/adr/README.md
}
expect_protected_fail 'a new ADR index row hiding another README change' mut_new_adr_with_index_and_readme_drift
mut_ordinary_manifest_and_new_case() { printf '\n# ordinary manifest comment\n' >>crates/core/Cargo.toml; printf '[case]\nid = "c-new-9999"\n' >conformance/cases/c-new-9999.toml; }
expect_protected_pass 'an ordinary Cargo.toml edit and a newly added conformance case' mut_ordinary_manifest_and_new_case
mut_protected_rust_version() { sed 's/^rust-version = .*/rust-version = "999.0"/' Cargo.toml >Cargo.toml.mut; mv Cargo.toml.mut Cargo.toml; }
expect_protected_fail 'a rust-version change without BREAKING' mut_protected_rust_version
mut_deleted_conformance_case() { rm conformance/cases/acl/c-acl-0005.toml; }
expect_protected_fail 'a deleted conformance case without BREAKING' mut_deleted_conformance_case
mut_new_protocol_overlay() { printf '[[quirk]]\nid = "q-new-9999"\n' >model/overlays/quirks/new-guard-fixture.toml; }
expect_protected_fail 'a newly added protocol overlay without BREAKING' mut_new_protocol_overlay
mut_protected_table_drift() { sed 's/`rustfmt.toml`/`rustfmt-contract.toml`/' AGENTS.md >AGENTS.md.mut; mv AGENTS.md.mut AGENTS.md; }
expect_protected_fail 'the AGENTS protected path table drifting from the executable policy' mut_protected_table_drift

probe_protected_missing_body() {
    local output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" "${SCRIPT_DIR}/check_protected_files.sh" 2>&1)" || rc=$?
    [[ "$rc" -ne 0 && "$output" == *'required input is missing: GATEWAY_PR_BODY_JSON'* ]] && \
        pass_msg 'check_protected_files.sh fails closed without the PR body' || \
        fail_msg 'check_protected_files.sh reported green without the PR body'
}
probe_protected_missing_body

# The untrusted input is validated before the comparison revisions, so this second half is
# what still proves the revisions are required at all.
probe_protected_missing_inputs() {
    local output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" GATEWAY_PR_BODY_JSON='""' \
        "${SCRIPT_DIR}/check_protected_files.sh" 2>&1)" || rc=$?
    [[ "$rc" -ne 0 && "$output" == *'required input is missing: GATEWAY_PROTECTED_BASE'* ]] && \
        pass_msg 'check_protected_files.sh fails closed without PR comparison inputs' || \
        fail_msg 'check_protected_files.sh reported green without PR comparison inputs'
}
probe_protected_missing_inputs

mut_inventory() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/Cargo.toml")
text = path.read_text()
anchor = "[dependencies]\n"
if text.count(anchor) != 1:
    raise SystemExit("core dependencies table is missing or ambiguous")
path.write_text(text.replace(anchor, anchor + 'inventory = "0.3"\n', 1))
PYEOF
}
expect_fail check_no_global_registry_deps.sh \
    'an `inventory` dependency' mut_inventory

mut_linkme() {
    python3 - <<'PY'
from pathlib import Path
path = Path("crates/core/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("[dependencies]\n", "[dependencies]\nlinkme = \"0.3\"\n", 1))
PY
}
expect_fail check_no_global_registry_deps.sh \
    'a `linkme` dependency' mut_linkme

# NOTE: appended to a manifest whose last table is `[dependencies]`. Appending
# to rustfs-gateway-types would land the line in its `[features]` table, where it is
# correctly NOT a dependency.
mut_ctor() {
    printf 'ctor = "0.2"\n' >>crates/xml/Cargo.toml
}
expect_fail check_no_global_registry_deps.sh \
    'a `ctor` dependency' mut_ctor

mut_renamed_inventory_package() {
    python3 - <<'PY'
from pathlib import Path
path = Path("crates/core/Cargo.toml")
text = path.read_text()
path.write_text(text.replace(
    "[dependencies]\n",
    '[dependencies]\nregistry_alias = { package = "inventory", version = "0.3" }\n',
    1,
))
PY
}
expect_fail check_no_global_registry_deps.sh \
    'an `inventory` package hidden behind a dependency alias' mut_renamed_inventory_package

mut_workspace_renamed_inventory_package() {
    cat >>Cargo.toml <<'TOML'

[workspace.dependencies.registry_alias]
package = "inventory"
version = "0.3"
TOML
}
expect_fail check_no_global_registry_deps.sh \
    'a renamed inventory package in workspace dependencies' mut_workspace_renamed_inventory_package

mut_target_renamed_linkme_package() {
    cat >>crates/core/Cargo.toml <<'TOML'

[target.'cfg(unix)'.dev-dependencies.registry_alias]
package = "linkme"
version = "0.3"
TOML
}
expect_fail check_no_global_registry_deps.sh \
    'a renamed linkme package in target-specific dev-dependencies' mut_target_renamed_linkme_package

mut_quoted_ctor_dependency() {
    python3 - <<'PY'
from pathlib import Path
path = Path("crates/core/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("[dependencies]\n", '[dependencies]\n"ctor" = "0.2"\n', 1))
PY
}
expect_fail check_no_global_registry_deps.sh \
    'a quoted ctor dependency key' mut_quoted_ctor_dependency

mut_untracked_renamed_inventory_package() {
    mkdir -p examples/untracked-registry
    cat >examples/untracked-registry/Cargo.toml <<'TOML'
[package]
name = "untracked-registry"
version = "0.0.0"

[dependencies]
registry_alias = { package = "inventory", version = "0.3" }
TOML
}
expect_fail_unstaged check_no_global_registry_deps.sh \
    'a renamed inventory package in an untracked manifest' mut_untracked_renamed_inventory_package

mut_global_registry_allowance_attempt() {
    python3 - <<'PY'
from pathlib import Path
path = Path("crates/core/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("[dependencies]\n", '[dependencies]\ninventory = "0.3"\n', 1))
PY
    printf 'core -> inventory\n' >scripts/allowances/global-registry-allowances.txt
}
expect_fail check_no_global_registry_deps.sh \
    'an allowance file attempting to bypass the absolute ban' mut_global_registry_allowance_attempt

mut_malformed_manifest_for_registry_guard() {
    printf '\nregistry_alias = { package = "inventory"\n' >>crates/core/Cargo.toml
}
expect_fail check_no_global_registry_deps.sh \
    'a malformed manifest that must fail closed rather than under-report' \
    mut_malformed_manifest_for_registry_guard

mut_missing_global_registry_adr() {
    rm -f docs/adr/0003-no-global-registry-crates.md
}
expect_fail check_no_global_registry_deps.sh \
    'the ADR rule input being missing' mut_missing_global_registry_adr

probe_global_registry_diagnostic() {
    local diagnostic_pattern output rc=0 sandbox
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    cat >>"$sandbox/crates/core/Cargo.toml" <<'TOML'

[dependencies.registry_alias]
package = "inventory"
version = "0.3"
TOML
    (cd "$sandbox" && git add -A >/dev/null 2>&1)
    output="$(GATEWAY_CHECK_ROOT="$sandbox" \
        "${SCRIPT_DIR}/check_no_global_registry_deps.sh" 2>&1)" || rc=$?
    diagnostic_pattern='crates/core/Cargo.toml:[0-9]+:.*\[dependencies\]\.registry_alias.*inventory'
    if [[ "$rc" -ne 0 &&
        "$output" =~ $diagnostic_pattern &&
        "$output" == *'rule: docs/adr/0003-no-global-registry-crates.md'* ]]; then
        pass_msg 'check_no_global_registry_deps.sh reports path, line, alias, package and ADR rule'
    else
        fail_msg 'check_no_global_registry_deps.sh emitted an incomplete diagnostic'
    fi
}
probe_global_registry_diagnostic

probe_global_registry_text_decoys() {
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    mkdir -p "$sandbox/examples/registry-decoy"
    cat >"$sandbox/examples/registry-decoy/Cargo.toml" <<'TOML'
[package]
name = "registry-decoy"
version = "0.0.0"
description = "an inventory of linkme and ctor alternatives"

# inventory = "0.3"

[dependencies]
ordinary_helper = { package = "inventory-helper", version = "0.1" }
TOML
    (cd "$sandbox" && git add -A >/dev/null 2>&1)
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_no_global_registry_deps.sh" \
        >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_no_global_registry_deps.sh ignores text decoys and allows non-banned inventory-helper'
    else
        fail_msg 'check_no_global_registry_deps.sh reported a text decoy or non-banned package'
    fi
}
probe_global_registry_text_decoys

probe_global_registry_guard_missing_python() {
    local output rc=0 sandbox tool_path
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-registry-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    output="$(GATEWAY_CHECK_ROOT="$sandbox" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_no_global_registry_deps.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: python3'* ]]; then
        pass_msg 'check_no_global_registry_deps.sh fails closed without python3'
    else
        fail_msg 'check_no_global_registry_deps.sh reported green without python3'
    fi
}
probe_global_registry_guard_missing_python

mut_handler_bundle_trait() {
    cat >>crates/core/src/handler.rs <<'RS'

pub trait ObjectApi:
    Handler<rustfs_gateway_types::dto::GetObject>
    + Handler<rustfs_gateway_types::dto::PutObject>
{
}
RS
}
expect_fail check_no_bundle_trait.sh \
    '[c-reg-1003] a multi-operation Handler bundle supertrait' mut_handler_bundle_trait

mut_handler_bundle_where_clause() {
    cat >>crates/core/src/handler.rs <<'RS'

pub trait ObjectApi
where
    Self: crate::handler::Handler<rustfs_gateway_types::dto::GetObject>
        + crate::handler::Handler<rustfs_gateway_types::dto::PutObject>,
{
}
RS
}
expect_fail check_no_bundle_trait.sh \
    '[c-reg-1003] a qualified Handler bundle hidden in a where clause' mut_handler_bundle_where_clause

mut_extension_async_fn() {
    cat >>crates/gateway/src/ext/observer.rs <<'RS'

pub trait AsyncObserver {
    async fn observe(&self);
}
RS
}
expect_fail check_dyn_policy.sh \
    '[c-reg-1013] AFIT on a non-handler extension trait' mut_extension_async_fn

mut_extension_rpitit_future() {
    cat >>crates/gateway/src/ext/observer.rs <<'RS'

pub trait RpititObserver {
    fn observe(&self) -> impl core::future::Future<Output = ()> + Send;
}
RS
}
expect_fail check_dyn_policy.sh \
    '[c-reg-1013] RPITIT Future on a non-handler extension trait' mut_extension_rpitit_future

mut_extension_async_trait_macro() {
    cat >>crates/gateway/src/ext/observer.rs <<'RS'

#[async_trait::async_trait]
pub trait MacroObserver {
    async fn observe(&self);
}
RS
}
expect_fail check_dyn_policy.sh \
    '[c-reg-1013] async_trait on an extension trait' mut_extension_async_trait_macro

probe_registry_trait_policy_decoys() {
    local output rc=0 sandbox
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    cat >>"$sandbox/crates/core/src/handler.rs" <<'RS'

// trait CommentBundle: Handler<A> + Handler<B> {}
const TRAIT_POLICY_DECOY: &str = "trait StringBundle: Handler<A> + Handler<B> { async fn call(); }";
RS
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_no_bundle_trait.sh" >/dev/null 2>&1 || rc=$?
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_dyn_policy.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'registry trait-policy guards ignore comment and string decoys'
    else
        fail_msg 'registry trait-policy guards reported a comment or string decoy'
    fi
}
probe_registry_trait_policy_decoys

mut_c_sig_0126_derived_signature() {
    cat >crates/sig/src/proof.rs <<'RS'
// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Fixture.

/// A signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature([u8; 32]);
RS
}
expect_ct_eq_fail \
    '[c-sig-0126] a Signature type deriving Debug/PartialEq/Eq' mut_c_sig_0126_derived_signature

mut_strip_header() {
    grep -v 'Licensed under the Apache License' crates/core/src/lib.rs >/tmp/.lh.$$ &&
        mv /tmp/.lh.$$ crates/core/src/lib.rs
}
expect_fail check_license_headers.sh \
    'a Rust file with the licence header removed' mut_strip_header

mut_restore_license_grep_q_pipeline() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_license_headers.sh")
text = path.read_text().replace(
    'head -n "$HEADER_WINDOW" "$file" | grep -F "$HEADER_MARKER" >/dev/null',
    'head -n "$HEADER_WINDOW" "$file" | grep -qF "$HEADER_MARKER"',
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'the license guard restoring an early-exit grep pipeline' mut_restore_license_grep_q_pipeline

mut_restore_secret_grep_q_pipeline() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_secret_hygiene.sh")
text = path.read_text().replace(
    "grep -E '^impl ([a-z_:]+)?fmt::Debug for Credentials \\{' >/dev/null",
    "grep -qE '^impl ([a-z_:]+)?fmt::Debug for Credentials \\{'",
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'the secret guard restoring an early-exit grep pipeline' mut_restore_secret_grep_q_pipeline

mut_restore_multiline_combined_grep_q_pipeline() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_license_headers.sh")
text = path.read_text().replace(
    'head -n "$HEADER_WINDOW" "$file" | grep -F "$HEADER_MARKER" >/dev/null',
    'head -n "$HEADER_WINDOW" "$file" |\n        grep -Fqi "$HEADER_MARKER"',
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'a multiline pipeline restoring combined quiet grep flags' mut_restore_multiline_combined_grep_q_pipeline

mut_restore_multiline_long_quiet_pipeline() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_secret_hygiene.sh")
text = path.read_text().replace(
    "printf '%s\\n' \"$credentials_code\" | grep -E '^impl ([a-z_:]+)?fmt::Debug for Credentials \\{' >/dev/null",
    "printf '%s\\n' \"$credentials_code\" |\\n    grep --quiet -E '^impl ([a-z_:]+)?fmt::Debug for Credentials \\{'",
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'a multiline pipeline restoring the long quiet option' mut_restore_multiline_long_quiet_pipeline

mut_quiet_grep_in_command_substitution() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_license_headers.sh")
text = path.read_text().replace(
    'checked=0',
    'status="$(head -n 1 "$0" | grep -qF marker)"\nchecked=0',
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'a quiet grep inside command substitution' mut_quiet_grep_in_command_substitution

mut_split_grep_and_quiet_flag() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_secret_hygiene.sh")
text = path.read_text().replace(
    "grep -E '^impl ([a-z_:]+)?fmt::Debug for Credentials \\{' >/dev/null",
    "grep \\\n+        -qiE '^impl ([a-z_:]+)?fmt::Debug for Credentials \\{'",
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'grep and its combined quiet flag split across lines' mut_split_grep_and_quiet_flag

mut_grep_e_and_quiet_combined() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_license_headers.sh")
text = path.read_text().replace(
    'checked=0',
    'grep -eq pattern input\nchecked=0',
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'grep combining the expression and quiet flags' mut_grep_e_and_quiet_combined

mut_multiline_grep_e_and_quiet_combined() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_license_headers.sh")
text = path.read_text().replace(
    'checked=0',
    'grep \\\n+    -eq pattern input\nchecked=0',
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'multiline grep combining the expression and quiet flags' mut_multiline_grep_e_and_quiet_combined

probe_guard_grep_policy_allows_shell_eq() {
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    printf '\n[[ 1 -eq 1 ]]\n' >>"${sandbox}/scripts/check_license_headers.sh"
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_guard_grep_pipelines.sh" \
        >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_guard_grep_pipelines.sh allows the shell -eq operator'
    else
        fail_msg 'check_guard_grep_pipelines.sh mistook the shell -eq operator for quiet grep'
    fi
}
probe_guard_grep_policy_allows_shell_eq

# -----------------------------------------------------------------------------
# The pipe half of the policy, which is the half that has cost CI cycles. The two named
# targets above are scanned for the option token anywhere; every other guard is scanned
# for the option token on the receiving end of a pipe. The three mutations put the shape
# back into three guards, none of which is a named target, and the two probes keep the
# rule from degenerating into a blanket ban on quiet grep.
# -----------------------------------------------------------------------------
mut_restore_sig_coverage_grep_q_pipeline() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_sig_case_coverage.sh")
text = path.read_text()
old = '''    printf '%s\\n' "${p2_04_hard_constraints[@]}" | grep -Fx "$hard_constraint" >/dev/null || {'''
new = '''    printf '%s\\n' "${p2_04_hard_constraints[@]}" | grep -Fxq "$hard_constraint" || {'''
if text.count(old) != 1:
    raise SystemExit("missing the P2-04 hard-constraint membership pipeline")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'the signature coverage guard restoring the pipeline that failed on a clean tree' \
    mut_restore_sig_coverage_grep_q_pipeline

mut_restore_allowance_grep_q_pipeline() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_ct_eq.sh")
text = path.read_text()
old = '''    printf '%s' "$ALLOWANCES" | grep -xF "$1" >/dev/null'''
new = '''    printf '%s' "$ALLOWANCES" | grep -qxF "$1"'''
if text.count(old) != 1:
    raise SystemExit("missing the ct-eq allowance membership pipeline")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'a guard outside the two named targets restoring an early-exit grep pipeline' \
    mut_restore_allowance_grep_q_pipeline

mut_restore_grep_q_pipeline_over_a_line_break() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_english_only.sh")
text = path.read_text()
old = '''    printf '%s' "$ALLOWANCES" | grep -xF "$1" >/dev/null'''
new = '''    printf '%s' "$ALLOWANCES" |\n        grep --quiet -xF "$1"'''
if text.count(old) != 1:
    raise SystemExit("missing the english-only allowance membership pipeline")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'a pipeline continued over a bare trailing pipe with the quiet consumer on the next line' \
    mut_restore_grep_q_pipeline_over_a_line_break

probe_guard_grep_policy_allows_unpiped_quiet_grep() {
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    printf '\ngrep -qxF marker "$0"\n' >>"${sandbox}/scripts/check_ct_eq.sh"
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_guard_grep_pipelines.sh" \
        >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_guard_grep_pipelines.sh allows a quiet grep reading a named file'
    else
        fail_msg 'check_guard_grep_pipelines.sh rejected a quiet grep that consumes no pipe'
    fi
}
probe_guard_grep_policy_allows_unpiped_quiet_grep

probe_guard_grep_policy_allows_quiet_grep_after_or() {
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    printf '\n[[ -n "$ROOT_DIR" ]] ||\n    grep -qxF marker "$0"\n' \
        >>"${sandbox}/scripts/check_ct_eq.sh"
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_guard_grep_pipelines.sh" \
        >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_guard_grep_pipelines.sh allows a quiet grep after a logical or'
    else
        fail_msg 'check_guard_grep_pipelines.sh mistook a logical or for a pipe'
    fi
}
probe_guard_grep_policy_allows_quiet_grep_after_or


probe_guard_grep_policy_missing_grep() {
    local sandbox tool_path output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    ln -s "$(command -v mktemp)" "${tool_path}/mktemp"
    output="$(GATEWAY_CHECK_ROOT="$sandbox" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_guard_grep_pipelines.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: grep'* ]]; then
        pass_msg 'check_guard_grep_pipelines.sh fails closed without grep'
    else
        fail_msg 'check_guard_grep_pipelines.sh reported green without grep'
    fi
}
probe_guard_grep_policy_missing_grep

probe_guard_grep_policy_missing_awk() {
    local sandbox tool_path output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    ln -s "$(command -v grep)" "${tool_path}/grep"
    output="$(GATEWAY_CHECK_ROOT="$sandbox" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_guard_grep_pipelines.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: awk'* ]]; then
        pass_msg 'check_guard_grep_pipelines.sh fails closed without awk'
    else
        fail_msg 'check_guard_grep_pipelines.sh reported green without awk'
    fi
}
probe_guard_grep_policy_missing_awk

probe_guard_grep_policy_awk_error() {
    local sandbox tool_path output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    ln -s "$(command -v grep)" "${tool_path}/grep"
    ln -s "$(command -v mktemp)" "${tool_path}/mktemp"
    ln -s "$(command -v rm)" "${tool_path}/rm"
    printf '#!/bin/sh\nexit 75\n' >"${tool_path}/awk"
    chmod +x "${tool_path}/awk"
    output="$(GATEWAY_CHECK_ROOT="$sandbox" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_guard_grep_pipelines.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 ]]; then
        pass_msg 'check_guard_grep_pipelines.sh fails closed on an awk processing error'
    else
        fail_msg 'check_guard_grep_pipelines.sh reported green after an awk processing error'
    fi
}
probe_guard_grep_policy_awk_error


# -----------------------------------------------------------------------------
# check_ct_eq.sh grew from one rule to eight when P2-02 and P0-10 landed. Each new rule
# needs its own negative control here: a rule with no failing case is a rule
# nobody has ever seen work.
# -----------------------------------------------------------------------------

mut_secret_display() {
    printf '\nimpl core::fmt::Display for SecretBytes {\n    fn fmt(&self, _: &mut core::fmt::Formatter<\x27_>) -> core::fmt::Result { Ok(()) }\n}\n' \
        >>crates/sig/src/secret.rs
}
expect_ct_eq_fail \
    'a Display impl on a secret-bearing type' mut_secret_display

mut_c_sig_0127_second_bool_from() {
    printf '\nfn leak(c: subtle::Choice) -> bool { bool::from(c) }\n' \
        >>crates/sig/src/verdict.rs
}
expect_ct_eq_fail \
    '[c-sig-0127] a second bool::from(Choice), which turns constant time back into a branch' mut_c_sig_0127_second_bool_from

mut_unwrap_u8() {
    printf '\nfn peek(c: subtle::Choice) -> u8 { c.unwrap_u8() }\n' \
        >>crates/sig/src/verdict.rs
}
expect_ct_eq_fail \
    'Choice::unwrap_u8, which discards the constant-time wrapper' mut_unwrap_u8

mut_secret_in_log() {
    printf '\nfn oops(s: &SecretBytes) -> String { format!("secret={s:?}") }\n' \
        >>crates/sig/src/secret.rs
}
expect_ct_eq_fail \
    'a secret interpolated into a formatting macro' mut_secret_in_log

mut_unboxed_key_material() {
    printf '\npub(crate) struct Leaky { signing_key: Vec<u8> }\n' \
        >>crates/sig/src/timing.rs
}
expect_ct_eq_fail \
    'key material held in Vec<u8> instead of a zeroizing box' mut_unboxed_key_material

mut_strip_negative_floor() {
    # The floor counts across the whole crate, so stripping one file is not enough
    # to trip it — the mutation has to remove the annotations everywhere.
    find crates/sig -name '*.rs' -print0 | while IFS= read -r -d '' f; do
        grep -v '^/// Negative' "$f" >"${f}.nf" && mv "${f}.nf" "$f"
    done
}
expect_ct_eq_fail \
    'negative-case coverage dropping below its floor' mut_strip_negative_floor

mut_c_sig_0551_signature_equality() {
    printf '\nfn oops(presented: &[u8], expected_signature: &[u8]) -> bool { presented == expected_signature }\n' \
        >>crates/sig/src/verdict.rs
}
expect_ct_eq_fail \
    '[c-sig-0551] ordinary == on signature material, which no PartialEq rule sees' mut_c_sig_0551_signature_equality

mut_c_sig_0551_sig_v2_equality() {
    printf '\nfn oops(a: u8, b: u8) -> bool { a == b }\n' \
        >>crates/sig/src/sig_v2/mod.rs
}
expect_ct_eq_fail \
    '[c-sig-0551] any == inside the sig_v2 subtree, which compares nothing directly' mut_c_sig_0551_sig_v2_equality

# rustfs/gateway#240 named this guard as one of five that blank from `#[cfg(test)]`
# to a brace a bodyless `mod tests;` never opens. It does not — it blanks
# comment-only lines and nothing else, and says so at check_ct_eq.sh:649 — and
# this case is the evidence rather than the reading. `crates/sig/src/signer.rs`
# is the file the issue measured: its declaration sits at line 685 of 687, so
# the appended comparison lands *after* it. A guard that stopped at the
# attribute would report this file clean, which is the one outcome that must
# not be possible on the path that verifies signatures.
mut_c_sig_0551_equality_after_bodyless_cfg_test() {
    printf '\nfn oops(signature: &[u8], other: &[u8]) -> bool { signature == other }\n' \
        >>crates/sig/src/signer.rs
}
expect_ct_eq_fail \
    '[c-sig-0551] == on signature material appended after the bodyless #[cfg(test)] mod tests; in signer.rs' \
    mut_c_sig_0551_equality_after_bodyless_cfg_test

mut_secret_partial_eq_without_ct_eq() {
    cat >>crates/sig/src/secret.rs <<'RS'

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}
RS
}
expect_ct_eq_fail \
    'a hand-written PartialEq for secret material without ct_eq in the same impl' \
    mut_secret_partial_eq_without_ct_eq

mut_secret_partial_eq_with_decoys() {
    cat >>crates/sig/src/secret.rs <<'RS'

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        // self.expose().ct_eq(other.expose())
        let decoy = "ct_eq(";
        let _ = decoy;
        self.expose() == other.expose()
    }
}
RS
}
expect_ct_eq_fail \
    'ct_eq appearing only in comments or literals beside ordinary equality' \
    mut_secret_partial_eq_with_decoys

mut_secret_partial_eq_with_bare_helper() {
    cat >>crates/sig/src/secret.rs <<'RS'

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        fn ct_eq(_: &[u8], _: &[u8]) -> bool { true }
        let _ = ct_eq(self.expose(), other.expose());
        self.expose() == other.expose()
    }
}
RS
}
expect_ct_eq_fail \
    'a bare local ct_eq helper authorizing ordinary equality' \
    mut_secret_partial_eq_with_bare_helper

mut_secret_partial_eq_with_type_alias() {
    cat >>crates/sig/src/secret.rs <<'RS'

type Material = SecretBytes;
impl PartialEq for Material {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}
RS
}
expect_ct_eq_fail \
    'a secret type alias hiding an ordinary PartialEq implementation' \
    mut_secret_partial_eq_with_type_alias

mut_secret_partial_eq_with_trait_alias() {
    cat >>crates/sig/src/secret.rs <<'RS'

use core::cmp::PartialEq as Same;
impl Same for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}
RS
}
expect_ct_eq_fail \
    'a PartialEq import alias hiding ordinary comparison' \
    mut_secret_partial_eq_with_trait_alias

mut_secret_partial_eq_with_fake_authority() {
    cat >>crates/sig/src/secret.rs <<'RS'

mod fake {
    pub fn ct_eq(a: &[u8], b: &[u8]) -> bool { a == b }
}
impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        fake::ct_eq(self.expose(), other.expose())
    }
}
RS
}
expect_ct_eq_fail \
    'a look-alike ct_eq function that performs ordinary equality' \
    mut_secret_partial_eq_with_fake_authority

mut_secret_partial_eq_with_shadowed_subtle() {
    cat >>crates/sig/src/secret.rs <<'RS'

mod subtle {
    pub trait ConstantTimeEq {
        fn ct_eq(&self, other: &Self) -> bool;
    }
    impl ConstantTimeEq for [u8] {
        fn ct_eq(&self, other: &Self) -> bool { self == other }
    }
}
impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self.expose(), other.expose())
    }
}
RS
}
expect_ct_eq_fail \
    'a local subtle module shadowing the constant-time authority' \
    mut_secret_partial_eq_with_shadowed_subtle

mut_secret_partial_eq_with_constant_time_decoy() {
    cat >>crates/sig/src/secret.rs <<'RS'

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        let _ = ::subtle::ConstantTimeEq::ct_eq(self.expose(), other.expose());
        self.expose() == other.expose()
    }
}
RS
}
expect_ct_eq_fail \
    'a real constant-time call used as a decoy before ordinary equality' \
    mut_secret_partial_eq_with_constant_time_decoy

mut_secret_partial_eq_with_ordinary_ne() {
    cat >>crates/sig/src/secret.rs <<'RS'

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        ::subtle::ConstantTimeEq::ct_eq(self.expose(), other.expose()).into()
    }
    fn ne(&self, other: &Self) -> bool {
        self.expose() != other.expose()
    }
}
RS
}
expect_ct_eq_fail \
    'an ordinary comparison hidden in a PartialEq ne override' \
    mut_secret_partial_eq_with_ordinary_ne

mut_secret_partial_eq_from_macro() {
    cat >>crates/sig/src/secret.rs <<'RS'

macro_rules! unsafe_eq {
    ($t:ty) => {
        impl PartialEq for $t {
            fn eq(&self, other: &Self) -> bool {
                self.expose() == other.expose()
            }
        }
    }
}
unsafe_eq!(SecretBytes);
RS
}
expect_ct_eq_fail \
    'a macro parameter generating PartialEq for secret material' \
    mut_secret_partial_eq_from_macro

mut_secret_partial_eq_from_nested_macro() {
    cat >>crates/sig/src/secret.rs <<'RS'

macro_rules! inner_eq {
    ($t:ty) => {
        impl PartialEq for $t {
            fn eq(&self, other: &Self) -> bool {
                self.expose() == other.expose()
            }
        }
    }
}
macro_rules! outer_eq {
    ($t:ty) => { inner_eq!($t); }
}
outer_eq!(SecretBytes);
RS
}
expect_ct_eq_fail \
    'a nested macro forwarding secret material into a PartialEq generator' \
    mut_secret_partial_eq_from_nested_macro

mut_secret_partial_eq_from_macro_metavariable() {
    cat >>crates/sig/src/secret.rs <<'RS'

macro_rules! inner_meta_eq {
    ($t:ty) => {
        impl PartialEq for $t {
            fn eq(&self, other: &Self) -> bool {
                self.expose() == other.expose()
            }
        }
    }
}
macro_rules! outer_meta_eq {
    ($m:ident, $t:ty) => { $m!($t); }
}
outer_meta_eq!(inner_meta_eq, SecretBytes);
RS
}
expect_ct_eq_fail \
    'a macro name passed through a metavariable before generating PartialEq' \
    mut_secret_partial_eq_from_macro_metavariable

probe_secret_partial_eq_with_constant_time_call() {
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_ct_eq_sandbox
    sandbox="$CT_EQ_SANDBOX"
    cat >"${sandbox}/ct_eq_positive.rs" <<'RS'
struct FixtureSecret([u8; 4]);

impl PartialEq for FixtureSecret {
    fn eq(&self, other: &Self) -> bool {
        ::subtle::ConstantTimeEq::ct_eq(&self.0, &other.0).into()
    }
}

trait FixtureMarker {}
impl<T: PartialEq> FixtureMarker for FixtureSecret {}
RS
    (cd "$sandbox" && git add ct_eq_positive.rs)
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_ct_eq.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_ct_eq.sh accepts a hand-written PartialEq that calls ConstantTimeEq'
    else
        fail_msg 'check_ct_eq.sh rejected a hand-written PartialEq that calls ConstantTimeEq'
    fi
}
probe_secret_partial_eq_with_constant_time_call

probe_secret_partial_eq_allowance() {
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_ct_eq_sandbox
    sandbox="$CT_EQ_SANDBOX"
    cat >"${sandbox}/ct_eq_allowed.rs" <<'RS'
struct FixtureSecretAlgorithm;

impl PartialEq for FixtureSecretAlgorithm {
    fn eq(&self, _: &Self) -> bool { true }
}
RS
    printf 'ct_eq_allowed.rs:FixtureSecretAlgorithm # names an algorithm and carries no secret material\n' \
        >>"${sandbox}/scripts/allowances/ct-eq-allowances.txt"
    (cd "$sandbox" && git add ct_eq_allowed.rs scripts/allowances/ct-eq-allowances.txt)
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_ct_eq.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_ct_eq.sh honours a reasoned false-positive allowance for PartialEq'
    else
        fail_msg 'check_ct_eq.sh ignored a reasoned false-positive allowance for PartialEq'
    fi
}
probe_secret_partial_eq_allowance

probe_ct_eq_missing_git_inputs() {
    local empty output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    empty="$(mktemp -d "${TMPDIR:-/tmp}/gateway-ct-eq-empty.XXXXXX")"
    output="$(GATEWAY_CHECK_ROOT="$empty" "${SCRIPT_DIR}/check_ct_eq.sh" 2>&1)" || rc=$?
    rmdir "$empty"
    if [[ "$rc" -ne 0 && "$output" == *'cannot enumerate Rust source inputs'* ]]; then
        pass_msg 'check_ct_eq.sh fails closed when git source inputs are unavailable'
    else
        fail_msg 'check_ct_eq.sh reported green without git source inputs'
    fi
}
probe_ct_eq_missing_git_inputs

probe_role_verdict_guard_exists() {
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    if [[ -x "${SCRIPT_DIR}/check_role_verdicts.sh" ]]; then
        pass_msg 'check_role_verdicts.sh exists and is executable'
    else
        fail_msg 'check_role_verdicts.sh is missing or not executable'
    fi
}
probe_role_verdict_guard_exists

expect_role_result() {
    local expected="$1" desc="$2" changed="$3" body="$4" changed_diff="${5:-}" diagnostic="${6:-}" rc=0 output
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" \
        GATEWAY_CHANGED_FILES="$changed" \
        GATEWAY_CHANGED_DIFF="$changed_diff" \
        GATEWAY_PR_BODY_JSON="$(json_string "$body")" \
        "${SCRIPT_DIR}/check_role_verdicts.sh" 2>&1)" || rc=$?
    if [[ -n "$diagnostic" && "$output" != *"$diagnostic"* ]]; then
        fail_msg "check_role_verdicts.sh missing diagnostic for: ${desc}"
        return
    fi
    if [[ "$expected" == pass && "$rc" -eq 0 ]]; then
        pass_msg "check_role_verdicts.sh allows: ${desc}"
    elif [[ "$expected" == fail && "$rc" -ne 0 ]]; then
        pass_msg "check_role_verdicts.sh catches: ${desc}"
    else
        fail_msg "check_role_verdicts.sh unexpected result for: ${desc}"
    fi
}

expect_role_result pass 'documentation-only changes without a role section' \
    $'M\tdocs/guide.md' ''
expect_role_result pass 'an ordinary script change with a substantive simplicity verdict' \
    $'M\tscripts/check_example.sh' \
    $'## Role Verdicts\n- simplicity-adversary: scripts/check_example.sh:12 accepts a missing input and can report false green.'
expect_role_result pass 'a types change with both required roles' \
    $'M\tcrates/types/src/lib.rs' \
    $'## Role Verdicts\n- simplicity-adversary: attacked public surface and abstraction count — no break found.\n- protocol-auditor: attacked wire names and optional-field boundaries — no break found.'
expect_role_result pass 'a signature change with its high-risk three-role exception' \
    $'M\tcrates/sig/src/lib.rs' \
    $'## Role Verdicts\n- simplicity-adversary: attacked API surface and abstraction count — no break found.\n- security-adversary: attacked timing and secret exposure paths — no break found.\n- test-adversary: attacked comparison reversion and negative cases — no break found.'
expect_role_result pass 'an HTTP change with its high-risk four-role exception' \
    $'M\tcrates/http/src/lib.rs' \
    $'## Role Verdicts\n- simplicity-adversary: attacked API surface and abstraction count — no break found.\n- security-adversary: attacked parser limits and malformed input — no break found.\n- concurrency-durability: attacked cancellation and partial-read paths — no break found.\n- perf-engineer: attacked allocation and copy boundaries — no break found.'
expect_role_result pass 'a canonical list item ending in the null-report suffix' \
    $'M\tscripts/check_example.sh' \
    $'## Role Verdicts\n- simplicity-adversary: attacked missing inputs and stale PR metadata — no break found'
expect_role_result fail 'a null report without the required list marker' \
    $'M\tscripts/check_example.sh' \
    $'## Role Verdicts\nsimplicity-adversary: attacked missing inputs — no break found' '' \
    '- simplicity-adversary: attacked <specific surfaces> — no break found'
expect_role_result fail 'a null report without the terminal no-break suffix' \
    $'M\tscripts/check_example.sh' \
    $'## Role Verdicts\n- simplicity-adversary: attacked missing inputs' '' \
    '- simplicity-adversary: attacked <specific surfaces> — no break found'
expect_role_result fail 'a null report with prose after the terminal suffix' \
    $'M\tscripts/check_example.sh' \
    $'## Role Verdicts\n- simplicity-adversary: attacked missing inputs — no break found after review' '' \
    'The suffix must end the null report'
expect_role_result fail 'a missing role section explains stale workflow event metadata' \
    $'M\tscripts/check_example.sh' '' '' \
    'Re-running an old workflow uses its original PR event payload'
expect_role_result fail 'a missing required security verdict' \
    $'M\tcrates/sig/src/lib.rs' \
    $'## Role Verdicts\n- simplicity-adversary: attacked API surface and abstraction count — no break found.\n- test-adversary: attacked comparison reversion and negative cases — no break found.'
expect_role_result fail 'a bare pass presented as a verdict' \
    $'M\tscripts/check_example.sh' \
    $'## Role Verdicts\n- simplicity-adversary: pass'
expect_role_result fail 'a one-word pass synonym presented as a verdict' \
    $'M\tscripts/check_example.sh' \
    $'## Role Verdicts\n- simplicity-adversary: passed'
expect_role_result fail 'two-word approval prose presented as a verdict' \
    $'M\tscripts/check_example.sh' \
    $'## Role Verdicts\n- simplicity-adversary: looks good'
expect_role_result fail 'a role section hidden in an HTML comment' \
    $'M\tscripts/check_example.sh' \
    $'<!--\n## Role Verdicts\n- simplicity-adversary: attacked the input boundary.\n-->'
expect_role_result fail 'a role section hidden in a fenced block' \
    $'M\tscripts/check_example.sh' \
    $'```markdown\n## Role Verdicts\n- simplicity-adversary: attacked the input boundary.\n```'
expect_role_result fail 'a role section hidden by a backtick fence whose info starts with tilde' \
    $'M\tscripts/check_example.sh' \
    $'```~markdown\n## Role Verdicts\n- simplicity-adversary: attacked the input boundary.\n```'
expect_role_result fail 'a role heading hidden in an indented code block' \
    $'M\tscripts/check_example.sh' \
    $'    ## Role Verdicts\n- simplicity-adversary: attacked the input boundary.'
expect_role_result fail 'a role heading hidden in a raw HTML block' \
    $'M\tscripts/check_example.sh' \
    $'<pre>\n## Role Verdicts\n- simplicity-adversary: attacked the input boundary.\n</pre>'
expect_role_result fail 'duplicate visible role sections' \
    $'M\tscripts/check_example.sh' \
    $'## Role Verdicts\n- simplicity-adversary: attacked the input boundary — no break found.\n## Role Verdicts\n- simplicity-adversary: attacked the error boundary — no break found.'
expect_role_result fail 'duplicate verdict lines for one role' \
    $'M\tscripts/check_example.sh' \
    $'## Role Verdicts\n- simplicity-adversary: attacked the input boundary — no break found.\n- simplicity-adversary: attacked the error boundary — no break found.'
expect_role_result fail 'a rename into signature code without its path roles' \
    $'R100\tcrates/core/src/old.rs\tcrates/sig/src/new.rs' \
    $'## Role Verdicts\n- simplicity-adversary: attacked rename path selection — no break found.'
expect_role_result fail 'a hidden HIGH-RISK marker authorizing four roles' \
    $'M\tcrates/types/src/lib.rs\nA\tconformance/cases/example.toml\nM\tcrates/core/src/lib.rs' \
    $'<!-- HIGH-RISK -->\n## Role Verdicts\n- simplicity-adversary: attacked the surface — no break found.\n- protocol-auditor: attacked the protocol — no break found.\n- security-adversary: attacked the trust boundary — no break found.\n- test-adversary: attacked the case — no break found.'

probe_role_verdict_missing_inputs() {
    local rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    GATEWAY_CHECK_ROOT="$REPO_ROOT" GATEWAY_PR_BODY_JSON='""' \
        "${SCRIPT_DIR}/check_role_verdicts.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        pass_msg 'check_role_verdicts.sh fails closed without changed-file inputs'
    else
        fail_msg 'check_role_verdicts.sh reported green without changed-file inputs'
    fi
}
probe_role_verdict_missing_inputs

# rustfs/gateway#224. The pull-request body is exported JSON-encoded so that no line of it
# starts a CI log line, where the runner would read a leading `::` as a workflow command.
# Both consumers refuse anything that still carries a raw newline, because a raw newline
# means the encoding did not happen and the body may already have forged or suppressed an
# annotation before the guard ever ran. The other direction -- that a well-formed
# single-line body is accepted -- is every passing expect_role_result case above.
probe_pr_body_multiline_is_refused() {
    local guard="$1" output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" \
        GATEWAY_CHANGED_FILES=$'M\tscripts/check_example.sh' \
        GATEWAY_PROTECTED_BASE=HEAD^ GATEWAY_PROTECTED_HEAD=HEAD \
        GATEWAY_ROLE_BASE=HEAD^ GATEWAY_ROLE_HEAD=HEAD \
        GATEWAY_PR_BODY_JSON=$'"## Role Verdicts"\n::warning::forged finding' \
        "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 && "$output" == *'must be a single-line JSON string'* ]]; then
        pass_msg "${guard} refuses a pull-request body that was never JSON-encoded"
    else
        fail_msg "${guard} accepted a multi-line GATEWAY_PR_BODY_JSON"
    fi
}
probe_pr_body_multiline_is_refused check_role_verdicts.sh
probe_pr_body_multiline_is_refused check_protected_files.sh

probe_pr_body_non_json_is_refused() {
    local guard="$1" output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" \
        GATEWAY_CHANGED_FILES=$'M\tscripts/check_example.sh' \
        GATEWAY_PROTECTED_BASE=HEAD^ GATEWAY_PROTECTED_HEAD=HEAD \
        GATEWAY_ROLE_BASE=HEAD^ GATEWAY_ROLE_HEAD=HEAD \
        GATEWAY_PR_BODY_JSON='## Role Verdicts - simplicity-adversary: attacked it - no break found.' \
        "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 && "$output" == *'is not JSON'* ]]; then
        pass_msg "${guard} refuses a single-line body that was never JSON-encoded"
    else
        fail_msg "${guard} accepted a GATEWAY_PR_BODY_JSON that is not JSON"
    fi
}
probe_pr_body_non_json_is_refused check_role_verdicts.sh
probe_pr_body_non_json_is_refused check_protected_files.sh

probe_role_verdict_table_drift() {
    local sandbox rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    sed -i.bak 's/at most 60k tokens per PR/at most 61k tokens per PR/' "${sandbox}/AGENTS.md"
    rm -f "${sandbox}/AGENTS.md.bak"
    GATEWAY_CHECK_ROOT="$sandbox" \
        GATEWAY_CHANGED_FILES=$'M\tscripts/check_example.sh' \
        GATEWAY_PR_BODY_JSON="$(json_string $'## Role Verdicts\n- simplicity-adversary: attacked the input boundary — no break found.')" \
        "${SCRIPT_DIR}/check_role_verdicts.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        pass_msg 'check_role_verdicts.sh catches AGENTS.md trigger-table drift'
    else
        fail_msg 'check_role_verdicts.sh accepted AGENTS.md trigger-table drift'
    fi
}
probe_role_verdict_table_drift

# -----------------------------------------------------------------------------
# Role selection reads the merge base, not the base branch tip.
#
# GATEWAY_ROLE_BASE is `github.event.pull_request.base.sha`, which tracks `main` live and
# therefore moves under an open pull request every time anything else merges. These three
# cases share one repository shape: a common commit, a branch that touches `scripts/`
# only, and a base branch that has since moved on with a commit under `crates/core/`.
# A two-dot diff between the two tips reports that `crates/core/` file as changed and
# demands `security-adversary` from an author who never touched it.
# -----------------------------------------------------------------------------
build_role_base_moved_repo() {
    local repo="$1" branch_touches_core="$2"
    mkdir -p "${repo}/scripts" "${repo}/crates/core/src"
    cp "${REPO_ROOT}/AGENTS.md" "${repo}/AGENTS.md"
    printf 'echo shared\n' >"${repo}/scripts/keep.sh"
    printf 'pub fn resolution() {}\n' >"${repo}/crates/core/src/thing.rs"
    (
        cd "$repo"
        git init -q .
        git add -A
        git -c user.name=t -c user.email=t@t commit -qm common
    )
    ROLE_MERGE_BASE="$(git -C "$repo" rev-parse HEAD)"
    # The branch under review.
    printf 'echo branch\n' >>"${repo}/scripts/keep.sh"
    if [[ "$branch_touches_core" == core ]]; then
        printf 'pub fn owned_by_the_branch() {}\n' >"${repo}/crates/core/src/branch_owned.rs"
    fi
    (
        cd "$repo"
        git add -A
        git -c user.name=t -c user.email=t@t commit -qm branch
    )
    ROLE_HEAD_SHA="$(git -C "$repo" rev-parse HEAD)"
    # The base branch, moving on without the branch under review.
    (
        cd "$repo"
        git checkout -q "$ROLE_MERGE_BASE"
        printf 'pub fn landed_after_the_branch_was_cut() {}\n' >>crates/core/src/thing.rs
        git add -A
        git -c user.name=t -c user.email=t@t commit -qm "base branch moved"
    )
    ROLE_BASE_SHA="$(git -C "$repo" rev-parse HEAD)"
}

ROLE_SIMPLICITY_ONLY_BODY=$'## Role Verdicts\n- simplicity-adversary: attacked the changed scripts — no break found.'

probe_role_verdict_ignores_base_branch_commits() {
    local repo rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-role-base-moved.XXXXXX")"
    build_role_base_moved_repo "$repo" scripts
    GATEWAY_CHECK_ROOT="$repo" \
        GATEWAY_ROLE_BASE="$ROLE_BASE_SHA" \
        GATEWAY_ROLE_HEAD="$ROLE_HEAD_SHA" \
        GATEWAY_PR_BODY_JSON="$(json_string "$ROLE_SIMPLICITY_ONLY_BODY")" \
        "${SCRIPT_DIR}/check_role_verdicts.sh" >/dev/null 2>&1 || rc=$?
    rm -rf "$repo"
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_role_verdicts.sh ignores a commit that landed on the base branch after the branch was cut'
    else
        fail_msg 'check_role_verdicts.sh demanded a role for a file only the base branch changed'
    fi
}
probe_role_verdict_ignores_base_branch_commits

probe_role_verdict_still_sees_branch_paths() {
    local repo rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-role-branch-core.XXXXXX")"
    build_role_base_moved_repo "$repo" core
    GATEWAY_CHECK_ROOT="$repo" \
        GATEWAY_ROLE_BASE="$ROLE_BASE_SHA" \
        GATEWAY_ROLE_HEAD="$ROLE_HEAD_SHA" \
        GATEWAY_PR_BODY_JSON="$(json_string "$ROLE_SIMPLICITY_ONLY_BODY")" \
        "${SCRIPT_DIR}/check_role_verdicts.sh" >/dev/null 2>&1 || rc=$?
    rm -rf "$repo"
    if [[ "$rc" -ne 0 ]]; then
        pass_msg 'check_role_verdicts.sh still demands a role for a path the branch itself changed'
    else
        fail_msg 'check_role_verdicts.sh missed a crates/core path the branch itself changed'
    fi
}
probe_role_verdict_still_sees_branch_paths

mut_role_verdict_two_dot_diff() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
old = '    role_base = os.fsdecode(git("merge-base", base, head)).strip()'
if text.count(old) != 1:
    raise SystemExit("missing the merge-base resolution")
path.write_text(text.replace(old, "    role_base = base", 1))
PY
}

probe_role_verdict_two_dot_diff_is_caught() {
    local repo mutated rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-role-two-dot.XXXXXX")"
    mutated="$(mktemp -d "${TMPDIR:-/tmp}/gateway-role-two-dot-guard.XXXXXX")"
    build_role_base_moved_repo "$repo" scripts
    cp "${SCRIPT_DIR}/check_role_verdicts.sh" "${mutated}/check_role_verdicts.sh"
    mut_role_verdict_two_dot_diff "${mutated}/check_role_verdicts.sh"
    GATEWAY_CHECK_ROOT="$repo" \
        GATEWAY_ROLE_BASE="$ROLE_BASE_SHA" \
        GATEWAY_ROLE_HEAD="$ROLE_HEAD_SHA" \
        GATEWAY_PR_BODY_JSON="$(json_string "$ROLE_SIMPLICITY_ONLY_BODY")" \
        bash "${mutated}/check_role_verdicts.sh" >/dev/null 2>&1 || rc=$?
    rm -rf "$repo" "$mutated"
    if [[ "$rc" -ne 0 ]]; then
        pass_msg 'the two-dot diff restored in check_role_verdicts.sh demands a role for somebody else'"'"'s commit'
    else
        fail_msg 'restoring the two-dot diff changed nothing, so the merge-base case cannot fail'
    fi
}
probe_role_verdict_two_dot_diff_is_caught


probe_compat_role_required() {
    local repo base head rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-role-compat.XXXXXX")"
    mkdir -p "${repo}/crates/types"
    cp "${REPO_ROOT}/AGENTS.md" "${repo}/AGENTS.md"
    printf '[features]\ndefault = []\n' >"${repo}/crates/types/Cargo.toml"
    (
        cd "$repo"
        git init -q .
        git add -A
        git -c user.name=t -c user.email=t@t commit -qm base
    )
    base="$(git -C "$repo" rev-parse HEAD)"
    printf 'compat-s3s = []\n' >>"${repo}/crates/types/Cargo.toml"
    (
        cd "$repo"
        git add -A
        git -c user.name=t -c user.email=t@t commit -qm compat
    )
    head="$(git -C "$repo" rev-parse HEAD)"
    GATEWAY_CHECK_ROOT="$repo" \
        GATEWAY_ROLE_BASE="$base" \
        GATEWAY_ROLE_HEAD="$head" \
        GATEWAY_PR_BODY_JSON="$(json_string $'## Role Verdicts\n- simplicity-adversary: attacked the compatibility surface — no break found.')" \
        "${SCRIPT_DIR}/check_role_verdicts.sh" >/dev/null 2>&1 || rc=$?
    rm -rf "$repo"
    if [[ "$rc" -ne 0 ]]; then
        pass_msg 'check_role_verdicts.sh requires migration safety when compat-s3s changes'
    else
        fail_msg 'check_role_verdicts.sh missed a compat-s3s change'
    fi
}
probe_compat_role_required

probe_compat_source_role_required() {
    local repo base head rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-role-compat-source.XXXXXX")"
    mkdir -p "${repo}/crates/types/src"
    cp "${REPO_ROOT}/AGENTS.md" "${repo}/AGENTS.md"
    printf 'pub fn ordinary() {}\n' >"${repo}/crates/types/src/lib.rs"
    (
        cd "$repo"
        git init -q .
        git add -A
        git -c user.name=t -c user.email=t@t commit -qm base
    )
    base="$(git -C "$repo" rev-parse HEAD)"
    printf '#[cfg(feature = "compat-s3s")]\npub fn compatibility() {}\n' \
        >>"${repo}/crates/types/src/lib.rs"
    (
        cd "$repo"
        git add -A
        git -c user.name=t -c user.email=t@t commit -qm compat-source
    )
    head="$(git -C "$repo" rev-parse HEAD)"
    GATEWAY_CHECK_ROOT="$repo" \
        GATEWAY_ROLE_BASE="$base" \
        GATEWAY_ROLE_HEAD="$head" \
        GATEWAY_PR_BODY_JSON="$(json_string $'## Role Verdicts\n- simplicity-adversary: attacked the compatibility surface — no break found.\n- protocol-auditor: attacked the wire contract — no break found.')" \
        "${SCRIPT_DIR}/check_role_verdicts.sh" >/dev/null 2>&1 || rc=$?
    rm -rf "$repo"
    if [[ "$rc" -ne 0 ]]; then
        pass_msg 'check_role_verdicts.sh requires migration safety for compat-s3s source cfg changes'
    else
        fail_msg 'check_role_verdicts.sh missed a compat-s3s source cfg change'
    fi
}
probe_compat_source_role_required

probe_existing_compat_body_role_required() {
    local repo base head rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-role-compat-body.XXXXXX")"
    mkdir -p "${repo}/crates/types/src"
    cp "${REPO_ROOT}/AGENTS.md" "${repo}/AGENTS.md"
    printf '#[cfg(feature = "compat-s3s")]\npub fn adapter() { old(); }\n' \
        >"${repo}/crates/types/src/lib.rs"
    (
        cd "$repo"
        git init -q .
        git add -A
        git -c user.name=t -c user.email=t@t commit -qm base
    )
    base="$(git -C "$repo" rev-parse HEAD)"
    sed -i.bak 's/old()/new()/' "${repo}/crates/types/src/lib.rs"
    rm -f "${repo}/crates/types/src/lib.rs.bak"
    (
        cd "$repo"
        git add -A
        git -c user.name=t -c user.email=t@t commit -qm compat-body
    )
    head="$(git -C "$repo" rev-parse HEAD)"
    GATEWAY_CHECK_ROOT="$repo" \
        GATEWAY_ROLE_BASE="$base" \
        GATEWAY_ROLE_HEAD="$head" \
        GATEWAY_PR_BODY_JSON="$(json_string $'## Role Verdicts\n- simplicity-adversary: attacked the compatibility surface — no break found.\n- protocol-auditor: attacked the wire contract — no break found.')" \
        "${SCRIPT_DIR}/check_role_verdicts.sh" >/dev/null 2>&1 || rc=$?
    rm -rf "$repo"
    if [[ "$rc" -ne 0 ]]; then
        pass_msg 'check_role_verdicts.sh requires migration safety when an existing compat item body changes'
    else
        fail_msg 'check_role_verdicts.sh missed a body-only change inside an existing compat item'
    fi
}
probe_existing_compat_body_role_required

# P2-01 case coverage. Each failure mode has an independent mutation: a mapping can disappear,
# lie about its polarity, point nowhere, name no case, point at no executable assertion, lose its
# golden, reuse another fixture, or stop being wired into trybuild.
mut_sig_case_mapping_deleted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_sig_case_coverage.sh")
text = path.read_text()
line = "    'c-sig-0025|negative|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0025_non_canonical_base64_is_rejected'\n"
if line not in text:
    raise SystemExit("missing mapping mutation subject")
path.write_text(text.replace(line, "", 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'one of the 25 acceptance mappings being deleted' mut_sig_case_mapping_deleted

mut_sig_case_order_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_sig_case_coverage.sh")
text = path.read_text()
first = "    'c-sig-0001|positive|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0001_empty_is_not_framed'"
second = "    'c-sig-0002|positive|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0002_hex_digest_keeps_its_signed_spelling'"
if first not in text or second not in text:
    raise SystemExit("missing order mutation subject")
text = text.replace(first, "__FIRST__", 1).replace(second, first, 1).replace("__FIRST__", second, 1)
path.write_text(text)
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'the acceptance mappings being reordered' mut_sig_case_order_changed

mut_sig_case_polarity_unknown() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_sig_case_coverage.sh")
text = path.read_text()
old = "c-sig-0008|positive|"
if old not in text:
    raise SystemExit("missing polarity mutation subject")
path.write_text(text.replace(old, "c-sig-0008|unknown|", 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'a case mapping using an unknown polarity' mut_sig_case_polarity_unknown

mut_sig_case_polarity_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_sig_case_coverage.sh")
text = path.read_text()
old = "c-sig-0008|positive|"
if old not in text:
    raise SystemExit("missing polarity mutation subject")
path.write_text(text.replace(old, "c-sig-0008|negative|", 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'the required 8 positive and 17 negative split changing' mut_sig_case_polarity_changed

mut_sig_case_file_missing() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_sig_case_coverage.sh")
text = path.read_text()
old = "crates/sig/tests/frozen_dimensions.rs|fn c_sig_0025"
if old not in text:
    raise SystemExit("missing file mutation subject")
path.write_text(text.replace(old, "crates/sig/tests/missing.rs|fn c_sig_0025", 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'a case mapping pointing to a missing file' mut_sig_case_file_missing

mut_sig_case_id_missing() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/frozen_dimensions.rs")
text = path.read_text()
if "c-sig-0025" not in text:
    raise SystemExit("missing id mutation subject")
path.write_text(text.replace("c-sig-0025", "removed-sig-0025"))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a mapped file no longer naming its acceptance id' mut_sig_case_id_missing

mut_sig_case_evidence_missing() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/frozen_dimensions.rs")
text = path.read_text()
old = "fn c_sig_0025_non_canonical_base64_is_rejected"
if old not in text:
    raise SystemExit("missing evidence mutation subject")
path.write_text(text.replace(old, "fn removed_sig_0025_non_canonical_base64_is_rejected", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a mapping no longer reaching its named executable assertion' mut_sig_case_evidence_missing

mut_sig_runtime_line_comment_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/frozen_dimensions.rs")
text = path.read_text()
old = "#[test]\nfn c_sig_0025_non_canonical_base64_is_rejected()"
new = "// #[test]\n// fn c_sig_0025_non_canonical_base64_is_rejected()\nfn removed_sig_0025_non_canonical_base64_is_rejected()"
if old not in text:
    raise SystemExit("missing line-comment decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a commented-out #[test] and function being used as runtime evidence' mut_sig_runtime_line_comment_decoy

mut_sig_runtime_string_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/frozen_dimensions.rs")
text = path.read_text()
old = "#[test]\nfn c_sig_0025_non_canonical_base64_is_rejected()"
new = 'const DECOY: &str = "#[test]\nfn c_sig_0025_non_canonical_base64_is_rejected(";\n#[test]\nfn removed_sig_0025_non_canonical_base64_is_rejected()'
if old not in text:
    raise SystemExit("missing runtime string decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a string containing #[test] and a function name being used as runtime evidence' mut_sig_runtime_string_decoy

mut_sig_runtime_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/frozen_dimensions.rs")
text = path.read_text()
old = "#[test]\nfn c_sig_0025_non_canonical_base64_is_rejected()"
new = "#[cfg(\n    any()\n)]\n#[test]\nfn c_sig_0025_non_canonical_base64_is_rejected()"
if old not in text:
    raise SystemExit("missing disabled test mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a multiline cfg-disabled #[test] being counted as executable evidence' mut_sig_runtime_disabled_by_cfg

mut_sig_runtime_macro_body_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/frozen_dimensions.rs")
text = path.read_text()
old = "#[test]\nfn c_sig_0025_non_canonical_base64_is_rejected()"
new = """macro_rules! fake_test {
    () => {
        #[test]
        fn c_sig_0025_non_canonical_base64_is_rejected() {}
    };
}
#[test]
fn removed_sig_0025_non_canonical_base64_is_rejected()"""
if old not in text:
    raise SystemExit("missing runtime macro decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a #[test] function inside a macro body being accepted as runtime evidence' mut_sig_runtime_macro_body_decoy

mut_sig_compile_fixture_not_executable() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
text = path.read_text()
old = "fn main()"
if old not in text:
    raise SystemExit("missing executable mutation subject")
path.write_text(text.replace(old, "fn removed_main()", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a compile-fail fixture losing its executable entry' mut_sig_compile_fixture_not_executable

mut_sig_compile_block_comment_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
text = path.read_text()
old = "fn main()"
new = "fn removed_main()\n/* fn main() {} */"
if old not in text:
    raise SystemExit("missing block-comment decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a block-comment fn main decoy being accepted as executable evidence' mut_sig_compile_block_comment_decoy

mut_sig_compile_string_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
text = path.read_text()
old = "fn main()"
new = 'const DECOY: &str = "fn main()";\nfn removed_main()'
if old not in text:
    raise SystemExit("missing compile string decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a string containing fn main being accepted as an entry point' mut_sig_compile_string_decoy

mut_sig_compile_main_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
text = path.read_text()
old = "fn main()"
new = "#[cfg(\n    any()\n)]\nfn main()"
if old not in text:
    raise SystemExit("missing disabled main mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a multiline cfg-disabled fn main being counted as an executable fixture' mut_sig_compile_main_disabled_by_cfg

mut_sig_compile_macro_body_main_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
text = path.read_text()
old = "fn main()"
new = """macro_rules! fake_main {
    () => { fn main() {} };
}
fn removed_main()"""
if old not in text:
    raise SystemExit("missing compile macro decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a fn main inside a macro body being accepted as an entry point' mut_sig_compile_macro_body_main_decoy

mut_sig_compile_evidence_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
text = path.read_text()
old = "    let _ = left == right;"
new = "    #[cfg(\n        any()\n    )]\n    let _ = left == right;"
if old not in text:
    raise SystemExit("missing disabled evidence mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'mapped compile evidence being disabled inside an active main' mut_sig_compile_evidence_disabled_by_cfg

mut_sig_serialize_evidence_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.rs")
text = path.read_text()
old = "    let _ = serde_json::to_string(&token);"
new = "    #[cfg(\n        any()\n    )]\n    let _ = serde_json::to_string(&token);"
if old not in text:
    raise SystemExit("missing disabled serialization evidence mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0018 evidence being disabled at its statement boundary' mut_sig_serialize_evidence_disabled_by_cfg

mut_sig_family_evidence_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0019_sig_family_exhaustive.rs")
text = path.read_text()
old = "    let _ = match family {"
new = "    #[cfg(\n        any()\n    )]\n    let _ = match family {"
if old not in text:
    raise SystemExit("missing disabled family evidence mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0019 evidence being disabled at its statement boundary' mut_sig_family_evidence_disabled_by_cfg

# P3-01 raw-request boundary (rustfs/backlog#1689). The three ways to undo the type boundary are to
# return the raw head, accept it by reference so it survives, or reconstruct it downstream.
mut_wire_boundary_raw_accessor() {
    cat >>crates/http/src/wire.rs <<'RUST'

pub fn raw_headers(request: &WireRequest<()>) -> &http::HeaderMap {
    &request.headers
}
RUST
}
expect_fail check_wire_boundary.sh \
    'the wire layer returning its raw HeaderMap through a public accessor' \
    mut_wire_boundary_raw_accessor \
    'public API returns a raw request capability'

mut_wire_boundary_borrowed_accept() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/src/wire.rs")
text = path.read_text()
old = "pub fn accept(request: Request<B>, limits: &Limits) -> Result<Self, WireReject>"
new = "pub fn accept(request: &mut Request<B>, limits: &Limits) -> Result<Self, WireReject>"
if text.count(old) != 1:
    raise SystemExit("wire accept mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_wire_boundary.sh \
    'WireRequest acceptance borrowing the raw request instead of consuming it' \
    mut_wire_boundary_borrowed_accept \
    'no longer consumes exactly one Request<B> by value'

mut_wire_boundary_downstream_request() {
    cat >>crates/core/src/lib.rs <<'RUST'

fn bypass_wire_acceptance(request: http::Request<()>) {
    let _ = request;
}
RUST
}
expect_fail check_wire_boundary.sh \
    'core production code regaining a raw http::Request' \
    mut_wire_boundary_downstream_request \
    'downstream production code regains a raw request'

# P3-01 wire case coverage (rustfs/backlog#1689). Three failure modes, one mutation each: a mapping
# can be deleted, it can point at a function nobody wrote, and the assertion it points at can be
# replaced by something that reads like an assertion and cannot fail.
mut_wire_case_mapping_deleted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_wire_case_coverage.sh")
text = path.read_text()
line = next((line for line in text.splitlines(True) if line.lstrip().startswith("'c-wire-0021|")), None)
if line is None:
    raise SystemExit("missing wire mapping mutation subject")
path.write_text(text.replace(line, "", 1))
PYEOF
}
expect_fail_self_mutation check_wire_case_coverage.sh \
    'one of the 39 wire acceptance mappings being deleted' mut_wire_case_mapping_deleted

mut_wire_case_function_missing() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_wire_case_coverage.sh")
text = path.read_text()
old = "c_wire_0021_repeated_transfer_encoding_is_rejected"
if old not in text:
    raise SystemExit("missing wire function mutation subject")
path.write_text(text.replace(old, "c_wire_0021_a_function_nobody_wrote", 1))
PYEOF
}
expect_fail_self_mutation check_wire_case_coverage.sh \
    'a wire mapping naming a function that does not exist' mut_wire_case_function_missing

mut_wire_case_assertion_is_a_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/framing_smuggling.rs")
text = path.read_text()
old = "    assert_eq!(reject, WireReject::TransferEncodingMalformed);\n}"
new = (
    "    // assert_eq!(reject, WireReject::TransferEncodingMalformed);\n"
    '    let decoy = "assert_eq!(reject, WireReject::TransferEncodingMalformed);";\n'
    "    let _ = (reject, decoy);\n}"
)
if old not in text:
    raise SystemExit("missing wire decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_wire_case_coverage.sh \
    'a commented-out assertion and a string of it standing in for wire evidence' mut_wire_case_assertion_is_a_decoy

# P3-03 ingest case coverage (rustfs/backlog#1691). Four failure modes, one mutation each: a
# mapping can be deleted, it can point at a function nobody wrote, the assertion it points at can
# be replaced by something that reads like an assertion and cannot fail, and the hardware gate can
# stop rejecting crc-fast's software fallback.
mut_ingest_case_mapping_deleted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_ingest_case_coverage.sh")
text = path.read_text()
line = next((line for line in text.splitlines(True) if line.lstrip().startswith("'c-ing-0021|")), None)
if line is None:
    raise SystemExit("missing ingest mapping mutation subject")
path.write_text(text.replace(line, "", 1))
PYEOF
}
expect_fail_self_mutation check_ingest_case_coverage.sh \
    'one of the 40 ingest acceptance mappings being deleted' mut_ingest_case_mapping_deleted

mut_ingest_case_function_missing() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_ingest_case_coverage.sh")
text = path.read_text()
old = "c_ing_0021_a_four_gigabyte_chunk_is_refused_at_the_header_without_reading_a_data_byte"
if old not in text:
    raise SystemExit("missing ingest function mutation subject")
path.write_text(text.replace(old, "c_ing_0021_a_function_nobody_wrote", 1))
PYEOF
}
expect_fail_self_mutation check_ingest_case_coverage.sh \
    'an ingest mapping naming a function that does not exist' mut_ingest_case_function_missing

mut_gzip_raw_limit_identity_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/gate_tests.rs")
text = path.read_text()
old = "c_ing_0044_c_lim_0027_gzip_wire_bytes_set_the_body_ceiling"
new = "c_ing_0044_gzip_wire_bytes_set_the_body_ceiling"
if text.count(old) != 1:
    raise SystemExit("missing or ambiguous c-lim-0027 identity mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_ingest_case_coverage.sh \
    'c-lim-0027 losing its shared executable identity' mut_gzip_raw_limit_identity_removed

mut_ingest_hardware_fallback_gate_dropped() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_perf_gates.rs")
text = path.read_text()
old = '    assert_ne!(\n        target, "software-fallback-tables",\n'
new = '    assert_eq!(\n        target, "software-fallback-tables",\n'
if text.count(old) != 1:
    raise SystemExit("missing or ambiguous ingest hardware-gate mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_ingest_case_coverage.sh \
    'the CRC32C gate accepting crc-fast software fallback' mut_ingest_hardware_fallback_gate_dropped

mut_ingest_case_assertion_is_a_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_perf_gates.rs")
text = path.read_text()
old = '    assert!(pipeline.window_bytes() <= 64 * 1024, "a 16 MiB ceiling must not mean a 16 MiB allocation");\n'
new = (
    '    // assert!(pipeline.window_bytes() <= 64 * 1024, "a 16 MiB ceiling ...");\n'
    '    let decoy = "assert!(pipeline.window_bytes() <= 64 * 1024);";\n'
    "    let _ = (pipeline, decoy);\n"
)
if text.count(old) != 1:
    raise SystemExit("missing or ambiguous ingest decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_ingest_case_coverage.sh \
    'a commented-out assertion and a string of it standing in for ingest evidence' mut_ingest_case_assertion_is_a_decoy

mut_sig_compile_char_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
guard = Path("scripts/check_sig_case_coverage.sh")
guard_text = guard.read_text()
old = "c-sig-0014|negative|crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs|let _ = left == right;"
new = "c-sig-0014|negative|crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs|u{10FFFD}"
if old not in guard_text:
    raise SystemExit("missing char-decoy mapping mutation subject")
guard.write_text(guard_text.replace(old, new, 1))

fixture = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
fixture_text = fixture.read_text()
old = "    let _ = left == right;"
new = "    let _ = (left, right);\n    const DECOY: char = '\\u{10FFFD}';\n    let _ = DECOY;"
if old not in fixture_text:
    raise SystemExit("missing char-decoy fixture mutation subject")
fixture.write_text(fixture_text.replace(old, new, 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'a character literal being accepted as compile evidence' mut_sig_compile_char_decoy

mut_sig_compile_golden_missing() {
    rm crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.stderr
}
expect_fail check_sig_case_coverage.sh \
    'a compile-fail fixture losing its stderr golden' mut_sig_compile_golden_missing

mut_sig_compile_golden_hollow() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.stderr")
text = path.read_text()
if "error[E" not in text:
    raise SystemExit("missing diagnostic mutation subject")
path.write_text(text.replace("error[E", "diagnostic[E", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a compile-fail golden containing no rustc error' mut_sig_compile_golden_hollow

mut_sig_compile_golden_unrelated_error() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.stderr")
path.write_text("error[E0425]: cannot find value `unrelated` in this scope\n")
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a compile-fail golden retaining only an unrelated rustc error' mut_sig_compile_golden_unrelated_error

mut_sig_compile_evidence_not_independent() {
    python3 - <<'PYEOF'
from pathlib import Path
guard = Path("scripts/check_sig_case_coverage.sh")
text = guard.read_text()
old = "c-sig-0014|negative|crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs|let _ = left == right;"
new = "c-sig-0014|negative|crates/sig/tests/frozen_dimensions.rs|fn secret_bearing_types_derive_nothing_that_compares_or_prints"
if old not in text:
    raise SystemExit("missing independence mutation subject")
guard.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'one compile-time case being replaced by an unrelated runtime source guard' mut_sig_compile_evidence_not_independent

mut_sig_compile_fixture_reused() {
    python3 - <<'PYEOF'
from pathlib import Path
guard = Path("scripts/check_sig_case_coverage.sh")
text = guard.read_text()
old = "c-sig-0015|negative|crates/sig/tests/compile_fail/c_sig_0015_ctbytes_debug.rs|println!"
new = "c-sig-0015|negative|crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs|println!"
if old not in text:
    raise SystemExit("missing distinct-fixture mutation subject")
guard.write_text(text.replace(old, new, 1))
fixture = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
fixture_text = fixture.read_text()
old_fixture = "    let _ = left == right;"
new_fixture = "    let _ = left == right;\n    let bytes = left;\n    println!(\"{bytes:?}\");"
if old_fixture not in fixture_text:
    raise SystemExit("missing fixture reuse insertion point")
fixture.write_text(fixture_text.replace(old_fixture, new_fixture, 1) + "\n// c-sig-0015\n")
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'two compile-time cases reusing one fixture' mut_sig_compile_fixture_reused

mut_sig_trybuild_dependency_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/Cargo.toml")
text = path.read_text()
old = "trybuild = { workspace = true }\n"
if old not in text:
    raise SystemExit("missing dependency mutation subject")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the sig crate dropping its trybuild dependency' mut_sig_trybuild_dependency_removed

mut_sig_trybuild_harness_removed() {
    rm crates/sig/tests/compile_fail.rs
}
expect_fail check_sig_case_coverage.sh \
    'the independent compile-fail harness being deleted' mut_sig_trybuild_harness_removed

mut_sig_trybuild_harness_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail.rs")
text = path.read_text()
old = "#[test]\nfn p2_01_compile_time_boundaries_are_not_openable()"
new = "#[cfg(\n    any()\n)]\n#[test]\nfn p2_01_compile_time_boundaries_are_not_openable()"
if old not in text:
    raise SystemExit("missing disabled harness mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a multiline cfg-disabled sig trybuild harness being counted as active' mut_sig_trybuild_harness_disabled

mut_sig_trybuild_call_outside_test() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail.rs")
text = path.read_text()
old = '''    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/c_sig_001[4-79]_*.rs");'''
new = '''    run_cases();
}

fn run_cases() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/c_sig_001[4-79]_*.rs");'''
if old not in text:
    raise SystemExit("missing harness body mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the sig compile_fail call moving outside its active test body' mut_sig_trybuild_call_outside_test

mut_sig_trybuild_glob_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail.rs")
text = path.read_text()
old = 'cases.compile_fail("tests/compile_fail/c_sig_001[4-79]_*.rs")'
if old not in text:
    raise SystemExit("missing harness mutation subject")
path.write_text(text.replace(old, 'cases.compile_fail("tests/compile_fail/never_*.rs")', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the harness no longer executing the P2-01 fixtures' mut_sig_trybuild_glob_removed

mut_sig_manifest_gains_serde() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/Cargo.toml")
text = path.read_text()
marker = "[dev-dependencies]\n"
if marker not in text:
    raise SystemExit("missing sig manifest mutation subject")
path.write_text(text.replace(marker, "serde = { workspace = true }\n\n" + marker, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the sig production manifest gaining serde' mut_sig_manifest_gains_serde

mut_sig_manifest_gains_renamed_serde() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/Cargo.toml")
text = path.read_text()
marker = "[dev-dependencies]\n"
if marker not in text:
    raise SystemExit("missing renamed serde mutation subject")
dependency = 'hidden_codec = { package = "serde", version = "1" }\n\n'
path.write_text(text.replace(marker, dependency + marker, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the sig manifest hiding serde behind a renamed dependency' mut_sig_manifest_gains_renamed_serde

mut_sig_target_manifest_gains_renamed_serde() {
    python3 - <<'PYEOF'
from pathlib import Path

manifest = Path("crates/sig/Cargo.toml")
manifest.write_text(manifest.read_text() + '''
[target.'cfg(target_os = "none")'.dependencies]
hidden_codec = { package = "serde", version = "1" }
''')
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a target-specific sig dependency hiding serde behind a rename' mut_sig_target_manifest_gains_renamed_serde

mut_sig_manifest_inherits_renamed_serde() {
    python3 - <<'PYEOF'
from pathlib import Path

workspace = Path("Cargo.toml")
workspace_text = workspace.read_text()
marker = "[workspace.dependencies]\n"
if marker not in workspace_text:
    raise SystemExit("missing workspace dependency mutation subject")
workspace.write_text(workspace_text.replace(
    marker,
    marker + 'hidden_codec = { package = "serde", version = "1" }\n',
    1,
))

manifest = Path("crates/sig/Cargo.toml")
manifest_text = manifest.read_text()
marker = "[dev-dependencies]\n"
if marker not in manifest_text:
    raise SystemExit("missing inherited serde mutation subject")
manifest.write_text(manifest_text.replace(
    marker,
    'hidden_codec = { workspace = true }\n\n' + marker,
    1,
))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the sig manifest inheriting a workspace-renamed serde dependency' mut_sig_manifest_inherits_renamed_serde

mut_sig_real_serde_dependency_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/Cargo.toml")
text = path.read_text()
old = "serde_json = { workspace = true }\n"
if old not in text:
    raise SystemExit("missing core serde_json dependency mutation subject")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the real serde_json dev dependency being removed' mut_sig_real_serde_dependency_removed

mut_sig_core_harness_removed() {
    rm crates/core/tests/compile_fail.rs
}
expect_fail check_sig_case_coverage.sh \
    'the c-sig-0018 real-serde harness being deleted' mut_sig_core_harness_removed

mut_sig_p2_03_mapping_deleted() {
    sed -i.bak '/^c-sig-0258|/d' scripts/sig-case-coverage-p2-03.txt
}
expect_fail check_sig_case_coverage.sh \
    'a P2-03 acceptance mapping being deleted' mut_sig_p2_03_mapping_deleted

mut_sig_p2_03_mapping_reordered() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/sig-case-coverage-p2-03.txt")
rows = path.read_text().splitlines()
rows[0], rows[1] = rows[1], rows[0]
path.write_text("\n".join(rows) + "\n")
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the P2-03 acceptance mappings being reordered' mut_sig_p2_03_mapping_reordered

mut_sig_p2_03_case_wrongly_bound() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/sig-case-coverage-p2-03.txt")
text = path.read_text()
old = "c-sig-0201|positive|crates/sig/tests/canonical_request.rs|fn c_sig_0201_an_encoded_key_is_not_encoded_a_second_time"
new = "c-sig-0201|positive|crates/sig/tests/canonical_request.rs|fn c_sig_0202_header_values_are_trimmed_and_collapsed"
if text.count(old) != 1:
    raise SystemExit("missing P2-03 wrong-binding mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'one P2-03 id being bound to another active test in the same file' mut_sig_p2_03_case_wrongly_bound

mut_sig_p2_03_compile_fixture_reused() {
    python3 - <<'PYEOF'
from pathlib import Path
manifest = Path("scripts/sig-case-coverage-p2-03.txt")
text = manifest.read_text()
old = "c-sig-0254|negative|crates/sig/tests/compile_fail/c_sig_0254_verified_scope_required.rs|signing_key"
new = "c-sig-0254|negative|crates/sig/tests/compile_fail/c_sig_0253_raw_host_required.rs|CanonicalRequestSpec::new"
if text.count(old) != 1:
    raise SystemExit("missing P2-03 fixture-reuse mapping subject")
manifest.write_text(text.replace(old, new, 1))
fixture = Path("crates/sig/tests/compile_fail/c_sig_0253_raw_host_required.rs")
fixture.write_text(fixture.read_text() + "\n// c-sig-0254\n")
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the two P2-03 compile-time cases reusing one fixture' mut_sig_p2_03_compile_fixture_reused

mut_sig_p2_03_harness_glob_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail.rs")
text = path.read_text()
old = 'cases.compile_fail("tests/compile_fail/c_sig_025[34]_*.rs")'
if text.count(old) != 1:
    raise SystemExit("missing P2-03 harness mutation subject")
path.write_text(text.replace(old, 'cases.compile_fail("tests/compile_fail/never_*.rs")', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the harness no longer executing c-sig-0253 and c-sig-0254' mut_sig_p2_03_harness_glob_removed

mut_sig_p2_03_diagnostic_hollow() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0253_raw_host_required.stderr")
text = path.read_text()
old = 'expected reference `&RawHost`'
if text.count(old) != 1:
    raise SystemExit("missing P2-03 diagnostic mutation subject")
path.write_text(text.replace(old, 'expected another type', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0253 losing its RawHost-specific diagnostic' mut_sig_p2_03_diagnostic_hollow

mut_sig_core_harness_comment_string_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail.rs")
text = path.read_text()
old = '''#[test]
fn compile_time_contracts_are_not_openable() {'''
new = '''// #[test]
// fn compile_time_contracts_are_not_openable() {}
const DECOY: &str = r#"#[test]
fn compile_time_contracts_are_not_openable() {
    cases.compile_fail("tests/compile_fail/c_sig_0018_*.rs");
}"#;
fn removed_compile_time_contracts_are_not_openable() {'''
if old not in text:
    raise SystemExit("missing core harness decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'comment and string decoys replacing the active core trybuild harness' mut_sig_core_harness_comment_string_decoy

mut_sig_core_glob_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail.rs")
text = path.read_text()
old = 'cases.compile_fail("tests/compile_fail/c_sig_0018_*.rs")'
if old not in text:
    raise SystemExit("missing core harness mutation subject")
path.write_text(text.replace(old, 'cases.compile_fail("tests/compile_fail/never_*.rs")', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the core harness no longer executing c-sig-0018' mut_sig_core_glob_removed

mut_sig_serialize_trait_diagnostic_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.stderr")
text = path.read_text()
old = 'error[E0277]: the trait bound `SessionToken: serde::Serialize` is not satisfied'
if old not in text:
    raise SystemExit("missing serialization diagnostic mutation subject")
path.write_text(text.replace(old, 'the serialization diagnostic was weakened', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0018 losing the exact missing-Serialize diagnostic' mut_sig_serialize_trait_diagnostic_changed

mut_sig_serialize_impl_diagnostic_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.stderr")
text = path.read_text()
old = 'the trait `serde_core::ser::Serialize` is not implemented for `SessionToken`'
if old not in text:
    raise SystemExit("missing implementation diagnostic mutation subject")
path.write_text(text.replace(old, 'the implementation diagnostic was weakened', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0018 losing the exact missing implementation diagnostic' mut_sig_serialize_impl_diagnostic_changed

mut_sig_serialize_call_diagnostic_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.stderr")
text = path.read_text()
old = 'required by a bound in `serde_json::to_string`'
if old not in text:
    raise SystemExit("missing serialization-bound diagnostic mutation subject")
path.write_text(text.replace(old, 'required by another call', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0018 no longer diagnosing its serialization bound' mut_sig_serialize_call_diagnostic_changed

mut_sig_p2_04_runtime_mapping_deleted() {
    sed -i.bak '/^c-sig-0378|/d' scripts/sig-case-coverage-p2-04-runtime.txt
}
expect_fail check_sig_case_coverage.sh \
    'a P2-04 runtime case mapping being deleted' mut_sig_p2_04_runtime_mapping_deleted

mut_sig_p2_04_runtime_polarity_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/sig-case-coverage-p2-04-runtime.txt")
text = path.read_text()
old = "c-sig-0308|positive|H4|"
if text.count(old) != 1:
    raise SystemExit("missing P2-04 polarity mutation subject")
path.write_text(text.replace(old, "c-sig-0308|negative|H4|", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the P2-04 runtime polarity split changing' mut_sig_p2_04_runtime_polarity_changed

mut_sig_p2_04_runtime_evidence_reused() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/sig-case-coverage-p2-04-runtime.txt")
text = path.read_text()
old = "fn c_sig_0324_expiry_one_second_over_the_ceiling_is_refused"
new = "fn c_sig_0323_expiry_over_the_ceiling_is_refused"
if text.count(old) != 1:
    raise SystemExit("missing P2-04 evidence-reuse mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'two P2-04 cases reusing one named runtime test' mut_sig_p2_04_runtime_evidence_reused

mut_sig_p2_04_async_test_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/custom_signature_verifier.rs")
text = path.read_text()
old = "#[tokio::test]\nasync fn c_sig_0308_a_non_aws_request_reaches_the_installed_custom_verifier()"
new = "#[cfg(any())]\n#[tokio::test]\nasync fn c_sig_0308_a_non_aws_request_reaches_the_installed_custom_verifier()"
if text.count(old) != 1:
    raise SystemExit("missing P2-04 async-test mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a P2-04 tokio test being disabled by cfg' mut_sig_p2_04_async_test_disabled

mut_sig_p2_04_h7_constraint_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/sig-case-coverage-p2-04-runtime.txt")
text = path.read_text()
old = "h7-replay-hook|positive|H7|"
if text.count(old) != 1:
    raise SystemExit("missing H7 ledger mutation subject")
path.write_text(text.replace(old, "h7-replay-hook|positive|BOUNDARY|", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the P2-04 ledger losing H7 executable evidence' mut_sig_p2_04_h7_constraint_removed

mut_sig_p2_04_h7_documentation_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("docs/security-model.md")
text = path.read_text()
old = "Presigned URLs are replayable within their validity window."
if text.count(old) != 1:
    raise SystemExit("missing H7 documentation mutation subject")
path.write_text(text.replace(old, "Presigned URLs are single-use by default.", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the security model losing the H7 replay semantics' mut_sig_p2_04_h7_documentation_removed

mut_sig_p2_04_route_inventory_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/custom_signature_verifier.rs")
text = path.read_text()
old = 'for entry in generated_entries().expect("the generated route table is valid") {'
new = 'for entry in Vec::<rustfs_gateway_core::RouteEntry>::new() {'
if text.count(old) != 1:
    raise SystemExit("missing posture route-inventory mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0378 replacing the real route inventory with an empty proxy' mut_sig_p2_04_route_inventory_removed

mut_sig_p2_04_dangerous_floor_mapping_deleted() {
    sed -i.bak '/^c-sig-0375|/d' scripts/sig-case-coverage-p2-04-runtime.txt
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0375 losing its runtime mapping' mut_sig_p2_04_dangerous_floor_mapping_deleted

mut_sig_p2_04_gateway_feature_forwarding_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/Cargo.toml")
text = path.read_text()
old = 'dangerous-replace-signature-verifier = ["rustfs-gateway-sig/dangerous-replace-signature-verifier"]'
if text.count(old) != 1:
    raise SystemExit("missing gateway feature-forwarding mutation subject")
path.write_text(text.replace(old, 'dangerous-replace-signature-verifier = []', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the gateway dangerous replacement feature losing sig forwarding' \
    mut_sig_p2_04_gateway_feature_forwarding_removed

mut_sig_p2_04_danger_ack_removed_from_builder() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/builder.rs")
text = path.read_text()
old = "        _acknowledgement: DangerAck,"
if text.count(old) != 1:
    raise SystemExit("missing DangerAck builder mutation subject")
path.write_text(text.replace(old, "        _acknowledgement: (),", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the replacement builder losing its explicit DangerAck' mut_sig_p2_04_danger_ack_removed_from_builder

mut_sig_p2_04_replacement_assignment_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/builder.rs")
text = path.read_text()
old = "        self.dangerously_replaced_signature_verifier = Some(Arc::new(verifier));"
if text.count(old) != 1:
    raise SystemExit("missing replacement assignment mutation subject")
path.write_text(text.replace(old, "        let _ = verifier;", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the replacement builder dropping the supplied verifier' mut_sig_p2_04_replacement_assignment_removed

mut_sig_p2_04_replacement_dispatch_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/service.rs")
text = path.read_text()
old = "                    .map(|verifier| verifier.verify_sealed(&sealed));"
if text.count(old) != 1:
    raise SystemExit("missing replacement dispatch mutation subject")
path.write_text(text.replace(old, "                    .and_then(|_| None);", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the replacement verifier no longer receiving the sealed request' mut_sig_p2_04_replacement_dispatch_removed

mut_sig_p2_04_floor_uses_stale_clock() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/service.rs")
text = path.read_text()
old = "self.inner.floor.admit(view, M::floor(&op), now)"
if text.count(old) != 1:
    raise SystemExit("missing live floor clock mutation subject")
path.write_text(text.replace(old, "self.inner.floor.admit(view, M::floor(&op), RequestNow::from_unix_seconds(1_577_836_800))", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the security floor no longer using the request clock snapshot' mut_sig_p2_04_floor_uses_stale_clock

mut_sig_p2_04_dangerous_posture_forced_false() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/builder.rs")
text = path.read_text()
old = "let dangerously_replaced_signature_verifier = self.dangerously_replaced_signature_verifier.is_some();"
if text.count(old) != 1:
    raise SystemExit("missing dangerous posture mutation subject")
path.write_text(text.replace(old, "let dangerously_replaced_signature_verifier = false;", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'dangerous replacement posture being forced off' mut_sig_p2_04_dangerous_posture_forced_false

mut_sig_p2_04_custom_posture_forced_false() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/builder.rs")
text = path.read_text()
old = "let custom_signature_verifier = self.custom_signature_verifier.is_some();"
if text.count(old) != 1:
    raise SystemExit("missing custom posture mutation subject")
path.write_text(text.replace(old, "let custom_signature_verifier = false;", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'custom verifier posture being forced off' mut_sig_p2_04_custom_posture_forced_false

mut_sig_p2_04_warning_literal_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/builder.rs")
text = path.read_text()
old = '        "WARN: the built-in AWS signature verifier is dangerously replaced; the H1..H7 security floor remains enforced"'
if text.count(old) != 1:
    raise SystemExit("missing replacement warning mutation subject")
new = '        // "WARN: the built-in AWS signature verifier is dangerously replaced; the H1..H7 security floor remains enforced"\n        "WARN: signature replacement enabled"'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the replacement warning drifting beside a comment decoy' mut_sig_p2_04_warning_literal_changed

mut_sig_p2_04_warning_call_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/builder.rs")
text = path.read_text()
old = '''            eprintln!(
                "WARN: the built-in AWS signature verifier is dangerously replaced; the H1..H7 security floor remains enforced"
            );'''
if text.count(old) != 1:
    raise SystemExit("missing replacement warning call mutation subject")
path.write_text(text.replace(old, "            let _ = dangerously_replaced_signature_verifier;", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'assembly no longer emitting the replacement warning' mut_sig_p2_04_warning_call_removed

mut_sig_p2_04_floor_test_feature_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/custom_signature_verifier.rs")
text = path.read_text()
old = '#[cfg(feature = "dangerous-replace-signature-verifier")]\n#[tokio::test]\nasync fn c_sig_0375_the_floor_rejects_before_the_replacement_runs()'
if text.count(old) != 1:
    raise SystemExit("missing c-sig-0375 feature mutation subject")
new = '// #[cfg(feature = "dangerous-replace-signature-verifier")]\n#[cfg(feature = "another-feature")]\n#[tokio::test]\nasync fn c_sig_0375_the_floor_rejects_before_the_replacement_runs()'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0375 moving behind another feature beside a comment decoy' mut_sig_p2_04_floor_test_feature_changed

mut_sig_p2_04_floor_test_replacement_call_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/custom_signature_verifier.rs")
text = path.read_text()
anchor = "async fn c_sig_0375_the_floor_rejects_before_the_replacement_runs()"
start = text.find(anchor)
if start == -1:
    raise SystemExit("missing c-sig-0375 mutation anchor")
old = ".with_dangerously_replaced_signature_verifier("
position = text.find(old, start)
if position == -1:
    raise SystemExit("missing c-sig-0375 replacement-call mutation subject")
text = text[:position] + ".without_dangerously_replaced_signature_verifier(" + text[position + len(old):]
path.write_text(text)
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0375 no longer assembling the dangerous replacement' \
    mut_sig_p2_04_floor_test_replacement_call_removed

mut_sig_p2_04_dangerous_posture_display_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/posture.rs")
text = path.read_text()
old = '            f.write_str("; AWS signature verifier: dangerously replaced")?;'
if text.count(old) != 1:
    raise SystemExit("missing dangerous posture display mutation subject")
new = '            // f.write_str("; AWS signature verifier: dangerously replaced")?;\n            f.write_str("; AWS signature verifier: custom")?;'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'dangerous posture display drifting beside a comment decoy' mut_sig_p2_04_dangerous_posture_display_changed

mut_sig_p2_04_custom_posture_display_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/posture.rs")
text = path.read_text()
old = '            f.write_str("; custom signature verifier: installed")'
if text.count(old) != 1:
    raise SystemExit("missing custom posture display mutation subject")
new = '            // f.write_str("; custom signature verifier: installed")\n            f.write_str("; custom signature verifier: present")'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'custom posture display drifting beside a comment decoy' mut_sig_p2_04_custom_posture_display_changed

mut_sig_p2_04_startup_posture_log_call_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/builder.rs")
text = path.read_text()
old = """        log_startup_posture(
            routing.dispatch.floors(),
            &self.floor,
            custom_signature_verifier,
            dangerously_replaced_signature_verifier,
        );
"""
if text.count(old) != 1:
    raise SystemExit("missing startup posture log mutation subject")
path.write_text(text.replace(old, "        let _ = (&routing.dispatch, &self.floor);\n", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'assembly no longer writing the startup posture report' mut_sig_p2_04_startup_posture_log_call_removed

mut_sig_p2_04_startup_posture_floor_inventory_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/dispatch.rs")
text = path.read_text()
old = "        self.entries.values().map(OperationDispatch::floor)"
if text.count(old) != 1:
    raise SystemExit("missing startup posture floor inventory mutation subject")
path.write_text(text.replace(old, "        core::iter::empty()", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the startup posture no longer enumerating registered operation floors' \
    mut_sig_p2_04_startup_posture_floor_inventory_removed

mut_sig_p2_04_startup_posture_anonymous_filter_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/posture.rs")
text = path.read_text()
old = "        .filter(|operation| floor.admits_anonymous(operation))"
if text.count(old) != 1:
    raise SystemExit("missing anonymous startup posture mutation subject")
path.write_text(text.replace(old, "        .filter(|_| false)", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the startup posture forcing the anonymous operation list empty' \
    mut_sig_p2_04_startup_posture_anonymous_filter_removed

mut_sig_p2_04_startup_posture_presigned_filter_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/posture.rs")
text = path.read_text()
old = "        .filter(|operation| !operation.privileged() && operation.allowed_schemes().allows_presigned())"
if text.count(old) != 1:
    raise SystemExit("missing presigned startup posture mutation subject")
path.write_text(text.replace(old, "        .filter(|_| false)", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the startup posture forcing the presigned operation list empty' \
    mut_sig_p2_04_startup_posture_presigned_filter_removed

mut_sig_p2_04_startup_posture_sigv2_switch_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/posture.rs")
text = path.read_text()
old = "    let sigv2_policy = floor.sigv2_policy().as_str();"
if text.count(old) != 1:
    raise SystemExit("missing startup posture SigV2 mutation subject")
path.write_text(text.replace(old, '    let sigv2_policy = "HeaderOnly";', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the startup posture no longer reading the live SigV2 switch' mut_sig_p2_04_startup_posture_sigv2_switch_removed

mut_sig_p2_04_startup_posture_custom_switch_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/posture.rs")
text = path.read_text()
old = '    let custom_verifier = if custom_signature_verifier { "installed" } else { "none" };'
if text.count(old) != 1:
    raise SystemExit("missing startup posture custom-verifier mutation subject")
path.write_text(text.replace(old, '    let custom_verifier = "none";', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the startup posture no longer reading the live custom verifier switch' \
    mut_sig_p2_04_startup_posture_custom_switch_removed

mut_sig_p2_04_startup_posture_aws_switch_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/posture.rs")
text = path.read_text()
old = "    let aws_signature_verifier = if dangerously_replaced_signature_verifier {"
if text.count(old) != 1:
    raise SystemExit("missing startup posture AWS-verifier mutation subject")
path.write_text(text.replace(old, "    let aws_signature_verifier = if false {", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the startup posture no longer reading the live AWS verifier switch' mut_sig_p2_04_startup_posture_aws_switch_removed

mut_sig_p2_04_startup_posture_format_dropped_field() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/posture.rs")
text = path.read_text()
old = '        "SECURITY_POSTURE anonymous_reachable_ops=[{}] custom_verifier={custom_verifier} sigv2_policy={sigv2_policy} presigned_allowed_ops=[{}] aws_signature_verifier={aws_signature_verifier}",'
if text.count(old) != 1:
    raise SystemExit("missing startup posture format mutation subject")
new = '        // "SECURITY_POSTURE anonymous_reachable_ops=[{}] custom_verifier={custom_verifier} sigv2_policy={sigv2_policy} presigned_allowed_ops=[{}] aws_signature_verifier={aws_signature_verifier}",\n        "SECURITY_POSTURE anonymous_reachable_ops=[{}] custom_verifier={custom_verifier} sigv2_policy={sigv2_policy} presigned_allowed_ops=[{}]",'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the startup posture output dropping a required field beside a comment decoy' \
    mut_sig_p2_04_startup_posture_format_dropped_field

mut_sig_p2_04_startup_posture_log_render_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/src/posture.rs")
text = path.read_text()
old = """    eprintln!(
        "{}",
        render_startup_posture(operations, floor, custom_signature_verifier, dangerously_replaced_signature_verifier,)
    );
"""
if text.count(old) != 1:
    raise SystemExit("missing startup posture renderer mutation subject")
new = """    let _ = render_startup_posture(
        operations,
        floor,
        custom_signature_verifier,
        dangerously_replaced_signature_verifier,
    );
"""
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the startup posture report being rendered but never written' mut_sig_p2_04_startup_posture_log_render_removed

mut_sig_p2_04_dry_run_arguments_unchecked() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/src/security_posture.rs")
text = path.read_text()
old = '    if args != ["--dry-run"] {'
if text.count(old) != 1:
    raise SystemExit("missing dry-run argument mutation subject")
path.write_text(text.replace(old, '    // if args != ["--dry-run"] {\n    if false {', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'security-posture accepting arguments other than --dry-run' \
    mut_sig_p2_04_dry_run_arguments_unchecked \
    'check_sig_case_coverage: security-posture accepts arguments other than --dry-run'

mut_sig_p2_04_dry_run_dispatch_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/src/main.rs")
text = path.read_text()
old = '        Some("security-posture") => security_posture::command(&rest),'
if text.count(old) != 1:
    raise SystemExit("missing dry-run dispatch mutation subject")
new = '        // Some("security-posture") => security_posture::command(&rest),\n        Some("security-posture") => ExitCode::SUCCESS,'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'security-posture dispatch bypassing the dry-run command' \
    mut_sig_p2_04_dry_run_dispatch_removed \
    'check_sig_case_coverage: security-posture dry-run is not dispatched'

mut_sig_p2_04_dry_run_floor_parser_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/src/security_posture.rs")
text = path.read_text()
old = '    let floors = parse_standard_floors(&root.join("crates/core/src/ops"))?;'
if text.count(old) != 1:
    raise SystemExit("missing dry-run floor-parser mutation subject")
new = '    // let floors = parse_standard_floors(&root.join("crates/core/src/ops"))?;\n    let floors = BTreeMap::new();'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'dry-run replacing real operation floors with an empty proxy' \
    mut_sig_p2_04_dry_run_floor_parser_removed \
    'check_sig_case_coverage: dry-run does not join real floors to the route-table inventory'

mut_sig_p2_04_dry_run_route_inventory_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/src/security_posture.rs")
text = path.read_text()
old = '''    let routed: BTreeSet<_> = rustfs_gateway_core::route::ROUTES
        .iter()
        .filter(|row| row.handler_registration)
        .map(|row| row.operation.to_owned())
        .collect();'''
if text.count(old) != 1:
    raise SystemExit("missing dry-run route-inventory mutation subject")
new = '    let routed: BTreeSet<String> = BTreeSet::new();'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'dry-run replacing the route-table inventory with an empty proxy' \
    mut_sig_p2_04_dry_run_route_inventory_removed \
    'check_sig_case_coverage: dry-run does not join real floors to the route-table inventory'

mut_sig_p2_04_dry_run_handler_filter_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/src/security_posture.rs")
text = path.read_text()
old = '        .filter(|row| row.handler_registration)'
if text.count(old) != 1:
    raise SystemExit("missing dry-run handler-filter mutation subject")
path.write_text(text.replace(old, '        .filter(|_| true)', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'dry-run including route-only operations in the handler inventory' \
    mut_sig_p2_04_dry_run_handler_filter_removed \
    'check_sig_case_coverage: dry-run does not exclude route-only operations from the handler inventory'

mut_sig_p2_04_dry_run_inventory_check_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/src/security_posture.rs")
text = path.read_text()
old = '    if parsed != routed {'
if text.count(old) != 1:
    raise SystemExit("missing dry-run inventory-check mutation subject")
path.write_text(text.replace(old, '    // if parsed != routed {\n    if false {', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'dry-run ignoring route-table and floor inventory drift' \
    mut_sig_p2_04_dry_run_inventory_check_removed \
    'check_sig_case_coverage: dry-run no longer rejects operation inventory drift'

mut_sig_p2_04_dry_run_real_source_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/src/security_posture.rs")
text = path.read_text()
old = '    let entries = std::fs::read_dir(directory)'
if text.count(old) != 1:
    raise SystemExit("missing dry-run source-directory mutation subject")
new = '    let entries = std::fs::read_dir(directory.join("../../../spec/operations"))'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'dry-run reading spec instead of real operation-floor sources' \
    mut_sig_p2_04_dry_run_real_source_removed \
    'check_sig_case_coverage: dry-run no longer parses the real operation sources'

mut_sig_p2_04_dry_run_floor_binding_check_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/src/security_posture.rs")
text = path.read_text()
old = '        validate_operation_impl_uses_floor(&file, &path)?;'
if text.count(old) != 1:
    raise SystemExit("missing dry-run floor-binding mutation subject")
path.write_text(text.replace(old, '        // validate_operation_impl_uses_floor(&file, &path)?;', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'dry-run trusting a FLOOR static that Operation::floor does not return' \
    mut_sig_p2_04_dry_run_floor_binding_check_removed \
    'check_sig_case_coverage: dry-run no longer proves Operation::floor returns the parsed floor'

mut_sig_p2_04_dry_run_floor_shape_check_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/src/security_posture.rs")
text = path.read_text()
old = '    if segments.len() != 2 || segments[0] != "OperationFloor" || call.args.len() != 2 {'
if text.count(old) != 1:
    raise SystemExit("missing dry-run floor-shape mutation subject")
path.write_text(text.replace(old, '    // ' + old.strip() + '\n    if false {', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'dry-run accepting a non-canonical operation-floor expression' \
    mut_sig_p2_04_dry_run_floor_shape_check_removed \
    'check_sig_case_coverage: dry-run accepts a non-canonical operation floor expression'

mut_sig_p2_04_dry_run_presigned_constructor_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/src/security_posture.rs")
text = path.read_text()
old = '        "builtin_presigned" => true,'
if text.count(old) != 1:
    raise SystemExit("missing presigned-constructor mutation subject")
new = '        // "builtin_presigned" => true,\n        "builtin_presigned" => false,'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'dry-run treating presigned operation floors as ordinary floors' \
    mut_sig_p2_04_dry_run_presigned_constructor_disabled \
    'check_sig_case_coverage: dry-run no longer recognizes the presigned floor constructor'

mut_sig_p2_04_dry_run_presigned_filter_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/src/security_posture.rs")
text = path.read_text()
old = '        .filter_map(|(name, floor)| floor.presigned.then_some(name.as_str()))'
if text.count(old) != 1:
    raise SystemExit("missing dry-run presigned-filter mutation subject")
path.write_text(text.replace(old, '        .filter_map(|_| None)', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'dry-run forcing the presigned operation list empty' \
    mut_sig_p2_04_dry_run_presigned_filter_removed \
    'check_sig_case_coverage: dry-run no longer derives the presigned operation list'

mut_sig_p2_04_dry_run_anonymous_filter_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/src/security_posture.rs")
text = path.read_text()
old = '        .filter_map(|(name, floor)| floor.anonymous.then_some(name.as_str()))'
if text.count(old) != 1:
    raise SystemExit("missing dry-run anonymous-filter mutation subject")
path.write_text(text.replace(old, '        .filter_map(|_| None)', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'dry-run forcing the anonymous operation list empty' \
    mut_sig_p2_04_dry_run_anonymous_filter_removed \
    'check_sig_case_coverage: dry-run no longer derives the anonymous operation list'

mut_sig_p2_04_dry_run_output_dropped_field() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/src/security_posture.rs")
text = path.read_text()
old = '        "SECURITY_POSTURE anonymous_reachable_ops=[{anonymous}] custom_verifier=none sigv2_policy=HeaderOnly presigned_allowed_ops=[{presigned}] aws_signature_verifier=built-in"'
if text.count(old) != 1:
    raise SystemExit("missing dry-run output mutation subject")
new = '        // "SECURITY_POSTURE anonymous_reachable_ops=[{anonymous}] custom_verifier=none sigv2_policy=HeaderOnly presigned_allowed_ops=[{presigned}] aws_signature_verifier=built-in"\n        "SECURITY_POSTURE anonymous_reachable_ops=[{anonymous}] custom_verifier=none sigv2_policy=HeaderOnly presigned_allowed_ops=[{presigned}]"'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'dry-run output dropping a required field beside a comment decoy' \
    mut_sig_p2_04_dry_run_output_dropped_field \
    'check_sig_case_coverage: dry-run output lost a required startup-posture field'

mut_sig_p2_04_replay_store_call_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/security_floor_schemes.rs")
text = path.read_text()
old = "let decision = store.record_first_use(fingerprint);"
new = "let decision = ReplayDecision::FirstUse;\n    let _ = (store, fingerprint);"
if text.count(old) != 1:
    raise SystemExit("missing replay-store mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the H7 evidence no longer invoking the replay hook' mut_sig_p2_04_replay_store_call_removed

mut_sig_p2_04_compile_fail_mapping_deleted() {
    sed -i.bak '/^c-sig-0377|/d' scripts/sig-case-coverage-p2-04-compile-fail.txt
}
expect_fail check_sig_case_coverage.sh \
    'a P2-04 compile-fail mapping being deleted' mut_sig_p2_04_compile_fail_mapping_deleted

mut_sig_p2_04_compile_fail_polarity_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/sig-case-coverage-p2-04-compile-fail.txt")
text = path.read_text()
old = "c-sig-0345|negative|H5|"
if text.count(old) != 1:
    raise SystemExit("missing P2-04 compile-fail polarity mutation subject")
path.write_text(text.replace(old, "c-sig-0345|positive|H5|", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a P2-04 compile-fail case becoming positive' mut_sig_p2_04_compile_fail_polarity_changed

mut_sig_p2_04_compile_fail_feature_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/sig-case-coverage-p2-04-compile-fail.txt")
text = path.read_text()
old = "|dangerous-replace-signature-verifier\n"
if text.count(old) != 1:
    raise SystemExit("missing P2-04 compile-fail feature mutation subject")
path.write_text(text.replace(old, "|default\n", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0376 losing its dangerous feature boundary' mut_sig_p2_04_compile_fail_feature_changed

mut_sig_p2_04_compile_fail_fixture_removed() {
    rm crates/sig/tests/compile_fail/c_sig_0354_anonymous_ack_private.rs
}
expect_fail check_sig_case_coverage.sh \
    'a P2-04 compile-fail fixture being removed' mut_sig_p2_04_compile_fail_fixture_removed

mut_sig_p2_04_compile_fail_evidence_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0354_anonymous_ack_private.rs")
text = path.read_text()
old = "    let _ = AnonymousAck(());"
if text.count(old) != 1:
    raise SystemExit("missing anonymous-ack compile-fail mutation subject")
path.write_text(text.replace(old, "    let _ = ();", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0354 losing its active private-constructor evidence' mut_sig_p2_04_compile_fail_evidence_removed

mut_sig_p2_04_compile_fail_golden_removed() {
    rm crates/sig/tests/compile_fail/c_sig_0345_verified_scope_private.stderr
}
expect_fail check_sig_case_coverage.sh \
    'a P2-04 compile-fail golden being removed' mut_sig_p2_04_compile_fail_golden_removed

mut_sig_p2_04_compile_fail_diagnostic_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0377_verifier_returns_verdict.stderr")
text = path.read_text()
old = "method `verify` has an incompatible type for trait"
if text.count(old) != 1:
    raise SystemExit("missing verifier diagnostic mutation subject")
path.write_text(text.replace(old, "method `verify` was accepted", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0377 losing its case-specific rustc diagnostic' mut_sig_p2_04_compile_fail_diagnostic_changed

mut_sig_p2_04_compile_fail_harness_call_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail.rs")
text = path.read_text()
old = 'cases.compile_fail("tests/compile_fail/c_sig_034[56]_*.rs")'
if text.count(old) != 1:
    raise SystemExit("missing P2-04 compile-fail harness mutation subject")
path.write_text(text.replace(old, 'cases.compile_fail("tests/compile_fail/never_*.rs")', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the P2-04 default compile-fail harness losing c-sig-0345 and c-sig-0346' \
    mut_sig_p2_04_compile_fail_harness_call_removed

mut_sig_p2_04_danger_ack_feature_gate_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail.rs")
text = path.read_text()
old = '#[cfg(feature = "dangerous-replace-signature-verifier")]'
if text.count(old) != 1:
    raise SystemExit("missing danger-ack feature-gate mutation subject")
new = '// #[cfg(feature = "dangerous-replace-signature-verifier")]\n#[cfg(feature = "another-feature")]'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the DangerAck compile-fail harness moving behind another feature beside a comment decoy' \
    mut_sig_p2_04_danger_ack_feature_gate_changed

mut_sig_p2_04_danger_ack_harness_call_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail.rs")
text = path.read_text()
old = 'cases.compile_fail("tests/compile_fail/c_sig_0376_*.rs")'
if text.count(old) != 1:
    raise SystemExit("missing danger-ack harness mutation subject")
path.write_text(text.replace(old, 'cases.compile_fail("tests/compile_fail/never_*.rs")', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the dangerous feature harness losing c-sig-0376' mut_sig_p2_04_danger_ack_harness_call_removed

"${SCRIPT_DIR}/test_sig_case_coverage.sh"

# -----------------------------------------------------------------------------
# ADR-0005. Each of the three mutations below is a way the generated dto silently
# stops being part of the `rustfs-gateway-types` package: the escaping `#[path]`
# is the original defect, the real directory is the well-meaning "fix" that
# duplicates generated output, and the text file is what a Windows checkout
# without `core.symlinks` produces.
# -----------------------------------------------------------------------------
mut_escaping_dto_path() {
    # The spelling the crate had before ADR-0005: reaches the generated tree, but
    # from outside the package, so `cargo package` cannot see it.
    sed -e 's|"../generated/ops/mod.rs"|"../../../generated/dto/ops/mod.rs"|' \
        -e 's|"../generated/flat.rs"|"../../../generated/dto/flat.rs"|' \
        crates/types/src/lib.rs >crates/types/src/lib.rs.mut
    mv crates/types/src/lib.rs.mut crates/types/src/lib.rs
}
expect_fail check_generated_dto_packaged.sh \
    'a #[path] reaching outside the package directory' mut_escaping_dto_path

mut_dto_copy_instead_of_symlink() {
    rm -f crates/types/generated
    cp -R generated/dto crates/types/generated
}
expect_fail check_generated_dto_packaged.sh \
    'the dto mount replaced by a real directory (a second copy of generated output)' \
    mut_dto_copy_instead_of_symlink

mut_dto_symlink_as_text() {
    rm -f crates/types/generated
    printf '../../generated/dto' >crates/types/generated
}
expect_fail check_generated_dto_packaged.sh \
    'the dto symlink materialised as a text file, as on Windows without core.symlinks' \
    mut_dto_symlink_as_text


# -----------------------------------------------------------------------------
# ADR-0004's SemVer policy was prose until now. These guards are what make
# "a new optional field is a minor change" enforceable rather than aspirational.
# The mutations cover attributes independent of layout and every Rust pattern
# position where exhaustive destructuring can hide.
# -----------------------------------------------------------------------------

mut_dto_non_exhaustive() {
    f=generated/dto/ops/get_bucket_location.rs
    awk '/^pub struct / && !done { print "#[non_exhaustive]"; done = 1 } { print }' \
        "$f" >"${f}.mut" && mv "${f}.mut" "$f"
}
expect_semver_fail check_no_dto_non_exhaustive.sh \
    'a dto struct marked #[non_exhaustive], which forbids FRU' mut_dto_non_exhaustive

mut_dto_non_exhaustive_same_line() {
    f=generated/dto/ops/get_bucket_location.rs
    awk '/^pub struct / && !done { sub(/^pub struct /, "#[non_exhaustive] pub struct "); done = 1 } { print }' \
        "$f" >"${f}.mut" && mv "${f}.mut" "$f"
}
expect_semver_fail check_no_dto_non_exhaustive.sh \
    'a same-line #[non_exhaustive] dto struct attribute' mut_dto_non_exhaustive_same_line

mut_dto_cfg_attr_non_exhaustive() {
    f=generated/dto/ops/get_bucket_location.rs
    awk '/^pub struct / && !done { print "#[cfg_attr(all(), non_exhaustive)]"; done = 1 } { print }' \
        "$f" >"${f}.mut" && mv "${f}.mut" "$f"
}
expect_semver_fail check_no_dto_non_exhaustive.sh \
    'a cfg_attr that applies non_exhaustive to a dto struct' mut_dto_cfg_attr_non_exhaustive

mut_dto_non_exhaustive_missing_inputs() {
    mv generated/dto generated/dto-hidden
}
expect_semver_fail check_no_dto_non_exhaustive.sh \
    'the required generated dto inputs are missing' mut_dto_non_exhaustive_missing_inputs

mut_dto_non_exhaustive_missing_rule() {
    rm docs/adr/0004-semver-policy.md
}
expect_semver_fail check_no_dto_non_exhaustive.sh \
    'the governing ADR input is missing' mut_dto_non_exhaustive_missing_rule

mut_dto_non_exhaustive_malformed_source() {
    printf '\npub struct Unclosed {\n' >>generated/dto/ops/get_bucket_location.rs
}
expect_semver_fail check_no_dto_non_exhaustive.sh \
    'a generated Rust input cannot be parsed completely' mut_dto_non_exhaustive_malformed_source

mut_dto_non_exhaustive_missing_parser() {
    rm scripts/lib/rust_semver_surface.py
}
expect_semver_fail check_no_dto_non_exhaustive.sh \
    'the required Rust source parser is missing' mut_dto_non_exhaustive_missing_parser

mut_exhaustive_destructuring_multiline() {
    cat >>crates/types/src/lib.rs <<'RS'

#[cfg(test)]
mod destructure_fixture {
    #[test]
    fn fixture() {
        let out = crate::ops::get_bucket_location::Output::default();
        let crate::ops::get_bucket_location::Output {
            location_constraint,
        } = out;
        let _ = location_constraint;
    }
}
RS
}
expect_semver_fail check_no_exhaustive_destructuring.sh \
    'a multiline dto pattern without a trailing ..' mut_exhaustive_destructuring_multiline

mut_destructuring_nested_rest() {
    cat >>crates/types/src/lib.rs <<'RS'

fn semver_nested_rest(value: crate::ops::get_bucket_location::Output) {
    let crate::ops::get_bucket_location::Output {
        location_constraint: Some(crate::types::Nested { .. }),
    } = value;
}
RS
}
expect_semver_fail check_no_exhaustive_destructuring.sh \
    'a nested rest pattern that does not make the outer dto additive' mut_destructuring_nested_rest

mut_destructuring_range_decoy() {
    cat >>crates/types/src/lib.rs <<'RS'

fn semver_range(value: crate::ops::get_bucket_location::Output) {
    let crate::ops::get_bucket_location::Output { location_constraint: 0..=10 } = value;
}
RS
}
expect_semver_fail check_no_exhaustive_destructuring.sh \
    'a range pattern that is not a top-level rest pattern' mut_destructuring_range_decoy

mut_destructuring_pattern_positions() {
    cat >>crates/types/src/lib.rs <<'RS'

fn semver_pattern_positions<T>(
    crate::ops::get_bucket_location::Output { location_constraint }: crate::ops::get_bucket_location::Output,
    values: T,
) {
    for crate::ops::get_bucket_location::Output { location_constraint } in values {}
    let closure = |crate::ops::get_bucket_location::Output { location_constraint }| location_constraint;
    match crate::ops::get_bucket_location::Output::default() {
        crate::ops::get_bucket_location::Output { location_constraint } => (),
    }
    let _ = matches!(
        crate::ops::get_bucket_location::Output::default(),
        crate::ops::get_bucket_location::Output { location_constraint }
    );
    (crate::ops::get_bucket_location::Output { location_constraint }) =
        crate::ops::get_bucket_location::Output::default();
}
RS
}
expect_semver_fail check_no_exhaustive_destructuring.sh \
    'for, parameter, closure, match, matches, and assignment dto patterns' \
    mut_destructuring_pattern_positions

mut_destructuring_match_block_without_comma() {
    cat >>crates/types/src/lib.rs <<'RS'

fn semver_match_blocks(value: crate::ops::get_bucket_location::Output) {
    match value {
        crate::ops::get_bucket_location::Output { location_constraint, .. } => {}
        crate::ops::get_bucket_location::Output { location_constraint } => {}
    }
}
RS
}
expect_semver_fail check_no_exhaustive_destructuring.sh \
    'a later exhaustive match arm after a comma-less block arm' \
    mut_destructuring_match_block_without_comma

mut_destructuring_match_if_block_without_comma() {
    cat >>crates/types/src/lib.rs <<'RS'

fn semver_match_if_blocks(value: crate::ops::get_bucket_location::Output, flag: bool) {
    match value {
        crate::ops::get_bucket_location::Output { location_constraint: None, .. } => if flag {}
        crate::ops::get_bucket_location::Output { location_constraint } => {}
    }
}
RS
}
expect_semver_fail check_no_exhaustive_destructuring.sh \
    'a later exhaustive arm after a comma-less if expression with block' \
    mut_destructuring_match_if_block_without_comma

mut_destructuring_import_alias() {
    cat >>crates/types/src/lib.rs <<'RS'

use crate::ops::get_bucket_location::Output as SemverReply;
use crate::ops::get_bucket_location as semver_op;
use rustfs_gateway_types::dto;
type SemverLock = dto::ObjectLockConfiguration;

fn semver_import_alias(
    value: SemverReply,
    operation_value: semver_op::Output,
    lock: dto::ObjectLockConfiguration,
    typed_lock: SemverLock,
) {
    let SemverReply { location_constraint } = value;
    let semver_op::Output { location_constraint } = operation_value;
    let dto::ObjectLockConfiguration { object_lock_enabled, rule } = lock;
    let SemverLock { object_lock_enabled, rule } = typed_lock;
}
RS
}
expect_semver_fail check_no_exhaustive_destructuring.sh \
    'a dto destructured through an alias or dto namespace' mut_destructuring_import_alias

mut_destructuring_untracked_source() {
    cat >crates/types/src/semver_untracked.rs <<'RS'
fn semver_untracked(value: crate::ops::get_bucket_location::Output) {
    let crate::ops::get_bucket_location::Output { location_constraint } = value;
}
RS
}
expect_semver_fail check_no_exhaustive_destructuring.sh \
    'an exhaustive dto pattern in an untracked Rust source' mut_destructuring_untracked_source

mut_destructuring_allowance_bypass() {
    f=crates/types/src/lib.rs
    line=$(($(wc -l <"$f") + 1))
    mkdir -p scripts/allowances
    printf '%s\n' \
        'fn semver_allowed(value: crate::ops::get_bucket_location::Output) { let crate::ops::get_bucket_location::Output { location_constraint } = value; }' \
        >>"$f"
    printf '%s:%s # exhaustive patterns cannot be allowed\n' "$f" "$line" \
        >scripts/allowances/exhaustive-destructuring-allowances.txt
}
expect_semver_fail check_no_exhaustive_destructuring.sh \
    'a path-and-line allowance attempting to bypass ADR-0004 P3' mut_destructuring_allowance_bypass

mut_destructuring_missing_inputs() {
    mv generated/dto generated/dto-hidden
}
expect_semver_fail check_no_exhaustive_destructuring.sh \
    'the dto name source is missing instead of silently skipping' mut_destructuring_missing_inputs

mut_destructuring_malformed_source() {
    printf '\nfn semver_unclosed( {\n' >>crates/types/src/lib.rs
}
expect_semver_fail check_no_exhaustive_destructuring.sh \
    'a hand-written Rust input cannot be parsed completely' mut_destructuring_malformed_source

mut_destructuring_missing_parser() {
    rm scripts/lib/rust_semver_surface.py
}
expect_semver_fail check_no_exhaustive_destructuring.sh \
    'the required Rust source parser is missing' mut_destructuring_missing_parser

probe_semver_guards_missing_python() {
    local guard output rc tool_path all_failed=1
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_semver_sandbox
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-semver-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    for guard in check_no_dto_non_exhaustive.sh check_no_exhaustive_destructuring.sh; do
        rc=0
        output="$(GATEWAY_CHECK_ROOT="$SEMVER_SANDBOX" PATH="$tool_path" /bin/bash \
            "$SEMVER_SANDBOX/scripts/${guard}" 2>&1)" || rc=$?
        if [[ "$rc" -eq 0 || "$output" != *'required command is missing: python3'* ]]; then
            all_failed=0
        fi
    done
    rm -rf "$tool_path"
    if [[ "$all_failed" -eq 1 ]]; then
        pass_msg 'ADR-0004 guards fail closed when python3 is unavailable'
    else
        fail_msg 'an ADR-0004 guard reported green without python3'
    fi
}
probe_semver_guards_missing_python

probe_semver_guard_decoys() {
    local sandbox rc=0 non_exhaustive_output destructuring_output
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_semver_sandbox
    sandbox="$SEMVER_SANDBOX"
    cat >>"$sandbox/generated/dto/ops/get_bucket_location.rs" <<'RS'

// #[non_exhaustive] pub struct CommentOnly {}
const NON_EXHAUSTIVE_TEXT: &str = r#"#[non_exhaustive] pub struct StringOnly {}"#;
#[non_exhaustive]
pub enum FutureEnum { Value }
#[cfg_attr(all(), allow(non_exhaustive))]
pub struct AttributeArgumentOnly {}
RS
    cat >>"$sandbox/crates/types/src/lib.rs" <<'RS'

struct Output { local: bool }
struct Owner { local: bool }

mod local {
    pub struct Owner { pub local: bool }
}
mod dto {
    pub struct Owner { pub local: bool }
}
mod ops {
    pub struct Owner { pub local: bool }
}

fn semver_safe_patterns(
    value: crate::ops::get_bucket_location::Output,
    output: Output,
    owner: Owner,
    qualified_owner: local::Owner,
    local_dto_owner: dto::Owner,
    local_ops_owner: ops::Owner,
) {
    let crate::ops::get_bucket_location::Output { location_constraint, .. } = value;
    let _constructed = crate::ops::get_bucket_location::Output { location_constraint, ..Default::default() };
    let Output { local } = output;
    let Owner { local } = owner;
    let local::Owner { local } = qualified_owner;
    let dto::Owner { local } = local_dto_owner;
    let ops::Owner { local } = local_ops_owner;
    // let crate::ops::get_bucket_location::Output { location_constraint } = value;
    let _text = r#"let crate::ops::get_bucket_location::Output { location_constraint } = value;"#;
}
RS
    non_exhaustive_output="$(GATEWAY_CHECK_ROOT="$sandbox" \
        "$sandbox/scripts/check_no_dto_non_exhaustive.sh" 2>&1)" || rc=1
    destructuring_output="$(GATEWAY_CHECK_ROOT="$sandbox" \
        "$sandbox/scripts/check_no_exhaustive_destructuring.sh" 2>&1)" || rc=1
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'ADR-0004 guards ignore enum/comment/string/construction decoys and accept top-level rest'
    else
        fail_msg 'ADR-0004 guards reject a valid enum/comment/string/construction/rest control'
        printf '%s\n%s\n' "$non_exhaustive_output" "$destructuring_output" >&2
    fi
}
probe_semver_guard_decoys


# -----------------------------------------------------------------------------
# English-only. The first version of this guard used a grep bracket expression,
# which is interpreted by locale collation rather than by codepoint and matched
# an em dash — it reported every English file in the tree. The negative control
# is what tells the two versions apart.
# -----------------------------------------------------------------------------

# The Chinese is written as UTF-8 byte escapes so this file stays pure ASCII.
# Spelling it literally would make the guard flag its own test, and allowing the
# file would then permit real Chinese to sit here unnoticed forever.
# \xe4\xb8\xad\xe6\x96\x87 is the two-character word for "Chinese".
mut_chinese_comment() {
    printf '\n// \xe4\xb8\xad\xe6\x96\x87\n' >>crates/core/src/lib.rs
}
expect_english_fail_minimal \
    'a Chinese comment in a source file' mut_chinese_comment \
    crates/core/src/lib.rs tracked

mut_chinese_markdown() {
    printf '\n\xe4\xb8\xad\xe6\x96\x87\n' >>docs/msrv.md
}
expect_english_fail_minimal \
    'a Chinese paragraph in a Markdown document' mut_chinese_markdown \
    docs/msrv.md tracked


# -----------------------------------------------------------------------------
# The guards read `git ls-files --cached --others --exclude-standard`, not a bare
# `git ls-files`. The bare form lists only tracked files, so a brand-new file is
# invisible until `git add -A` commits it — which is how CJK text reached commit
# 343f044 through a guard run that had just reported success. These two cases
# fail if anyone drops the flags: the sandbox never stages the mutation, so an
# untracked-blind guard sees nothing and exits 0.
# -----------------------------------------------------------------------------

mut_untracked_chinese_source() {
    # \xe4\xb8\xad\xe6\x96\x87 is the two-character word for "Chinese"; written as
    # bytes so this file stays ASCII and does not trip the guard it is testing.
    printf '// \xe4\xb8\xad\xe6\x96\x87\n' >crates/core/src/brand_new_file.rs
}
expect_english_fail_minimal \
    'CJK in a file that has never been added to the index' mut_untracked_chinese_source \
    crates/core/src/brand_new_file.rs untracked

mut_untracked_missing_header() {
    printf '//! No licence header.\npub fn f() {}\n' >crates/core/src/no_header_yet.rs
}
expect_fail_unstaged check_license_headers.sh \
    'a new .rs file with no licence header, still untracked' mut_untracked_missing_header


# -----------------------------------------------------------------------------
# A `//! Members:` line is how a reader learns which operations share a rule. It
# had already drifted before this guard existed — precondition.rs named seven
# operations while one file in the tree used it — and nothing noticed for four
# commits. Both directions matter: a claimed member that does not use the module
# is a contract wired into nothing, and a user missing from the list hides a
# dependency from the next person to change the rule.
# -----------------------------------------------------------------------------

mut_members_claims_unused() {
    python3 - <<'PYEOF'
import pathlib, re
p = pathlib.Path("crates/core/src/ops/shared/pagination.rs")
t = p.read_text()
t = re.sub(r"^//! Members:.*$", "//! Members: ListBuckets, GetObject", t, count=1, flags=re.M)
p.write_text(t)
PYEOF
}
expect_fail check_shared_members.sh \
    'a Members: line naming an operation that does not use the module' mut_members_claims_unused


# -----------------------------------------------------------------------------
# A shared contract only this workspace can reach is one every backend rewrites.
# It happened to copy_source, to precondition, to Checksummer, and the guard
# caught pagination the moment it existed. The control adds a fifth to prove the
# guard is looking at the facade rather than at a list of the four known names.
# -----------------------------------------------------------------------------

mut_unexported_shared_item() {
    printf '\n/// A contract no backend can reach.\npub fn brand_new_contract() {}\n' \
        >>crates/core/src/ops/shared/pagination.rs
}
expect_fail check_shared_reachable.sh \
    'a new public item in shared/ that the facade does not re-export' mut_unexported_shared_item

# -----------------------------------------------------------------------------
# `check_shared_members.sh` implements both directions and, until now, proved
# one: the case above breaks "claimed but unused", and nothing broke "used but
# unclaimed". A guard half of whose code has never been observed to fail is half
# a guard — this is the other half.
# -----------------------------------------------------------------------------

mut_members_omits_user() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/ops/shared/pagination.rs")
t = p.read_text()
old = "//! Members: ListBuckets, ListObjectVersions, ListObjects, ListObjectsV2"
if old not in t:
    raise SystemExit("pagination Members mutation subject is missing")
p.write_text(t.replace(old, "//! Members: ListObjectVersions, ListObjects, ListObjectsV2", 1))
PYEOF
}
expect_fail_with_diagnostic check_shared_members.sh \
    'an operation dropping off Members: while it still uses the module' \
    'used by operations absent from' \
    mut_members_omits_user

# -----------------------------------------------------------------------------
# check_op_file_shape.sh — rustfs/backlog#1895.
#
# Two documents said this guard enforced the One Operation Per File rule from
# P1. The file did not exist. The mutations below are grouped by the three rules
# it carries, and the two `//! Shares:` edges are broken separately in each
# direction, because the interesting property is not that one of them fails but
# that neither can be satisfied from one file alone.
# -----------------------------------------------------------------------------

# -- Rule 1: one operation per file -------------------------------------------

mut_op_shape_second_operation() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/ops/get_bucket_versioning.rs")
p.write_text(p.read_text() + "\nimpl Operation for GetBucketVersioningAgain {}\n")
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'a second operation moving into an existing operation file' \
    'declares 2 `impl Operation`' \
    mut_op_shape_second_operation

# The same declaration one turn of the screw away. `impl<T> Operation for X<T>` is
# what a second operation looks like when the author has read the guard.
mut_op_shape_second_operation_generic() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/ops/list_objects.rs")
p.write_text(p.read_text() + "\nimpl<T> Operation for ListObjectsGeneric<T> {}\n")
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'a second operation written with a generic parameter' \
    'declares 2 `impl Operation`' \
    mut_op_shape_second_operation_generic

mut_op_shape_impl_outside_ops() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/registry/opset.rs")
p.write_text(p.read_text() + "\nimpl Operation for SmuggledIn {}\n")
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'an operation declared outside the ops tree entirely' \
    'declares `impl Operation` outside the ops tree' \
    mut_op_shape_impl_outside_ops

# The other direction of the same control. A guard that rejected every
# `impl Operation` outside `ops/` would reject the fixtures and the third-party
# dialect examples the trait is public for, and would have to be silenced with
# an allowance list within a week. The line is `#[cfg(test)]`, and it is real:
# the same text one scope deeper must pass.
mut_op_shape_impl_in_test_module() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/registry/opset.rs")
p.write_text(
    p.read_text()
    + "\n#[cfg(test)]\nmod smuggle_probe {\n    impl Operation for SmuggledIn {}\n}\n"
)
PYEOF
}
expect_guard_pass check_op_file_shape.sh \
    'the same operation impl inside a #[cfg(test)] module' \
    mut_op_shape_impl_in_test_module

# Dialect crates register extension operations as first-class Operations (rustfs/gateway#769's
# `minio:PutObjectReplica`), so `crates/dialect-*/src/ops` is held to the same shape, not exempted.
mut_op_shape_dialect_second_operation() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/dialect-minio/src/ops/put_object_replica.rs")
if "impl Operation for PutObjectReplica" not in p.read_text():
    raise SystemExit("missing mutation subject: the dialect replica operation file")
p.write_text(p.read_text() + "\nimpl Operation for PutObjectReplicaAgain {}\n")
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'a second operation moving into a dialect operation file' \
    'declares 2 `impl Operation`' \
    mut_op_shape_dialect_second_operation

mut_op_shape_dialect_impl_outside_ops() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/dialect-minio/src/replication.rs")
if "pub fn replication_dialect" not in p.read_text():
    raise SystemExit("missing mutation subject: the replication dialect module")
p.write_text(p.read_text() + "\nimpl Operation for SmuggledReplica {}\n")
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'a dialect operation declared outside its ops tree' \
    'declares `impl Operation` outside the ops tree' \
    mut_op_shape_dialect_impl_outside_ops

mut_op_shape_dialect_unmounted() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/dialect-minio/src/ops/mod.rs")
text = p.read_text()
if text.count("pub mod put_object_replica;\n") != 1:
    raise SystemExit("missing mutation subject: the dialect ops mount")
p.write_text(text.replace("pub mod put_object_replica;\n", "", 1))
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'a dialect operation file no ops/mod.rs mounts' \
    'no `pub mod`' \
    mut_op_shape_dialect_unmounted

mut_op_shape_dialect_misnamed() {
    python3 - <<'PYEOF'
import pathlib
ops = pathlib.Path("crates/dialect-minio/src/ops")
source = ops / "put_object_replica.rs"
mount = ops / "mod.rs"
if not source.exists() or mount.read_text().count("pub mod put_object_replica;\n") != 1:
    raise SystemExit("missing mutation subject: the dialect replica operation file")
source.rename(ops / "replica.rs")
mount.write_text(mount.read_text().replace("pub mod put_object_replica;\n", "pub mod replica;\n", 1))
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'a dialect operation whose file stem is not its snake_case name' \
    'operation name and file name disagree' \
    mut_op_shape_dialect_misnamed

# rustfs/gateway#240. The same smuggled operation, behind a `#[cfg(test)]` item
# that never opens a brace — the `#[path] mod tests;` split this repository uses
# when a file crosses 800 lines. `cfg_test_spans` used to search ahead for the
# next `{` from the attribute, which walks straight past a bodyless declaration
# and lands on the *following* item, suppressing it as though it were test code.
# On origin/main@089f760 this mutation exits 0 in silence while the identical
# `impl Operation for SmuggledIn {}` one line higher — the case above — is
# caught, which is the whole difference: not that the guard is wrong about the
# declaration, but that a declaration is enough to switch it off for what comes
# after. 35 declarations in this workspace have that shape.
mut_op_shape_impl_after_bodyless_cfg_test() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/registry/opset.rs")
p.write_text(
    p.read_text()
    + '\n#[cfg(test)]\n#[path = "opset_probe_tests.rs"]\nmod probe_tests;\n'
    + "\nimpl Operation for SmuggledIn {}\n"
)
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'an operation smuggled in after a bodyless #[cfg(test)] mod declaration' \
    'declares `impl Operation` outside the ops tree' \
    mut_op_shape_impl_after_bodyless_cfg_test

# The same blind spot on rule 1 rather than rule 3, because the two rules read
# the span list through different call sites and one of them passing proves
# nothing about the other. A second operation appended to an existing operation
# file — the git conflict the whole One Operation Per File rule exists to
# prevent — is invisible to origin/main@089f760 once a bodyless declaration sits
# above it, and the guard reports the file as declaring exactly one.
mut_op_shape_second_operation_after_bodyless_cfg_test() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/ops/get_bucket_versioning.rs")
p.write_text(
    p.read_text()
    + '\n#[cfg(test)]\n#[path = "get_bucket_versioning_extra_tests.rs"]\nmod extra_tests;\n'
    + "\nimpl Operation for GetBucketVersioningAgain {}\n"
)
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'a second operation after a bodyless #[cfg(test)] mod declaration' \
    'declares 2 `impl Operation`' \
    mut_op_shape_second_operation_after_bodyless_cfg_test

# And the other direction, so the fix cannot be "stop suppressing test code".
# A real `#[cfg(test)] mod { .. }` that *follows* a bodyless declaration must
# still be a test module: the semicolon ends the declaration and nothing else.
mut_op_shape_test_module_after_bodyless_cfg_test() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/registry/opset.rs")
p.write_text(
    p.read_text()
    + '\n#[cfg(test)]\n#[path = "opset_probe_tests.rs"]\nmod probe_tests;\n'
    + "\n#[cfg(test)]\nmod smuggle_probe {\n    impl Operation for SmuggledIn {}\n}\n"
)
PYEOF
}
expect_guard_pass check_op_file_shape.sh \
    'a #[cfg(test)] module following a bodyless #[cfg(test)] declaration' \
    mut_op_shape_test_module_after_bodyless_cfg_test

mut_op_shape_name_disagrees() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/ops/head_bucket.rs")
t = p.read_text()
old = "impl Operation for HeadBucket {"
if old not in t:
    raise SystemExit("head_bucket impl mutation subject is missing")
p.write_text(t.replace(old, "impl Operation for HeadBucketV2 {", 1))
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'an operation whose name no longer matches the file it lives in' \
    'operation name and file name disagree' \
    mut_op_shape_name_disagrees

mut_op_shape_unmounted_module() {
    python3 - <<'PYEOF'
import pathlib
source = pathlib.Path("crates/core/src/ops/head_bucket.rs").read_text()
pathlib.Path("crates/core/src/ops/head_bucket_v2.rs").write_text(
    source.replace("impl Operation for HeadBucket {", "impl Operation for HeadBucketV2 {", 1)
    .replace("//! `HeadBucket`", "//! `HeadBucketV2`", 1)
)
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'an operation file that no `pub mod` in ops/mod.rs mounts' \
    'mounts it, so nothing compiles it' \
    mut_op_shape_unmounted_module

mut_op_shape_operation_in_shared() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/ops/shared/pagination.rs")
p.write_text(p.read_text() + "\nimpl Operation for ListEverything {}\n")
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'an operation growing inside a shared contract module' \
    'a shared contract declares `impl Operation for' \
    mut_op_shape_operation_in_shared

# -- Rule 2, edge (a): `//! Shares:` against the use graph ----------------------

# Broken so that only edge (a) can see it: the module is added to the operation's
# `Shares:` line *and* to that module's `Members:` list, so the two declarations
# agree with each other and disagree only with the code.
mut_op_shape_shares_claims_unreached() {
    python3 - <<'PYEOF'
import pathlib
op = pathlib.Path("crates/core/src/ops/get_object.rs")
t = op.read_text()
old = "//! Shares: precondition, etag"
if old not in t:
    raise SystemExit("get_object Shares mutation subject is missing")
op.write_text(t.replace(old, "//! Shares: precondition, etag, pagination", 1))

shared = pathlib.Path("crates/core/src/ops/shared/pagination.rs")
s = shared.read_text()
shared.write_text(s.replace("//! Members: ListBuckets", "//! Members: GetObject, ListBuckets", 1))
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'a Shares: line naming a contract the file never reaches' \
    'names `pagination`, which this file never reaches' \
    mut_op_shape_shares_claims_unreached

mut_op_shape_shares_omits_reached() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/ops/get_object.rs")
t = p.read_text()
old = "//! Shares: precondition, etag"
if old not in t:
    raise SystemExit("get_object Shares mutation subject is missing")
p.write_text(t.replace(old, "//! Shares: precondition", 1))
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'a contract the file reaches dropping off its Shares: line' \
    'reaches `shared::etag`, which its `//! Shares:` line does not name' \
    mut_op_shape_shares_omits_reached

# -- Rule 2, edge (b): `//! Shares:` against `//! Members:` ---------------------

# The case edge (b) exists for. The declaration is added as an intra-doc link,
# which is itself a `shared::pagination` reference, so edge (a) is satisfied by
# the very text that makes the claim. Only the far end of the declaration can
# refuse it.
mut_op_shape_shares_link_without_membership() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/ops/get_object.rs")
t = p.read_text()
old = "//! Shares: precondition, etag"
if old not in t:
    raise SystemExit("get_object Shares mutation subject is missing")
new = (
    "//! Shares: precondition, etag. Its listing behaviour is\n"
    "//! [`shared::pagination`](super::shared::pagination)."
)
p.write_text(t.replace(old, new, 1))
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'a Shares: declaration whose far end never agreed to it' \
    '`Members:` does not name it' \
    mut_op_shape_shares_link_without_membership

mut_op_shape_members_without_shares() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/ops/shared/pagination.rs")
t = p.read_text()
old = "//! Members: ListBuckets"
if old not in t:
    raise SystemExit("pagination Members mutation subject is missing")
p.write_text(t.replace(old, "//! Members: HeadBucket, ListBuckets", 1))
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'a Members: list claiming an operation that never claimed it back' \
    'does not name `pagination` back' \
    mut_op_shape_members_without_shares

# -- Rule 2: the declaration itself --------------------------------------------

mut_op_shape_shares_names_non_module() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/ops/get_object.rs")
t = p.read_text()
old = "//! Shares: precondition, etag"
if old not in t:
    raise SystemExit("get_object Shares mutation subject is missing")
p.write_text(t.replace(old, "//! Shares: precondition, etag, range_header", 1))
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'a Shares: line naming something that is not a module at all' \
    'which is not a module under' \
    mut_op_shape_shares_names_non_module

mut_op_shape_shares_line_removed() {
    python3 - <<'PYEOF'
import pathlib
import re
p = pathlib.Path("crates/core/src/ops/get_bucket_location.rs")
t = p.read_text()
if not re.search(r"^//! Shares:", t, re.M):
    raise SystemExit("get_bucket_location Shares mutation subject is missing")
p.write_text(re.sub(r"^//! Shares:.*\n", "", t, count=1, flags=re.M))
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'an operation module with no Shares: declaration at all' \
    'has no `//! Shares:` declaration' \
    mut_op_shape_shares_line_removed

# The other direction of the parse. Seven operations share a rule with a family
# that has no module under `shared/` and say so in prose; a guard that scanned
# the block for module-shaped words would read `precondition` out of the
# sentence "it carries no precondition header" — which is a real sentence in
# `put_object_tagging.rs` — and demand a contract that must not be there.
mut_op_shape_shares_prose_mentions_module() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/ops/list_parts.rs")
t = p.read_text()
old = "//! Shares: the cursor-and-truncation contract with the listing family;"
if old not in t:
    raise SystemExit("list_parts Shares mutation subject is missing")
p.write_text(
    t.replace(old, old + " it needs no pagination cursor codec and no etag comparison;", 1)
)
PYEOF
}
expect_guard_pass check_op_file_shape.sh \
    'prose naming a module in order to say it is not used' \
    mut_op_shape_shares_prose_mentions_module

# -- Rule 3: the ceiling and its absent exemption -------------------------------

mut_op_shape_over_ceiling() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("crates/core/src/ops/get_bucket_location.rs")
p.write_text(p.read_text() + "\n".join("// pad" for _ in range(900)))
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'an operation file growing past the 800-line ceiling' \
    'over the 800-line ceiling' \
    mut_op_shape_over_ceiling

# `check_file_size.sh` accepts this entry — it is a well-formed allowance with a
# real issue behind it. The ops tree is the one place where raising the number is
# not an answer, so the two guards deliberately disagree about this file.
mut_op_shape_ceiling_allowance() {
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("allowances/file_size.txt")
p.write_text(
    p.read_text()
    + "crates/core/src/ops/get_object.rs 1200 https://github.com/rustfs/backlog/issues/1895"
    + " Existing operation; split later.\n"
)
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'the size allowance list being used to raise an operation file ceiling' \
    'the ops tree has no ceiling exemption' \
    mut_op_shape_ceiling_allowance

# The lifecycle and replication validators must share their filter grammar.
# A doc link alone cannot establish the production call between these modules.
mut_rule_filter_local_copy() {
    python3 - "$RULE_FILTER_FAMILY" <<'PYEOF'
from pathlib import Path
import sys
p = Path("crates/core/src/ops/shared") / (sys.argv[1] + ".rs")
p.write_text(p.read_text() + "\nfn validate_filter() {}\n")
PYEOF
}

mut_rule_filter_call_only_in_comment() {
    python3 - "$RULE_FILTER_FAMILY" <<'PYEOF'
from pathlib import Path
import sys
p = Path("crates/core/src/ops/shared") / (sys.argv[1] + ".rs")
family = sys.argv[1]
call = f"rule_filter::{family}("
text = p.read_text()
if call not in text:
    raise SystemExit(f"missing mutation subject in {p}: {call}")
p.write_text(text.replace(call, "independent_filter(")
    + f'\n// {call}filter)\n'
    + f'const _: &str = r#"{call}filter)"#;\n'
    + f'#[cfg(test)]\nfn filter_probe(filter: &Filter) {{ {call}filter); }}\n')
PYEOF
}

# An inline copy under a name the guard does not know: it still has to read
# `And`, which only the filter grammar has any reason to read.
mut_rule_filter_inline_copy() {
    python3 - "$RULE_FILTER_FAMILY" <<'PYEOF'
from pathlib import Path
import sys
p = Path("crates/core/src/ops/shared") / (sys.argv[1] + ".rs")
call = f"rule_filter::{sys.argv[1]}(filter)"
text = p.read_text()
if call not in text:
    raise SystemExit(f"missing mutation subject in {p}: {call}")
p.write_text(text.replace(call, f"{{ let _ = filter.and.is_some(); {call} }}"))
PYEOF
}

for RULE_FILTER_FAMILY in lifecycle replication; do
    expect_fail_with_diagnostic check_op_file_shape.sh \
        "$RULE_FILTER_FAMILY restoring a private filter validator" \
        'filter grammar belongs to shared::rule_filter' \
        mut_rule_filter_local_copy
    expect_fail_with_diagnostic check_op_file_shape.sh \
        "$RULE_FILTER_FAMILY keeping only comments, strings and a test-only shared call" \
        "must call shared::rule_filter::$RULE_FILTER_FAMILY from production code" \
        mut_rule_filter_call_only_in_comment
    expect_fail_with_diagnostic check_op_file_shape.sh \
        "$RULE_FILTER_FAMILY counting a Filter member inline beside the shared call" \
        'reads the Filter member `and`' \
        mut_rule_filter_inline_copy
done

mut_rule_filter_removed() {
    rm crates/core/src/ops/shared/rule_filter.rs
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'the shared filter authority disappearing' \
    'shared filter authority is missing' \
    mut_rule_filter_removed

mut_rule_filter_code_mentions() {
    cat >> crates/core/src/ops/shared/lifecycle.rs <<'RUST'

// fn validate_filter() is intentionally only prose.
const _: &str = r#"fn validate_filter() {}"#;
#[cfg(test)]
mod filter_probe { fn validate_filter() {} }
RUST
}
expect_guard_pass check_op_file_shape.sh \
    'non-production mentions of an old filter validator' \
    mut_rule_filter_code_mentions

# -- The guard's own inputs ----------------------------------------------------

# `[[ -d x ]] || exit 0` is right for an input that may not exist yet and wrong
# for one that always exists: it turns "the tree moved" into a green check.
mut_op_shape_shared_dir_removed() {
    python3 - <<'PYEOF'
import pathlib
import shutil
shutil.rmtree(pathlib.Path("crates/core/src/ops/shared"))
PYEOF
}
expect_fail_with_diagnostic check_op_file_shape.sh \
    'the shared contract directory disappearing, which must fail rather than skip' \
    'required input is missing' \
    mut_op_shape_shared_dir_removed

# -----------------------------------------------------------------------------
# The route-coverage register has to move in both directions or it stops being a
# measurement. Growing it silently is how `PUT /b/k?acl` came to write the ACL
# document over the object; shrinking it silently is how a closed exposure keeps
# being counted, and a count that only ever says the same number is a count nobody
# reads. The mutation removes the first live debt row rather than naming one
# operation, because successful route work deliberately retires those names.
#
# Once the register reaches zero debt, there is no live row to remove. The
# missing-row control therefore creates one real exposure from the guard's two
# runtime inputs: it marks a modeled operation deferred and makes its generated
# selector name the wrong operation. The stale-row control still mutates the
# register directly. Together they keep both directions observable at zero.
# -----------------------------------------------------------------------------

mut_forgotten_exposure() {
    python3 - <<'PYEOF'
from pathlib import Path

overlay = Path("model/overlays/ops/object-advanced.toml")
overlay.write_text(
    overlay.read_text()
    + '\n[[deferred]]\noperations = ["UpdateObjectEncryption"]\n'
)

routes = Path("generated/routes.rs")
text = routes.read_text()
subject = 'operation: "UpdateObjectEncryption"'
if text.count(subject) != 1:
    raise SystemExit("route-coverage generated-row mutation subject is not unique")
routes.write_text(text.replace(subject, 'operation: "UpdateObjectEncryptionProbe"', 1))
PYEOF
}
expect_fail check_route_coverage.sh \
    'a swallowed operation missing from the register' mut_forgotten_exposure

mut_stale_exposure() {
    printf 'NoSuchOperation -> NoSuchNeighbour\n' >>scripts/allowances/route-coverage-allowances.txt
}
expect_fail check_route_coverage.sh \
    'a register entry for an exposure that no longer exists' mut_stale_exposure

# -----------------------------------------------------------------------------
# The cross-precedence shadowing record has exactly one hand-written source:
# `model/overlays/route.toml`. Until rustfs/gateway#4 it had two — the overlay it
# was specified to have, and six files of Rust that were the one the runtime
# actually read. Two sources for one fact is the defect this repository keeps
# re-finding, and it is invisible in review because both copies read like the
# reviewed answer.
#
# Five controls, one per way the single source can be lost: the field that says
# why is deleted; the field that says where it comes from is emptied; a
# declaration is written back into Rust; a pair is added straight to the
# generated file; and the generated file is left behind by an overlay edit.
#
# The fourth and fifth are the two directions of the same equality. An earlier
# draft of the fourth used `GetBucketAcl over ListObjects`, which the overlay
# already declares — so the guard passed, and the control proved nothing. The
# pair it injects now is the reverse of a declared one, which no overlay entry
# can carry because a winner has the lower precedence by definition.
# -----------------------------------------------------------------------------

mut_route_shadowing_reason_deleted() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/route.toml")
text = path.read_text()
anchor = 'reason   = "A request carrying both ?location and ?list-type=2'
if text.count(anchor) != 1:
    raise SystemExit("shadowing reason mutation anchor is not unique")
path.write_text(text.replace(anchor, 'unrelated_note = "' + anchor.split('"', 1)[1], 1))
PYEOF
}
expect_fail check_route_shadowing_authority.sh \
    'a shadowing pair whose reason was deleted' mut_route_shadowing_reason_deleted \
    'an undeclared ordering is a guess'

mut_route_shadowing_evidence_emptied() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/route.toml")
text = path.read_text()
anchor = 'evidence = ["get-bucket-location", "list-objects-v2"]'
if anchor not in text:
    raise SystemExit("shadowing evidence mutation anchor is missing")
path.write_text(text.replace(anchor, "evidence = []", 1))
PYEOF
}
expect_fail check_route_shadowing_authority.sh \
    'a shadowing pair whose evidence list was emptied' mut_route_shadowing_evidence_emptied \
    'an unsourced ordering is a guess'

mut_route_shadowing_declared_in_rust() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/route/shadowing.rs")
text = path.read_text()
anchor = "pub const SHADOWING: ShadowingDecls = ShadowingDecls::over(&[data::SHADOWING]);"
if text.count(anchor) != 1:
    raise SystemExit("shadowing runtime mutation anchor is not unique")
residual = """const EXTRA: &[ShadowingDecl] = &[ShadowingDecl {
    winner: "GetBucketAcl",
    shadowed: "ListObjects",
    reason: "a hand-written declaration kept beside the generated one",
    evidence: &["https://example.invalid - a fabricated citation"],
}];

pub const SHADOWING: ShadowingDecls = ShadowingDecls::over(&[data::SHADOWING, EXTRA]);"""
path.write_text(text.replace(anchor, residual, 1))
PYEOF
}
expect_fail check_route_shadowing_authority.sh \
    'a shadowing declaration written back into Rust beside the generated one' \
    mut_route_shadowing_declared_in_rust \
    'a hand-written `ShadowingDecl` literal'

mut_route_shadowing_added_to_generated_only() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("generated/route_shadowing.rs")
text = path.read_text()
anchor = "pub const SHADOWING: &[ShadowingDecl] = &[\n"
if text.count(anchor) != 1:
    raise SystemExit("generated shadowing mutation anchor is not unique")
injected = anchor + """    ShadowingDecl {
        winner: "ListObjects",
        shadowed: "GetBucketAcl",
        reason: "added straight into the generated file, bypassing the overlay entirely",
        evidence: &[
            "https://example.invalid - a fabricated citation",
        ],
    },
"""
path.write_text(text.replace(anchor, injected, 1))
PYEOF
}
expect_fail check_route_shadowing_authority.sh \
    'a shadowing pair added straight to the generated file' \
    mut_route_shadowing_added_to_generated_only \
    'The generated file is output, never a place to add a pair'

mut_route_shadowing_overlay_not_regenerated() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/route.toml")
text = path.read_text()
anchor = '[[shadowing]]\nwinner   = "GetBucketLocation"\nshadowed = "ListObjectsV2"'
if text.count(anchor) != 1:
    raise SystemExit("shadowing pair mutation anchor is not unique")
path.write_text(text.replace(anchor, anchor.replace('"ListObjectsV2"', '"ListParts"'), 1))
PYEOF
}
expect_fail check_route_shadowing_authority.sh \
    'an overlay pair that never reached the generated file' \
    mut_route_shadowing_overlay_not_regenerated \
    'never reached generated/route_shadowing.rs'

# -----------------------------------------------------------------------------
# `generated/OPERATIONS.json` is the machine-readable half of the wire reverse
# index: seven fields per operation, one index inverting each. An agent holding
# a failure has a query key, a header or an error code — not an operation name —
# so a field that quietly stopped being emitted leaves a document that answers
# every question except the one it exists for, and nothing about its shape says
# so.
#
# Seven controls. Three on the field set (a field deleted, the order changed, an
# index dropped), two on the equality between forward table and index — one per
# direction, because an index that keeps a name after the fact that put it there
# was deleted reads exactly like a live one — one on membership drifting from
# `OPERATIONS.md`, and one on the emitter's own `FIELDS` declaration, which is
# where a field would be dropped in practice.
# -----------------------------------------------------------------------------

mut_operations_json_field_deleted() {
    python3 - <<'PYEOF'
import json
import pathlib

path = pathlib.Path("generated/OPERATIONS.json")
document = json.loads(path.read_text(encoding="utf-8"))
for entry in document["operations"].values():
    entry.pop("host_classes", None)
document.pop("by_host_class", None)
path.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
PYEOF
}
expect_fail check_operations_json_fields.sh \
    'an operation entry that lost one of its seven wire fields' \
    mut_operations_json_field_deleted \
    'carries the wrong wire fields'

mut_operations_json_fields_reordered() {
    python3 - <<'PYEOF'
import json
import pathlib

path = pathlib.Path("generated/OPERATIONS.json")
document = json.loads(path.read_text(encoding="utf-8"))
name = sorted(document["operations"])[0]
entry = document["operations"][name]
document["operations"][name] = {key: entry[key] for key in reversed(list(entry))}
path.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
PYEOF
}
expect_fail check_operations_json_fields.sh \
    'an operation entry whose fields were silently reordered' \
    mut_operations_json_fields_reordered \
    'out of order'

mut_operations_json_index_dropped() {
    python3 - <<'PYEOF'
import json
import pathlib

path = pathlib.Path("generated/OPERATIONS.json")
document = json.loads(path.read_text(encoding="utf-8"))
document.pop("by_error_code", None)
path.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
PYEOF
}
expect_fail check_operations_json_fields.sh \
    'a reverse index removed, leaving a field that cannot be entered from the wire' \
    mut_operations_json_index_dropped \
    'cannot be entered from the wire'

mut_operations_json_forward_fact_unindexed() {
    python3 - <<'PYEOF'
import json
import pathlib

path = pathlib.Path("generated/OPERATIONS.json")
document = json.loads(path.read_text(encoding="utf-8"))
key = next(code for code, names in document["by_error_code"].items() if len(names) > 1)
document["by_error_code"][key] = document["by_error_code"][key][1:]
path.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
PYEOF
}
expect_fail check_operations_json_fields.sh \
    'an operation whose error code never reached the index' \
    mut_operations_json_forward_fact_unindexed \
    'but by_error_code'

mut_operations_json_stale_index_row() {
    python3 - <<'PYEOF'
import json
import pathlib

path = pathlib.Path("generated/OPERATIONS.json")
document = json.loads(path.read_text(encoding="utf-8"))
# Delete the fact, keep the index row. This is the direction a forward-only
# walk cannot see: every remaining fact is still indexed, so a check that only
# asked "is each fact indexed?" would report success over a stale row.
name = next(op for op, entry in sorted(document["operations"].items()) if entry["query_keys"])
document["operations"][name]["query_keys"] = []
path.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
PYEOF
}
expect_fail check_operations_json_fields.sh \
    'an index row that outlived the fact that built it' \
    mut_operations_json_stale_index_row \
    'a stale index outlives the fact that built it'

mut_operations_json_operation_dropped() {
    python3 - <<'PYEOF'
import json
import pathlib

path = pathlib.Path("generated/OPERATIONS.json")
document = json.loads(path.read_text(encoding="utf-8"))
name = "GetObject"
document["operations"].pop(name)
for index in [key for key in document if key.startswith("by_")]:
    for key in list(document[index]):
        remaining = [op for op in document[index][key] if op != name]
        if remaining:
            document[index][key] = remaining
        else:
            document[index].pop(key)
path.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
PYEOF
}
expect_fail check_operations_json_fields.sh \
    'an operation documented in OPERATIONS.md with no entry in the index' \
    mut_operations_json_operation_dropped \
    'but has no entry'

mut_operations_json_emitter_field_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/codegen/src/emit/operations_json.rs")
text = path.read_text(encoding="utf-8")
declaration = 'pub const FIELDS: [&str; 7] = ['
if text.count(declaration) != 1:
    raise SystemExit("operations_json FIELDS mutation anchor is not unique")
text = text.replace(declaration, 'pub const FIELDS: [&str; 6] = [', 1)
field = '    "host_classes",\n    "error_codes",'
if text.count(field) != 1:
    raise SystemExit("operations_json host_classes mutation anchor is not unique")
path.write_text(text.replace(field, '    "error_codes",', 1), encoding="utf-8")
PYEOF
}
expect_fail check_operations_json_fields.sh \
    'the emitter declaring six wire fields instead of seven' \
    mut_operations_json_emitter_field_removed \
    'this guard and the wire index require'

# -----------------------------------------------------------------------------
# `generated/error_codes.json` and `generated/ERROR_CODES.md` are the published
# renderings of the error-status authority (rustfs/backlog#1694). `spec verify`
# proves each equals what the emitter emits; it cannot notice that the emitter
# emits a document nobody can use. Five controls, one per property the guard
# owns: the field set, an index, an index that stopped inverting its own field,
# the two renderings disagreeing, and the 5xx allowlist drifting off the band.
# -----------------------------------------------------------------------------

mut_error_codes_json_field_deleted() {
    python3 - <<'PYEOF'
import json
import pathlib

path = pathlib.Path("generated/error_codes.json")
document = json.loads(path.read_text(encoding="utf-8"))
for entry in document["codes"].values():
    entry.pop("server_fault", None)
document.pop("by_server_fault", None)
path.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
PYEOF
}
expect_fail check_error_codes_json_fields.sh \
    'a code entry that lost one of its three fields' \
    mut_error_codes_json_field_deleted \
    'carries the wrong fields'

mut_error_codes_json_index_dropped() {
    python3 - <<'PYEOF'
import json
import pathlib

path = pathlib.Path("generated/error_codes.json")
document = json.loads(path.read_text(encoding="utf-8"))
document.pop("by_status", None)
path.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
PYEOF
}
expect_fail check_error_codes_json_fields.sh \
    'the status index removed, leaving a field that cannot be entered by value' \
    mut_error_codes_json_index_dropped \
    'cannot be entered by value'

mut_error_codes_json_index_outlives_its_fact() {
    python3 - <<'PYEOF'
import json
import pathlib

path = pathlib.Path("generated/error_codes.json")
document = json.loads(path.read_text(encoding="utf-8"))
name = next(code for code, entry in document["codes"].items() if entry["status"] == 404)
document["codes"][name]["status"] = 409
path.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
PYEOF
}
expect_fail check_error_codes_json_fields.sh \
    'a code whose status moved while the index kept pointing at the old one' \
    mut_error_codes_json_index_outlives_its_fact \
    'a stale index outlives the fact that built it'

mut_error_codes_markdown_row_deleted() {
    python3 - <<'PYEOF'
import pathlib
import re

path = pathlib.Path("generated/ERROR_CODES.md")
text = path.read_text(encoding="utf-8")
head, _, table = text.partition("## Every code")
rows = [line for line in table.splitlines() if re.match(r"^\| `\w+` \| \d+ \|", line)]
if not rows:
    raise SystemExit("ERROR_CODES.md carries no code rows to delete")
path.write_text(head + "## Every code" + table.replace(rows[0] + "\n", "", 1), encoding="utf-8")
PYEOF
}
expect_fail check_error_codes_json_fields.sh \
    'a code the JSON carries and the Markdown no longer renders' \
    mut_error_codes_markdown_row_deleted \
    'but is absent from'

mut_error_codes_json_fault_flag_flipped() {
    python3 - <<'PYEOF'
import json
import pathlib

path = pathlib.Path("generated/error_codes.json")
document = json.loads(path.read_text(encoding="utf-8"))
name = next(code for code, entry in document["codes"].items() if entry["status"] >= 500)
document["codes"][name]["server_fault"] = False
document["by_server_fault"]["true"].remove(name)
document["by_server_fault"].setdefault("false", []).append(name)
document["by_server_fault"]["false"].sort()
path.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
PYEOF
}
expect_fail check_error_codes_json_fields.sh \
    'a 5xx code dropped off the allowlist an SDK reads to decide what to retry' \
    mut_error_codes_json_fault_flag_flipped \
    'is not flagged `server_fault`'

# -----------------------------------------------------------------------------
# `ci.yml` defers the fuzz job on purpose — a full run does not fit the ten
# minute gate — so nothing in CI compiles `fuzz/`. That makes an unregistered
# target invisible: the file sits in the tree, `cargo fuzz list` never names it,
# and it reads exactly like a target that runs clean.
#
# Four controls, one per way a target stops being one: it is never declared, it
# is declared against a path that moved, it loses the macro that makes it fuzz
# anything, and it loses the attribute that hands main to libFuzzer.
# -----------------------------------------------------------------------------

mut_fuzz_target_unregistered() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("fuzz/Cargo.toml")
text = path.read_text(encoding="utf-8")
anchor = '[[bin]]\nname = "route_disjoint"'
if text.count(anchor) != 1:
    raise SystemExit("fuzz registration mutation anchor is not unique")
path.write_text(text[: text.index(anchor)], encoding="utf-8")
PYEOF
}
expect_fail check_fuzz_targets_registered.sh \
    'a fuzz target file that no [[bin]] declares' mut_fuzz_target_unregistered \
    'never runs and never says so'

mut_fuzz_target_path_moved() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("fuzz/Cargo.toml")
text = path.read_text(encoding="utf-8")
anchor = 'path = "fuzz_targets/route_disjoint.rs"'
if text.count(anchor) != 1:
    raise SystemExit("fuzz path mutation anchor is not unique")
path.write_text(text.replace(anchor, 'path = "fuzz_targets/route_disjoint_moved.rs"', 1), encoding="utf-8")
PYEOF
}
expect_fail check_fuzz_targets_registered.sh \
    'a [[bin]] declared against a path that is not there' mut_fuzz_target_path_moved \
    'but the file is'

mut_fuzz_target_macro_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("fuzz/fuzz_targets/route_disjoint.rs")
text = path.read_text(encoding="utf-8")
anchor = "fuzz_target!(|input: &[u8]| {"
if text.count(anchor) != 1:
    raise SystemExit("fuzz macro mutation anchor is not unique")
path.write_text(text.replace(anchor, "fn never_called(input: &[u8]) {", 1), encoding="utf-8")
PYEOF
}
expect_fail check_fuzz_targets_registered.sh \
    'a target that kept its name and lost its fuzz_target! body' mut_fuzz_target_macro_removed \
    'runs nothing, and reports no failure'

mut_fuzz_target_no_main_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("fuzz/fuzz_targets/route_disjoint.rs")
text = path.read_text(encoding="utf-8")
anchor = "#![no_main]\n"
if text.count(anchor) != 1:
    raise SystemExit("fuzz no_main mutation anchor is not unique")
path.write_text(text.replace(anchor, "", 1), encoding="utf-8")
PYEOF
}
expect_fail check_fuzz_targets_registered.sh \
    'a target that stopped handing main to libFuzzer' mut_fuzz_target_no_main_removed \
    'libFuzzer supplies main'

# -----------------------------------------------------------------------------
# A conformance case may only declare what the harness reads. Twice already a
# case declared a precondition — `setup.buckets[].object_lock`,
# `connection.pipeline` — that was parsed, schema-checked and then dropped, so
# the case measured a scenario other than the one it described and reported
# green. The guard runs the corpus and audits which schema keys the harness
# actually read.
#
# The controls mutate the SCHEMA in the sandbox rather than the harness,
# because check_case_keys_honoured.sh audits the sandbox's corpus using the
# binary built next to this script: a harness mutation would need a cold
# compile of the whole workspace inside the sandbox, and this suite has a
# 480-second wall-clock budget (declared at the top of this file).
#
# The first control is the defect itself: a key the frozen schema allows and
# nothing reads. The second is the guard's other end — an entry in DECLARED
# that no longer names a field, which is how an exemption list rots into a
# list of excuses for fields that stopped existing.
# -----------------------------------------------------------------------------

mut_unread_schema_key() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
schema["$defs"]["expect"]["properties"]["nothing_reads_this"] = {
    "type": "boolean",
    "description": "A declaration no code looks at. The guard must say so.",
}
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
# Executed by the build-guard worker above.

mut_declaration_for_a_dropped_field() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
# `evidence.kind` is carried in keys::DECLARED as inert. Removing the field
# leaves the entry naming something the schema no longer declares.
del schema["$defs"]["evidence"]["properties"]["kind"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
# Executed by the build-guard worker above.



# -----------------------------------------------------------------------------
# P8-01 freezes the case language and the baseline contract. These controls
# remove one required dimension at a time, weaken evidence, add a regression to
# the baseline, and replace the raw socket write with an HTTP client dependency.
# A green guard without these mutations would only restate the intended policy.
# -----------------------------------------------------------------------------

mut_schema_chunk_timing() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["dataChunk"]["properties"]["delay_ms"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the chunk arrival timing field removed from the frozen schema' mut_schema_chunk_timing

mut_schema_abnormal_close() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
schema["$defs"]["controlChunk"]["properties"]["action"]["enum"].remove("half_close")
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'half-close removed from abnormal termination actions' mut_schema_abnormal_close

mut_schema_stream_error() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["expect"]["properties"]["body_bytes_before_error"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the mid-stream response byte counter removed' mut_schema_stream_error

mut_schema_stream_error_optional() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
for condition in schema["$defs"]["expect"]["allOf"]:
    if condition.get("if", {}).get("properties", {}).get("kind", {}).get("const") == "stream_error":
        condition["then"]["required"].remove("body_bytes_before_error")
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the mid-stream byte counter made optional' mut_schema_stream_error_optional

mut_schema_clock() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["clock"]["properties"]["fixed"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the fixed clock injection field removed' mut_schema_clock

mut_schema_reuse() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["connection"]["properties"]["reuse"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the connection reuse field removed' mut_schema_reuse

mut_schema_events() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["expect"]["properties"]["events"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the response event sequence removed' mut_schema_events

mut_schema_events_optional() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
for condition in schema["$defs"]["expect"]["allOf"]:
    if condition.get("if", {}).get("properties", {}).get("kind", {}).get("const") == "event_stream":
        condition["then"]["required"].remove("events")
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the event sequence made optional for an event-stream expectation' mut_schema_events_optional

mut_schema_golden() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["bodyExpectation"]["properties"]["golden"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the byte-exact golden field removed' mut_schema_golden

mut_schema_header_absence() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["expect"]["properties"]["headers_absent"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the absent-header assertion removed' mut_schema_header_absence

mut_schema_transport_field() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
schema["properties"]["transport"] = {"type": "string"}
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'transport made case-selectable instead of runner-injected' mut_schema_transport_field

mut_missing_evidence() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("conformance/cases/acl/c-acl-0002.toml")
text = path.read_text()
start = text.index("[[case.evidence]]")
end = text.find("\n[", start + 2)
path.write_text(text[:start] + (text[end + 1:] if end >= 0 else ""))
PYEOF
}
expect_fail check_evidence_shape.sh \
    'a case with its evidence removed' mut_missing_evidence

mut_pasted_evidence() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("conformance/cases/acl/c-acl-0002.toml")
text = path.read_text()
needle = 'summary = "'
at = text.index(needle) + len(needle)
path.write_text(text[:at] + ("x" * 201) + text[at:])
PYEOF
}
expect_fail check_evidence_shape.sh \
    'an evidence summary longer than the compliance ceiling' mut_pasted_evidence

mut_baseline_regression() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/baseline.json")
baseline = json.loads(path.read_text())
case = next(case for case, verdict in baseline["cases"].items() if verdict == "passed")
baseline["cases"][case] = "failed"
path.write_text(json.dumps(baseline, indent=2) + "\n")
PYEOF
}
expect_fail check_baseline_ratchet.sh \
    'a newly failing case added to the baseline' mut_baseline_regression

# The other way to buy silence, and the cheaper one: a skip carries no diagnosis to argue with.
# Until rustfs/gateway#192 the runner could not call a skip a regression at all, so this shape was
# free — #203's `object/` domain and #214's thirty-nine `acl` cases both went quiet underneath a
# green ratchet.
mut_baseline_downgraded_to_a_skip() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/baseline.json")
baseline = json.loads(path.read_text())
case = next(case for case, verdict in baseline["cases"].items() if verdict == "passed")
baseline["cases"][case] = "skipped"
path.write_text(json.dumps(baseline, indent=2) + "\n")
PYEOF
}
expect_fail check_baseline_ratchet.sh \
    'a passing case downgraded to a skip in the baseline' mut_baseline_downgraded_to_a_skip

mut_baseline_deleted() {
    rm -f conformance/baseline.json
}
expect_fail check_baseline_ratchet.sh \
    "the guard's baseline input deleted, which must fail rather than skip" mut_baseline_deleted

# ---------------------------------------------------------------------------
# External acceptance suites (P8-05). The same ratchet argument as the baseline
# above, one layer out: the suite is external, so the tolerated set, the marker
# filter, the pin and the report tool are each a way to make a weekly run look
# clean without the implementation improving.
# ---------------------------------------------------------------------------

append_xfail_entry() {
    python3 - "$1" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path("ci/s3tests/xfail.txt")
path.write_text(path.read_text() + sys.argv[1] + "\n")
PYEOF
}

set_xfail_generation() {
    python3 - "$1" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path("ci/s3tests/xfail.txt")
text = path.read_text()
if "# generation:" not in text:
    raise SystemExit("xfail generation mutation subject is missing")
path.write_text(text.replace("# generation: 1", f"# generation: {sys.argv[1]}", 1))
PYEOF
}

# The cheapest way to turn a red external suite green is to paste its failures into the
# tolerated set. This is the mutation that has to stay red for the ratchet to mean anything.
mut_xfail_entry_added_without_generation() {
    append_xfail_entry "s3tests_boto3.functional.test_s3::test_multipart_upload_small"
}
expect_fail check_xfail_ratchet.sh \
    'a tolerated failure appended without raising the generation' mut_xfail_entry_added_without_generation

# The escape has to work, or the ratchet cannot record a first baseline at all and somebody
# deletes it. Proving it works is also what stops this guard becoming stuck on one answer.
mut_xfail_entry_added_with_generation() {
    append_xfail_entry "s3tests_boto3.functional.test_s3::test_multipart_upload_small"
    set_xfail_generation 2
}
expect_guard_pass check_xfail_ratchet.sh \
    'a tolerated failure added in the same change that raises the generation' \
    mut_xfail_entry_added_with_generation

mut_xfail_generation_jumped() {
    append_xfail_entry "s3tests_boto3.functional.test_s3::test_multipart_upload_small"
    set_xfail_generation 9
}
expect_fail check_xfail_ratchet.sh \
    'a generation jumped several steps at once, banking room for later additions' \
    mut_xfail_generation_jumped

mut_xfail_generation_backwards() {
    set_xfail_generation 0
}
expect_fail check_xfail_ratchet.sh \
    'a generation moved backwards' mut_xfail_generation_backwards

mut_xfail_header_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/s3tests/xfail.txt")
lines = [line for line in path.read_text().splitlines() if not line.startswith("# generation:")]
path.write_text("\n".join(lines) + "\n")
PYEOF
}
expect_fail check_xfail_ratchet.sh \
    'the generation header removed, which would leave nothing to ratchet against' \
    mut_xfail_header_removed

mut_xfail_deleted() {
    rm -f ci/s3tests/xfail.txt
}
expect_fail check_xfail_ratchet.sh \
    "the guard's xfail input deleted, which must fail rather than skip" mut_xfail_deleted

# An excluded case is an absent case: it leaves no failure to tolerate, no entry to shrink
# and nothing in the report to grep for. That makes widening the filter strictly cheaper
# than widening the xfail list, and strictly less visible.
mut_filter_adds_an_exclusion() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/s3tests/filter.txt")
path.write_text(path.read_text() + "and not test_bucket_policy\n")
PYEOF
}
expect_fail check_s3tests_filter.sh \
    'a marker exclusion added to the s3-tests filter' mut_filter_adds_an_exclusion

# The 39 fails_on_rgw cases are the ones Ceph's own gateway does not pass, which usually
# means they encode the correct AWS behaviour. Excluding them reads as consistency with the
# other fails_on_* markers and is instead the most valuable subset of the suite deleted.
mut_filter_excludes_fails_on_rgw() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/s3tests/filter.txt")
path.write_text(path.read_text() + "and not fails_on_rgw\n")
PYEOF
}
expect_fail check_s3tests_filter.sh \
    'fails_on_rgw excluded, deleting the cases that encode correct AWS behaviour' \
    mut_filter_excludes_fails_on_rgw

mut_filter_stops_excluding_fails_on_aws() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/s3tests/filter.txt")
lines = [line for line in path.read_text().splitlines() if "fails_on_aws" not in line or line.startswith("#")]
path.write_text("\n".join(lines) + "\n")
PYEOF
}
expect_fail check_s3tests_filter.sh \
    'fails_on_aws no longer excluded, admitting RGW-specific behaviour as a target' \
    mut_filter_stops_excluding_fails_on_aws

mut_filter_emptied() {
    python3 - <<'PYEOF'
import pathlib

pathlib.Path("ci/s3tests/filter.txt").write_text("# every clause removed\n")
PYEOF
}
expect_fail check_s3tests_filter.sh \
    'every clause removed, leaving a marker expression that selects everything' mut_filter_emptied

mut_pin_becomes_a_branch() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/s3tests/pins.env")
text = path.read_text()
head, _, tail = text.partition("S3TESTS_SHA=")
path.write_text(head + "S3TESTS_SHA=master\n" + tail.split("\n", 1)[1])
PYEOF
}
expect_fail check_suites_pinned.sh \
    'the s3-tests pin replaced by a branch name, making two runs incomparable' \
    mut_pin_becomes_a_branch

mut_suite_workflow_enters_the_pull_request_gate() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/e2e-s3tests.yml")
text = path.read_text()
path.write_text(text.replace("on:\n  schedule:", "on:\n  pull_request:\n  schedule:", 1))
PYEOF
}
expect_fail check_suites_pinned.sh \
    'a 30-90 minute external suite added to the ten-minute pull-request gate' \
    mut_suite_workflow_enters_the_pull_request_gate

mut_suite_image_pulled_by_a_moving_tag() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/e2e-s3tests.yml")
path.write_text(path.read_text() + "\n        run: docker run minio/mint:latest\n")
PYEOF
}
expect_fail check_suites_pinned.sh \
    'a container image pulled by a moving tag rather than by digest' \
    mut_suite_image_pulled_by_a_moving_tag

mut_s3tests_toolchain_pin_deleted() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/e2e-s3tests.yml")
text = path.read_text()
old = "uses: dtolnay/rust-toolchain@6bed0761d98439e5a578e2877258200ad565ba87"
if old not in text:
    raise SystemExit("s3-tests Rust toolchain pin fixture is missing")
path.write_text(text.replace(old, "uses: dtolnay/rust-toolchain@stable", 1))
PYEOF
}
expect_fail check_suites_pinned.sh \
    'the weekly s3-tests Rust toolchain action changed from an immutable pin to a branch' \
    mut_s3tests_toolchain_pin_deleted \
    'must install Rust through a toolchain action pinned to an exact 40-hex revision'

mut_s3tests_toolchain_selection() {
    python3 - "$1" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path(".github/workflows/e2e-s3tests.yml")
text = path.read_text()
old = "        with:\n          toolchain: stable\n"
if text.count(old) != 1:
    raise SystemExit("s3-tests explicit Rust toolchain fixture is missing or ambiguous")
mode = sys.argv[1]
replacement = {
    "deleted": "",
    "changed": "        with:\n          toolchain: beta\n",
    "misplaced": "",
}[mode]
text = text.replace(old, replacement, 1)
if mode == "misplaced":
    text = text.replace("      - name: Build the compatibility SUT\n",
                        "      - name: Build the compatibility SUT\n" + old, 1)
path.write_text(text)
PYEOF
}
mut_s3tests_toolchain_selection_deleted() { mut_s3tests_toolchain_selection deleted; }
mut_s3tests_toolchain_selection_changed() { mut_s3tests_toolchain_selection changed; }
mut_s3tests_toolchain_selection_misplaced() { mut_s3tests_toolchain_selection misplaced; }
expect_fail check_suites_pinned.sh \
    'the weekly Rust action loses its explicit toolchain input' \
    mut_s3tests_toolchain_selection_deleted \
    'must set with.toolchain to stable on the pinned Rust action step'
expect_fail check_suites_pinned.sh \
    'the weekly Rust action selects beta instead of stable' \
    mut_s3tests_toolchain_selection_changed \
    'must set with.toolchain to stable on the pinned Rust action step'
expect_fail check_suites_pinned.sh \
    'the stable toolchain input is attached to the build step instead of the Rust action' \
    mut_s3tests_toolchain_selection_misplaced \
    'must set with.toolchain to stable on the pinned Rust action step'

mut_s3tests_release_build_deleted() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/e2e-s3tests.yml")
text = path.read_text()
old = "run: cargo build --release -p rustfs-gateway-compat-sut"
if old not in text:
    raise SystemExit("s3-tests release build fixture is missing")
path.write_text(text.replace(old, "run: cargo build -p rustfs-gateway-compat-sut", 1))
PYEOF
}
expect_fail check_suites_pinned.sh \
    'the weekly s3-tests job stops building the release compatibility SUT' \
    mut_s3tests_release_build_deleted \
    'must run `cargo build --release -p rustfs-gateway-compat-sut`'

mut_s3tests_release_build_moved_after_suite() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/e2e-s3tests.yml")
text = path.read_text()
step = (
    "      - name: Build the compatibility SUT\n"
    "        run: cargo build --release -p rustfs-gateway-compat-sut\n\n"
)
if step not in text:
    raise SystemExit("s3-tests release build step fixture is missing")
path.write_text(text.replace(step, "", 1) + "\n" + step)
PYEOF
}
expect_fail check_suites_pinned.sh \
    'the compatibility SUT release build moved after the suite invocation' \
    mut_s3tests_release_build_moved_after_suite \
    'must install Rust and build the release compatibility SUT before invoking'

mut_s3tests_default_command_stops_being_overridable() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/s3tests/run.sh")
text = path.read_text()
old = ': "${GATEWAY_SUT_COMMAND:='
if old not in text:
    raise SystemExit("s3-tests overridable command fixture is missing")
path.write_text(text.replace(old, ': "${GATEWAY_SUT_COMMAND=', 1))
PYEOF
}
expect_fail check_suites_pinned.sh \
    'the local compatibility SUT command stops being an overridable default' \
    mut_s3tests_default_command_stops_being_overridable \
    'must default GATEWAY_SUT_COMMAND with the overridable `:=` form before sut_start'

mut_s3tests_default_command_binary_deleted() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/s3tests/run.sh")
text = path.read_text()
old = "${ROOT_DIR}/target/release/compat-sut"
if old not in text:
    raise SystemExit("s3-tests compatibility SUT binary fixture is missing")
path.write_text(text.replace(old, "/bin/false", 1))
PYEOF
}
expect_fail check_suites_pinned.sh \
    'the default command stops launching the built compatibility SUT' \
    mut_s3tests_default_command_binary_deleted \
    'default GATEWAY_SUT_COMMAND must launch target/release/compat-sut'

mut_s3tests_default_command_flag_deleted() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/s3tests/run.sh")
text = path.read_text()
old = "--lc-debug-interval"
if old not in text:
    raise SystemExit("s3-tests compatibility SUT flag fixture is missing")
path.write_text(text.replace(old, "--removed-lc-debug-interval", 1))
PYEOF
}
expect_fail check_suites_pinned.sh \
    'a required compatibility SUT launch flag is deleted' \
    mut_s3tests_default_command_flag_deleted \
    'default GATEWAY_SUT_COMMAND is missing required flags: --lc-debug-interval'

mut_s3tests_exports_moved_after_start() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/s3tests/run.sh")
text = path.read_text()
export_line = "export S3TESTS_BUCKET_PREFIX S3TESTS_LC_DEBUG_INTERVAL\n"
if text.count(export_line) != 1 or "\nsut_start\n" not in text:
    raise SystemExit("s3-tests export ordering fixture is missing or ambiguous")
text = text.replace(export_line, "", 1)
path.write_text(text.replace("\nsut_start\n", "\nsut_start\n" + export_line, 1))
PYEOF
}
expect_fail check_suites_pinned.sh \
    'configured s3-tests values move after the SUT launch boundary' \
    mut_s3tests_exports_moved_after_start \
    'must export every configured S3TESTS value before sut_start'

mut_s3tests_external_endpoint_loses_precedence() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/lib/sut.sh")
text = path.read_text()
endpoint = 'if [[ -n "${GATEWAY_SUT_ENDPOINT:-}" ]]; then'
command = 'if [[ -z "${GATEWAY_SUT_COMMAND:-}" ]]; then'
if text.count(endpoint) != 1 or text.count(command) != 1:
    raise SystemExit("SUT endpoint/command precedence fixture is missing or ambiguous")
placeholder = "if [[ S3TESTS_SUT_PRECEDENCE_PLACEHOLDER ]]; then"
text = text.replace(endpoint, placeholder, 1).replace(command, endpoint, 1)
path.write_text(text.replace(placeholder, command, 1))
PYEOF
}
expect_fail check_suites_pinned.sh \
    'the external endpoint branch moves behind the local command requirement' \
    mut_s3tests_external_endpoint_loses_precedence \
    'must prefer GATEWAY_SUT_ENDPOINT before requiring GATEWAY_SUT_COMMAND'

mut_vendored_suite_tree() {
    mkdir -p tests/s3-tests
    printf 'from setuptools import setup\nsetup(name="s3tests")\n' >tests/s3-tests/setup.py
}
expect_fail check_no_vendored_suites.sh \
    'a copy of the external suite tree committed to this repository' mut_vendored_suite_tree

mut_vendored_suite_by_content() {
    mkdir -p tests/support
    printf 'import s3tests_boto3.functional as functional\n\nprint(functional)\n' >tests/support/helpers.py
}
expect_fail check_no_vendored_suites.sh \
    'a renamed file that is still the external suite by its imports' mut_vendored_suite_by_content

mut_third_party_licence_dropped() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("THIRD-PARTY-NOTICES.md")
text = path.read_text()
at = text.index("### Ceph s3-tests")
end = text.index("### MinIO mint")
path.write_text(text[:at] + text[at:end].replace("**MIT**", "permissive") + text[end:])
PYEOF
}
expect_fail check_third_party_doc.sh \
    'a suite licence recorded as prose instead of an SPDX identifier' mut_third_party_licence_dropped

# A conclusion nobody can re-derive is re-derived from scratch by everyone who needs it, and
# mint is the row people get wrong: it is Apache-2.0 while the server beside it is not.
mut_third_party_verification_dropped() {
    python3 - <<'PYEOF'
import pathlib
import re

path = pathlib.Path("THIRD-PARTY-NOTICES.md")
text = path.read_text()
at = text.index("### MinIO mint")
end = text.index("### MinIO server")
section = re.sub(r"`gh api[^`]*`", "the upstream repository", text[at:end])
path.write_text(text[:at] + section + text[end:])
PYEOF
}
expect_fail check_third_party_doc.sh \
    'a licence review that states its conclusion without the command that verified it' \
    mut_third_party_verification_dropped

mut_third_party_pin_drifts_from_the_runner() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/s3tests/pins.env")
text = path.read_text()
needle = "S3TESTS_SHA=5522d1c351f75bc00ae0f64f742f3f095f5939d9"
if needle not in text:
    raise SystemExit("third-party pin mutation subject is missing")
path.write_text(text.replace(needle, "S3TESTS_SHA=0123456789abcdef0123456789abcdef01234567", 1))
PYEOF
}
expect_fail check_third_party_doc.sh \
    'the reviewed commit and the commit the runner clones drifting apart' \
    mut_third_party_pin_drifts_from_the_runner

# The seven checks in AGENTS.md "Measurement" were all this shape: a judgement that stopped
# judging and read exactly like a judgement that passed. These three are the same shape one
# level out, and the weekly job's entire value rests on them staying red.
mut_report_never_sees_a_failure() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/s3tests/report.py")
text = path.read_text()
needle = '        elif element.find("failure") is not None:\n            outcome = "failed"\n'
if needle not in text:
    raise SystemExit("report failure-parsing mutation subject is missing")
path.write_text(text.replace(needle, "", 1))
PYEOF
}
expect_fail check_s3tests_report.sh \
    'the report no longer reading a failure element, so every red run looks clean' \
    mut_report_never_sees_a_failure

mut_report_tolerates_every_failure() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/s3tests/report.py")
text = path.read_text()
needle = "            (known if case.id in tolerated else regression).append(case.id)"
if needle not in text:
    raise SystemExit("report tolerance mutation subject is missing")
path.write_text(text.replace(needle, "            known.append(case.id)", 1))
PYEOF
}
expect_fail check_s3tests_report.sh \
    'every failure treated as tolerated, so no regression can ever fail the job' \
    mut_report_tolerates_every_failure

mut_report_records_a_dead_service_as_failures() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/s3tests/report.py")
text = path.read_text()
needle = "    if errored == len(cases):"
if needle not in text:
    raise SystemExit("report environment-detection mutation subject is missing")
path.write_text(text.replace(needle, "    if False:", 1))
PYEOF
}
expect_fail check_s3tests_report.sh \
    'a run where nothing was reachable recorded as ~980 regressions instead of an environment failure' \
    mut_report_records_a_dead_service_as_failures

mut_sut_is_always_ready() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/lib/sut.sh")
text = path.read_text()
needle = 'sut_wait_ready() {\n    local host="$1" port="$2" deadline="$3" pid="${4:-}"\n'
if needle not in text:
    raise SystemExit("sut readiness mutation subject is missing")
path.write_text(text.replace(needle, needle + "    return 0\n", 1))
PYEOF
}
expect_fail check_sut_launcher.sh \
    'a readiness probe that reports ready without a socket ever being bound' mut_sut_is_always_ready

mut_sut_renders_a_blank_credential() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("ci/lib/sut.sh")
text = path.read_text()
needle = "if missing:\n"
if needle not in text:
    raise SystemExit("sut render-refusal mutation subject is missing")
path.write_text(text.replace(needle, "if False:\n", 1))
PYEOF
}
expect_fail check_sut_launcher.sh \
    'a configuration rendered with a blank credential, which reads as a signing defect' \
    mut_sut_renders_a_blank_credential

# ---------------------------------------------------------------------------
# MinIO mint (P8-05, rustfs/backlog#1764). Every case names the diagnostic it
# expects, so a guard that goes red for an unrelated reason does not count.
# ---------------------------------------------------------------------------

# mint_mutate <path> <old> <new>: replaces the first occurrence of <old>; a literal `\n` in
# either argument is a newline. A missing subject is refused, so a mutation that stopped
# matching cannot pass as a guard that stopped catching.
mint_mutate() {
    python3 - "$@" <<'PYEOF'
import pathlib
import sys

path, old, new = sys.argv[1], sys.argv[2].replace("\\n", "\n"), sys.argv[3].replace("\\n", "\n")
target = pathlib.Path(path)
text = target.read_text()
if old not in text:
    raise SystemExit(f"missing mutation subject in {path}: {old}")
target.write_text(text.replace(old, new, 1))
PYEOF
}

# mint_generation [path]: the generation the baseline carries. Read from the file and never
# spelled in a case: a subject naming a generation value stops matching the first time the
# reviewed baseline raises it (generation 2, rustfs/gateway#723).
mint_generation() {
    local line pattern='^# generation: ([0-9]+)$'
    while IFS= read -r line; do
        if [[ "$line" =~ $pattern ]]; then
            printf '%s\n' "${BASH_REMATCH[1]}"
            return 0
        fi
    done <"${1:-ci/mint/baseline.txt}"
    return 1
}
# An unreadable header leaves a value no subject matches, so every case below fails loudly.
MINT_GENERATION="$(mint_generation "${REPO_ROOT}/ci/mint/baseline.txt")" || MINT_GENERATION="unreadable"

# mint_set_generation <n>: rewrites the sandbox baseline's header, whatever it says now.
mint_set_generation() {
    mint_mutate ci/mint/baseline.txt "# generation: $(mint_generation)" "# generation: $1"
}

MINT_REPORT=ci/mint/report.py

mut_mint_report_counts_na_as_failure() {
    mint_mutate "$MINT_REPORT" '        elif status == "NA":\n            tally.na += 1' \
        '        elif status == "NA":\n            tally.failed += 1'
}
expect_fail check_mint_report.sh 'mint NA records counted as failures' \
    mut_mint_report_counts_na_as_failure 'NA is reported apart and is neither a failure nor a pass'

mut_mint_report_skips_malformed_json() {
    mint_mutate "$MINT_REPORT" \
        '            problems.append(f"{sdk}: record {ordinal} in {sdk}/log.json is not valid JSON")\n            return None' \
        '            break'
}
expect_fail check_mint_report.sh 'a truncated mint record silently ends the log instead of failing closed' \
    mut_mint_report_skips_malformed_json 'a truncated JSON record is an incomplete run'

mut_mint_report_accepts_unknown_status() {
    mint_mutate "$MINT_REPORT" '        else:\n            problems.append(\n                f"{sdk}: record {ordinal} has status' \
        '        else:\n            continue\n            problems.append(\n                f"{sdk}: record {ordinal} has status'
}
expect_fail check_mint_report.sh 'a mint record with an unknown status silently ignored' \
    mut_mint_report_accepts_unknown_status 'an unknown status is an incomplete run'

mut_mint_report_ignores_unknown_suite() {
    mint_mutate "$MINT_REPORT" 'if entry.is_dir() and entry.name not in sdks:' 'if False:'
}
expect_fail check_mint_report.sh 'a mint suite outside the census ignored' \
    mut_mint_report_ignores_unknown_suite 'a suite the runner never asked for is an incomplete run'

mut_mint_report_tolerates_missing_record() {
    mint_mutate "$MINT_REPORT" '        problems.append(f"{sdk}: produced no record ({sdk}/log.json is missing)")\n' ''
}
expect_fail check_mint_report.sh 'a baseline SDK that left no mint record dropped from the verdict' \
    mut_mint_report_tolerates_missing_record 'a baseline SDK that left no record is an incomplete run'

mut_mint_report_tolerates_regression() {
    mint_mutate "$MINT_REPORT" '    if failed > baseline:\n        return "REGRESSION"' \
        '    if False:\n        return "REGRESSION"'
}
expect_fail check_mint_report.sh 'a mint failure count above the baseline read as tolerated' \
    mut_mint_report_tolerates_regression 'a count above the baseline is a REGRESSION and fails'

mut_mint_report_hides_improvement() {
    mint_mutate "$MINT_REPORT" '    if failed < baseline:\n        return "IMPROVED"' \
        '    if False:\n        return "IMPROVED"'
}
expect_fail check_mint_report.sh 'a mint count below the baseline no longer asks for the baseline to shrink' \
    mut_mint_report_hides_improvement 'a count below the baseline is IMPROVED, not silently KNOWN'

mut_mint_report_environment_as_result() {
    mint_mutate "$MINT_REPORT" '    if problems:\n        code = EXIT_ENVIRONMENT' '    if False:\n        code = EXIT_ENVIRONMENT'
}
expect_fail check_mint_report.sh 'an incomplete mint run judged as a result instead of exiting 3' \
    mut_mint_report_environment_as_result 'is an incomplete run'

mut_mint_report_tolerates_silent_sdk_failure() {
    mint_mutate "$MINT_REPORT" 'if outcomes.get(sdk) == "FAILED" and tally.failed == 0:' 'if False:'
}
expect_fail check_mint_report.sh 'a mint SDK that exited non-zero without a FAIL record read as clean' \
    mut_mint_report_tolerates_silent_sdk_failure 'an SDK whose runner failed without a FAIL record is an incomplete run'

mut_mint_report_ignores_unstarted_sdk() {
    mint_mutate "$MINT_REPORT" '            problems.append(f"{sdk}: the console never reported it starting")' '            pass'
}
expect_fail check_mint_report.sh 'a mint SDK the console never started accepted' \
    mut_mint_report_ignores_unstarted_sdk 'an SDK the console never saw start is an incomplete run'

mut_mint_report_ignores_cut_short_sdk() {
    mint_mutate "$MINT_REPORT" \
        '            problems.append(f"{name}: the console never reported it finishing; the run was cut short")\n            continue' \
        '            continue'
}
expect_fail check_mint_report.sh 'a mint SDK cut short mid-run accepted' \
    mut_mint_report_ignores_cut_short_sdk 'an SDK the console never saw finish is an incomplete run'

mut_mint_report_ignores_baseline_census() {
    mint_mutate "$MINT_REPORT" '    if missing:\n        problems.append("the baseline has no line for: "' \
        '    if False:\n        problems.append("the baseline has no line for: "'
}
expect_fail check_mint_report.sh 'a mint SDK without a baseline line dropped from the verdict' \
    mut_mint_report_ignores_baseline_census "a baseline without an SDK's line is an incomplete run"

mut_mint_report_keeps_generation() {
    mint_mutate "$MINT_REPORT" 'f"# generation: {generation + 1}",' 'f"# generation: {generation}",'
}
expect_fail check_mint_report.sh 'a mint record proposal that does not raise the generation' \
    mut_mint_report_keeps_generation 'record mode proposes generation + 1'

mut_mint_report_proposes_incomplete_run() {
    mint_mutate "$MINT_REPORT" '        if problems:\n            # A stale' '        if False:\n            # A stale'
}
expect_fail check_mint_report.sh 'a partial mint run turned into a baseline proposal' \
    mut_mint_report_proposes_incomplete_run 'record mode writes no proposal for an incomplete run'

mut_mint_report_may_overwrite_baseline() {
    mint_mutate "$MINT_REPORT" '    if record_path is not None and record_path.resolve() == baseline_path.resolve():' \
        '    if False:'
}
expect_fail check_mint_report.sh 'mint record mode allowed to overwrite the reviewed baseline' \
    mut_mint_report_may_overwrite_baseline 'record mode refuses to overwrite the reviewed baseline'

mut_mint_report_redacts_nothing() {
    mint_mutate "$MINT_REPORT" '    for pattern in REDACTIONS:' '    for pattern in ():'
}
expect_fail check_mint_report.sh 'mint evidence redaction reduced to the secret literal alone' \
    mut_mint_report_redacts_nothing 'redaction left'

mut_mint_report_leaks_error_text() {
    mint_mutate "$MINT_REPORT" '            tally.failing.append(printable(document.get("function")))' \
        '            tally.failing.append(printable(document.get("function")) + str(document.get("error")))'
}
expect_fail check_mint_report.sh "upstream failure text carried into the uploaded mint aggregate" \
    mut_mint_report_leaks_error_text "the aggregate report never carries a record's error text"

# Excluded SDKs (rustfs/backlog#1764, generation 1): run and reported, never judged, and never
# a place for a counted SDK's records to disappear into.
mut_mint_report_ignores_exclusions() {
    mint_mutate "$MINT_REPORT" '            if sdk in exclusions:\n                observed: list[str] = []' \
        '            if False:\n                observed: list[str] = []'
}
expect_fail check_mint_report.sh 'a mint exclusion that no longer takes the SDK out of the completeness check' \
    mut_mint_report_ignores_exclusions 'an excluded SDK that left no record is reported apart and the run is complete'

mut_mint_report_excluded_may_hide_counted() {
    mint_mutate "$MINT_REPORT" 'sorted(records_naming(log_dir, sdk, counted_names).items())' 'sorted({}.items())'
}
expect_fail check_mint_report.sh "a counted mint SDK's records hidden inside an excluded SDK's log" \
    mut_mint_report_excluded_may_hide_counted "an excluded SDK whose log carries a counted SDK's records is an incomplete run"

mut_mint_report_hides_recovery() {
    mint_mutate "$MINT_REPORT" '        recovered = tally is not None and not observed' '        recovered = False'
}
expect_fail check_mint_report.sh 'an excluded mint SDK that writes valid records again never flagged' \
    mut_mint_report_hides_recovery 'flagged RECOVERED and still not judged'

mut_mint_report_recovers_on_records_alone() {
    mint_mutate "$MINT_REPORT" '        recovered = tally is not None and not observed' '        recovered = tally is not None'
}
expect_fail check_mint_report.sh 'an excluded mint SDK flagged RECOVERED while its failure is still unattributed' \
    mut_mint_report_recovers_on_records_alone 'whose runner failed without a FAIL record is not RECOVERED'

mut_mint_report_judges_excluded_as_zero() {
    mint_mutate "$MINT_REPORT" '            exclusions[parts[0]] = Exclusion(parts[2], " ".join(parts[3:]))\n            continue' \
        '            counts[parts[0]] = 0\n            continue'
}
expect_fail check_mint_report.sh 'an excluded mint SDK judged against a zero count' \
    mut_mint_report_judges_excluded_as_zero 'is reported apart and the run is complete'

mut_mint_report_drops_excluded_section() {
    mint_mutate "$MINT_REPORT" '    lines += render_excluded(excluded)\n' ''
}
expect_fail check_mint_report.sh 'excluded mint SDKs silently dropped from the uploaded summary' \
    mut_mint_report_drops_excluded_section 'an excluded SDK that left no record is reported apart'

mut_mint_report_proposal_drops_exclusion() {
    mint_mutate "$MINT_REPORT" \
        '            lines.append(f"{sdk} {EXCLUDED} {entry.exclusion.owner} {entry.exclusion.reason}")' '            pass'
}
expect_fail check_mint_report.sh 'a mint record proposal that loses the exclusion list' \
    mut_mint_report_proposal_drops_exclusion 'record mode carries an exclusion into the proposal unchanged'

mut_mint_report_excluded_leave_console() {
    mint_mutate "$MINT_REPORT" 'outcomes = read_progress(Path(args.progress), sdks, problems)' \
        'outcomes = read_progress(Path(args.progress), [sdk for sdk in sdks if sdk not in exclusions], problems)'
}
expect_fail check_mint_report.sh 'an excluded mint SDK no longer has to start and finish in order' \
    mut_mint_report_excluded_leave_console 'an excluded SDK the console never saw start is still an incomplete run'

mut_mint_report_accepts_ownerless_exclusion() {
    mint_mutate "$MINT_REPORT" '            if len(parts) < 3 or not OWNER.fullmatch(parts[2]):' '            if False:'
}
expect_fail check_mint_report.sh 'a mint exclusion accepted without an owning issue' \
    mut_mint_report_accepts_ownerless_exclusion 'an exclusion without an owning issue is refused'

mut_mint_report_accepts_foreign_owner() {
    mint_mutate "$MINT_REPORT" 'github\.com/rustfs/(?:gateway|backlog)/issues/' 'github\.com/[^/]+/[^/]+/issues/'
}
expect_fail check_mint_report.sh 'a mint exclusion owned by an issue outside this project' \
    mut_mint_report_accepts_foreign_owner 'an exclusion owned outside this project is refused'

mut_mint_report_accepts_reasonless_exclusion() {
    mint_mutate "$MINT_REPORT" '            if len(parts[3:]) < REASON_MIN_WORDS:' '            if False:'
}
expect_fail check_mint_report.sh 'a mint exclusion accepted without a reason' \
    mut_mint_report_accepts_reasonless_exclusion 'an exclusion without a reason is refused'

mut_mint_input_deleted() {
    rm -f ci/mint/report.py
}
expect_fail check_suites_pinned.sh 'the mint reporter deleted from the runner inputs' \
    mut_mint_input_deleted 'the mint runner is incomplete; required inputs are missing: ci/mint/report.py'

mut_mint_image_short_digest() {
    mint_mutate ci/mint/pins.env \
        'MINT_IMAGE=docker.io/minio/mint@sha256:08a05e68893c68be2a83b6f79556853ed6aa3c6c9e64c823a00853e4e55d2200' \
        'MINT_IMAGE=docker.io/minio/mint@sha256:08a05e68'
}
expect_fail check_suites_pinned.sh 'the mint image pinned by a truncated digest' \
    mut_mint_image_short_digest 'must set MINT_IMAGE to docker.io/minio/mint@sha256:<64 hex>'

mut_mint_image_by_tag() {
    mint_mutate ci/mint/pins.env \
        'MINT_IMAGE=docker.io/minio/mint@sha256:08a05e68893c68be2a83b6f79556853ed6aa3c6c9e64c823a00853e4e55d2200' \
        'MINT_IMAGE=docker.io/minio/mint:edge'
}
expect_fail check_suites_pinned.sh 'the mint image pinned by a tag an archived repository can re-point' \
    mut_mint_image_by_tag 'pulls docker.io/minio/mint:edge, a moving tag'

mut_mint_platform_changed() {
    mint_mutate ci/mint/pins.env 'MINT_PLATFORM=linux/amd64' 'MINT_PLATFORM=linux/arm64'
}
expect_fail check_suites_pinned.sh 'the mint platform moved off the pinned linux/amd64 manifest' \
    mut_mint_platform_changed 'must set MINT_PLATFORM=linux/amd64'

mut_mint_sdk_listed_twice() {
    mint_mutate ci/mint/pins.env 'MINT_SDKS=".minio-dotnet ' 'MINT_SDKS=".minio-dotnet .minio-dotnet '
}
expect_fail check_suites_pinned.sh 'a mint SDK named twice in the census' \
    mut_mint_sdk_listed_twice 'must name each SDK in MINT_SDKS exactly once'

mut_mint_workflow_enters_the_pull_request_gate() {
    mint_mutate .github/workflows/e2e-mint.yml 'on:\n  schedule:' 'on:\n  pull_request:\n  schedule:'
}
expect_fail check_suites_pinned.sh 'the mint workflow added to the ten-minute pull-request gate' \
    mut_mint_workflow_enters_the_pull_request_gate 'e2e-mint.yml triggers on pull_request'

mut_mint_workflow_loses_its_schedule() {
    mint_mutate .github/workflows/e2e-mint.yml '    - cron: "0 4 * * 2"\n' ''
}
expect_fail check_suites_pinned.sh 'the mint workflow left with no schedule' \
    mut_mint_workflow_loses_its_schedule 'e2e-mint.yml declares no cron schedule'

mut_mint_workflow_loses_dispatch() {
    mint_mutate .github/workflows/e2e-mint.yml '  workflow_dispatch:\n' ''
}
expect_fail check_suites_pinned.sh 'the mint workflow can no longer be dispatched for a record run' \
    mut_mint_workflow_loses_dispatch 'must stay dispatchable'

mut_mint_workflow_uploads_raw_evidence() {
    mint_mutate .github/workflows/e2e-mint.yml 'path: ${{ runner.temp }}/mint-out' 'path: ${{ runner.temp }}/mint-work'
}
expect_fail check_suites_pinned.sh 'the mint workflow uploading the raw console and per-SDK JSON' \
    mut_mint_workflow_uploads_raw_evidence 'must upload exactly one artifact'

mut_mint_workflow_action_by_tag() {
    mint_mutate .github/workflows/e2e-mint.yml \
        'uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2' 'uses: actions/upload-artifact@v4'
}
expect_fail check_suites_pinned.sh 'a mint workflow action pinned by a moving tag' \
    mut_mint_workflow_action_by_tag 'every action is pinned by a 40-hex commit'

mut_mint_workflow_debug_build() {
    mint_mutate .github/workflows/e2e-mint.yml 'run: cargo build --release -p rustfs-gateway-compat-sut' \
        'run: cargo build -p rustfs-gateway-compat-sut'
}
expect_fail check_suites_pinned.sh 'the mint workflow stops building the release compatibility SUT' \
    mut_mint_workflow_debug_build 'e2e-mint.yml must run `cargo build --release -p rustfs-gateway-compat-sut`'

mut_mint_workflow_build_after_runner() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/e2e-mint.yml")
text = path.read_text()
step = (
    "      - name: Build the compatibility SUT\n"
    "        run: cargo build --release -p rustfs-gateway-compat-sut\n\n"
)
if step not in text:
    raise SystemExit("missing mutation subject: the mint release build step")
path.write_text(text.replace(step, "", 1) + "\n" + step)
PYEOF
}
expect_fail check_suites_pinned.sh 'the mint release SUT build moved after the runner invocation' \
    mut_mint_workflow_build_after_runner \
    'e2e-mint.yml must install Rust and build the release compatibility SUT before invoking ci/mint/run.sh'

mut_mint_workflow_never_runs_the_runner() {
    mint_mutate .github/workflows/e2e-mint.yml 'ci/mint/run.sh --mode' 'ci/mint/other.sh --mode'
}
expect_fail check_suites_pinned.sh 'the mint workflow stops invoking its runner' \
    mut_mint_workflow_never_runs_the_runner 'e2e-mint.yml never invokes ci/mint/run.sh'

mut_mint_workflow_files_issue_for_environment() {
    mint_mutate .github/workflows/e2e-mint.yml "if: failure() && steps.suite.outputs.status == '1'" 'if: failure()'
}
expect_fail check_suites_pinned.sh 'the mint workflow filing a regression issue for an incomplete run' \
    mut_mint_workflow_files_issue_for_environment 'the issue step must run only on'

mut_mint_runner_bypasses_shared_sut() {
    mint_mutate ci/mint/run.sh '\nsut_start\n' '\n"$MINT_SUT_BINARY" &\n'
}
expect_fail check_suites_pinned.sh 'the mint runner launching its own SUT outside ci/lib/sut.sh' \
    mut_mint_runner_bypasses_shared_sut 'must start or adopt its SUT through ci/lib/sut.sh'

mut_mint_runner_default_flag_deleted() {
    mint_mutate ci/mint/run.sh '--access-key' '--removed-access-key'
}
expect_fail check_suites_pinned.sh 'the mint default SUT command loses its credential flag' \
    mut_mint_runner_default_flag_deleted 'is missing required flags: --access-key'

mut_mint_runner_stops_naming_sdks() {
    mint_mutate ci/mint/run.sh '"$MINT_IMAGE" "${MINT_SDK_LIST[@]}" >"$CONSOLE"' '"$MINT_IMAGE" >"$CONSOLE"'
}
expect_fail check_suites_pinned.sh 'the mint runner lets mint pick its SDKs, skipping hidden ones' \
    mut_mint_runner_stops_naming_sdks 'lost its suite run naming every SDK explicitly'

mut_mint_runner_skips_census() {
    mint_mutate ci/mint/run.sh '-A /mint/run/core' '-A /mint'
}
expect_fail check_suites_pinned.sh 'the mint runner no longer checks the image census' \
    mut_mint_runner_skips_census 'lost its SDK census check against the image'

mut_mint_runner_pulls_without_platform() {
    mint_mutate ci/mint/run.sh 'docker pull --quiet --platform "$MINT_PLATFORM" "$MINT_IMAGE"' \
        'docker pull --quiet "$MINT_IMAGE"'
}
expect_fail check_suites_pinned.sh 'the mint image pulled for whatever platform the host is' \
    mut_mint_runner_pulls_without_platform 'must pull the pinned image with --platform'

mut_mint_runner_runs_without_platform() {
    mint_mutate ci/mint/run.sh '    --platform "$MINT_PLATFORM" \' '    \'
}
expect_fail check_suites_pinned.sh 'the mint suite container run without the pinned platform' \
    mut_mint_runner_runs_without_platform 'must run the suite container with --platform'

mut_mint_runner_skips_redaction() {
    mint_mutate ci/mint/run.sh 'report.py" redact --secret-env' 'report.py" judge --secret-env'
}
expect_fail check_suites_pinned.sh 'the mint runner judging evidence nobody redacted' \
    mut_mint_runner_skips_redaction 'lost its redaction of the copied evidence'

mut_mint_runner_reports_before_log() {
    mint_mutate ci/mint/run.sh 'MINT_LOG="${WORK_DIR}/mint-log"\n' \
        'python3 "${ROOT_DIR}/ci/mint/report.py" "${REPORT_ARGS[@]}"\nMINT_LOG="${WORK_DIR}/mint-log"\n'
}
expect_fail check_suites_pinned.sh 'the mint report written before /mint/log is copied out' \
    mut_mint_runner_reports_before_log 'in that order'

mut_mint_baseline_raised_without_generation() {
    mint_mutate ci/mint/baseline.txt '\nminio-go 0\n' '\nminio-go 3\n'
}
expect_fail check_mint_baseline.sh 'a mint count raised without raising the generation' \
    mut_mint_baseline_raised_without_generation 'went up without raising the generation'

mut_mint_baseline_raised_with_generation() {
    mint_mutate ci/mint/baseline.txt '\nminio-go 0\n' '\nminio-go 3\n'
    mint_set_generation "$((MINT_GENERATION + 1))"
}
expect_guard_pass check_mint_baseline.sh 'a mint count raised in the change that raises the generation by one' \
    mut_mint_baseline_raised_with_generation

mut_mint_baseline_generation_jumped() {
    mint_mutate ci/mint/baseline.txt '\nminio-go 0\n' '\nminio-go 3\n'
    mint_set_generation "$((MINT_GENERATION + 2))"
}
expect_fail check_mint_baseline.sh 'a mint generation jumped to bank room for later increases' \
    mut_mint_baseline_generation_jumped "the generation jumped ${MINT_GENERATION} -> $((MINT_GENERATION + 2))"

mut_mint_baseline_generation_backwards() {
    mint_set_generation "$((MINT_GENERATION + 1))"
    git add ci/mint/baseline.txt
    git -c user.name=t -c user.email=t@t commit -qm 'mint baseline generation raised'
    mint_set_generation "$MINT_GENERATION"
}
expect_fail check_mint_baseline.sh 'a mint generation moved backwards' \
    mut_mint_baseline_generation_backwards "the generation went backwards, $((MINT_GENERATION + 1)) -> ${MINT_GENERATION}"

mut_mint_baseline_drops_an_sdk() {
    mint_mutate ci/mint/baseline.txt '\nminio-go 0\n' '\n'
}
expect_fail check_mint_baseline.sh 'a mint SDK the runner runs left without a baseline line' \
    mut_mint_baseline_drops_an_sdk 'no line for [minio-go]'

mut_mint_census_drops_an_sdk() {
    mint_mutate ci/mint/pins.env 'MINT_SDKS=".minio-dotnet ' 'MINT_SDKS="'
}
expect_fail check_mint_baseline.sh 'a mint baseline line for an SDK the census no longer runs' \
    mut_mint_census_drops_an_sdk 'lines for SDKs the runner does not run [.minio-dotnet]'

mut_mint_baseline_duplicate_sdk() {
    mint_mutate ci/mint/baseline.txt '\nminio-go 0\n' '\nminio-go 0\nminio-go 0\n'
}
expect_fail check_mint_baseline.sh 'a mint SDK listed twice in the baseline' \
    mut_mint_baseline_duplicate_sdk 'minio-go is listed more than once'

# The exclusion list shrinks freely and widens only with the generation, and every entry
# names an in-project owner and a reason. The java-v2 line is generation 1's, reviewed, and
# its owner is the only exclusion owned by #719, so a first-occurrence mutation hits it.
MINT_JAVA_V2_EXCLUSION='aws-sdk-java-v2 excluded https://github.com/rustfs/gateway/issues/719 every test returns without a record unless ENABLE_HTTPS=1, and the SUT serves plaintext only'

mut_mint_baseline_excludes_without_generation() {
    mint_mutate ci/mint/baseline.txt '\nminio-go 0\n' \
        '\nminio-go excluded https://github.com/rustfs/gateway/issues/718 an SDK hidden to make a red run green\n'
}
expect_fail check_mint_baseline.sh 'a counted mint SDK excluded without raising the generation' \
    mut_mint_baseline_excludes_without_generation '1 SDK(s) newly excluded without raising the generation'

mut_mint_baseline_excludes_with_generation() {
    mut_mint_baseline_excludes_without_generation
    mint_set_generation "$((MINT_GENERATION + 1))"
}
expect_guard_pass check_mint_baseline.sh 'a mint SDK excluded in the change that raises the generation by one' \
    mut_mint_baseline_excludes_with_generation

mut_mint_baseline_restores_excluded_sdk() {
    mint_mutate ci/mint/baseline.txt "$MINT_JAVA_V2_EXCLUSION" 'aws-sdk-java-v2 4'
}
expect_guard_pass check_mint_baseline.sh 'an excluded mint SDK put back under a count, which only narrows' \
    mut_mint_baseline_restores_excluded_sdk

mut_mint_baseline_exclusion_without_owner() {
    mint_mutate ci/mint/baseline.txt 'aws-sdk-java-v2 excluded https://github.com/rustfs/gateway/issues/719 ' \
        'aws-sdk-java-v2 excluded '
}
expect_fail check_mint_baseline.sh 'a mint exclusion that names no owning issue' \
    mut_mint_baseline_exclusion_without_owner 'the exclusion of aws-sdk-java-v2 names no owner'

mut_mint_baseline_exclusion_foreign_owner() {
    mint_mutate ci/mint/baseline.txt 'https://github.com/rustfs/gateway/issues/719' 'https://github.com/minio/mint/issues/719'
}
expect_fail check_mint_baseline.sh 'a mint exclusion owned by an issue outside this project' \
    mut_mint_baseline_exclusion_foreign_owner 'the exclusion of aws-sdk-java-v2 names no owner'

mut_mint_baseline_exclusion_without_reason() {
    mint_mutate ci/mint/baseline.txt "$MINT_JAVA_V2_EXCLUSION" \
        'aws-sdk-java-v2 excluded https://github.com/rustfs/gateway/issues/719 flaky'
}
expect_fail check_mint_baseline.sh 'a mint exclusion whose reason is one word' \
    mut_mint_baseline_exclusion_without_reason 'the exclusion of aws-sdk-java-v2 gives no reason'

mut_mint_baseline_excluded_and_counted() {
    mint_mutate ci/mint/baseline.txt '\nminio-go 0\n' '\nminio-go 0\naws-sdk-java-v2 0\n'
}
expect_fail check_mint_baseline.sh 'an excluded mint SDK that also carries a count' \
    mut_mint_baseline_excluded_and_counted 'aws-sdk-java-v2 is listed more than once'

mut_mint_baseline_excludes_outside_census() {
    mint_mutate ci/mint/baseline.txt '\nminio-go 0\n' \
        '\nminio-go 0\naws-sdk-rust excluded https://github.com/rustfs/gateway/issues/718 an SDK the pinned image never runs\n'
    mint_set_generation "$((MINT_GENERATION + 1))"
}
expect_fail check_mint_baseline.sh 'a mint exclusion for an SDK outside the pinned census' \
    mut_mint_baseline_excludes_outside_census 'lines for SDKs the runner does not run [aws-sdk-rust]'

mut_mint_baseline_header_removed() {
    mint_mutate ci/mint/baseline.txt "# generation: ${MINT_GENERATION}\n" ''
}
expect_fail check_mint_baseline.sh 'the mint baseline generation header removed' \
    mut_mint_baseline_header_removed 'no `# generation: <n>` header'

mut_mint_baseline_deleted() {
    rm -f ci/mint/baseline.txt
}
expect_fail check_mint_baseline.sh "the mint baseline deleted, which must fail rather than skip" \
    mut_mint_baseline_deleted 'required input is missing: ci/mint/baseline.txt'

mut_mint_pin_drifts_from_the_notice() {
    mint_mutate ci/mint/pins.env \
        'MINT_IMAGE=docker.io/minio/mint@sha256:08a05e68893c68be2a83b6f79556853ed6aa3c6c9e64c823a00853e4e55d2200' \
        'MINT_IMAGE=docker.io/minio/mint@sha256:1111111111111111111111111111111111111111111111111111111111111111'
}
expect_fail check_third_party_doc.sh 'the mint runner pulling a digest the licence review never saw' \
    mut_mint_pin_drifts_from_the_notice 'does not record the image digest the mint runner pulls'

mut_mint_notice_drops_the_digest() {
    mint_mutate THIRD-PARTY-NOTICES.md \
        'docker.io/minio/mint@sha256:08a05e68893c68be2a83b6f79556853ed6aa3c6c9e64c823a00853e4e55d2200' \
        'docker.io/minio/mint:edge'
}
expect_fail check_third_party_doc.sh 'the mint licence review recording a tag instead of the pulled digest' \
    mut_mint_notice_drops_the_digest 'does not record the image digest the mint runner pulls'

# Built from fragments: check_no_vendored_suites.sh reads this file too, and a literal copy
# of the preamble here would make the self-test the violation it tests for.
mut_vendored_mint_runner_by_content() {
    local prefix='MINT_'
    mkdir -p tools/sdk-runner
    printf '#!/bin/bash\n%sMODE=${%sMODE:-core}\n%sDATA_DIR=${%sDATA_DIR:-/mint/data}\n' \
        "$prefix" "$prefix" "$prefix" "$prefix" >tools/sdk-runner/entry.sh
}
expect_fail check_no_vendored_suites.sh "a renamed copy of mint's runner, still mint by its preamble" \
    mut_vendored_mint_runner_by_content "carries mint's runner environment preamble"

mut_vendored_mint_run_tree() {
    mkdir -p third_party/mint/run/core/awscli
    printf 'echo placeholder\n' >third_party/mint/run/core/awscli/run.sh
}
expect_fail check_no_vendored_suites.sh "mint's per-SDK runner tree committed to this repository" \
    mut_vendored_mint_run_tree "sits under a vendored copy of mint's runner tree"

mut_runner_sdk_dependency() {
    add_conformance_dependency 'aws-sdk-s3 = "1"'
}
expect_fail check_runner_raw_bytes.sh \
    'an S3 SDK dependency added to the conformance runner' mut_runner_sdk_dependency

mut_runner_raw_write_removed() {
    sed 's/\.write_all(bytes)/.write_all(\&[])/' crates/conformance/src/socket.rs \
        >crates/conformance/src/socket.rs.mut
    mv crates/conformance/src/socket.rs.mut crates/conformance/src/socket.rs
}
expect_fail check_runner_raw_bytes.sh \
    'the request bytes no longer written verbatim to the socket' mut_runner_raw_write_removed

mut_runner_raw_write_hidden_in_comment() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/conformance/src/socket.rs")
text = path.read_text()
old = "            .write_all(bytes)"
new = "            .write_all(&[]) // .write_all(bytes)"
if old not in text:
    raise SystemExit("raw write call not found")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_runner_raw_bytes.sh \
    'the raw-write marker surviving only inside a comment' mut_runner_raw_write_hidden_in_comment

mut_runner_raw_write_hidden_in_string() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/conformance/src/socket.rs")
text = path.read_text()
old = "            .write_all(bytes)"
new = '            .write_all(&[])\n            .and(Ok({ let _marker = ".write_all(bytes)"; }))?'
if old not in text:
    raise SystemExit("raw write call not found")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_runner_raw_bytes.sh \
    'the raw-write marker surviving only inside a string' mut_runner_raw_write_hidden_in_string

mut_runner_conn_call_bypassed() {
    sed 's/connection\.write(\&head\.bytes)/connection.write(\&[])/' crates/conformance/src/conn.rs \
        >crates/conformance/src/conn.rs.mut
    mv crates/conformance/src/conn.rs.mut crates/conformance/src/conn.rs
}
expect_fail check_runner_raw_bytes.sh \
    'the conn transport bypassing the case head bytes' mut_runner_conn_call_bypassed

mut_runner_body_write_bypassed() {
    sed 's/self\.write(bytes)?/self.write(\&[])?/' crates/conformance/src/socket.rs \
        >crates/conformance/src/socket.rs.mut
    mv crates/conformance/src/socket.rs.mut crates/conformance/src/socket.rs
}
expect_fail check_runner_raw_bytes.sh \
    'Connection::write_body dropping the declared chunk bytes' mut_runner_body_write_bypassed

mut_runner_chunk_call_bypassed() {
    sed 's/connection\.write_body(bytes)?/connection.write_body(\&[])?/' crates/conformance/src/conn.rs \
        >crates/conformance/src/conn.rs.mut
    mv crates/conformance/src/conn.rs.mut crates/conformance/src/conn.rs
}
expect_fail check_runner_raw_bytes.sh \
    'the conn body loop dropping a declared data chunk' mut_runner_chunk_call_bypassed

mut_runner_raw_connect_bypassed() {
    sed 's/TcpStream::connect(addr)/TcpStream::connect("127.0.0.1:9")/' crates/conformance/src/socket.rs \
        >crates/conformance/src/socket.rs.mut
    mv crates/conformance/src/socket.rs.mut crates/conformance/src/socket.rs
}
expect_fail check_runner_raw_bytes.sh \
    'Connection::open ignoring the selected raw socket address' mut_runner_raw_connect_bypassed

mut_runner_unlisted_client_dependency() {
    add_conformance_dependency 'ureq = "3"'
}
expect_fail check_runner_raw_bytes.sh \
    'an unlisted HTTP client dependency bypassing a name deny-list' mut_runner_unlisted_client_dependency

# -----------------------------------------------------------------------------
# check_resolver_pure.sh has four rules and each gets its own control, because
# three of them are regexes over source text and the fourth is an awk field
# extractor — every one of which turns into a no-op from a single typo. The
# properties are worth this much: the resolver runs before authentication, so
# "it cannot await", "it holds no store handle" and "it cannot see a forwarded
# header" are the three sentences standing between an unauthenticated caller and
# either an amplifier or a bucket of somebody else's choosing.
# -----------------------------------------------------------------------------

mut_async_compile_fixture_in_runtime() {
    cp crates/gateway/tests/compile_fail/host_resolver_async.rs \
        crates/gateway/src/host_resolver_async.rs
}
expect_fail check_resolver_pure.sh \
    'the compile-fail async resolver copied into runtime source' mut_async_compile_fixture_in_runtime \
    'HostResolver::resolve may not be async'

mut_async_resolver() {
    perl -0pi -e 's/    fn resolve\(&self, query: &HostQuery/    async fn resolve(&self, query: &HostQuery/' \
        crates/gateway/src/ext/vhost.rs
}
expect_fail check_resolver_pure.sh \
    'a host resolver whose resolve() is async' mut_async_resolver

mut_awaiting_resolver() {
    perl -0pi -e 's/        let host = query\.host\.host_without_port\(\);/        let host = lookup(query).await;/' \
        crates/gateway/src/ext/vhost.rs
}
expect_fail check_resolver_pure.sh \
    'a host resolver that awaits' mut_awaiting_resolver

mut_resolver_store_handle() {
    perl -0pi -e 's/pub struct VirtualHostStyle \{/pub struct VirtualHostStyle {\n    buckets: std::sync::Arc<dyn BucketStore>,/' \
        crates/gateway/src/ext/vhost.rs
}
expect_fail check_resolver_pure.sh \
    'a resolver holding a store handle' mut_resolver_store_handle

mut_forwarded_field_on_the_query() {
    perl -0pi -e 's/    \/\/\/ The request method\.\n    pub method: &.a Method,/    \/\/\/ The request method.\n    pub method: &\x27a Method,\n    pub extra: &\x27a str,/' \
        crates/gateway/src/ext/host.rs
}
expect_fail check_resolver_pure.sh \
    'a field added to the resolver input surface' mut_forwarded_field_on_the_query

mut_forwarded_header_read() {
    perl -0pi -e 's/        let host = query\.host\.host_without_port\(\);/        let host = lookup("x-forwarded-host");/' \
        crates/gateway/src/ext/vhost.rs
}
expect_fail check_resolver_pure.sh \
    'a forwarded header named in resolver code' mut_forwarded_header_read

mut_no_resolver_trait_file() {
    rm -f crates/gateway/src/ext/host.rs
}
expect_fail check_resolver_pure.sh \
    'the resolver trait file missing entirely (a guard whose input is gone must fail, not skip)' mut_no_resolver_trait_file

# -----------------------------------------------------------------------------
# check_single_normalization.sh has four rules and each one gets its own
# negative control. The rule this file exists for is the second normalisation:
# a guard that only catches a renamed function would have missed the one that
# was actually here, which was a hand-rolled percent decoder in the conformance
# fixture parsing x-amz-copy-source a second time.
# -----------------------------------------------------------------------------

mut_second_normalisation() {
    printf '\nfn normalize_key(_s: &str) -> String { String::new() }\n' \
        >>crates/core/src/codec/view.rs
}
expect_fail check_single_normalization.sh \
    'a second normalize_key, which is how the two values start to differ' mut_second_normalisation

mut_second_floor() {
    printf '\nfn floor_check_key(_s: &str) -> Result<(), ()> { Ok(()) }\n' \
        >>crates/core/src/codec/value.rs
}
expect_fail check_single_normalization.sh \
    'a second floor_check_key, whose verdict would differ from the real one' mut_second_floor

mut_unallowed_percent_decode() {
    printf '\nfn again(s: &str) -> String {\n    percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned()\n}\n' \
        >>crates/gateway/src/wire.rs
}
expect_fail check_single_normalization.sh \
    'a percent decoder in a file no allowance covers' mut_unallowed_percent_decode

mut_object_key_deref() {
    printf '\nimpl std::ops::Deref for ObjectKey {\n    type Target = str;\n    fn deref(&self) -> &str { &self.key }\n}\n' \
        >>crates/types/src/scalar/name.rs
}
expect_fail check_single_normalization.sh \
    'a Deref on ObjectKey, which hands the storage layer a &str to re-parse' mut_object_key_deref

mut_lossy_in_scalar() {
    printf '\nfn repair(b: &[u8]) -> String { String::from_utf8_lossy(b).into_owned() }\n' \
        >>crates/types/src/scalar/naming.rs
}
expect_fail check_single_normalization.sh \
    'a lossy decode in the scalar vocabulary, which merges two client inputs' mut_lossy_in_scalar

mut_decoded_utf8_current_is_lossy() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("model/overlays/quirks/naming.toml")
text = path.read_text()
old = 'mutation_dimension = "decoded_utf8"\ncontract_value = "strict"'
new = 'mutation_dimension = "decoded_utf8"\ncontract_value = "lossy"'
if text.count(old) != 1:
    raise SystemExit("decoded_utf8 strict source is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_single_normalization.sh \
    'the typed UTF-8 mutation arm becoming the overlay current' mut_decoded_utf8_current_is_lossy

mut_decoded_utf8_source_is_duplicated() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("model/overlays/quirks/naming.toml")
text = path.read_text()
old = 'mutation_dimension = "default_slash_policy"'
if text.count(old) != 1:
    raise SystemExit("default slash source is not unique")
path.write_text(text.replace(old, 'mutation_dimension = "decoded_utf8"', 1))
PYEOF
}
expect_fail check_single_normalization.sh \
    'a second overlay record claiming the decoded UTF-8 dimension' mut_decoded_utf8_source_is_duplicated

mut_lossy_arm_line_drifts() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/naming.rs")
text = path.read_text()
old = "DecodedUtf8Policy::Lossy => Ok(percent_decode_str(value).decode_utf8_lossy().into_owned()),"
if text.count(old) != 1:
    raise SystemExit("lossy mutation arm is not unique")
path.write_text(text.replace(old, old.replace("Lossy =>", "Lossy  =>"), 1))
PYEOF
}
expect_fail check_single_normalization.sh \
    'the one audited lossy mutation arm drifting from its exact spelling' mut_lossy_arm_line_drifts

mut_drop_percent_decode_allowances() {
    rm -f scripts/allowances/percent-decode-allowances.txt
}
expect_fail check_single_normalization.sh \
    'a missing allowance file, which must fail rather than skip' mut_drop_percent_decode_allowances

# check_authz_consumption.sh guards the type transition, not a call-site convention. Each mutation
# below compiles as plausible framework code and must still make the source guard fail.
mut_dispatch_decoded() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/registry/handlers.rs")
text = path.read_text()
text = text.replace("authorized: Authorized<O>", "authorized: Decoded<O>", 1)
path.write_text(text)
PYEOF
}
expect_fail check_authz_consumption.sh \
    'dispatch widened back to Decoded<O>' mut_dispatch_decoded

mut_authorized_constructor() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/authz/mod.rs")
text = path.read_text()
needle = "impl<O: Operation> Authorized<O> {"
text = text.replace(needle, needle + "\n    pub fn forge(input: O::Input, resources: O::DerivedResources, read: AuthorizedRead) -> Self { Self { input, resources, read } }", 1)
path.write_text(text)
PYEOF
}
expect_fail check_authz_consumption.sh \
    'a public Authorized<O> constructor' mut_authorized_constructor

mut_public_read_proof() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/authz/mod.rs")
path.write_text(path.read_text().replace("    resources: Vec<OwnedResource>,", "    pub resources: Vec<OwnedResource>,", 1))
PYEOF
}
expect_fail check_authz_consumption.sh \
    'a publicly constructible AuthorizedRead proof' mut_public_read_proof

mut_public_authorize_input() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/authz/mod.rs")
path.write_text(path.read_text().replace("pub(crate) fn authorize_input", "pub fn authorize_input", 1))
PYEOF
}
expect_fail check_authz_consumption.sh \
    'a public function that can mint Authorized<O>' mut_public_authorize_input

mut_public_erased_proof() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/registry/handlers.rs")
path.write_text(path.read_text().replace("pub struct ErasedRequest(Box<dyn Any + Send>);", "pub struct ErasedRequest(pub Box<dyn Any + Send>);", 1))
PYEOF
}
expect_fail check_authz_consumption.sh \
    'a public erased authorization payload' mut_public_erased_proof

# ADR-0022 added exactly one dispatch parameter, the request context. Any further parameter, or a
# dispatch that takes an already-built Req<O> instead of Authorized<O>, must fail.
mut_dispatch_extra_parameter() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/registry/handlers.rs")
text = path.read_text()
old = "    request_context: RequestContextView,\n) -> Result<ErasedResponse, HandlerError>\n"
if text.count(old) != 1:
    raise SystemExit("missing mutation subject: the dispatch parameter list")
path.write_text(text.replace(old, "    request_context: RequestContextView,\n    bypass: bool,\n) -> Result<ErasedResponse, HandlerError>\n", 1))
PYEOF
}
expect_fail check_authz_consumption.sh \
    'dispatch gaining a parameter beyond the ADR-0022 request context' mut_dispatch_extra_parameter

mut_dispatch_takes_request() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/registry/handlers.rs")
text = path.read_text()
old = (
    "    authorized: Authorized<O>,\n    sse: SseEnforced,\n    request_context: RequestContextView,\n"
    ") -> Result<ErasedResponse, HandlerError>\n"
)
if text.count(old) != 1:
    raise SystemExit("missing mutation subject: the dispatch parameter list")
path.write_text(text.replace(old, "    request: crate::Req<O>,\n) -> Result<ErasedResponse, HandlerError>\n", 1))
PYEOF
}
expect_fail check_authz_consumption.sh \
    'dispatch taking a built Req<O> instead of consuming Authorized<O>' mut_dispatch_takes_request
# check_cors_credentials_exclusive.sh has four rules, and the fourth exists only to keep the third
# from being defeated by an import. Each is mutated separately: a single case would leave three of
# them as prose. GHSA-x5xv-223c-8vm7 is the advisory all four are about.

mut_credentials_in_the_reflected_arm() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/core/src/cors/answer.rs")
text = path.read_text()
# The refactor the guard exists to catch: the credentials writer folded into the function that
# knows about the wildcard forms, with the reflected arm now able to reach it.
text = text.replace(
    "        AllowOrigin::Reflected(_) | AllowOrigin::Wildcard if contracts::cors_wildcard_credentials_omitted() => None,\n        AllowOrigin::Reflected(_) | AllowOrigin::Wildcard => credentials_header(policy, matched.request_origin),",
    "        AllowOrigin::Reflected(value) => Some((ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static(\"true\"))).filter(|_| !value.is_empty()),\n        AllowOrigin::Wildcard => None,",
)
path.write_text(text)
PYEOF
}
expect_fail check_cors_credentials_exclusive.sh \
    'the credentials header written from the reflected-origin arm' mut_credentials_in_the_reflected_arm

mut_second_credentials_writer() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/core/src/cors/answer.rs")
text = path.read_text()
text += """
fn a_second_writer() -> (HeaderName, HeaderValue) {
    (ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"))
}
"""
path.write_text(text)
PYEOF
}
expect_fail check_cors_credentials_exclusive.sh \
    'a second function writing the credentials header' mut_second_credentials_writer

mut_credentials_written_elsewhere() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text()
text += """
fn a_second_component_writing_credentials() -> &'static str {
    "access-control-allow-credentials"
}
"""
path.write_text(text)
PYEOF
}
expect_fail check_cors_credentials_exclusive.sh \
    'the credentials header written outside the one answer builder' mut_credentials_written_elsewhere

mut_allow_origin_imported_unqualified() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/core/src/cors/answer.rs")
text = path.read_text()
text = text.replace(
    "use super::rule::{AllowOrigin, RuleMatch};",
    "use super::rule::AllowOrigin::*;\nuse super::rule::{AllowOrigin, RuleMatch};",
)
path.write_text(text)
PYEOF
}
expect_fail check_cors_credentials_exclusive.sh \
    "AllowOrigin's variants imported unqualified, which would blind rule 3" mut_allow_origin_imported_unqualified

mut_credentials_constant_renamed() {
    python3 - <<'PYEOF'
import pathlib
# The guard's subject renamed out from under it. Rules 2 and 3 would then be checking nothing,
# which must be a failure and not a pass.
for name in ("crates/core/src/cors/answer.rs", "crates/core/src/cors/mod.rs", "crates/gateway/src/lib.rs"):
    path = pathlib.Path(name)
    path.write_text(path.read_text().replace("ACCESS_CONTROL_ALLOW_CREDENTIALS", "ALLOW_CREDS"))
PYEOF
}
expect_fail check_cors_credentials_exclusive.sh \
    'the credentials constant renamed, leaving the guard with nothing to check' mut_credentials_constant_renamed

# -----------------------------------------------------------------------------
# check_codec_policy.sh
#
# Lifecycle deliberately has two controls: the selected persisted MinIO policy preserves its
# registered field, while the unselected generic HTTP codec keeps skipping vendor elements. These
# mutations attack both directions and the protected record joining them. CORS separately selects
# Lenient at its persisted-runtime entry point; its mutation proves the guard watches that
# production choice rather than only Lifecycle's dialect path. The bucket configuration family's
# write grading (security writes allow-registered, persisted reads and switch writes lenient) has
# its own group below.
# -----------------------------------------------------------------------------

mut_codec_policy_runtime_cors_made_strict() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/types/src/cors_tagging.rs")
text = path.read_text()
old = "    let policy = CodecPolicy::new(UnknownElementPolicy::Lenient);\n"
if text.count(old) != 1:
    raise SystemExit("runtime CORS policy mutation anchor is not unique")
path.write_text(text.replace(old, "    let policy = CodecPolicy::security_relevant();\n", 1))
PYEOF
}
expect_fail check_codec_policy.sh \
    'the persisted runtime CORS reader becoming strict' \
    mut_codec_policy_runtime_cors_made_strict

mut_codec_policy_registration_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/dialect-minio/src/lib.rs")
text = path.read_text()
old = "        policy.register::<DelMarkerExpiration>()?;\n"
if text.count(old) != 1:
    raise SystemExit("codec policy registration mutation anchor is not unique")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_codec_policy.sh \
    'the selected lifecycle dialect dropping its concrete registration' \
    mut_codec_policy_registration_removed

mut_codec_policy_default_made_lenient() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/types/src/ext.rs")
text = path.read_text()
old = "        Self::new(UnknownElementPolicy::AllowRegistered)\n"
if text.count(old) != 1:
    raise SystemExit("codec policy default mutation anchor is not unique")
path.write_text(text.replace(old, "        Self::new(UnknownElementPolicy::Lenient)\n", 1))
PYEOF
}
expect_fail check_codec_policy.sh \
    'persisted security-relevant XML becoming silently lenient' \
    mut_codec_policy_default_made_lenient

mut_codec_policy_slot_moved() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/dialect-minio/src/lib.rs")
text = path.read_text()
old = '    const INSERT_AFTER: &\'static str = "Expiration";\n'
if text.count(old) != 1:
    raise SystemExit("codec policy slot mutation anchor is not unique")
path.write_text(text.replace(old, '    const INSERT_AFTER: &\'static str = "Status";\n', 1))
PYEOF
}
expect_fail check_codec_policy.sh \
    'DelMarkerExpiration leaving its reviewed sibling slot' \
    mut_codec_policy_slot_moved

mut_codec_policy_unselected_control_weakened() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/lifecycle/c-lifecycle-0018.toml")
text = path.read_text()
old = 'not_contains_utf8 = ["DelMarkerExpiration", "FutureKnob"]\n'
if text.count(old) != 1:
    raise SystemExit("codec policy no-dialect mutation anchor is not unique")
path.write_text(text.replace(old, 'not_contains_utf8 = ["FutureKnob"]\n', 1))
PYEOF
}
expect_fail check_codec_policy.sh \
    'the no-dialect control no longer proving the vendor field is not global' \
    mut_codec_policy_unselected_control_weakened

mut_codec_policy_contract_renamed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("model/overlays/quirks/lifecycle.toml")
text = path.read_text()
old = 'id      = "q-lc-0015"\n'
if text.count(old) != 1:
    raise SystemExit("codec policy quirk mutation anchor is not unique")
path.write_text(text.replace(old, 'id      = "q-lc-9999"\n', 1))
PYEOF
}
expect_fail check_codec_policy.sh \
    'the protected lifecycle dialect contract leaving its deterministic id' \
    mut_codec_policy_contract_renamed

# The bucket configuration family's grading (rustfs/backlog#1728, ADR-0007): each mutation moves one
# write or read path to the other side of allow-registered / lenient, or cuts the evidence binding
# them, and the guard must refuse every one.

mut_codec_policy_pab_guard_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("generated/codec/ops/put_public_access_block.rs")
text = path.read_text()
old = '    if node.children.iter().any(|child| !known.contains(&child.name.as_str())) {\n        return Err(CodecError::malformed_xml("the body contains an unknown element"));\n    }\n'
if text.count(old) != 1:
    raise SystemExit("public access block guard mutation anchor is not unique")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_codec_policy.sh \
    'the generated PutPublicAccessBlock decoder skipping unregistered elements' \
    mut_codec_policy_pab_guard_removed

mut_codec_policy_pab_rule_made_lenient() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("model/overlays/quirks/bucket-policy.toml")
text = path.read_text()
old = 'mutation_dimension = "unknown_element_policy"\ncodec_value = "reject"\ntarget = "PutPublicAccessBlock"\n'
if text.count(old) != 1:
    raise SystemExit("public access block rule mutation anchor is not unique")
path.write_text(text.replace(old, old.replace('"reject"', '"skip"'), 1))
PYEOF
}
expect_fail check_codec_policy.sh \
    'the PutPublicAccessBlock write rule flipped from reject to skip' \
    mut_codec_policy_pab_rule_made_lenient

mut_codec_policy_pab_case_unbound() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/bucketconfig/c-bucketconfig-0061.toml")
text = path.read_text()
old = 'quirks = ["q-pab-0005"]\n'
if text.count(old) != 1:
    raise SystemExit("public access block case mutation anchor is not unique")
path.write_text(text.replace(old, "quirks = []\n", 1))
PYEOF
}
expect_fail check_codec_policy.sh \
    'the public access block refusal case losing its rule binding' \
    mut_codec_policy_pab_case_unbound

mut_codec_policy_persisted_pab_made_strict() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/types/src/persistence.rs")
text = path.read_text()
old = '    let root = parse_persistence_root(input, "PublicAccessBlockConfiguration")?;\n'
if text.count(old) != 1:
    raise SystemExit("persisted public access block mutation anchor is not unique")
strict = old + '    if root.children.iter().any(|child| child.name == "FutureSetting") {\n        return Err(PersistenceCodecError::InvalidBoolean);\n    }\n'
path.write_text(text.replace(old, strict, 1))
PYEOF
}
expect_fail check_codec_policy.sh \
    'the persisted PublicAccessBlock reader refusing an unknown element' \
    mut_codec_policy_persisted_pab_made_strict

mut_codec_policy_policy_gate_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/conformance/src/fixture.rs")
text = path.read_text()
old = "        validate_policy(&input.policy).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;\n"
if text.count(old) != 1:
    raise SystemExit("policy gate mutation anchor is not unique")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_codec_policy.sh \
    'a PutBucketPolicy write stored without the policy check' \
    mut_codec_policy_policy_gate_removed

mut_codec_policy_repeated_name_admitted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/ops/shared/bucket_policy.rs")
text = path.read_text()
old = "                if !names.insert(name) {\n                    return Err(PolicyRejection::NotJson);\n                }\n"
if text.count(old) != 1:
    raise SystemExit("repeated policy name mutation anchor is not unique")
path.write_text(text.replace(old, "                names.insert(name);\n", 1))
PYEOF
}
expect_fail check_codec_policy.sh \
    'the policy check admitting a repeated member name' \
    mut_codec_policy_repeated_name_admitted

mut_codec_policy_versioning_made_strict() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("generated/codec/ops/put_bucket_versioning.rs")
path.write_text(
    path.read_text()
    + '\nfn refuse_unknown() -> Result<(), CodecError> {\n    Err(CodecError::malformed_xml("the body contains an unknown element"))\n}\n'
)
PYEOF
}
expect_fail check_codec_policy.sh \
    'the persisted versioning write refusing unknown elements' \
    mut_codec_policy_versioning_made_strict

mut_codec_policy_website_rule_made_reject() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("model/overlays/quirks/bucket-website.toml")
path.write_text(
    path.read_text()
    + '\n[[quirk]]\nid = "q-web-9999"\nkind = "security_unknown_elements"\nclassification = "mutable"\n'
    + 'mutation_dimension = "unknown_element_policy"\ncodec_value = "reject"\ntarget = "PutBucketWebsite"\n'
    + 'summary = "A stricter website write."\ncases = []\n'
)
PYEOF
}
expect_fail check_codec_policy.sh \
    'an overlay rule making the persisted website write strict' \
    mut_codec_policy_website_rule_made_reject

mut_codec_policy_persisted_boundary_test_lost() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/security_request_policy.rs")
text = path.read_text()
old = "fn persisted_public_access_bytes_with_an_unknown_root_element_stay_readable()"
if text.count(old) != 1:
    raise SystemExit("persisted boundary test mutation anchor is not unique")
path.write_text(text.replace(old, "fn persisted_public_access_bytes_renamed()", 1))
PYEOF
}
expect_fail check_codec_policy.sh \
    'the executable persisted PublicAccessBlock boundary disappearing' \
    mut_codec_policy_persisted_boundary_test_lost

# -----------------------------------------------------------------------------
# check_no_minio_source.sh
#
# The clean-room provenance guard. Rule 1 (AGPL licence text) is exemptable through
# scripts/allowances/clean-room-allowances.txt, so it gets two cases: one for a file
# that is not on the list, and one proving the list is read as a list of paths rather
# than as a licence to say anything anywhere. Rules 2, 3 and 4 have no exemption.
#
# The licence text and the provenance sentence are written with byte escapes, the same
# device the Chinese cases above use and for the same reason: spelling them literally
# would make the guard flag this file, and allowing this file would then let real AGPL
# text and a real port comment sit here unnoticed forever. `\x41` is `A` and `\x6f` is
# `o`, so the strings reach the sandbox intact and are absent from this source.
# -----------------------------------------------------------------------------

fi
# These provenance mutations scan text and manifests without compiling. The general shards own
# them so a cold Cargo cache cannot spend the build-backed budget on repository scans.
if [[ "$QUIRK_LEDGER_ONLY" == 0 && "$DTO_COMPILER_ONLY" == 0 && "$BUILD_GUARDS_ONLY" == 0 && "$ERROR_STATUS_ONLY" == 0 ]]; then
mut_agpl_licence_text() {
    printf '\n// Licensed under the GNU \x41FFERO GENERAL PUBLIC LICENSE Version 3\n' \
        >>crates/core/src/dialect/overlay.rs
}
expect_fail check_no_minio_source.sh \
    'AGPL licence text in a source file' mut_agpl_licence_text

mut_agpl_in_unlisted_prose() {
    printf 'This component is offered under \x41GPL-3.0.\n' >crates/core/PROVENANCE.md
}
expect_fail check_no_minio_source.sh \
    'a file naming the AGPL that the allowance list does not carry' mut_agpl_in_unlisted_prose

mut_port_provenance_comment() {
    printf '\n// The ordering above was p\x6frted from the minio server bucket handler.\n' \
        >>crates/core/src/dialect/mod.rs
}
expect_fail check_no_minio_source.sh \
    'a comment giving the contents a MinIO-server origin' mut_port_provenance_comment

mut_dialect_minio_copied_provenance() {
    printf '\nThis implementation was c\x6fpied from MinIO server source.\n' \
        >>crates/dialect-minio/MAP.md
}
expect_fail check_no_minio_source.sh \
    'a copied-source claim beside the narrow clean-room policy sentence' \
    mut_dialect_minio_copied_provenance

mut_vendored_server_tree() {
    mkdir -p vendor/github.com/minio/minio/cmd
    printf 'package cmd\n' >vendor/github.com/minio/minio/cmd/api-router.go
}
expect_fail check_no_minio_source.sh \
    'a vendored MinIO server tree' mut_vendored_server_tree

mut_minio_submodule() {
    printf '[submodule "minio"]\n\tpath = third_party/minio\n\turl = https://github.com/minio/minio.git\n' \
        >.gitmodules
}
expect_fail check_no_minio_source.sh \
    'the MinIO server declared as a git submodule' mut_minio_submodule

mut_clean_room_allowance_widened() {
    # The allowance list turned into a blanket permission. The guard reads it as a list of
    # paths, so a glob is not a path and the offending file is still reported -- which is the
    # behaviour under test: widening the list must not silence rule 1 for everything.
    printf '*\n' >scripts/allowances/clean-room-allowances.txt
    printf 'Offered under the \x41ffero General Public License.\n' >crates/core/PROVENANCE.md
}
expect_fail check_no_minio_source.sh \
    'an allowance list widened to a glob, which is not a path' mut_clean_room_allowance_widened

mut_tracked_symlink_to_ignored_agpl() {
    mkdir -p ignored-provenance crates/core/src/dialect
    printf 'ignored-provenance/\n' >>.gitignore
    printf '// GNU \x41FFERO GENERAL PUBLIC LICENSE Version 3\n' \
        >ignored-provenance/hidden.rs
    ln -s ../../../../ignored-provenance/hidden.rs crates/core/src/dialect/tracked-link.rs
}
expect_fail check_no_minio_source.sh \
    'a tracked Rust symlink resolving to ignored AGPL source' mut_tracked_symlink_to_ignored_agpl

mut_broken_tracked_source_symlink() {
    ln -s missing-provenance.rs crates/core/src/dialect/broken-source-link.rs
}
expect_fail check_no_minio_source.sh \
    'a broken tracked source symlink whose content cannot be inspected' mut_broken_tracked_source_symlink

mut_binary_tracked_manifest() {
    mkdir -p crates/binary-manifest
    printf '[package]\nname = "binary-manifest"\n\0\nminio = "forbidden"\n' \
        >crates/binary-manifest/Cargo.toml
}
expect_fail check_no_minio_source.sh \
    'a tracked NUL-bearing Cargo.toml hiding a minio dependency' mut_binary_tracked_manifest

mut_binary_untracked_manifest() {
    mkdir -p untracked-binary-manifest
    printf '[package]\nname = "binary-manifest"\n\0\nminio = "forbidden"\n' \
        >untracked-binary-manifest/Cargo.toml
}
expect_fail_unstaged check_no_minio_source.sh \
    'an untracked NUL-bearing Cargo.toml hiding a minio dependency' mut_binary_untracked_manifest

fi
# Keep the scanner-budget probes in the single-process build mode: they measure subprocesses in a
# reused sandbox, so earlier mutations in the broader general corpus can disturb the observation.
if [[ "$BUILD_GUARDS_ONLY" == 1 ]]; then
SCANNER_TOOLS=(grep rg awk sed perl find git)

write_scanner_shim() {
    local shim_dir="$1" scanner="$2" real dispatch
    real="$(command -v "$scanner" 2>/dev/null)" || real=""
    [[ -z "$real" || -x "$real" ]] || return 1
    if [[ -n "$real" ]]; then
        dispatch="exec \"${real}\" \"\$@\""
    else
        dispatch='exit 127'
    fi
    printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        ': "${GATEWAY_SCANNER_COUNT_DIR:?}"' \
        "printf '.\\n' >>\"\${GATEWAY_SCANNER_COUNT_DIR}/${scanner}\"" \
        "$dispatch" >"${shim_dir}/${scanner}"
    chmod +x "${shim_dir}/${scanner}"
}

prepare_scanner_shims() {
    local shim_dir="$1" scanner
    for scanner in "${SCANNER_TOOLS[@]}"; do
        write_scanner_shim "$shim_dir" "$scanner" || return 1
    done
}

validate_scanner_shims() {
    local shim_dir="$1" count_dir="$2" scanner
    for scanner in "${SCANNER_TOOLS[@]}"; do
        rm -f "${count_dir}/${scanner}"
        PATH="${shim_dir}:${PATH}" GATEWAY_SCANNER_COUNT_DIR="$count_dir" \
            "${shim_dir}/${scanner}" </dev/null >/dev/null 2>&1 || true
        [[ -s "${count_dir}/${scanner}" ]] || return 1
        : >"${count_dir}/${scanner}"
    done
}

scanner_process_count() {
    local count_dir="$1" scanner line total=0
    for scanner in "${SCANNER_TOOLS[@]}"; do
        while IFS= read -r line; do
            total=$((total + 1))
        done <"${count_dir}/${scanner}"
    done
    printf '%s\n' "$total"
}

scanner_budget_case() {
    local guard="$1" ceiling="$2" expectation="$3" desc="$4" mutate="${5:-}"
    local sandbox shim_dir count_dir rc=0 observed
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    if [[ -n "$mutate" ]]; then
        (cd "$sandbox" && "$mutate" >/dev/null)
    fi
    shim_dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scanner-shims.XXXXXX")"
    count_dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scanner-counts.XXXXXX")"
    if ! prepare_scanner_shims "$shim_dir" || ! validate_scanner_shims "$shim_dir" "$count_dir"; then
        fail_msg "scanner process harness could not validate every shim: ${desc}"
        rm -rf "$shim_dir" "$count_dir"
        return
    fi
    GATEWAY_CHECK_ROOT="$sandbox" PATH="${shim_dir}:${PATH}" GATEWAY_SCANNER_COUNT_DIR="$count_dir" \
        "$sandbox/scripts/$guard" >/dev/null 2>&1 || rc=$?
    observed="$(scanner_process_count "$count_dir")"
    rm -rf "$shim_dir" "$count_dir"

    if [[ "$rc" -ne 0 ]]; then
        fail_msg "${guard} failed for the wrong reason while measuring scanner processes: ${desc}"
    elif [[ "$expectation" == within && "$observed" -le "$ceiling" ]]; then
        pass_msg "${guard} uses ${observed}/${ceiling} scanner processes: ${desc}"
    elif [[ "$expectation" == over && "$observed" -gt "$ceiling" ]]; then
        pass_msg "${guard} exceeds ${ceiling} scanner processes after mutation (${observed}): ${desc}"
    else
        fail_msg "${guard} scanner process count ${observed} did not satisfy ${expectation} ceiling ${ceiling}: ${desc}"
    fi
}

insert_guard_probe() {
    local path="$1" probe="$2"
    python3 - "$path" "$probe" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
probe = sys.argv[2]
text = path.read_text()
marker = '\nexit "$status"\n'
if text.count(marker) != 1:
    raise SystemExit("guard exit marker is missing or ambiguous")
path.write_text(text.replace(marker, f"\n{probe}\nexit \"$status\"\n"))
PYEOF
}

mut_single_per_candidate_scan() {
    insert_guard_probe scripts/check_single_normalization.sh $'for candidate in "${sources[@]}"; do\n    grep -E "never-match" "$candidate" >/dev/null || true\ndone'
}

mut_no_minio_candidate_slice_scan() {
    insert_guard_probe scripts/check_no_minio_source.sh $'for candidate in "${content_files[@]:0:64}"; do\n    git grep -E "never-match" -- "$candidate" >/dev/null || true\ndone'
}

mut_no_minio_wrapper_alias_scan() {
    insert_guard_probe scripts/check_no_minio_source.sh $'GREP=grep\nscan_candidate() { "${GREP}" -E "never-match" "$1" >/dev/null || true; }\nfor candidate in "${content_files[@]:0:64}"; do\n    scan_candidate "$candidate"\ndone'
}

mut_no_minio_rg_scan() {
    insert_guard_probe scripts/check_no_minio_source.sh $'for candidate in "${content_files[@]:0:64}"; do\n    rg "never-match" "$candidate" >/dev/null || true\ndone'
}

absolute_scanner_path_case() {
    local expectation="$1" desc="$2" mutate="${3:-}" sandbox hits rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    if [[ -n "$mutate" ]]; then
        (cd "$sandbox" && "$mutate" >/dev/null)
    fi
    hits="$(mktemp "${TMPDIR:-/tmp}/gateway-absolute-scanner-hits.XXXXXX")"
    if grep -nE '/[^[:space:]]*/(grep|rg|awk|sed|perl|find|git)([^[:alnum:]_.-]|$)' \
        "$sandbox/scripts/check_single_normalization.sh" \
        "$sandbox/scripts/check_no_minio_source.sh" >"$hits"; then
        rc=0
    else
        rc=$?
    fi
    if [[ "$rc" -gt 1 ]]; then
        fail_msg "absolute scanner path check could not inspect both target guards: ${desc}"
    elif [[ "$expectation" == clean && "$rc" -eq 1 ]]; then
        pass_msg "target guards contain no literal absolute scanner path: ${desc}"
    elif [[ "$expectation" == caught && "$rc" -eq 0 ]]; then
        pass_msg "target guards reject a literal absolute scanner path: ${desc}"
    else
        fail_msg "absolute scanner path check did not satisfy ${expectation}: ${desc}"
    fi
    rm -f "$hits"
}

mut_absolute_scanner_path() {
    insert_guard_probe scripts/check_no_minio_source.sh $'for candidate in "${content_files[@]:0:64}"; do\n    /usr/bin/grep -E "never-match" "$candidate" >/dev/null || true\ndone'
}

scanner_budget_case check_single_normalization.sh 21 within \
    'the repository-wide source corpus is scanned in constant process count'
scanner_budget_case check_no_minio_source.sh 12 within \
    'tracked, untracked, symlink and manifest scans stay batched'
scanner_budget_case check_single_normalization.sh 21 over \
    'a scanner process restored for every source candidate' mut_single_per_candidate_scan
scanner_budget_case check_no_minio_source.sh 12 over \
    'a per-candidate loop hidden behind an array slice' mut_no_minio_candidate_slice_scan
scanner_budget_case check_no_minio_source.sh 12 over \
    'a per-candidate scanner hidden behind a wrapper and command alias' mut_no_minio_wrapper_alias_scan
scanner_budget_case check_no_minio_source.sh 12 over \
    'a per-candidate scanner switched from grep to rg' mut_no_minio_rg_scan
absolute_scanner_path_case clean \
    'PATH shims remain the only scanner resolution path'
absolute_scanner_path_case caught \
    'an absolute grep path cannot bypass the process counter' mut_absolute_scanner_path

cases=$((cases + 1))
if guard_case_owned "$cases"; then
    missing_shim_dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scanner-missing.XXXXXX")"
    missing_count_dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scanner-missing-count.XXXXXX")"
    if prepare_scanner_shims "$missing_shim_dir"; then
        rm -f "${missing_shim_dir}/grep"
    fi
    if validate_scanner_shims "$missing_shim_dir" "$missing_count_dir"; then
        fail_msg 'scanner process harness reported green with a missing grep shim'
    else
        pass_msg 'scanner process harness fails closed when a shim is missing'
    fi
    rm -rf "$missing_shim_dir" "$missing_count_dir"
fi

cases=$((cases + 1))
if guard_case_owned "$cases"; then
    missing_tool_dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scanner-missing-tool.XXXXXX")"
    missing_tool_count_dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scanner-missing-tool-count.XXXXXX")"
    missing_tool_rc=0
    if write_scanner_shim "$missing_tool_dir" gateway-scanner-tool-that-does-not-exist; then
        GATEWAY_SCANNER_COUNT_DIR="$missing_tool_count_dir" \
            "$missing_tool_dir/gateway-scanner-tool-that-does-not-exist" \
            >/dev/null 2>&1 || missing_tool_rc=$?
    fi
    if [[ "$missing_tool_rc" -ne 0 \
        && -s "$missing_tool_count_dir/gateway-scanner-tool-that-does-not-exist" ]]; then
        pass_msg 'scanner process harness counts a missing scanner tool and fails closed'
    else
        fail_msg 'scanner process harness reported green or did not count a missing scanner tool'
    fi
    rm -rf "$missing_tool_dir" "$missing_tool_count_dir"
fi
fi
if [[ "$QUIRK_LEDGER_ONLY" == 0 && "$DTO_COMPILER_ONLY" == 0 && "$BUILD_GUARDS_ONLY" == 0 && "$ERROR_STATUS_ONLY" == 0 ]]; then
# check_stage_filter_sync.sh has four rules and each one gets its own negative
# control, for the reason check_resolver_pure.sh's do: two of the three seams
# run before the request has been authenticated, so "it cannot await", "it holds
# no store handle", "there are exactly these three seams" and "it cannot reach
# the method, the target or the routed bucket" are the four sentences standing
# between a deployment's own rewrite and a pre-authentication storage read or a
# forged signature input.
# -----------------------------------------------------------------------------

mut_async_seam() {
    perl -0pi -e 's/    fn on_wire\(&self, _head: &mut WireHead/    async fn on_wire(&self, _head: &mut WireHead/' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'a StageFilter seam declared async' mut_async_seam

mut_awaiting_filter() {
    perl -0pi -e 's/        \(\*\*self\)\.on_wire\(head\)/        lookup().await;\n        (**self).on_wire(head)/' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'a StageFilter implementation that awaits' mut_awaiting_filter

mut_filter_store_handle() {
    perl -0pi -e 's/pub struct WireHead<.a> \{/pub struct WireHead<\x27a> {\n    buckets: std::sync::Arc<dyn BucketStore>,/' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'a store handle in a guarded StageFilter file' mut_filter_store_handle

mut_fourth_seam() {
    perl -0pi -e 's/    fn on_routed\(&self, _routed: &RoutedView/    fn on_body(&self, _routed: &RoutedView<\x27_>) -> Result<\(\), S3Error> {\n        Ok\(\(\)\)\n    }\n\n    fn on_routed(&self, _routed: &RoutedView/' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'a fourth seam added to the trait without an argument for it' mut_fourth_seam

mut_writable_routed_view() {
    perl -0pi -e 's/    \/\/\/ The bucket, from the one place a bucket is produced\./    pub fn bucket_mut(&mut self) -> Option<&mut BucketName> {\n        None\n    }\n\n    \/\/\/ The bucket, from the one place a bucket is produced./' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'a mutable accessor on RoutedView, which would be a second producer of the target' mut_writable_routed_view

mut_head_target_setter() {
    perl -0pi -e 's/    \/\/\/ The frozen check, in one place/    pub fn set_path(&mut self, _path: \&str) {}\n\n    \/\/\/ The frozen check, in one place/' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'a request-target setter on WireHead, which the frozen header snapshot does not cover' mut_head_target_setter

mut_no_filter_trait_file() {
    rm -f crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'the StageFilter trait file missing entirely (a guard whose input is gone must fail, not skip)' mut_no_filter_trait_file

# -----------------------------------------------------------------------------
# check_patch_layer_map.sh is checked in both directions plus the count, because
# the failure it exists to prevent is silent: a renamed test leaves the table
# saying what it said, and the table is what P10-06 deletes nine tower layers
# against.
# -----------------------------------------------------------------------------

mut_orphan_table_row() {
    perl -0pi -e 's/`bodyless_status_fix_is_the_response_invariant`/`bodyless_status_fix_renamed_away`/' \
        docs/middleware.md
}
expect_fail check_patch_layer_map.sh \
    'a table row naming a test that does not exist' mut_orphan_table_row

mut_orphan_test() {
    printf '\n/// A landing with no row.\n#[test]\nfn a_tenth_landing_nobody_wrote_down() {}\n' \
        >>crates/gateway/tests/patch_layer_landings.rs
}
expect_fail check_patch_layer_map.sh \
    'a landing test with no row in the table' mut_orphan_test

mut_deleted_table_row() {
    perl -0ni -e 's/^\| 3 \|.*\n//m; print' docs/middleware.md
}
expect_fail check_patch_layer_map.sh \
    'a landing row deleted, leaving eight layers accounted for out of nine' mut_deleted_table_row

mut_no_landing_test_file() {
    rm -f crates/gateway/tests/patch_layer_landings.rs
}
expect_fail check_patch_layer_map.sh \
    'the landings file missing entirely (a guard whose input is gone must fail, not skip)' mut_no_landing_test_file
# check_sse_key_never_leaks.sh has five rules over the SSE-C customer key, plus the missing-input
# rule every guard owes. Each is mutated separately: one case would leave four of them as prose.
# rustfs/backlog#1751 is the task all six are about, and GHSA-8cm2-h255-v749 is what a key in a log
# line looks like once it has happened.

mut_sse_key_bound_as_an_output() {
    python3 - <<'SSEPY'
import pathlib
path = pathlib.Path("spec/operations/PutObject.toml")
# The generated encoder that would write the key onto the response, spelled the way the emitter
# spells one.
path.write_text(path.read_text() + """
[[output]]
name = "SSECustomerKey"
wire_name = "x-amz-server-side-encryption-customer-key"
binding = "Header"
type = "String"
required = false
hot = false
quirks = []
""")
SSEPY
}
expect_fail check_sse_key_never_leaks.sh \
    'an operation output binding the customer key header' mut_sse_key_bound_as_an_output

mut_sse_copy_source_key_dropped_from_the_list() {
    python3 - <<'SSEPY'
import pathlib
path = pathlib.Path("crates/core/src/sse/headers.rs")
# The half of the list nobody looks at: a CopyObject's source-side key.
path.write_text(path.read_text().replace(
    "pub const NEVER_IN_A_RESPONSE: &[&str] = &[SSEC_KEY, COPY_SSEC_KEY];",
    "pub const NEVER_IN_A_RESPONSE: &[&str] = &[SSEC_KEY];",
))
SSEPY
}
expect_fail check_sse_key_never_leaks.sh \
    'the copy-source key dropped from the never-echoed list' mut_sse_copy_source_key_dropped_from_the_list

mut_sse_response_strip_removed() {
    python3 - <<'SSEPY'
import pathlib
path = pathlib.Path("crates/gateway/src/invariants.rs")
# The strip deleted from the one place every response passes through.
path.write_text(path.read_text().replace(
    "    for name in rustfs_gateway_core::sse::NEVER_IN_A_RESPONSE {",
    "    for name in [] as [&str; 0] {",
))
SSEPY
}
expect_fail check_sse_key_never_leaks.sh \
    'the response invariant no longer stripping the customer-key headers' mut_sse_response_strip_removed

mut_sse_second_expose_call_site() {
    python3 - <<'SSEPY'
import pathlib
path = pathlib.Path("crates/core/src/sse/mod.rs")
path.write_text(path.read_text() + """
fn a_second_reader(text: &headers::KeyText<'_>) -> usize {
    text.expose().len()
}
""")
SSEPY
}
expect_fail check_sse_key_never_leaks.sh \
    'a second reader of the customer key text' mut_sse_second_expose_call_site

mut_sse_second_choice_to_bool() {
    python3 - <<'SSEPY'
import pathlib
path = pathlib.Path("crates/core/src/sse/consistency.rs")
path.write_text(path.read_text() + """
fn a_second_escape_hatch(choice: subtle::Choice) -> bool {
    bool::from(choice)
}
""")
SSEPY
}
expect_fail check_sse_key_never_leaks.sh \
    'a second subtle::Choice-to-bool conversion in the SSE module' mut_sse_second_choice_to_bool

mut_sse_key_in_a_log_line() {
    python3 - <<'SSEPY'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
path.write_text(path.read_text() + """
fn an_operator_friendly_diagnostic(customer_key: &str) -> String {
    format!("rejected the customer_key {customer_key}")
}
""")
SSEPY
}
expect_fail check_sse_key_never_leaks.sh \
    'a formatting macro naming the customer key' mut_sse_key_in_a_log_line

mut_sse_headers_module_deleted() {
    rm -f crates/core/src/sse/headers.rs
}
expect_fail check_sse_key_never_leaks.sh \
    "the guard's own subject deleted, which must fail rather than skip" mut_sse_headers_module_deleted

mut_clock_second_wall_reading() {
    python3 - <<'CLOCKPY'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
# The shape this guard exists for: a second reading taken half way down the
# pipeline, so the skew check and the expiry check judge two different presents.
path.write_text(path.read_text() + """
fn a_second_present() -> std::time::SystemTime {
    std::time::SystemTime::now()
}
""")
CLOCKPY
}
expect_fail check_clock_single_source.sh \
    'a second wall-clock reading inside the pipeline' mut_clock_second_wall_reading

mut_clock_stray_monotonic_reading() {
    python3 - <<'CLOCKPY'
import pathlib
path = pathlib.Path("crates/core/src/lib.rs")
path.write_text(path.read_text() + """
fn a_stray_stopwatch() -> std::time::Instant {
    std::time::Instant::now()
}
""")
CLOCKPY
}
expect_fail check_clock_single_source.sh \
    'a monotonic reading taken outside the monotonic source' mut_clock_stray_monotonic_reading

mut_clock_wall_source_reads_the_monotonic_clock() {
    python3 - <<'CLOCKPY'
import pathlib
path = pathlib.Path("crates/sig/src/clock.rs")
# Mixing the two: signature expiry judged against a source with no absolute time.
path.write_text(path.read_text() + """
fn expiry_on_a_stopwatch() -> std::time::Instant {
    std::time::Instant::now()
}
""")
CLOCKPY
}
expect_fail check_clock_single_source.sh \
    'the wall-clock source reading the monotonic clock' mut_clock_wall_source_reads_the_monotonic_clock

mut_clock_monotonic_source_reads_the_wall_clock() {
    python3 - <<'CLOCKPY'
import pathlib
path = pathlib.Path("crates/gateway/src/clock.rs")
# The other direction: a rate limiter an NTP step can steer.
path.write_text(path.read_text() + """
fn refill_on_the_wall_clock() -> std::time::SystemTime {
    std::time::SystemTime::now()
}
""")
CLOCKPY
}
expect_fail check_clock_single_source.sh \
    'the monotonic source reading the wall clock' mut_clock_monotonic_source_reads_the_wall_clock

mut_clock_wall_source_stops_reading_the_clock() {
    python3 - <<'CLOCKPY'
import pathlib
path = pathlib.Path("crates/sig/src/clock.rs")
# The subject refactored away. The guard must fail rather than pass vacuously.
path.write_text(path.read_text().replace("std::time::SystemTime::now()", "SOME_OTHER_SOURCE.read()"))
CLOCKPY
}
expect_fail check_clock_single_source.sh \
    "the guard's own subject refactored away, which must fail rather than skip" \
    mut_clock_wall_source_stops_reading_the_clock

mut_clock_monotonic_source_deleted() {
    rm -f crates/gateway/src/clock.rs
}
expect_fail check_clock_single_source.sh \
    "the monotonic source deleted, which must fail rather than skip" mut_clock_monotonic_source_deleted

mut_governor_moved_after_body_read() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text()
call_anchor = ".try_acquire(&GovernorRequest::new(operation, meta.bucket(), declared_length, None, client_addr, class))"
call = text.find(call_anchor)
if call < 0 or text.find(call_anchor, call + 1) >= 0:
    raise SystemExit("c-lim-0039 main-pipeline governor call anchor drifted")
start = text.rfind("        let lease = match self\n", 0, call)
if start < 0:
    raise SystemExit("c-lim-0039 governor block start drifted")
end = text.find("        let config = config.governed(lease);", call)
if end < 0:
    raise SystemExit("c-lim-0039 governed-stage anchor drifted")
block = text[start:end]
without = text[:start] + text[end:]
read = without.find("            let prelude = match sealed")
if read < 0:
    raise SystemExit("c-lim-0039 body-read anchor drifted")
insert = without.find("            RoutedBody::PostObject", read)
if insert < 0:
    raise SystemExit("c-lim-0039 body-read completion anchor drifted")
decoy = '        let _governor_position_decoy = r###"' + block + '"###;\n'
without = without[:start] + decoy + without[start:]
insert += len(decoy)
path.write_text(without[:insert] + "\n" + block + without[insert:])
PYEOF
}
expect_fail check_governor_position.sh \
    'c-lim-0039 moving the real governor after the POST Object pre-auth read beside a raw-string decoy' mut_governor_moved_after_body_read \
    'c-lim-0039 governor must remain after routing and before every body-read boundary'

mut_governor_runtime_identity_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/pipeline.rs")
old = "async fn c_lim_0040_refusing_governor_answers_before_the_body_is_read() {"
new = "async fn refusing_governor_answers_before_the_body_is_read() {"
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("c-lim-0040 identity anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_governor_position.sh \
    'c-lim-0040 losing its executable runtime identity' mut_governor_runtime_identity_removed \
    'c-lim-0040 runtime evidence is missing or duplicated'

mut_governor_runtime_disabled() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/pipeline.rs")
old = "#[tokio::test]\nasync fn c_lim_0040_refusing_governor_answers_before_the_body_is_read() {"
new = "#[cfg(any())]\n#[tokio::test]\nasync fn c_lim_0040_refusing_governor_answers_before_the_body_is_read() {"
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("c-lim-0040 active-test anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_governor_position.sh \
    'c-lim-0040 being disabled by cfg' mut_governor_runtime_disabled \
    'c-lim-0040 must be one unconditional tokio test'

mut_governor_runtime_status_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/pipeline.rs")
old = "assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);"
new = "assert_eq!(response.status(), http::StatusCode::OK);"
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("c-lim-0040 status anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_governor_position.sh \
    'c-lim-0040 losing its 503 refusal direction' mut_governor_runtime_status_removed \
    'c-lim-0040 runtime evidence lost its 503 refusal'

mut_governor_runtime_body_read() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/pipeline.rs")
old = 'assert_eq!(read.load(Ordering::SeqCst), 0, "the body must not have been read");'
new = 'assert_eq!(read.load(Ordering::SeqCst), 1, "the body was read before refusal");'
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("c-lim-0040 body-read anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_governor_position.sh \
    'c-lim-0040 losing its zero-body-read observation' mut_governor_runtime_body_read \
    'c-lim-0040 runtime evidence lost its zero body reads'

mut_governor_c_lim_0004_admission_removed() {
    python3 - <<'GOVPY'
import pathlib

path = pathlib.Path("crates/gateway/src/ext/governor/default.rs")
old = "            ClassKind::Authenticated => return Some(Lease::admit()),"
new = "            ClassKind::Authenticated => return None,"
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("c-lim-0004 synchronous admission anchor drifted")
path.write_text(text.replace(old, new, 1))
GOVPY
}
expect_fail check_governor_fast_path.sh \
    'c-lim-0004 synchronous admission being removed' mut_governor_c_lim_0004_admission_removed \
    'c-lim-0004 authenticated traffic no longer returns a permit'

mut_governor_sync_path_allocates() {
    python3 - <<'GOVPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/governor/default.rs")
text = path.read_text()
needle = "    pub fn try_acquire_sync(&self, request: &GovernorRequest<'_>) -> Option<Lease> {"
path.write_text(text.replace(needle, needle + "\n        let _allocation = Box::new(0_u8);", 1))
GOVPY
}
expect_fail check_governor_fast_path.sh \
    'c-lim-0004 synchronous governor path allocating' mut_governor_sync_path_allocates \
    'the synchronous decision path contains an allocating operation'

mut_governor_single_client_lock() {
    python3 - <<'GOVPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/governor/default.rs")
path.write_text(path.read_text().replace("const CLIENT_SHARDS: usize = 32;", "const CLIENT_SHARDS: usize = 1;", 1))
GOVPY
}
expect_fail check_governor_fast_path.sh \
    'the address table collapsed to one lock' mut_governor_single_client_lock

mut_governor_user_replaces_framework() {
    python3 - <<'GOVPY'
import pathlib
path = pathlib.Path("crates/gateway/src/builder.rs")
path.write_text(path.read_text().replace(
    "Arc::new(LayeredGovernor::new(framework_governor, user))",
    "user",
    1,
))
GOVPY
}
expect_fail check_governor_fast_path.sh \
    'a user governor replacing the framework governor' mut_governor_user_replaces_framework

mut_governor_request_constructor_public() {
    python3 - <<'GOVPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/governor.rs")
path.write_text(path.read_text().replace("pub(crate) const fn new(", "pub const fn new(", 1))
GOVPY
}
expect_fail check_governor_fast_path.sh \
    'GovernorRequest construction exposed to extensions' mut_governor_request_constructor_public

mut_governor_client_map_allocates_on_demand() {
    python3 - <<'GOVPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/governor/default.rs")
path.write_text(path.read_text().replace("HashMap::with_capacity(capacity)", "HashMap::new()", 1))
GOVPY
}
expect_fail check_governor_fast_path.sh \
    'client-map allocation moved into the decision path' mut_governor_client_map_allocates_on_demand

mut_chunk_limit_identity_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_chunk_rules.rs")
text = path.read_text()
old = "/// c-lim-0042 / c-ing-0021. Negative, and the reason this task exists:"
if text.count(old) != 1:
    raise SystemExit("c-lim-0042 identity anchor drifted")
path.write_text(text.replace(old, "/// c-ing-0021. Negative, and the reason this task exists:", 1))
PYEOF
}
expect_fail check_chunk_limits.sh \
    'c-lim-0042 losing its header-rejection identity' mut_chunk_limit_identity_removed \
    'c-lim-0042 header-rejection identity is missing or duplicated'

mut_chunk_limit_header_read_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_chunk_rules.rs")
text = path.read_text()
old = '''\
    let before = pipeline.window_bytes();
    let err = drain_pipeline(&mut pipeline, 4096).expect_err("an over-large chunk is refused");

    assert_eq!(err.bytes_before_error(), 0);
'''
new = old.replace("err.bytes_before_error(), 0", "err.bytes_before_error(), 1")
if text.count(old) != 1:
    raise SystemExit("c-lim-0042 header-read anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_chunk_limits.sh \
    'c-lim-0042 losing its zero-data-byte direction' mut_chunk_limit_header_read_removed \
    "c-lim-0042 header-rejection evidence lost 'err.bytes_before_error(), 0'"

mut_chunk_limit_attack_replaced_by_control() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_chunk_rules.rs")
text = path.read_text()
old = '''\
            let mut pipeline =
                unsigned_pipeline(FOUR_GIB_CHUNK_HEADER.to_vec(), 1024, 4096, no_observers(), ChunkLimits::default());
'''
new = '''\
            let mut pipeline =
                unsigned_pipeline(b"0\\r\\n\\r\\n".to_vec(), 8, 0, no_observers(), ChunkLimits::default());
'''
if text.count(old) != 1:
    raise SystemExit("c-lim-0042 attack anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_chunk_limits.sh \
    'c-lim-0042 measuring a legal request as its attack' mut_chunk_limit_attack_replaced_by_control \
    "c-lim-0042 peak-RSS probe lost 'FOUR_GIB_CHUNK_HEADER.to_vec()'"

mut_chunk_limit_ballast_control_reversed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_chunk_rules.rs")
text = path.read_text()
old = "ballast.saturating_sub(control) >= RSS_HEADROOM_BYTES"
if text.count(old) != 1:
    raise SystemExit("c-lim-0042 ballast anchor drifted")
path.write_text(text.replace(old, "ballast.saturating_sub(control) <= RSS_HEADROOM_BYTES", 1))
PYEOF
}
expect_fail check_chunk_limits.sh \
    'c-lim-0042 accepting an RSS instrument that cannot see ballast' mut_chunk_limit_ballast_control_reversed \
    "c-lim-0042 peak-RSS evidence lost 'ballast.saturating_sub(control) >= RSS_HEADROOM_BYTES'"

mut_chunk_limit_rss_ceiling_widened() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_chunk_rules.rs")
text = path.read_text()
old = "attack.saturating_sub(control) < RSS_HEADROOM_BYTES"
if text.count(old) != 1:
    raise SystemExit("c-lim-0042 RSS ceiling anchor drifted")
path.write_text(text.replace(old, "attack.saturating_sub(control) < u64::MAX", 1))
PYEOF
}
expect_fail check_chunk_limits.sh \
    'c-lim-0042 widening its RSS ceiling to an unfalsifiable value' mut_chunk_limit_rss_ceiling_widened \
    "c-lim-0042 peak-RSS evidence lost 'attack.saturating_sub(control) < RSS_HEADROOM_BYTES'"

mut_chunk_limit_rss_observer_constant() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_chunk_rules.rs")
text = path.read_text()
old = "    parse_peak_rss(&String::from_utf8_lossy(&output.stderr))"
if text.count(old) != 2:
    raise SystemExit("chunk-limit RSS observer anchor census drifted")
path.write_text(text.replace(old, "    0", 1))
PYEOF
}
expect_fail check_chunk_limits.sh \
    'c-lim-0042 replacing the OS peak-RSS observation with a constant' mut_chunk_limit_rss_observer_constant \
    "c-lim-0042 RSS instrument lost 'parse_peak_rss(&String::from_utf8_lossy(&output.stderr))'"

mut_concurrent_chunk_attack_count_reduced() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_chunk_rules.rs")
text = path.read_text()
old = "const CONCURRENT_ATTACKERS: usize = 100;"
if text.count(old) != 1:
    raise SystemExit("c-lim-0064 attacker count anchor drifted")
path.write_text(text.replace(old, "const CONCURRENT_ATTACKERS: usize = 1;", 1))
PYEOF
}
expect_fail check_chunk_limits.sh \
    'c-lim-0064 reducing the concurrent attack to one request' mut_concurrent_chunk_attack_count_reduced \
    'c-lim-0064 does not run exactly one hundred concurrent attackers'

mut_concurrent_chunk_attack_stops_slow_feeding() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_chunk_rules.rs")
text = path.read_text()
old = "                    let mut pipeline = unsigned_pipeline(body, 1, 4096, no_observers(), ChunkLimits::default());"
if text.count(old) != 1:
    raise SystemExit("c-lim-0064 slow-feed anchor drifted")
path.write_text(text.replace(old, old.replace("body, 1, 4096", "body, 4096, 4096"), 1))
PYEOF
}
expect_fail check_chunk_limits.sh \
    'c-lim-0064 no longer feeding the malicious request one byte at a time' mut_concurrent_chunk_attack_stops_slow_feeding \
    "c-lim-0064 concurrent probe lost 'unsigned_pipeline(body, 1, 4096'"

mut_concurrent_chunk_status_collapsed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_chunk_rules.rs")
text = path.read_text()
old = "reject.to_status() == http::StatusCode::BAD_REQUEST"
if text.count(old) != 1:
    raise SystemExit("c-lim-0064 status anchor drifted")
path.write_text(text.replace(old, "reject.to_status() == http::StatusCode::FORBIDDEN", 1))
PYEOF
}
expect_fail check_chunk_limits.sh \
    'c-lim-0064 no longer requiring HTTP 400 for every attack' mut_concurrent_chunk_status_collapsed \
    "c-lim-0064 concurrent probe lost 'http::StatusCode::BAD_REQUEST'"

mut_concurrent_chunk_all_rejections_weakened() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_chunk_rules.rs")
text = path.read_text()
old = "assert_eq!(valid, CONCURRENT_ATTACKERS"
if text.count(old) != 1:
    raise SystemExit("c-lim-0064 all-rejections anchor drifted")
path.write_text(text.replace(old, "assert_eq!(valid, 1", 1))
PYEOF
}
expect_fail check_chunk_limits.sh \
    'c-lim-0064 accepting one rejection as evidence for all one hundred' mut_concurrent_chunk_all_rejections_weakened \
    "c-lim-0064 concurrent probe lost 'assert_eq!(valid, CONCURRENT_ATTACKERS'"

mut_concurrent_chunk_rss_ceiling_widened() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_chunk_rules.rs")
text = path.read_text()
old = "attack_rss.saturating_sub(control_rss) < RSS_HEADROOM_BYTES"
if text.count(old) != 1:
    raise SystemExit("c-lim-0064 RSS ceiling anchor drifted")
path.write_text(text.replace(old, "attack_rss.saturating_sub(control_rss) < u64::MAX", 1))
PYEOF
}
expect_fail check_chunk_limits.sh \
    'c-lim-0064 widening concurrent RSS to an unfalsifiable ceiling' mut_concurrent_chunk_rss_ceiling_widened \
    "c-lim-0064 concurrent acceptance evidence lost 'attack_rss.saturating_sub(control_rss) < RSS_HEADROOM_BYTES'"

mut_concurrent_chunk_p99_ceiling_widened() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_chunk_rules.rs")
text = path.read_text()
old = "control_p99.saturating_mul(8) + std::time::Duration::from_millis(5)"
if text.count(old) != 1:
    raise SystemExit("c-lim-0064 p99 ceiling anchor drifted")
path.write_text(text.replace(old, "std::time::Duration::MAX", 1))
PYEOF
}
expect_fail check_chunk_limits.sh \
    'c-lim-0064 widening healthy p99 to an unfalsifiable ceiling' mut_concurrent_chunk_p99_ceiling_widened \
    "c-lim-0064 concurrent acceptance evidence lost 'control_p99.saturating_mul(8) + std::time::Duration::from_millis(5)'"

mut_concurrent_chunk_p99_returns_to_max_sample() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/ingest_chunk_rules.rs")
text = path.read_text()
old = "const HEALTHY_PROBES: usize = 500;"
if text.count(old) != 1:
    raise SystemExit("c-lim-0064 healthy probe census drifted")
path.write_text(text.replace(old, "const HEALTHY_PROBES: usize = 100;", 1))
PYEOF
}
expect_fail check_chunk_limits.sh \
    'c-lim-0064 reducing p99 to the maximum of one hundred samples' mut_concurrent_chunk_p99_returns_to_max_sample \
    'c-lim-0064 does not sample enough healthy requests for a non-max p99'

mut_missing_length_identity_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/object/c-object-0030.toml")
text = path.read_text()
old = "# c-lim-0020 / c-lim-0022 / c-object-0030"
if text.count(old) != 1:
    raise SystemExit("c-lim-0020 identity anchor drifted")
path.write_text(text.replace(old, "# c-object-0030", 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0020 losing its corpus identity' mut_missing_length_identity_removed \
    'c-lim-0020/c-lim-0022 corpus identity is missing or duplicated'

mut_unframed_body_identity_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/object/c-object-0030.toml")
text = path.read_text()
old = "# c-lim-0020 / c-lim-0022 / c-object-0030"
new = "# c-lim-0020 / c-object-0030"
if text.count(old) != 1:
    raise SystemExit("c-lim-0022 identity anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0022 losing its corpus identity' mut_unframed_body_identity_removed \
    'c-lim-0020/c-lim-0022 corpus identity is missing or duplicated'

mut_unframed_body_stream_shrunk() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/object/c-object-0030.toml")
text = path.read_text()
old = "repeat = 65536"
if text.count(old) != 1:
    raise SystemExit("c-lim-0022 repeat anchor drifted")
path.write_text(text.replace(old, "repeat = 1", 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0022 shrinking its trailing stream below four MiB' mut_unframed_body_stream_shrunk \
    'c-lim-0022 trailing stream is smaller than four MiB'

mut_unframed_body_progress_weakened() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/object/c-object-0030.toml")
text = path.read_text()
old = "body_bytes_sent_at_response = 0"
if text.count(old) != 1:
    raise SystemExit("c-lim-0022 progress anchor drifted")
path.write_text(text.replace(old, "body_bytes_sent_at_response = 1", 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0022 allowing one trailing byte before the refusal' mut_unframed_body_progress_weakened \
    'c-lim-0022 no longer proves the refusal precedes every trailing byte'

mut_missing_length_case_id_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/object/c-object-0030.toml")
text = path.read_text()
old = 'id = "c-object-0030"'
if text.count(old) != 1:
    raise SystemExit("c-lim-0020 case-ID anchor drifted")
path.write_text(text.replace(old, 'id = "c-object-0099"', 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0020 drifting to a different corpus case' mut_missing_length_case_id_changed \
    'c-lim-0020 corpus case ID drifted'

mut_missing_length_operation_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/object/c-object-0030.toml")
text = path.read_text()
old = 'operation = "PutObject"'
if text.count(old) != 1:
    raise SystemExit("c-lim-0020 operation anchor drifted")
path.write_text(text.replace(old, 'operation = "UploadPart"', 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0020 binding to a different operation' mut_missing_length_operation_changed \
    'c-lim-0020 is not bound to PutObject'

mut_missing_length_method_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/object/c-object-0030.toml")
text = path.read_text()
old = 'raw_head_utf8 = "PUT /conf-object/no-length-write HTTP/1.1'
if text.count(old) != 1:
    raise SystemExit("c-lim-0020 method anchor drifted")
path.write_text(text.replace(old, 'raw_head_utf8 = "POST /conf-object/no-length-write HTTP/1.1', 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0020 replacing the raw PUT with another method' mut_missing_length_method_changed \
    'c-lim-0020 no longer sends a raw PUT request head'

mut_missing_length_request_gains_length() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/object/c-object-0030.toml")
text = path.read_text()
old = "x-amz-content-sha256: UNSIGNED-PAYLOAD\\r\\n\\r\\n\""
new = "x-amz-content-sha256: UNSIGNED-PAYLOAD\\r\\ncontent-length: 0\\r\\n\\r\\n\""
if text.count(old) != 1:
    raise SystemExit("c-lim-0020 raw-head anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0020 gaining a declared zero-length body' mut_missing_length_request_gains_length \
    'c-lim-0020 request gained declared or chunked framing'

mut_missing_length_signing_mode_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/object/c-object-0030.toml")
text = path.read_text()
old = 'sign = { mode = "sigv4_unsigned_payload", service = "s3", region = "us-east-1", credential = "valid" }'
if text.count(old) != 1:
    raise SystemExit("c-lim-0020 signing-mode anchor drifted")
path.write_text(text.replace(old, old.replace("sigv4_unsigned_payload", "sigv4_streaming_payload"), 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0020 replacing the plain payload mode with streaming' mut_missing_length_signing_mode_changed \
    'c-lim-0020 is no longer the plain non-streaming PutObject form'

mut_missing_length_status_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/object/c-object-0030.toml")
text = path.read_text()
old = '''\
[expect]
kind = "response"
status = 411
connection_after = "closed"
'''
if text.count(old) != 1:
    raise SystemExit("c-lim-0020 status anchor drifted")
path.write_text(text.replace(old, old.replace("status = 411", "status = 400"), 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0020 accepting a generic 400 response' mut_missing_length_status_changed \
    'c-lim-0020 no longer requires status 411'

mut_missing_length_code_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/object/c-object-0030.toml")
text = path.read_text()
old = 'code = "MissingContentLength"'
if text.count(old) != 1:
    raise SystemExit("c-lim-0020 error-code anchor drifted")
path.write_text(text.replace(old, 'code = "InvalidRequest"', 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0020 losing its dedicated error code' mut_missing_length_code_changed \
    'c-lim-0020 no longer requires MissingContentLength'

mut_missing_length_connection_kept() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("conformance/cases/object/c-object-0030.toml")
text = path.read_text()
old = 'connection_after = "closed"'
if text.count(old) != 1:
    raise SystemExit("c-lim-0020 connection anchor drifted")
path.write_text(text.replace(old, 'connection_after = "open"', 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0020 keeping a desynchronised connection alive' mut_missing_length_connection_kept \
    'c-lim-0020 no longer requires the connection to close'

mut_missing_length_socket_case_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/conformance/tests/wired.rs")
text = path.read_text()
old = '["c-object-0015", "c-mpu-0045", "c-object-0030"]'
if text.count(old) != 1:
    raise SystemExit("c-lim-0020 socket-case anchor drifted")
path.write_text(text.replace(old, '["c-object-0015", "c-mpu-0045"]', 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0020 disappearing from the real socket runner' mut_missing_length_socket_case_removed \
    'c-lim-0020 socket evidence lost the corpus case'

mut_missing_length_socket_runner_replaced() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/conformance/tests/wired.rs")
text = path.read_text()
old = "        let report = run_over_a_socket(id);"
if text.count(old) != 1:
    raise SystemExit("c-lim-0020 socket-runner anchor drifted")
path.write_text(text.replace(old, "        let report = run(id);", 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0020 replacing the socket observer with in-process execution' mut_missing_length_socket_runner_replaced \
    "c-lim-0020 socket evidence lost 'run_over_a_socket(id)'"

mut_missing_length_socket_verdict_weakened() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/conformance/tests/wired.rs")
text = path.read_text()
old = '        assert_eq!(outcome.verdict, Verdict::Passed, "{id}: {:?}", failures(outcome));'
if text.count(old) != 1:
    raise SystemExit("c-lim-0020 socket-verdict anchor drifted")
path.write_text(text.replace(old, old.replace("Verdict::Passed", "Verdict::Skipped"), 1))
PYEOF
}
expect_fail check_missing_content_length.sh \
    'c-lim-0020 allowing the socket case to skip' mut_missing_length_socket_verdict_weakened \
    "c-lim-0020 socket evidence lost 'outcome.verdict, Verdict::Passed'"

mut_declared_body_identity_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
old = "c_wire_0063_c_lim_0021_an_over_large_body_is_refused_on_the_socket_before_it_is_sent"
new = "c_wire_0063_an_over_large_body_is_refused_on_the_socket_before_it_is_sent"
if text.count(old) != 1:
    raise SystemExit("c-lim-0021 identity anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 losing its executable identity' mut_declared_body_identity_removed \
    'c-lim-0021 executable socket evidence is missing or duplicated'

mut_declared_body_test_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
name = "c_wire_0063_c_lim_0021_an_over_large_body_is_refused_on_the_socket_before_it_is_sent"
old = f"#[tokio::test]\nasync fn {name}()"
new = f"async fn {name}()"
if text.count(old) != 1:
    raise SystemExit("c-lim-0021 active-test anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 being disabled as a test' mut_declared_body_test_disabled \
    'c-lim-0021 evidence is not an active tokio test'

mut_declared_body_module_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/integration.rs")
text = path.read_text()
old = '#[path = "connection_teardown.rs"]\nmod connection_teardown;'
new = '#[path = "connection_teardown.rs"]\nmod removed_connection_teardown;'
if text.count(old) != 1:
    raise SystemExit("c-lim-0021 integration-module anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 leaving the consolidated integration target' mut_declared_body_module_disabled \
    'c-lim-0021 socket module is not active in the integration target'

mut_declared_body_wire_edge_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_wire_case_coverage.sh")
text = path.read_text()
old = "crates/gateway/tests/connection_teardown.rs::c_wire_0063_c_lim_0021_an_over_large_body_is_refused_on_the_socket_before_it_is_sent"
new = "crates/gateway/tests/connection_teardown.rs::c_wire_0063_an_over_large_body_is_refused_on_the_socket_before_it_is_sent"
if text.count(old) != 1:
    raise SystemExit("c-lim-0021 wire-edge anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 losing the c-wire-0063 evidence edge' mut_declared_body_wire_edge_removed \
    'c-lim-0021 no longer shares the c-wire-0063 evidence edge'

mut_declared_body_ceiling_widened() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
old = "        max_body_bytes: 16,"
new = "        max_body_bytes: 8192,"
if text.count(old) != 1:
    raise SystemExit("c-lim-0021 ceiling anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 widening the declared-body ceiling beyond the request' mut_declared_body_ceiling_widened \
    'c-lim-0021 socket evidence lost the declared body ceiling'

mut_declared_body_socket_replaced() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
old = "TcpStream::connect(local_addr).await"
new = "fake_connect(local_addr).await"
if text.count(old) != 2:
    raise SystemExit("c-lim-0021 socket-connect census drifted")
target = text.index("async fn c_wire_0063_c_lim_0021_")
position = text.index(old, target)
path.write_text(text[:position] + new + text[position + len(old):])
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 replacing its real TCP observation' mut_declared_body_socket_replaced \
    'c-lim-0021 socket evidence lost a real TCP connection'

mut_declared_body_head_not_written() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
target = text.index("async fn c_wire_0063_c_lim_0021_")
old = "stream\n        .write_all("
position = text.index(old, target)
path.write_text(text[:position] + text[position:].replace(old, "stream\n        .fake_write_all(", 1))
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 no longer writing the request head' mut_declared_body_head_not_written \
    'c-lim-0021 socket evidence lost the request-head write'

mut_declared_body_length_lowered() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
old = "Content-Length: 4096\\r\\n\\r\\n"
new = "Content-Length: 8\\r\\n\\r\\n"
if text.count(old) != 1:
    raise SystemExit("c-lim-0021 declared-length anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 sending a body length below the configured ceiling' mut_declared_body_length_lowered \
    'c-lim-0021 no longer sends only an oversized declared request head'

mut_declared_body_byte_sent() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
old = "Content-Length: 4096\\r\\n\\r\\n\")"
new = "Content-Length: 4096\\r\\n\\r\\nx\")"
if text.count(old) != 1:
    raise SystemExit("c-lim-0021 head-only anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 sending a body byte before observing the refusal' mut_declared_body_byte_sent \
    'c-lim-0021 no longer sends only an oversized declared request head'

mut_declared_body_terminal_read_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
old = "stream.read_to_end(&mut response)"
new = "stream.read_buf(&mut response)"
if text.count(old) != 2:
    raise SystemExit("c-lim-0021 terminal-read census drifted")
target = text.index("async fn c_wire_0063_c_lim_0021_")
position = text.index(old, target)
path.write_text(text[:position] + new + text[position + len(old):])
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 no longer observing socket EOF' mut_declared_body_terminal_read_removed \
    'c-lim-0021 socket evidence lost the bounded terminal read'

mut_declared_body_deadline_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
old = "tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))"
new = "tokio::time::timeout(Duration::MAX, stream.read_to_end(&mut response))"
if text.count(old) != 1:
    raise SystemExit("c-lim-0021 response-deadline anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 losing its bounded refusal deadline' mut_declared_body_deadline_removed \
    'c-lim-0021 socket evidence lost the response deadline'

mut_declared_body_status_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
old = 'wire.starts_with("HTTP/1.1 400 ")'
new = 'wire.starts_with("HTTP/1.1 413 ")'
if text.count(old) != 1:
    raise SystemExit("c-lim-0021 status anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 forking from the 400 status authority' mut_declared_body_status_changed \
    'c-lim-0021 no longer requires status 400'

mut_declared_body_code_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
old = "ErrorCode::ENTITY_TOO_LARGE.as_str()"
new = "ErrorCode::INVALID_REQUEST.as_str()"
if text.count(old) != 1:
    raise SystemExit("c-lim-0021 code anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 losing the EntityTooLarge code' mut_declared_body_code_changed \
    'c-lim-0021 socket evidence lost the error-code assertion'

mut_declared_body_connection_kept() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
old = 'wire.to_ascii_lowercase().contains("connection: close\\r\\n")'
new = 'wire.to_ascii_lowercase().contains("connection: keep-alive\\r\\n")'
if text.count(old) != 2:
    raise SystemExit("c-lim-0021 close-assertion census drifted")
target = text.index("async fn c_wire_0063_c_lim_0021_")
position = text.index(old, target)
path.write_text(text[:position] + new + text[position + len(old):])
PYEOF
}
expect_fail check_declared_body_limit.sh \
    'c-lim-0021 accepting a reusable connection' mut_declared_body_connection_kept \
    'c-lim-0021 no longer requires an observed close announcement'
# check_secret_hygiene.sh has six rules over the credential containers in crates/gateway/src/ext/,
# which is outside the path scope of check_ct_eq.sh rules 3-6. Each is mutated separately, because
# one case would leave the other five as prose. rustfs/backlog#1736 is the task, and
# GHSA-333v-68xh-8mmq is what a secret in a diagnostic looks like once it has happened.

mut_credentials_debug_derived() {
    python3 - <<'CREDPY'
import pathlib, re
path = pathlib.Path("crates/gateway/src/ext/credentials.rs")
text = path.read_text()
# The redacting Debug deleted and the derive put back — the whole leak in two edits.
text = re.sub(r"impl core::fmt::Debug for Credentials \{.*?\n\}\n", "", text, flags=re.S)
text = text.replace("pub struct Credentials {", "#[derive(Debug)]\npub struct Credentials {")
path.write_text(text)
CREDPY
}
expect_fail check_secret_hygiene.sh \
    'the redacting Debug on Credentials replaced by a derive' mut_credentials_debug_derived

# ── check_authz_fail_closed.sh (P6-02) ─────────────────────────────────────────

expect_authz_fail_minimal() {
    local desc="$1" mutate="$2" expected="$3"
    local sandbox file output tool rc=0
    local -a sources=(
        crates/core/src/authz/mod.rs
        crates/core/tests/registration.rs
        crates/gateway/src/ext/authorizer.rs
        crates/gateway/src/ext/authz_audit.rs
        crates/gateway/src/ext/mod.rs
        crates/gateway/src/service.rs
        crates/gateway/examples/custom_authorizer.rs
        crates/gateway/examples/minimal.rs
        crates/gateway/tests/assembly.rs
        crates/gateway/tests/assembly_snapshot/authz_hot_update.rs
        crates/gateway/tests/authz_consumption.rs
        crates/gateway/tests/authz_contract.rs
        crates/gateway/tests/authz_contract/oracle.rs
        crates/gateway/tests/authz_implementations.rs
        crates/gateway/tests/compile_fail/azc_0014_missing_input.rs
        crates/gateway/tests/compile_fail/azc_0015_forge_authorized.rs
        crates/gateway/tests/compile_fail/azc_0016_denial_code.rs
        crates/gateway/tests/compile_fail/azc_0020_service_config_default.rs
        crates/gateway/tests/compile_fail/azc_0021_allow_all.rs
        crates/gateway/tests/compile_fail/azc_0025_request_extensions.rs
    )

    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    for tool in awk bash cat cp dirname git grep mkdir mktemp python3 rm sort tr; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            fail_msg "check_authz_fail_closed.sh cannot test ${desc}; required command is missing: ${tool}"
            return
        fi
    done
    if [[ ! -f "${SCRIPT_DIR}/check_authz_fail_closed.sh" ]]; then
        fail_msg "check_authz_fail_closed.sh cannot test ${desc}; the real guard source is missing"
        return
    fi
    for file in "${sources[@]}"; do
        if [[ ! -f "${REPO_ROOT}/${file}" ]]; then
            fail_msg "check_authz_fail_closed.sh cannot test ${desc}; required source is missing: ${file}"
            return
        fi
    done

    sandbox="$(mktemp -d "${TMPDIR:-/tmp}/gateway-authz-guard.XXXXXX")" || {
        fail_msg "check_authz_fail_closed.sh cannot create its fixture: ${desc}"
        return
    }
    if ! mkdir -p "$sandbox/scripts" ||
        ! cp "${SCRIPT_DIR}/check_authz_fail_closed.sh" "$sandbox/scripts/"; then
        rm -rf "$sandbox"
        fail_msg "check_authz_fail_closed.sh fixture initialization failed: ${desc}"
        return
    fi
    for file in "${sources[@]}"; do
        if ! mkdir -p "$(dirname "$sandbox/$file")" ||
            ! cp "${REPO_ROOT}/${file}" "$sandbox/$file"; then
            rm -rf "$sandbox"
            fail_msg "check_authz_fail_closed.sh fixture initialization failed while copying ${file}: ${desc}"
            return
        fi
    done
    if ! git -C "$sandbox" init -q ||
        ! git -C "$sandbox" add -A; then
        rm -rf "$sandbox"
        fail_msg "check_authz_fail_closed.sh fixture Git initialization failed: ${desc}"
        return
    fi

    output="$(GATEWAY_CHECK_ROOT="$sandbox" bash "$sandbox/scripts/check_authz_fail_closed.sh" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        rm -rf "$sandbox"
        fail_msg "check_authz_fail_closed.sh rejects its unmutated source closure: ${desc}"
        printf '%s\n' "$output" >&2
        return
    fi
    if ! (cd "$sandbox" && "$mutate" >/dev/null); then
        rm -rf "$sandbox"
        fail_msg "check_authz_fail_closed.sh mutation setup failed: ${desc}"
        return
    fi

    rc=0
    output="$(GATEWAY_CHECK_ROOT="$sandbox" bash "$sandbox/scripts/check_authz_fail_closed.sh" 2>&1)" || rc=$?
    rm -rf "$sandbox"
    if [[ "$rc" -ne 0 && "$output" == *"$expected"* ]]; then
        pass_msg "check_authz_fail_closed.sh catches: ${desc}"
    else
        fail_msg "check_authz_fail_closed.sh did not report its expected violation: ${desc}"
        printf '%s\n' "$output" >&2
    fi
}

mut_a_fourth_verdict_state() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/core/src/authz/mod.rs")
s = p.read_text()
s = s.replace("    Indeterminate,\n}", "    Indeterminate,\n    Unknown,\n}", 1)
p.write_text(s)
AZPY
}
expect_authz_fail_minimal \
    'a fourth Decision state, which no interpretation site was written for' \
    mut_a_fourth_verdict_state 'Decision declares [Allow Deny Indeterminate Unknown]'

mut_decision_from_a_bool() {
    cat >>crates/gateway/src/ext/mod.rs <<'AZEOF'

impl Default for Decision {
    fn default() -> Self {
        Self::Allow
    }
}
AZEOF
}
expect_authz_fail_minimal \
    'a Default impl for Decision, so a verdict nobody reached becomes Allow' \
    mut_decision_from_a_bool 'an impl of Default or From for Decision'

mut_a_second_interpretation_site() {
    cat >>crates/gateway/src/service.rs <<'AZEOF'

fn interpret(verdict: crate::ext::Decision) -> bool {
    match verdict {
        crate::ext::Decision::Allow => true,
        crate::ext::Decision::Deny => false,
        crate::ext::Decision::Indeterminate => true,
    }
}
AZEOF
}
expect_authz_fail_minimal \
    'a second place deciding what a verdict means, reading Indeterminate as allow' \
    mut_a_second_interpretation_site 'matches on a Decision variant'

mut_a_wildcard_in_settle() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/core/src/authz/mod.rs")
s = p.read_text()
s = s.replace("            Self::Deny | Self::Indeterminate => Err(Denied { decision: self }),",
              "            _ => Err(Denied { decision: self }),", 1)
p.write_text(s)
AZPY
}
expect_authz_fail_minimal \
    'a wildcard arm in settle, so a later state inherits a branch nobody chose for it' \
    mut_a_wildcard_in_settle 'settle has a wildcard arm'

mut_a_denial_that_picks_its_code() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/core/src/authz/mod.rs")
s = p.read_text()
s = s.replace("impl Denied {\n", "impl Denied {\n    pub fn with_code(code: ErrorCode) -> Self {\n        let _ = code;\n        Self { decision: Decision::Deny }\n    }\n\n", 1)
p.write_text(s)
AZPY
}
expect_authz_fail_minimal \
    'a Denial constructor taking an ErrorCode, which is a private-bucket enumeration oracle' \
    mut_a_denial_that_picks_its_code 'a Denial constructor takes an ErrorCode'

mut_an_audit_sink_that_answers() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/gateway/src/ext/authz_audit.rs")
s = p.read_text()
s = s.replace("    fn on_decision(&self, event: &AuthzAuditEvent<'_>);",
              "    fn on_decision(&self, event: &AuthzAuditEvent<'_>) -> Decision;", 1)
p.write_text(s)
AZPY
}
expect_authz_fail_minimal \
    'an audit sink whose method returns a verdict, so the hook could overturn the decision' \
    mut_an_audit_sink_that_answers 'an AuthzAuditSink method returns a value or takes a mutable reference'

mut_an_allow_all_example() {
    cat >>crates/gateway/examples/minimal.rs <<'AZEOF'

fn convenient() -> impl rustfs_gateway::Authorizer {
    rustfs_gateway::allow_when(|_| true)
}
AZEOF
}
expect_authz_fail_minimal \
    'a copy-pasteable allow-all in an example, which is API' \
    mut_an_allow_all_example 'an example ships an unconditional allow'
expect_fail check_no_allow_all_in_examples.sh \
    'a copy-pasteable allow-all in an example' mut_an_allow_all_example

mut_authorizer_module_deleted() {
    rm -f crates/gateway/src/ext/authorizer.rs
}
expect_authz_fail_minimal \
    "the guard's own subject deleted, which must fail rather than skip" \
    mut_authorizer_module_deleted 'authorizer.rs does not exist; the guard cannot find the surface it is written about'

mut_an_authz_case_removed() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/gateway/tests/authz_contract.rs")
p.write_text(p.read_text().replace("c-azc-0030", "removed-case", 1))
AZPY
}
expect_authz_fail_minimal \
    'one of the thirty executable authorization cases removed' \
    mut_an_authz_case_removed 'the executable authorization matrix is not exactly c-azc-0001 through c-azc-0030'

# ── check_policy_snapshot_once.sh (P6-02) ──────────────────────────────────────

mut_a_second_reading_in_the_pipeline() {
    cat >>crates/gateway/src/service.rs <<'AZEOF'

async fn reread(inner: &Inner) {
    let _ = inner.policy_source.snapshot(None).await;
}
AZEOF
}
expect_fail check_policy_snapshot_once.sh \
    'a second reading of policy inside the pipeline crate' mut_a_second_reading_in_the_pipeline

mut_a_reading_outside_the_pipeline() {
    cat >>crates/gateway/src/dispatch.rs <<'AZEOF'

async fn own_view(source: &dyn crate::ext::PolicySource) {
    let _ = source.snapshot(None).await;
}
AZEOF
}
expect_fail check_policy_snapshot_once.sh \
    'a stage reading its own view of policy instead of the one it was handed' mut_a_reading_outside_the_pipeline

mut_the_reading_taken_after_the_reader() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/gateway/src/service.rs")
lines = p.read_text().splitlines(keepends=True)
# An authorize call above the snapshot: the reading is then not the one the
# reader used, whatever the response looks like.
lines.insert(14, "fn early(a: &dyn crate::ext::Authorizer) { let _ = |c, r| a.authorize_route(c, r); }\n")
p.write_text("".join(lines))
AZPY
}
expect_fail check_policy_snapshot_once.sh \
    'the policy reading taken after the authorizer has already run' mut_the_reading_taken_after_the_reader

mut_policy_module_deleted() {
    rm -f crates/gateway/src/ext/policy.rs
}
expect_fail check_policy_snapshot_once.sh \
    "the guard's own subject deleted, which must fail rather than skip" mut_policy_module_deleted

mut_policy_source_no_longer_held() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/gateway/src/routing.rs")
s = p.read_text()
subject = "    pub(crate) policy_source: Arc<dyn PolicySource>,\n"
if s.count(subject) != 1:
    raise SystemExit("missing mutation subject: the captured generation's policy source field")
p.write_text(s.replace(subject, "    pub(crate) policy_source: fn() -> Box<dyn PolicySource>,\n", 1))
AZPY
}
expect_fail check_policy_snapshot_once.sh \
    'a request generation that builds its policy source instead of holding one' mut_policy_source_no_longer_held \
    'no `policy_source: Arc<dyn PolicySource>` field'

# ── check_authz_no_default_impl.sh (P6-02) ─────────────────────────────────────

mut_authorize_route_default_body() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/gateway/src/ext/authorizer.rs")
s = p.read_text()
s = s.replace(
    ") -> BoxFuture<'a, Decision>;",
    ") -> BoxFuture<'a, Decision> { Box::pin(async { Decision::Deny }) }",
    1,
)
p.write_text(s)
AZPY
}
expect_fail check_authz_no_default_impl.sh \
    'a default body on authorize_route' mut_authorize_route_default_body

# -----------------------------------------------------------------------------
# P7-06. An operation scaffold is deliberately red while it is being implemented,
# but the exact marker must never survive into a merge. Both tracked and brand-new
# files are controls because a guard that only reads the index misses the latter.
# -----------------------------------------------------------------------------

mut_scaffold_marker_in_module() {
    printf '\n// SCAF%s\n' 'FOLD: implement before merge' >>crates/core/src/ops/mod.rs
}
expect_fail check_no_scaffold_on_main.sh \
    'a scaffold marker inserted into an existing operation module' mut_scaffold_marker_in_module

mut_untracked_scaffold_marker() {
    printf '// SCAF%s\n' 'FOLD: implement before merge' >crates/core/tests/scaffold_untracked.rs
}
expect_fail_unstaged check_no_scaffold_on_main.sh \
    'a scaffold marker in a new unstaged test file' mut_untracked_scaffold_marker

# The operation-to-test map is codegen-owned. A guard that checks only its header
# accepts a hand-edited body, while a guard that regenerates in memory catches it.
mut_verify_map_edited() {
    printf '\n# hand-edited mapping\n' >>xtask/verify-map.toml
}
# Executed by the build-guard worker above.

mut_verify_map_deleted() {
    rm -f xtask/verify-map.toml
}
# Executed by the build-guard worker above.



# Tool pins are one reviewable block. Test a moving version, a missing pin and the
# explicitly rejected installer independently so each assertion has gone red.
mut_tool_version_latest() {
    sed 's/cargo-hack@0\.6\.45/cargo-hack@latest/' .github/workflows/ci.yml >.github/workflows/ci.yml.mut
    mv .github/workflows/ci.yml.mut .github/workflows/ci.yml
}
expect_fail check_tool_versions_pinned.sh \
    'a CI tool pin changed to latest' mut_tool_version_latest

mut_tool_pin_deleted() {
    grep -v 'CARGO_DENY_TOOL:' .github/workflows/ci.yml >.github/workflows/ci.yml.mut
    mv .github/workflows/ci.yml.mut .github/workflows/ci.yml
}
expect_fail check_tool_versions_pinned.sh \
    'one of the six CI tool pins being removed' mut_tool_pin_deleted

mut_cargo_binstall_added() {
    printf '\n# cargo install cargo-%s\n' 'binstall' >>.github/workflows/ci.yml
}
expect_fail check_tool_versions_pinned.sh \
    'cargo-binstall introduced into the CI workflow' mut_cargo_binstall_added

mut_credentials_display() {
    python3 - <<'CREDPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/credentials.rs")
path.write_text(path.read_text() + """
impl core::fmt::Display for Credentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.identity().access_key_id())
    }
}
""")
CREDPY
}
expect_fail check_secret_hygiene.sh \
    'a Display implementation on Credentials' mut_credentials_display
# P7-05 documentation/context guards. Each acceptance rule has an explicit mutation so a green
# guard proves both directions rather than merely describing the current tree.
mut_map_deleted() {
    rm -f crates/xml/MAP.md
}
expect_fail check_map_files.sh \
    'a workspace crate losing its MAP.md' mut_map_deleted

mut_map_too_long() {
    for _ in $(seq 1 101); do printf 'extra\n' >>crates/xml/MAP.md; done
}
expect_fail check_map_files.sh \
    'a MAP.md growing beyond the 100-line entry-point budget' mut_map_too_long

mut_map_has_no_file_entries() {
    printf '| File | Responsibility | Read it when |\n| --- | --- | --- |\n' >crates/xml/MAP.md
}
expect_fail check_map_files.sh \
    'a MAP.md retaining only an empty table header' mut_map_has_no_file_entries

mut_map_recommends_generated() {
    printf '| `generated/**` | generated details | Read it when debugging |\n' >>crates/xml/MAP.md
}
expect_fail check_map_files.sh \
    'a MAP.md directing an agent into generated output' mut_map_recommends_generated

mut_module_doc_loses_boundary() {
    sed '/NOT responsible for:/d' xtask/src/main.rs >xtask/src/main.rs.mut
    mv xtask/src/main.rs.mut xtask/src/main.rs
}
expect_fail check_module_doc.sh \
    'a Rust file documenting responsibility but not its boundary' mut_module_doc_loses_boundary

mut_module_doc_nested_cfg_decoy() {
    python3 - <<'PY'
from pathlib import Path

path = Path("xtask/src/main.rs")
lines = [
    line
    for line in path.read_text().splitlines()
    if not any(marker in line for marker in ("Responsible for:", "NOT responsible for:", "Upstream:", "Downstream:"))
]
decoy = """#[cfg(any())]
mod disabled_doc_decoy {
//! Responsible for: nothing active.
//! NOT responsible for: the actual file.
//! Upstream: disabled input.
//! Downstream: disabled output.
}
"""
path.write_text(decoy + "\n".join(lines) + "\n")
PY
}
expect_fail check_module_doc.sh \
    'a cfg-disabled nested module impersonating the root module docs' mut_module_doc_nested_cfg_decoy

mut_unallowed_large_file() {
    for _ in $(seq 1 801); do printf '// padding\n' >>xtask/src/main.rs; done
}
expect_fail check_file_size.sh \
    'a Rust file exceeding 800 lines without an allowance' mut_unallowed_large_file

mut_invalid_file_size_allowance() {
    printf 'xtask/src/main.rs 900 missing-reason\n' >>allowances/file_size.txt
}
expect_fail check_file_size.sh \
    'a file-size allowance without an issue URL and reason' mut_invalid_file_size_allowance

mut_stale_file_size_allowance() {
    printf 'crates/xml/src/lib.rs 900 https://github.com/rustfs/backlog/issues/1714 stale allowance decoy\n' \
        >>allowances/file_size.txt
}
expect_fail check_file_size.sh \
    'an allowance remaining on a file below the ordinary 800-line ceiling' mut_stale_file_size_allowance

mut_forbidden_list_loses_alternative() {
    sed 's|`cargo tree -p <crate> -e normal`|none|' AGENTS.md >AGENTS.md.mut
    mv AGENTS.md.mut AGENTS.md
}
expect_fail check_agents_forbidden_list.sh \
    'a forbidden-list entry losing its safe alternative' mut_forbidden_list_loses_alternative

mut_agents_context_budget_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("AGENTS.md")
path.write_text(path.read_text().replace("**≤8 files / ≤40k tokens**", "an unbounded input set", 1))
PY
}
expect_fail check_agents_context_contract.sh \
    'the task-start file and token budget becoming unbounded' mut_agents_context_budget_removed

mut_scoped_agents_file() {
    printf '# local rules\n' >crates/xml/AGENTS.md
}
expect_fail check_agents_layering.sh \
    'a scoped AGENTS.md introduced before the layering trigger' mut_scoped_agents_file

mut_secret_in_a_log_line() {
    python3 - <<'CREDPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/authenticator.rs")
path.write_text(path.read_text() + """
fn an_operator_friendly_diagnostic(secret: &str) -> String {
    format!("the secret did not match: {secret}")
}
""")
CREDPY
}
expect_fail check_secret_hygiene.sh \
    'a formatting macro naming a secret in the gateway extension tree' mut_secret_in_a_log_line

mut_refusal_in_a_log_line() {
    python3 - <<'CREDPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/authenticator.rs")
path.write_text(path.read_text() + """
fn why_it_was_refused(reason: crate::ext::CredentialRefusal) -> String {
    format!("refused: {reason:?}")
}
""")
CREDPY
}
expect_fail check_secret_hygiene.sh \
    'the refusal reason travelling out of the module that produced it' mut_refusal_in_a_log_line

mut_secret_in_a_growing_buffer() {
    python3 - <<'CREDPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/credentials.rs")
path.write_text(path.read_text() + """
fn accumulate(parts: &[&[u8]]) -> Vec<u8> {
    let mut secret: Vec<u8> = Vec::new();
    for part in parts {
        secret.extend_from_slice(part);
    }
    secret
}
""")
CREDPY
}
expect_fail check_secret_hygiene.sh \
    'key material accumulated into a reallocating buffer' mut_secret_in_a_growing_buffer

mut_extra_expose_call_site() {
    python3 - <<'CREDPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/credentials.rs")
path.write_text(path.read_text() + """
fn a_second_reader(credentials: &Credentials) -> usize {
    credentials.secret().expose().len()
}
""")
CREDPY
}
expect_fail check_secret_hygiene.sh \
    'one more place key material leaves its container' mut_extra_expose_call_site

mut_credentials_module_deleted() {
    rm -f crates/gateway/src/ext/credentials.rs
}
expect_fail check_secret_hygiene.sh \
    "the guard's own subject deleted, which must fail rather than skip" mut_credentials_module_deleted

mut_provider_error_interpolates_request() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/credentials.rs")
text = path.read_text().replace("pub enum ProviderError {", "pub enum ProviderError {\n    Request(String),", 1)
path.write_text(text)
PYEOF
}
expect_fail check_preauth_no_interp.sh \
    'a provider error carrying request-derived text' mut_provider_error_interpolates_request

mut_preauth_message_becomes_owned() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/core/src/error.rs")
text = path.read_text().replace("message: &'static str,", "message: String,", 1)
path.write_text(text)
PYEOF
}
expect_fail check_preauth_static_msg.sh \
    'a pre-authentication error owning runtime text' mut_preauth_message_becomes_owned \
    "PreAuthError message must remain exactly &'static str"

mut_preauth_formats_message() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/core/src/error.rs")
path.write_text(path.read_text() + '\nfn forged_message(value: &str) { let _ = format!("{value}"); }\n')
PYEOF
}
expect_fail check_preauth_static_msg.sh \
    'a pre-authentication message formatted at runtime' mut_preauth_formats_message \
    'PreAuthError must not format a message'

mut_preauth_leaks_message() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/core/src/dispatch.rs")
path.write_text(path.read_text() + '\nfn forged_static(value: String) -> &\x27static str { Box::leak(value.into_boxed_str()) }\n')
PYEOF
}
expect_fail check_preauth_static_msg.sh \
    'a runtime string laundered into a static message' mut_preauth_leaks_message \
    'a runtime string must not be laundered into a static message'

mut_preauth_subject_deleted() {
    rm -f crates/core/src/error.rs
}
expect_fail check_preauth_static_msg.sh \
    "the guard's subject deleted, which must fail rather than skip" mut_preauth_subject_deleted \
    'PreAuthError subject is missing'

mut_signing_key_cache() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/authenticator.rs")
path.write_text(path.read_text() + "\nstruct BadCache { signing_key_cache: std::collections::HashMap<String, rustfs_gateway_sig::SigningKey> }\n")
PYEOF
}
expect_fail check_no_signing_key_cache.sh \
    'a cache retaining derived signing keys' mut_signing_key_cache

fi

# These workflow mutations parse YAML and shell text without compiling. The general shards own
# them so the build-backed shards contain only cases whose guards genuinely invoke Cargo.
if [[ "$QUIRK_LEDGER_ONLY" == 0 && "$DTO_COMPILER_ONLY" == 0 && "$BUILD_GUARDS_ONLY" == 0 && "$ERROR_STATUS_ONLY" == 0 ]]; then

replace_ci_text() {
    python3 - "$1" "$2" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
old, new = sys.argv[1:]
if old not in text:
    raise SystemExit(f"missing mutation subject: {old}")
path.write_text(text.replace(old, new, 1))
PYEOF
}

mut_ci_time_static_command_weakened() {
    replace_ci_text 'cargo fmt --all --check' 'cargo fmt --check'
}
expect_fail check_ci_time_gate.sh \
    'the required Static checks job weakening the exact fmt command' mut_ci_time_static_command_weakened

mut_ci_time_clippy_command_weakened() {
    replace_ci_text 'cargo clippy --workspace --all-targets -- -D warnings' \
        'cargo clippy --workspace -- -D warnings'
}
expect_fail check_ci_time_gate.sh \
    'the required Clippy job dropping all-target coverage' mut_ci_time_clippy_command_weakened

mut_ci_time_static_failure_swallowed() {
    replace_ci_text '      - run: cargo fmt --all --check' \
        '      - run: cargo fmt --all --check || true'
}
expect_fail check_ci_time_gate.sh \
    'the required Static checks job swallowing fmt failure' mut_ci_time_static_failure_swallowed

mut_ci_time_clippy_continues_on_error() {
    replace_ci_text '      - run: cargo clippy --workspace --all-targets -- -D warnings' \
        '      - run: cargo clippy --workspace --all-targets -- -D warnings
        continue-on-error: true'
}
expect_fail check_ci_time_gate.sh \
    'the required Clippy step being allowed to fail' mut_ci_time_clippy_continues_on_error

mut_ci_time_static_name_changed() {
    replace_ci_text '    name: Static checks' '    name: Static check'
}
expect_fail check_ci_time_gate.sh \
    'the branch-protected Static checks context being renamed' mut_ci_time_static_name_changed

mut_ci_time_duplicate_required_name() {
    replace_ci_text '  clippy:
    name: Clippy' '  static-decoy:
    name: Static checks
    runs-on: ubuntu-latest
    timeout-minutes: 1
    steps:
      - run: true

  clippy:
    name: Clippy'
}
expect_fail check_ci_time_gate.sh \
    'a second job impersonating a branch-protected check name' mut_ci_time_duplicate_required_name

mut_ci_time_static_timeout_removed() {
    replace_ci_text '  static:
    name: Static checks
    runs-on: ubuntu-latest
    timeout-minutes: 9' '  static:
    name: Static checks
    runs-on: ubuntu-latest'
}
expect_fail check_ci_time_gate.sh \
    'the required Static checks job becoming unbounded' mut_ci_time_static_timeout_removed

mut_ci_time_feedback_timeout_removed() {
    replace_ci_text '  feedback-loop:
    name: Operation feedback loop
    runs-on: ubuntu-latest
    timeout-minutes: 9' '  feedback-loop:
    name: Operation feedback loop
    runs-on: ubuntu-latest'
}
expect_fail check_ci_time_gate.sh \
    'a non-required pull-request job becoming unbounded' mut_ci_time_feedback_timeout_removed

mut_ci_time_feedback_prebuild_drops_operation_runner() {
    replace_ci_text '          cargo build -p xtask --no-default-features --features operation
' ''
}
expect_fail check_ci_time_gate.sh \
    'operation verification dropping the exact bounded runner prebuild' mut_ci_time_feedback_prebuild_drops_operation_runner

mut_ci_time_msrv_timeout_removed() {
    replace_ci_text '  msrv:
    name: MSRV
    runs-on: ubuntu-latest
    timeout-minutes: 9' '  msrv:
    name: MSRV
    runs-on: ubuntu-latest'
}
expect_fail check_ci_time_gate.sh \
    'the MSRV job becoming unbounded' mut_ci_time_msrv_timeout_removed

mut_ci_time_dependency_path_exceeds_budget() {
    replace_ci_text '  feedback-loop:
    name: Operation feedback loop' '  feedback-loop:
    name: Operation feedback loop
    needs: bootstrap'
}
expect_fail check_ci_time_gate.sh \
    'serial jobs permitting a fifteen-minute dependency path' mut_ci_time_dependency_path_exceeds_budget

mut_ci_time_docs_job_removed() {
    replace_ci_text '  docs:' '  docs-removed:'
}
expect_fail check_ci_time_gate.sh \
    'an accepted pull-request job being renamed away' mut_ci_time_docs_job_removed

mut_ci_time_permissions_widened() {
    replace_ci_text 'permissions:
  contents: read' 'permissions:
  contents: write'
}
expect_fail check_ci_time_gate.sh \
    'workflow permissions being widened' mut_ci_time_permissions_widened

mut_ci_time_action_pin_replaced_by_tag() {
    replace_ci_text 'actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10' \
        'actions/checkout@v6'
}
expect_fail check_ci_time_gate.sh \
    'an action pin being replaced by a movable tag' mut_ci_time_action_pin_replaced_by_tag

mut_ci_time_job_permissions_override() {
    replace_ci_text '  docs:
    name: Documentation' '  docs:
    name: Documentation
    permissions:
      contents: write'
}
expect_fail check_ci_time_gate.sh \
    'a job overriding the workflow minimum permissions' mut_ci_time_job_permissions_override

mut_ci_time_required_step_skips() {
    replace_ci_text '      - run: cargo clippy --workspace --all-targets -- -D warnings' \
        '      - run: cargo clippy --workspace --all-targets -- -D warnings
        if: ${{ false }}'
}
expect_fail check_ci_time_gate.sh \
    'the required Clippy command being conditionally skipped' mut_ci_time_required_step_skips

mut_ci_time_job_concurrency_serializes() {
    replace_ci_text '  docs:
    name: Documentation' '  docs:
    name: Documentation
    concurrency: pull-request-gate'
}
expect_fail check_ci_time_gate.sh \
    'a job-level concurrency lane invalidating the dependency budget' mut_ci_time_job_concurrency_serializes

mut_ci_time_workflow_defaults_hide_failure() {
    replace_ci_text 'permissions:
  contents: read' 'defaults:
  run:
    shell: bash {0}

permissions:
  contents: read'
}
expect_fail check_ci_time_gate.sh \
    'workflow defaults disabling fail-fast shell behavior' mut_ci_time_workflow_defaults_hide_failure

mut_ci_time_workflow_env_overrides_cargo() {
    replace_ci_text 'env:
  CARGO_TERM_COLOR: always' 'env:
  PATH: scripts/fake-bin
  CARGO_TERM_COLOR: always'
}
expect_fail check_ci_time_gate.sh \
    'the workflow environment overriding the required command path' mut_ci_time_workflow_env_overrides_cargo

mut_ci_time_concurrency_cancel_disabled() {
    replace_ci_text '  cancel-in-progress: true' '  cancel-in-progress: false'
}
expect_fail check_ci_time_gate.sh \
    'superseded branch runs no longer being cancelled' mut_ci_time_concurrency_cancel_disabled

mut_ci_time_static_parent_fetch_dropped() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  static:")
position = text.index("          fetch-depth: 0", start)
path.write_text(text[:position] + text[position:].replace("          fetch-depth: 0", "          fetch-depth: 2", 1))
PYEOF
}
expect_fail check_ci_time_gate.sh \
    'the Static checks job losing the branch graph required by merge-base guards' mut_ci_time_static_parent_fetch_dropped

mut_ci_time_clippy_setup_action_replaced() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  clippy:")
old = "      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2"
position = text.index(old, start)
new = "      - uses: example/environment-injector@0000000000000000000000000000000000000000"
path.write_text(text[:position] + text[position:].replace(old, new, 1))
PYEOF
}
expect_fail check_ci_time_gate.sh \
    'a fully pinned action replacing the expected Clippy setup' mut_ci_time_clippy_setup_action_replaced

mut_ci_time_duplicate_fmt_execution() {
    replace_ci_text '  clippy:
    name: Clippy' '  fmt-decoy:
    name: Format duplicate
    runs-on: ubuntu-latest
    timeout-minutes: 1
    steps:
      - run: cargo fmt --all --check

  clippy:
    name: Clippy'
}
expect_fail check_ci_time_gate.sh \
    'a second CI job duplicating the authoritative fmt execution' mut_ci_time_duplicate_fmt_execution

mut_ci_time_matrix_serializes_job() {
    replace_ci_text '  docs:
    name: Documentation' '  docs:
    name: Documentation
    strategy:
      max-parallel: 1
      matrix:
        shard: [one, two]'
}
expect_fail check_ci_time_gate.sh \
    'a serial matrix invalidating the one-job timeout budget' mut_ci_time_matrix_serializes_job

mut_ci_time_nonrequired_job_skips() {
    replace_ci_text '  docs:
    name: Documentation' '  docs:
    name: Documentation
    if: ${{ false }}'
}
expect_fail check_ci_time_gate.sh \
    'a pull-request job being conditionally skipped' mut_ci_time_nonrequired_job_skips

mut_ci_time_dependency_cycle() {
    replace_ci_text '  docs:
    name: Documentation' '  docs:
    name: Documentation
    needs: feedback-loop'
    replace_ci_text '  feedback-loop:
    name: Operation feedback loop' '  feedback-loop:
    name: Operation feedback loop
    needs: docs'
}
expect_fail check_ci_time_gate.sh \
    'a cycle making the CI dependency budget undefined' mut_ci_time_dependency_cycle

mut_ci_time_required_shell_override() {
    replace_ci_text '      - run: cargo clippy --workspace --all-targets -- -D warnings' \
        '      - run: cargo clippy --workspace --all-targets -- -D warnings
        shell: bash {0}'
}
expect_fail check_ci_time_gate.sh \
    'the required Clippy command overriding fail-fast shell behavior' mut_ci_time_required_shell_override

mut_ci_time_required_runner_replaced() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  clippy:")
position = text.index("    runs-on: ubuntu-latest", start)
path.write_text(text[:position] + text[position:].replace("    runs-on: ubuntu-latest", "    runs-on: self-hosted", 1))
PYEOF
}
expect_fail check_ci_time_gate.sh \
    'the required Clippy command moving to an unexpected runner' mut_ci_time_required_runner_replaced

mut_ci_time_workflow_deleted() {
    rm -f .github/workflows/ci.yml
}
expect_fail check_ci_time_gate.sh \
    "the guard's own workflow input deleted, which must fail rather than skip" mut_ci_time_workflow_deleted

mut_ci_workspace_job_missing() {
    replace_ci_text '  workspace-tests:' '  workspace-testz:'
}
expect_fail check_ci_test_split.sh \
    'the workspace-tests job being renamed away' mut_ci_workspace_job_missing

mut_ci_second_workspace_job_missing() {
    replace_ci_text '  workspace-tests-2:' '  workspace-testz-2:'
}
expect_fail check_ci_test_split.sh \
    'the second workspace test job being renamed away' mut_ci_second_workspace_job_missing

mut_ci_third_workspace_job_missing() {
    replace_ci_text '  workspace-tests-3:' '  workspace-testz-3:'
}
expect_fail check_ci_test_split.sh \
    'the third workspace test job being renamed away' mut_ci_third_workspace_job_missing

mut_ci_workspace_command_weakened() {
    replace_ci_text 'scripts/ci_budget.sh 480 "workspace tests 1/3" cargo test --workspace --exclude rustfs-gateway-conformance --exclude rustfs-gateway --exclude rustfs-gateway-goldens --exclude rustfs-gateway-types' 'scripts/ci_budget.sh 480 "workspace tests 1/3" cargo test -p xtask'
}
expect_fail check_ci_test_split.sh \
    'the workspace test job running only one package' mut_ci_workspace_command_weakened

mut_ci_second_workspace_command_weakened() {
    replace_ci_text 'scripts/ci_budget.sh 480 "workspace tests 2/3" bash -c '\''cargo test --package rustfs-gateway-conformance && cargo check --package rustfs-gateway'\''' 'scripts/ci_budget.sh 480 "workspace tests 2/3" cargo test -p xtask'
}
expect_fail check_ci_test_split.sh \
    'the second workspace shard running the wrong package' mut_ci_second_workspace_command_weakened

mut_ci_second_workspace_gateway_prebuild_dropped() {
    replace_ci_text 'scripts/ci_budget.sh 480 "workspace tests 2/3" bash -c '\''cargo test --package rustfs-gateway-conformance && cargo check --package rustfs-gateway'\''' 'scripts/ci_budget.sh 480 "workspace tests 2/3" cargo test --package rustfs-gateway-conformance'
}
expect_fail check_ci_test_split.sh \
    'the facade fixture losing its same-profile gateway prebuild' \
    mut_ci_second_workspace_gateway_prebuild_dropped

mut_ci_third_workspace_command_weakened() {
    replace_ci_text 'scripts/ci_budget.sh 480 "workspace tests 3/3" bash -c '\''cargo test --package rustfs-gateway-goldens --package rustfs-gateway-types --features rustfs-gateway-types/compat-s3s && cargo test --package rustfs-gateway'\''' 'scripts/ci_budget.sh 480 "workspace tests 3/3" cargo test -p xtask'
}
expect_fail check_ci_test_split.sh \
    'the third workspace shard running the wrong package' mut_ci_third_workspace_command_weakened

mut_ci_third_workspace_compat_feature_dropped() {
    replace_ci_text 'scripts/ci_budget.sh 480 "workspace tests 3/3" bash -c '\''cargo test --package rustfs-gateway-goldens --package rustfs-gateway-types --features rustfs-gateway-types/compat-s3s && cargo test --package rustfs-gateway'\''' 'scripts/ci_budget.sh 480 "workspace tests 3/3" cargo test --package rustfs-gateway-goldens --package rustfs-gateway-types'
}

# The move of `rustfs-gateway` out of the shard that ran out of time and into the shard that was
# never above 4% of its clock is the whole point of the rebalance. A shard 3 that quietly drops it
# again would leave the gateway package tested nowhere while all three jobs stayed green.
mut_ci_third_workspace_gateway_package_dropped() {
    replace_ci_text 'scripts/ci_budget.sh 480 "workspace tests 3/3" bash -c '\''cargo test --package rustfs-gateway-goldens --package rustfs-gateway-types --features rustfs-gateway-types/compat-s3s && cargo test --package rustfs-gateway'\''' 'scripts/ci_budget.sh 480 "workspace tests 3/3" cargo test --package rustfs-gateway-goldens --package rustfs-gateway-types --features rustfs-gateway-types/compat-s3s'
}
expect_fail check_ci_test_split.sh \
    'the third workspace shard dropping the gateway package the second one handed it' \
    mut_ci_third_workspace_gateway_package_dropped
expect_fail check_ci_test_split.sh \
    'the types tests losing the workspace compat-s3s feature graph' \
    mut_ci_third_workspace_compat_feature_dropped

mut_ci_handlers_facade_fixture_removed() {
    replace_ci_text '          scripts/ci_budget.sh 60 "handlers facade fixture" scripts/test_handlers_facade_fixture.sh
' ''
}
expect_fail check_ci_test_split.sh \
    'the workspace test job dropping the facade-only downstream fixture' \
    mut_ci_handlers_facade_fixture_removed

mut_ci_handlers_facade_fixture_moved_before_gateway_prebuild() {
    replace_ci_text '          scripts/ci_budget.sh 480 "workspace tests 2/3" bash -c '\''cargo test --package rustfs-gateway-conformance && cargo check --package rustfs-gateway'\''
          scripts/ci_budget.sh 60 "handlers facade fixture" scripts/test_handlers_facade_fixture.sh' \
        '          scripts/ci_budget.sh 60 "handlers facade fixture" scripts/test_handlers_facade_fixture.sh
          scripts/ci_budget.sh 480 "workspace tests 2/3" bash -c '\''cargo test --package rustfs-gateway-conformance && cargo check --package rustfs-gateway'\'''
}
expect_fail check_ci_test_split.sh \
    'the facade-only fixture moving ahead of its authoritative gateway prebuild' \
    mut_ci_handlers_facade_fixture_moved_before_gateway_prebuild

mut_ci_workspace_failure_swallowed() {
    replace_ci_text '          scripts/ci_budget.sh 480 "workspace tests 1/3" cargo test --workspace --exclude rustfs-gateway-conformance --exclude rustfs-gateway --exclude rustfs-gateway-goldens --exclude rustfs-gateway-types' \
        '          scripts/ci_budget.sh 480 "workspace tests 1/3" cargo test --workspace --exclude rustfs-gateway-conformance --exclude rustfs-gateway --exclude rustfs-gateway-goldens --exclude rustfs-gateway-types || true'
}
expect_fail check_ci_test_split.sh \
    'the workspace test job swallowing a failure or timeout' mut_ci_workspace_failure_swallowed

mut_ci_signing_suite_run_dropped() {
    replace_ci_text '          scripts/ci_budget.sh 60 "signing suite run" target/debug/xtask sigsuite run' '          scripts/ci_budget.sh 60 "signing suite run" true'
}
expect_fail check_ci_test_split.sh \
    'the official signing suite run being replaced with a no-op' mut_ci_signing_suite_run_dropped

mut_ci_signing_suite_fetch_dropped() {
    replace_ci_text '          scripts/ci_budget.sh 60 "signing suite fetch" target/debug/xtask sigsuite fetch' '          scripts/ci_budget.sh 60 "signing suite fetch" true'
}
expect_fail check_ci_test_split.sh \
    'the official signing suite fetch being replaced with a no-op' mut_ci_signing_suite_fetch_dropped

mut_ci_signing_suite_build_dropped() {
    replace_ci_text '          scripts/ci_budget.sh 180 "signing suite build" cargo build --package xtask --bin xtask' '          scripts/ci_budget.sh 180 "signing suite build" true'
}
expect_fail check_ci_test_split.sh \
    'the official signing suite runner build being replaced with a no-op' mut_ci_signing_suite_build_dropped

mut_ci_signing_suite_not_aggregated() {
    replace_ci_text 'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test' \
        'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, guard-self-test'
}
expect_fail check_ci_test_split.sh \
    'the official signing suite result leaving the aggregate Test check' mut_ci_signing_suite_not_aggregated

mut_ci_persistence_goldens_job_missing() {
    replace_ci_text '  persistence-goldens:' '  persistence-goldenz:'
}
expect_fail check_ci_test_split.sh \
    'the persistence goldens job being renamed away' mut_ci_persistence_goldens_job_missing

mut_ci_persistence_corpus_report_dropped() {
    replace_ci_text 'target/debug/corpus-report' \
        'true # corpus report dropped'
}
expect_fail check_ci_test_split.sh \
    'the persistence gate replacing corpus-report with a no-op' \
    mut_ci_persistence_corpus_report_dropped

mut_ci_persistence_four_way_dropped() {
    replace_ci_text 'target/debug/four-way --all' \
        'true # four-way assertions dropped'
}
expect_fail check_ci_test_split.sh \
    'the persistence gate replacing four-way --all with a no-op' \
    mut_ci_persistence_four_way_dropped

mut_ci_persistence_size_uses_fake_directory() {
    replace_ci_text '    printf '\''%s\n'\'' "$report" |' \
        '    du -sb crates/goldens/corpus |'
}
expect_fail check_ci_test_split.sh \
    'the persistence size guard measuring a directory that is not the embedded corpus input' \
    mut_ci_persistence_size_uses_fake_directory

mut_ci_persistence_size_limit_widened() {
    replace_ci_text '  test "$corpus_bytes" -le 20971520' \
        '  test "$corpus_bytes" -le 209715200'
}
expect_fail check_ci_test_split.sh \
    'the persistence corpus limit being widened past twenty MiB' \
    mut_ci_persistence_size_limit_widened

mut_ci_persistence_job_budget_widened() {
    replace_ci_text '  persistence-goldens:
    name: Persistence goldens
    runs-on: ubuntu-latest
    timeout-minutes: 4' '  persistence-goldens:
    name: Persistence goldens
    runs-on: ubuntu-latest
    timeout-minutes: 5'
}
expect_fail check_ci_test_split.sh \
    'the persistence goldens job widening its four-minute budget' \
    mut_ci_persistence_job_budget_widened

mut_ci_persistence_not_aggregated() {
    replace_ci_text 'transport-parity, transport-parity-2, persistence-goldens, signing-suite' \
        'transport-parity, transport-parity-2, signing-suite'
}
expect_fail check_ci_test_split.sh \
    'the persistence goldens result leaving the required Test check' \
    mut_ci_persistence_not_aggregated

mut_ci_persistence_result_ignored() {
    replace_ci_text 'PERSISTENCE_GOLDENS_RESULT: ${{ needs.persistence-goldens.result }}' \
        'PERSISTENCE_GOLDENS_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate binding a constant persistence goldens result' \
    mut_ci_persistence_result_ignored

mut_ci_persistence_comparison_dropped() {
    replace_ci_text '          test "$PERSISTENCE_GOLDENS_RESULT" = success' \
        '          true # persistence goldens result ignored'
}
expect_fail check_ci_test_split.sh \
    'the aggregate no longer comparing the persistence goldens result' \
    mut_ci_persistence_comparison_dropped

mut_ci_workspace_budget_widened() {
    replace_ci_text '  workspace-tests:
    name: Workspace tests 1
    runs-on: ubuntu-latest
    timeout-minutes: 9' '  workspace-tests:
    name: Workspace tests 1
    runs-on: ubuntu-latest
    timeout-minutes: 10'
}
expect_fail check_ci_test_split.sh \
    'the workspace test job consuming the aggregation minute' mut_ci_workspace_budget_widened

mut_ci_workspace_serialized() {
    replace_ci_text '  workspace-tests:
    name: Workspace tests 1' '  workspace-tests:
    needs: guard-self-test
    name: Workspace tests 1'
}
expect_fail check_ci_test_split.sh \
    'the workspace test job waiting for guard mutations' mut_ci_workspace_serialized

mut_ci_workspace_setup_action_replaced() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  workspace-tests:")
old = "      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2"
position = text.index(old, start)
new = "      - uses: example/environment-injector@0000000000000000000000000000000000000000"
path.write_text(text[:position] + text[position:].replace(old, new, 1))
PYEOF
}
expect_fail check_ci_test_split.sh \
    'a workspace setup action being replaced by an environment injector' mut_ci_workspace_setup_action_replaced

mut_ci_guard_job_missing() {
    replace_ci_text '  guard-self-test:' '  guard-self-tesx:'
}
expect_fail check_ci_test_split.sh \
    'the guard-self-test job being renamed away' mut_ci_guard_job_missing

mut_ci_guard_parent_fetch_dropped() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  guard-self-test:")
old = "          fetch-depth: 0"
position = text.index(old, start)
path.write_text(text[:position] + text[position:].replace(old, "          fetch-depth: 1", 1))
PYEOF
}
expect_fail check_ci_test_split.sh \
    'the guard mutation job losing access to the branch merge base' mut_ci_guard_parent_fetch_dropped

mut_ci_guard_command_dropped() {
    replace_ci_text 'scripts/ci_budget.sh 300 "guard mutations 1/5" env GATEWAY_GUARD_BUDGET_SECONDS=300 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh' 'scripts/ci_budget.sh 300 "guard mutations 1/5" true'
}
expect_fail check_ci_test_split.sh \
    'the guard mutation suite being replaced with a no-op' mut_ci_guard_command_dropped

mut_ci_guard_failure_swallowed() {
    replace_ci_text '          scripts/ci_budget.sh 300 "guard mutations 1/5" env GATEWAY_GUARD_BUDGET_SECONDS=300 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh' \
        '          scripts/ci_budget.sh 300 "guard mutations 1/5" env GATEWAY_GUARD_BUDGET_SECONDS=300 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh || true'
}
expect_fail check_ci_test_split.sh \
    'the guard mutation job swallowing a failure or timeout' mut_ci_guard_failure_swallowed

mut_ci_guard_budget_widened() {
    replace_ci_text '  guard-self-test:
    name: Guard self-test
    runs-on: ubuntu-latest
    timeout-minutes: 6' '  guard-self-test:
    name: Guard self-test
    runs-on: ubuntu-latest
    timeout-minutes: 10'
}
expect_fail check_ci_test_split.sh \
    'the guard mutation job consuming the aggregation minute' mut_ci_guard_budget_widened

mut_ci_guard_serialized() {
    replace_ci_text '  guard-self-test:
    name: Guard self-test' '  guard-self-test:
    needs: workspace-tests
    name: Guard self-test'
}
expect_fail check_ci_test_split.sh \
    'the guard mutation job waiting for workspace tests' mut_ci_guard_serialized

mut_ci_target_job_missing() {
    replace_ci_text '  target-consolidation-self-test:' '  target-consolidation-self-tesx:'
}
expect_fail check_ci_test_split.sh \
    'the target-consolidation-self-test job being renamed away' mut_ci_target_job_missing

mut_ci_target_command_dropped() {
    replace_ci_text 'scripts/ci_budget.sh 120 "target consolidation self-test" bash scripts/test_test_target_consolidation.sh' \
        'scripts/ci_budget.sh 120 "target consolidation self-test" true'
}
expect_fail check_ci_test_split.sh \
    'the target-consolidation mutation suite being replaced with a no-op' mut_ci_target_command_dropped

mut_ci_target_failure_swallowed() {
    replace_ci_text '          scripts/ci_budget.sh 120 "target consolidation self-test" bash scripts/test_test_target_consolidation.sh' \
        '          scripts/ci_budget.sh 120 "target consolidation self-test" bash scripts/test_test_target_consolidation.sh || true'
}
expect_fail check_ci_test_split.sh \
    'the target-consolidation job swallowing a failure or timeout' mut_ci_target_failure_swallowed

# The coverage self-test shares that runner, and shares nothing else: it is a second timed command
# with a budget of its own. Both mutations below are the same two shapes as the pair above, which
# is the point — a suite added to an existing runner is exactly as easy to silence as one with a
# runner to itself, and neither is allowed to be.
mut_ci_coverage_command_dropped() {
    replace_ci_text 'scripts/ci_budget.sh 45 "test target coverage self-test" bash scripts/test_test_target_coverage.sh' \
        'scripts/ci_budget.sh 45 "test target coverage self-test" true'
}
expect_fail check_ci_test_split.sh \
    'the test-target coverage suite being replaced with a no-op' mut_ci_coverage_command_dropped \
    'target-consolidation-self-test command changed or can hide a failure'

mut_ci_coverage_failure_swallowed() {
    replace_ci_text '          scripts/ci_budget.sh 45 "test target coverage self-test" bash scripts/test_test_target_coverage.sh' \
        '          scripts/ci_budget.sh 45 "test target coverage self-test" bash scripts/test_test_target_coverage.sh || true'
}
expect_fail check_ci_test_split.sh \
    'the test-target coverage suite swallowing a failure or timeout' mut_ci_coverage_failure_swallowed \
    'target-consolidation-self-test command changed or can hide a failure'

mut_ci_target_budget_widened() {
    replace_ci_text '  target-consolidation-self-test:
    name: Target consolidation self-test
    runs-on: ubuntu-latest
    timeout-minutes: 3' '  target-consolidation-self-test:
    name: Target consolidation self-test
    runs-on: ubuntu-latest
    timeout-minutes: 4'
}
expect_fail check_ci_test_split.sh \
    'the target-consolidation job widening its three-minute budget' mut_ci_target_budget_widened

mut_ci_target_setup_action_replaced() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  target-consolidation-self-test:")
old = "      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6"
position = text.index(old, start)
new = "      - uses: example/environment-injector@0000000000000000000000000000000000000000"
path.write_text(text[:position] + text[position:].replace(old, new, 1))
PYEOF
}
expect_fail check_ci_test_split.sh \
    'the target-consolidation checkout being replaced by an environment injector' \
    mut_ci_target_setup_action_replaced

mut_ci_target_serialized() {
    replace_ci_text '  target-consolidation-self-test:
    name: Target consolidation self-test' '  target-consolidation-self-test:
    needs: guard-self-test
    name: Target consolidation self-test'
}
expect_fail check_ci_test_split.sh \
    'the target-consolidation job waiting for guard mutations' mut_ci_target_serialized

mut_ci_quirk_ledger_job_missing() {
    replace_ci_text '  quirk-ledger-self-test:' '  quirk-ledger-self-tesx:'
}
expect_fail check_ci_test_split.sh \
    'the quirk-ledger-self-test job being renamed away' mut_ci_quirk_ledger_job_missing

mut_ci_quirk_ledger_command_dropped() {
    replace_ci_text 'scripts/ci_budget.sh 150 "quirk ledger mutations 1/3" env GATEWAY_GUARD_BUDGET_SECONDS=150 GATEWAY_GUARD_QUIRK_LEDGER_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=3 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh' \
        'scripts/ci_budget.sh 60 "quirk ledger mutations 1/3" true'
}
expect_fail check_ci_test_split.sh \
    'the quirk-ledger mutation suite being replaced with a no-op' mut_ci_quirk_ledger_command_dropped

mut_ci_quirk_ledger_failure_swallowed() {
    replace_ci_text '          scripts/ci_budget.sh 150 "quirk ledger mutations 1/3" env GATEWAY_GUARD_BUDGET_SECONDS=150 GATEWAY_GUARD_QUIRK_LEDGER_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=3 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh' \
        '          scripts/ci_budget.sh 150 "quirk ledger mutations 1/3" env GATEWAY_GUARD_BUDGET_SECONDS=150 GATEWAY_GUARD_QUIRK_LEDGER_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=3 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh || true'
}
expect_fail check_ci_test_split.sh \
    'the quirk-ledger job swallowing a failure or timeout' mut_ci_quirk_ledger_failure_swallowed

mut_ci_quirk_ledger_budget_widened() {
    replace_ci_text '  quirk-ledger-self-test:
    name: Quirk ledger self-test 1
    runs-on: ubuntu-latest
    timeout-minutes: 3' '  quirk-ledger-self-test:
    name: Quirk ledger self-test 1
    runs-on: ubuntu-latest
    timeout-minutes: 4'
}
expect_fail check_ci_test_split.sh \
    'the quirk-ledger job widening its three-minute budget' mut_ci_quirk_ledger_budget_widened

mut_ci_quirk_ledger_setup_action_replaced() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  quirk-ledger-self-test:")
old = "      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6"
position = text.index(old, start)
new = "      - uses: example/environment-injector@0000000000000000000000000000000000000000"
path.write_text(text[:position] + text[position:].replace(old, new, 1))
PYEOF
}
expect_fail check_ci_test_split.sh \
    'the quirk-ledger checkout being replaced by an environment injector' \
    mut_ci_quirk_ledger_setup_action_replaced

mut_ci_quirk_ledger_serialized() {
    replace_ci_text '  quirk-ledger-self-test:
    name: Quirk ledger self-test 1' '  quirk-ledger-self-test:
    needs: guard-self-test
    name: Quirk ledger self-test 1'
}
expect_fail check_ci_test_split.sh \
    'the quirk-ledger job waiting for guard mutations' mut_ci_quirk_ledger_serialized

mut_ci_third_quirk_ledger_job_missing() {
    replace_ci_text '  quirk-ledger-self-test-3:' '  quirk-ledger-self-tesx-3:'
}
expect_fail check_ci_test_split.sh \
    'the third quirk-ledger shard being renamed away' mut_ci_third_quirk_ledger_job_missing

mut_ci_dto_compiler_command_dropped() {
    replace_ci_text 'scripts/ci_budget.sh 150 "DTO compiler self-test" env GATEWAY_GUARD_BUDGET_SECONDS=150 GATEWAY_GUARD_DTO_COMPILER_ONLY=1 bash scripts/test_guard_scripts.sh' \
        'scripts/ci_budget.sh 90 "DTO compiler self-test" true'
}
expect_fail check_ci_test_split.sh \
    'the DTO compiler mutation suite being replaced with a no-op' mut_ci_dto_compiler_command_dropped

mut_ci_dto_compiler_failure_swallowed() {
    replace_ci_text '          scripts/ci_budget.sh 150 "DTO compiler self-test" env GATEWAY_GUARD_BUDGET_SECONDS=150 GATEWAY_GUARD_DTO_COMPILER_ONLY=1 bash scripts/test_guard_scripts.sh' \
        '          scripts/ci_budget.sh 150 "DTO compiler self-test" env GATEWAY_GUARD_BUDGET_SECONDS=150 GATEWAY_GUARD_DTO_COMPILER_ONLY=1 bash scripts/test_guard_scripts.sh || true'
}
expect_fail check_ci_test_split.sh \
    'the DTO compiler job swallowing a failure or timeout' mut_ci_dto_compiler_failure_swallowed

mut_ci_build_guard_command_dropped() {
    replace_ci_text 'scripts/ci_budget.sh 380 "build-backed guards 1/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh' \
        'scripts/ci_budget.sh 380 "build-backed guards 1/5" true'
}
expect_fail check_ci_test_split.sh \
    'the build-backed mutation suite being replaced with a no-op' mut_ci_build_guard_command_dropped

mut_ci_build_guard_failure_swallowed() {
    replace_ci_text '          scripts/ci_budget.sh 380 "build-backed guards 1/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh' \
        '          scripts/ci_budget.sh 380 "build-backed guards 1/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh || true'
}
expect_fail check_ci_test_split.sh \
    'the build-backed guard job swallowing a failure or timeout' mut_ci_build_guard_failure_swallowed

mut_ci_build_guard_second_shard_duplicated() {
    replace_ci_text 'scripts/ci_budget.sh 380 "build-backed guards 2/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=1 bash scripts/test_guard_scripts.sh' \
        'scripts/ci_budget.sh 380 "build-backed guards 2/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh'
}
expect_fail check_ci_test_split.sh \
    'the second build-backed worker repeating the first fifth' \
    mut_ci_build_guard_second_shard_duplicated \
    'build-guard-self-test-2 command changed, lost its shard, or can hide a failure'

mut_ci_build_guard_second_failure_swallowed() {
    replace_ci_text '          scripts/ci_budget.sh 380 "build-backed guards 2/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=1 bash scripts/test_guard_scripts.sh' \
        '          scripts/ci_budget.sh 380 "build-backed guards 2/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=1 bash scripts/test_guard_scripts.sh || true'
}
expect_fail check_ci_test_split.sh \
    'the second build-backed worker swallowing a failure or timeout' \
    mut_ci_build_guard_second_failure_swallowed

mut_ci_build_guard_third_shard_duplicated() {
    replace_ci_text 'scripts/ci_budget.sh 380 "build-backed guards 3/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=2 bash scripts/test_guard_scripts.sh' \
        'scripts/ci_budget.sh 380 "build-backed guards 3/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh'
}
expect_fail check_ci_test_split.sh \
    'the third build-backed worker repeating the first fifth' \
    mut_ci_build_guard_third_shard_duplicated \
    'build-guard-self-test-3 command changed, lost its shard, or can hide a failure'

mut_ci_build_guard_third_failure_swallowed() {
    replace_ci_text '          scripts/ci_budget.sh 380 "build-backed guards 3/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=2 bash scripts/test_guard_scripts.sh' \
        '          scripts/ci_budget.sh 380 "build-backed guards 3/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=2 bash scripts/test_guard_scripts.sh || true'
}
expect_fail check_ci_test_split.sh \
    'the third build-backed worker swallowing a failure or timeout' \
    mut_ci_build_guard_third_failure_swallowed

mut_ci_build_guard_fourth_shard_duplicated() {
    replace_ci_text 'scripts/ci_budget.sh 380 "build-backed guards 4/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=3 bash scripts/test_guard_scripts.sh' \
        'scripts/ci_budget.sh 380 "build-backed guards 4/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh'
}
expect_fail check_ci_test_split.sh \
    'the fourth build-backed worker repeating the first fifth' \
    mut_ci_build_guard_fourth_shard_duplicated

mut_ci_build_guard_fourth_failure_swallowed() {
    replace_ci_text '          scripts/ci_budget.sh 380 "build-backed guards 4/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=3 bash scripts/test_guard_scripts.sh' \
        '          scripts/ci_budget.sh 380 "build-backed guards 4/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=3 bash scripts/test_guard_scripts.sh || true'
}
expect_fail check_ci_test_split.sh \
    'the fourth build-backed worker swallowing a failure or timeout' \
    mut_ci_build_guard_fourth_failure_swallowed

mut_ci_build_guard_fifth_shard_duplicated() {
    replace_ci_text 'scripts/ci_budget.sh 380 "build-backed guards 5/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=4 bash scripts/test_guard_scripts.sh' \
        'scripts/ci_budget.sh 380 "build-backed guards 5/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh'
}
expect_fail check_ci_test_split.sh \
    'the fifth build-backed worker repeating the first fifth' \
    mut_ci_build_guard_fifth_shard_duplicated

mut_ci_build_guard_fifth_failure_swallowed() {
    replace_ci_text '          scripts/ci_budget.sh 380 "build-backed guards 5/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=4 bash scripts/test_guard_scripts.sh' \
        '          scripts/ci_budget.sh 380 "build-backed guards 5/5" env GATEWAY_GUARD_BUDGET_SECONDS=380 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=4 bash scripts/test_guard_scripts.sh || true'
}
expect_fail check_ci_test_split.sh \
    'the fifth build-backed worker swallowing a failure or timeout' \
    mut_ci_build_guard_fifth_failure_swallowed

mut_ci_build_guard_macro_control_dropped() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = "    check_macro_governance.sh \\\n"
if text.count(old) != 1:
    raise SystemExit("macro governance build-control mutation anchor is not unique")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_ci_test_split.sh \
    'the build-backed job omitting the macro governance control' \
    mut_ci_build_guard_macro_control_dropped \
    'build-guard-self-test omits a build-backed control or mutation'

mut_ci_target_serialized_in_guard() {
    printf '%s\n' 'if "${SCRIPT_DIR}/test_test_target_consolidation.sh"; then' \
        >>scripts/test_guard_scripts.sh
}
expect_fail check_ci_test_split.sh \
    'the guard job serializing target-consolidation mutations again' mut_ci_target_serialized_in_guard

mut_ci_required_name_changed() {
    replace_ci_text '    name: Test' '    name: Tests'
}
expect_fail check_ci_test_split.sh \
    'the branch-protected Test check being renamed' mut_ci_required_name_changed

mut_ci_aggregate_drops_third_workspace() {
    replace_ci_text 'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]' \
        'needs: [workspace-tests, workspace-tests-2, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for the third workspace shard' \
    mut_ci_aggregate_drops_third_workspace

mut_ci_aggregate_drops_guard() {
    replace_ci_text 'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]' \
        'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, target-consolidation-self-test, quirk-ledger-self-test, dto-compiler-self-test, gateway-tsan]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for guard mutations' mut_ci_aggregate_drops_guard

mut_ci_aggregate_drops_transport_parity() {
    replace_ci_text 'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]' \
        'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for transport parity' \
    mut_ci_aggregate_drops_transport_parity

mut_ci_transport_parity_result_ignored() {
    replace_ci_text 'TRANSPORT_PARITY_RESULT: ${{ needs.transport-parity.result }}' \
        'TRANSPORT_PARITY_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the transport parity result' \
    mut_ci_transport_parity_result_ignored

mut_ci_transport_parity_comparison_removed() {
    replace_ci_text '          test "$TRANSPORT_PARITY_RESULT" = success' \
        '          true # transport parity result ignored'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check no longer comparing the transport parity result' \
    mut_ci_transport_parity_comparison_removed

mut_ci_aggregate_drops_target() {
    replace_ci_text 'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]' \
        'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, guard-self-test, quirk-ledger-self-test, dto-compiler-self-test, gateway-tsan]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for target-consolidation mutations' \
    mut_ci_aggregate_drops_target

mut_ci_aggregate_drops_quirk_ledger() {
    replace_ci_text 'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]' \
        'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, guard-self-test, target-consolidation-self-test, dto-compiler-self-test, gateway-tsan]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for quirk-ledger mutations' \
    mut_ci_aggregate_drops_quirk_ledger

mut_ci_aggregate_drops_dto_compiler() {
    replace_ci_text 'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]' \
        'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, guard-self-test, target-consolidation-self-test, quirk-ledger-self-test, gateway-tsan]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for DTO compiler mutations' \
    mut_ci_aggregate_drops_dto_compiler

mut_ci_aggregate_drops_build_guard() {
    replace_ci_text 'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]' \
        'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, guard-self-test, target-consolidation-self-test, quirk-ledger-self-test, dto-compiler-self-test, gateway-tsan]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for build-backed mutations' \
    mut_ci_aggregate_drops_build_guard

mut_ci_aggregate_drops_second_build_guard() {
    replace_ci_text 'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]' \
        'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, dto-compiler-self-test, build-guard-self-test, error-status-self-test, gateway-tsan]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for the second build-backed worker' \
    mut_ci_aggregate_drops_second_build_guard

mut_ci_aggregate_drops_third_build_guard() {
    replace_ci_text 'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]' \
        'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, error-status-self-test, gateway-tsan]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for the third build-backed worker' \
    mut_ci_aggregate_drops_third_build_guard

mut_ci_aggregate_drops_fourth_build_guard() {
    replace_ci_text 'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]' \
        'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for the fourth build-backed worker' \
    mut_ci_aggregate_drops_fourth_build_guard

mut_ci_aggregate_drops_fifth_build_guard() {
    replace_ci_text 'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]' \
        'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, error-status-self-test, gateway-tsan, docs, examples]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for the fifth build-backed worker' \
    mut_ci_aggregate_drops_fifth_build_guard

mut_ci_aggregate_drops_error_status() {
    replace_ci_text 'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]' \
        'needs: [workspace-tests, workspace-tests-2, workspace-tests-3, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, dto-compiler-self-test, build-guard-self-test, gateway-tsan]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for error-status mutations' \
    mut_ci_aggregate_drops_error_status

mut_ci_error_status_result_ignored() {
    replace_ci_text 'ERROR_STATUS_RESULT: ${{ needs.error-status-self-test.result }}' \
        'ERROR_STATUS_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the error-status result' mut_ci_error_status_result_ignored

mut_ci_error_status_comparison_dropped() {
    replace_ci_text '          test "$ERROR_STATUS_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check never comparing the error-status result' mut_ci_error_status_comparison_dropped

mut_ci_error_status_suite_is_a_no_op() {
    replace_ci_text 'scripts/ci_budget.sh 150 "error status self-test" env GATEWAY_GUARD_BUDGET_SECONDS=150 GATEWAY_GUARD_ERROR_STATUS_ONLY=1 bash scripts/test_guard_scripts.sh' \
        'scripts/ci_budget.sh 150 "error status self-test" true'
}
expect_fail check_ci_test_split.sh \
    'the error-status mutation suite being replaced with a no-op' \
    mut_ci_error_status_suite_is_a_no_op

mut_ci_error_status_job_widens_budget() {
    replace_ci_text '  error-status-self-test:
    name: Error status self-test
    runs-on: ubuntu-latest
    timeout-minutes: 3' '  error-status-self-test:
    name: Error status self-test
    runs-on: ubuntu-latest
    timeout-minutes: 9'
}
expect_fail check_ci_test_split.sh \
    'the error-status job widening its three-minute budget' \
    mut_ci_error_status_job_widens_budget

# The DTO-compiler and error-status jobs ran the suite with no GATEWAY_GUARD_BUDGET_SECONDS at all
# until this change: the suite defended its 480s default while ci_budget.sh enforced 90s and 60s,
# so the self-stop could never fire and an overrun would have been an unexplained 124. The check
# that would have caught it only looked at invocations carrying a shard group, which those two do
# not, so both of these cases exist: one for the missing declaration, one for a wrong one.
# Both cases add a NEW guard-suite invocation rather than editing an existing one. Every job named
# above is pinned to its exact `run:` text, so editing one is caught by the pin, and the case would
# then read green off a diagnostic that has nothing to do with budgets. A job the pinned lists have
# never heard of is exactly the shape that escaped the old check, which only inspected invocations
# carrying a shard group -- which is how the DTO-compiler and error-status jobs came to run the
# suite with no declared budget at all.
# ci_extra_guard_job <env-assignments>
# The YAML for one added job, with the budget declaration the caller wants in front of the mode
# flag. Written once: the two cases differ by that prefix alone, and two near-identical ten-line
# heredocs are how a mutation subject silently stops matching what CI actually runs.
ci_extra_guard_job() {
    printf '%s' '  dto-compiler-self-test-2:
    name: DTO compiler self-test 2
    runs-on: ubuntu-latest
    timeout-minutes: 3
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
      - name: DTO compiler mutations 2 of 2
        run: |
          scripts/ci_budget.sh 150 "DTO compiler self-test 2" env '"$1"'GATEWAY_GUARD_DTO_COMPILER_ONLY=1 bash scripts/test_guard_scripts.sh

  error-status-self-test:'
}

mut_ci_new_guard_job_without_a_budget() {
    replace_ci_text '  error-status-self-test:' "$(ci_extra_guard_job '')"
}
expect_fail check_ci_test_split.sh \
    'a new guard-suite job running without declaring the budget it must stop inside' \
    mut_ci_new_guard_job_without_a_budget \
    'without declaring the budget it must stop inside'

mut_ci_new_guard_job_defends_the_wrong_budget() {
    replace_ci_text '  error-status-self-test:' \
        "$(ci_extra_guard_job 'GATEWAY_GUARD_BUDGET_SECONDS=480 ')"
}
expect_fail check_ci_test_split.sh \
    'a new guard-suite job defending a budget CI does not enforce' \
    mut_ci_new_guard_job_defends_the_wrong_budget \
    'defends 480s but CI enforces 150s'

# rustfs/gateway#217 twice over: `Cold bootstrap` wrapped a command that defends its own
# five-minute budget in `timeout 300s`, the same number, so the kill always beat the verdict and
# the job printed exit 124 with nothing naming the clock.
mut_ci_bootstrap_bare_timeout_restored() {
    replace_ci_text '          scripts/ci_budget.sh 420 "cold bootstrap" cargo xtask bootstrap' \
        '          timeout 300s cargo xtask bootstrap'
}
expect_fail check_ci_time_gate.sh \
    'the cold bootstrap going back to a bare timeout that outruns its own diagnosis' \
    mut_ci_bootstrap_bare_timeout_restored

mut_ci_feedback_loop_bare_timeout_restored() {
    replace_ci_text '          scripts/ci_budget.sh 30 "verify --op GetObject" cargo xtask verify --op GetObject' \
        '          timeout 30s cargo xtask verify --op GetObject'
}
expect_fail check_ci_time_gate.sh \
    'an operation sample going back to a bare timeout that reports no margin' \
    mut_ci_feedback_loop_bare_timeout_restored

mut_ci_bootstrap_measurement_unwrapped() {
    replace_ci_text '          scripts/ci_budget.sh 420 "cold bootstrap" cargo xtask bootstrap' \
        '          cargo xtask bootstrap'
}
expect_fail check_rust_toolchain_msrv.sh \
    'the cold bootstrap measuring itself with no wall-clock budget at all' \
    mut_ci_bootstrap_measurement_unwrapped

mut_ci_aggregate_skips_on_failure() {
    replace_ci_text 'if: always()' 'if: success()'
}
expect_fail check_ci_test_split.sh \
    'the required Test check being skipped after a dependency failure' mut_ci_aggregate_skips_on_failure

mut_ci_aggregate_hides_always_in_comment() {
    replace_ci_text '    if: always()' '    if: success() # if: always()'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check hiding a skipped condition behind a comment' mut_ci_aggregate_hides_always_in_comment

mut_ci_aggregate_step_skips_failure() {
    replace_ci_text '      - name: Require test jobs' \
        '      - name: Require test jobs
        if: ${{ needs.workspace-tests.result == '\''success'\'' && needs.guard-self-test.result == '\''success'\'' }}'
}
expect_fail check_ci_test_split.sh \
    'the aggregate comparison step being skipped after a worker failure' mut_ci_aggregate_step_skips_failure

mut_ci_aggregate_budget_widened() {
    replace_ci_text '  test:
    name: Test
    needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]
    if: always()
    runs-on: ubuntu-latest
    timeout-minutes: 1' '  test:
    name: Test
    needs: [workspace-tests, workspace-tests-2, workspace-tests-3, transport-parity, transport-parity-2, persistence-goldens, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, guard-self-test-5, target-consolidation-self-test, quirk-ledger-self-test, quirk-ledger-self-test-2, quirk-ledger-self-test-3, dto-compiler-self-test, build-guard-self-test, build-guard-self-test-2, build-guard-self-test-3, build-guard-self-test-4, build-guard-self-test-5, error-status-self-test, gateway-tsan, docs, examples]
    if: always()
    runs-on: ubuntu-latest
    timeout-minutes: 2'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check widening the total job budget past ten minutes' mut_ci_aggregate_budget_widened

mut_ci_workspace_result_ignored() {
    replace_ci_text 'WORKSPACE_RESULT: ${{ needs.workspace-tests.result }}' 'WORKSPACE_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the workspace test result' mut_ci_workspace_result_ignored

mut_ci_second_workspace_result_ignored() {
    replace_ci_text 'WORKSPACE_2_RESULT: ${{ needs.workspace-tests-2.result }}' 'WORKSPACE_2_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the second workspace test result' mut_ci_second_workspace_result_ignored

mut_ci_third_workspace_result_ignored() {
    replace_ci_text 'WORKSPACE_3_RESULT: ${{ needs.workspace-tests-3.result }}' 'WORKSPACE_3_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the third workspace test result' \
    mut_ci_third_workspace_result_ignored

mut_ci_third_workspace_comparison_removed() {
    replace_ci_text '          test "$WORKSPACE_3_RESULT" = success' \
        '          true # third workspace result ignored'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check no longer comparing the third workspace test result' \
    mut_ci_third_workspace_comparison_removed

mut_ci_guard_result_ignored() {
    replace_ci_text 'GUARD_RESULT: ${{ needs.guard-self-test.result }}' 'GUARD_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the guard mutation result' mut_ci_guard_result_ignored

mut_ci_target_result_ignored() {
    replace_ci_text 'TARGET_CONSOLIDATION_RESULT: ${{ needs.target-consolidation-self-test.result }}' \
        'TARGET_CONSOLIDATION_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the target-consolidation result' mut_ci_target_result_ignored

mut_ci_quirk_ledger_result_ignored() {
    replace_ci_text 'QUIRK_LEDGER_RESULT: ${{ needs.quirk-ledger-self-test.result }}' \
        'QUIRK_LEDGER_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the quirk-ledger result' mut_ci_quirk_ledger_result_ignored

mut_ci_dto_compiler_result_ignored() {
    replace_ci_text 'DTO_COMPILER_RESULT: ${{ needs.dto-compiler-self-test.result }}' \
        'DTO_COMPILER_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the DTO compiler result' mut_ci_dto_compiler_result_ignored

mut_ci_build_guard_result_ignored() {
    replace_ci_text 'BUILD_GUARD_RESULT: ${{ needs.build-guard-self-test.result }}' \
        'BUILD_GUARD_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the build-backed guard result' mut_ci_build_guard_result_ignored

mut_ci_second_build_guard_result_ignored() {
    replace_ci_text 'BUILD_GUARD_2_RESULT: ${{ needs.build-guard-self-test-2.result }}' \
        'BUILD_GUARD_2_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the second build-backed guard result' \
    mut_ci_second_build_guard_result_ignored

mut_ci_third_build_guard_result_ignored() {
    replace_ci_text 'BUILD_GUARD_3_RESULT: ${{ needs.build-guard-self-test-3.result }}' \
        'BUILD_GUARD_3_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the third build-backed guard result' \
    mut_ci_third_build_guard_result_ignored

mut_ci_docs_result_ignored() {
    replace_ci_text 'DOCS_RESULT: ${{ needs.docs.result }}' 'DOCS_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the documentation and example result' mut_ci_docs_result_ignored

mut_ci_examples_result_ignored() {
    replace_ci_text 'EXAMPLES_RESULT: ${{ needs.examples.result }}' 'EXAMPLES_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the README and API examples result' mut_ci_examples_result_ignored

mut_ci_examples_comparison_dropped() {
    replace_ci_text '          test "$EXAMPLES_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check dropping the README and API examples comparison' mut_ci_examples_comparison_dropped

mut_ci_examples_worker_detached() {
    replace_ci_text 'error-status-self-test, gateway-tsan, docs, examples]' \
        'error-status-self-test, gateway-tsan, docs]'
}
expect_fail check_ci_test_split.sh \
    'the README and API examples worker leaving the Test gate' mut_ci_examples_worker_detached

mut_ci_fifth_guard_result_ignored() {
    replace_ci_text 'GUARD_5_RESULT: ${{ needs.guard-self-test-5.result }}' 'GUARD_5_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the fifth guard shard result' mut_ci_fifth_guard_result_ignored

mut_ci_fifth_guard_comparison_dropped() {
    replace_ci_text '          test "$GUARD_5_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check dropping the fifth guard shard comparison' mut_ci_fifth_guard_comparison_dropped

mut_ci_fifth_guard_repeats_the_fourth() {
    replace_ci_text '"guard mutations 5/5" env GATEWAY_GUARD_BUDGET_SECONDS=300 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=4 bash' \
        '"guard mutations 5/5" env GATEWAY_GUARD_BUDGET_SECONDS=300 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=3 bash'
}
expect_fail check_ci_test_split.sh \
    'the fifth guard shard repeating the fourth' mut_ci_fifth_guard_repeats_the_fourth

mut_ci_second_parity_result_ignored() {
    replace_ci_text 'TRANSPORT_PARITY_2_RESULT: ${{ needs.transport-parity-2.result }}' 'TRANSPORT_PARITY_2_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the second transport parity shard result' mut_ci_second_parity_result_ignored

mut_ci_second_parity_comparison_dropped() {
    replace_ci_text '          test "$TRANSPORT_PARITY_2_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check dropping the second transport parity shard comparison' mut_ci_second_parity_comparison_dropped

mut_ci_second_parity_repeats_the_first() {
    replace_ci_text '"production transport parity 2/2" cargo run --package rustfs-gateway-conformance --bin rustfs-gateway-conformance -- diff-transports --exclude-slow --shard 1/2' \
        '"production transport parity 2/2" cargo run --package rustfs-gateway-conformance --bin rustfs-gateway-conformance -- diff-transports --exclude-slow --shard 0/2'
}
expect_fail check_ci_test_split.sh \
    'the second transport parity shard repeating the first' mut_ci_second_parity_repeats_the_first

mut_ci_parity_shard_dropped() {
    replace_ci_text 'diff-transports --exclude-slow --shard 0/2' 'diff-transports --exclude-slow'
}
expect_fail check_ci_test_split.sh \
    'a transport parity runner comparing the whole corpus again instead of its shard' mut_ci_parity_shard_dropped

mut_ci_workspace_comparison_dropped() {
    replace_ci_text '          test "$WORKSPACE_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the workspace result comparison' mut_ci_workspace_comparison_dropped

mut_ci_docs_comparison_dropped() {
    replace_ci_text '          test "$DOCS_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the documentation result comparison' mut_ci_docs_comparison_dropped

mut_ci_second_workspace_comparison_dropped() {
    replace_ci_text '          test "$WORKSPACE_2_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the second workspace result comparison' \
    mut_ci_second_workspace_comparison_dropped

mut_ci_guard_comparison_dropped() {
    replace_ci_text '          test "$GUARD_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the guard result comparison' mut_ci_guard_comparison_dropped

mut_ci_target_comparison_dropped() {
    replace_ci_text '          test "$TARGET_CONSOLIDATION_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the target-consolidation result comparison' \
    mut_ci_target_comparison_dropped

mut_ci_quirk_ledger_comparison_dropped() {
    replace_ci_text '          test "$QUIRK_LEDGER_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the quirk-ledger result comparison' \
    mut_ci_quirk_ledger_comparison_dropped

mut_ci_dto_compiler_comparison_dropped() {
    replace_ci_text '          test "$DTO_COMPILER_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the DTO compiler result comparison' \
    mut_ci_dto_compiler_comparison_dropped

mut_ci_build_guard_comparison_dropped() {
    replace_ci_text '          test "$BUILD_GUARD_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the build-backed guard result comparison' \
    mut_ci_build_guard_comparison_dropped

mut_ci_second_build_guard_comparison_dropped() {
    replace_ci_text '          test "$BUILD_GUARD_2_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the second build-backed guard result comparison' \
    mut_ci_second_build_guard_comparison_dropped

mut_ci_third_build_guard_comparison_dropped() {
    replace_ci_text '          test "$BUILD_GUARD_3_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the third build-backed guard result comparison' \
    mut_ci_third_build_guard_comparison_dropped

mut_ci_workers_share_concurrency_lane() {
    replace_ci_text '  workspace-tests:
    name: Workspace tests 1' '  workspace-tests:
    concurrency: split-test-lane
    name: Workspace tests 1'
    replace_ci_text '  guard-self-test:
    name: Guard self-test' '  guard-self-test:
    concurrency: split-test-lane
    name: Guard self-test'
}
expect_fail check_ci_test_split.sh \
    'the parallel workers sharing a serial concurrency lane' mut_ci_workers_share_concurrency_lane

mut_ci_guard_quoted_dependency() {
    replace_ci_text '  guard-self-test:
    name: Guard self-test' '  guard-self-test:
    "needs": workspace-tests
    name: Guard self-test'
}
expect_fail check_ci_test_split.sh \
    'a quoted worker dependency serializing the split jobs' mut_ci_guard_quoted_dependency

mut_ci_worker_continues_on_error() {
    replace_ci_text '      - name: Workspace tests 1/3 (maximum 8 minutes after setup)' \
        '      - name: Workspace tests 1/3 (maximum 8 minutes after setup)
        continue-on-error: true'
}
expect_fail check_ci_test_split.sh \
    'the workspace test step being allowed to fail' mut_ci_worker_continues_on_error

mut_ci_worker_shell_disables_errexit() {
    replace_ci_text '      - name: Guard mutations 1 of 5 (maximum 5 minutes after setup)' \
        '      - name: Guard mutations 1 of 5 (maximum 5 minutes after setup)
        shell: bash {0}'
}
expect_fail check_ci_test_split.sh \
    'the guard mutation step overriding the fail-fast shell' mut_ci_worker_shell_disables_errexit

mut_ci_workflow_shell_disables_errexit() {
    replace_ci_text 'permissions:
  contents: read' 'defaults:
  run:
    shell: bash {0}

permissions:
  contents: read'
}
expect_fail check_ci_test_split.sh \
    'workflow defaults overriding the fail-fast shell' mut_ci_workflow_shell_disables_errexit

mut_ci_workflow_bash_env() {
    replace_ci_text 'env:
  CARGO_TERM_COLOR: always' 'env:
  BASH_ENV: scripts/disable-errexit.sh
  CARGO_TERM_COLOR: always'
}
expect_fail check_ci_test_split.sh \
    'the workflow environment overriding bash startup' mut_ci_workflow_bash_env

mut_ci_workflow_overrides_test() {
    replace_ci_text 'env:
  CARGO_TERM_COLOR: always' 'env:
  "BASH_FUNC_test%%": '\''() { return 0; }'\''
  CARGO_TERM_COLOR: always'
}
expect_fail check_ci_test_split.sh \
    'the workflow environment overriding the aggregate test command' mut_ci_workflow_overrides_test

mut_ci_workflow_overrides_timeout() {
    replace_ci_text 'env:
  CARGO_TERM_COLOR: always' 'env:
  "BASH_FUNC_timeout%%": '\''() { shift; "$@" || true; }'\''
  CARGO_TERM_COLOR: always'
}
expect_fail check_ci_test_split.sh \
    'the workflow environment overriding worker timeouts' mut_ci_workflow_overrides_timeout

mut_ci_serial_verify_returns() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
path.write_text(path.read_text() + """
  serialized-regression:
    name: Serialized regression
    runs-on: ubuntu-latest
    steps:
      - run: cargo xtask verify --all
""")
PYEOF
}
expect_fail check_ci_test_split.sh \
    'workspace tests and guard mutations being serialized again' mut_ci_serial_verify_returns

mut_ci_workflow_deleted() {
    rm -f .github/workflows/ci.yml
}
expect_fail check_ci_test_split.sh \
    "the guard's own workflow input deleted, which must fail rather than skip" mut_ci_workflow_deleted

mut_guard_budget_diverges_from_ci_timeout() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
before = 'scripts/ci_budget.sh 300 "guard mutations 3/5" env GATEWAY_GUARD_BUDGET_SECONDS=300 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=2'
after = 'scripts/ci_budget.sh 300 "guard mutations 3/5" env GATEWAY_GUARD_BUDGET_SECONDS=600 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=2'
if text.count(before) != 1:
    raise SystemExit("missing guard budget mutation subject")
path.write_text(text.replace(before, after, 1))
PYEOF
}
expect_fail check_ci_test_split.sh \
    'a guard shard defending a budget larger than the timeout CI enforces on it' \
    mut_guard_budget_diverges_from_ci_timeout

mut_guard_budget_env_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
before = "env GATEWAY_GUARD_BUDGET_SECONDS=300 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=1"
after = "env GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=1"
if text.count(before) != 1:
    raise SystemExit("missing guard budget env mutation subject")
path.write_text(text.replace(before, after, 1))
PYEOF
}
expect_fail check_ci_test_split.sh \
    'a guard shard running blind to the budget, so an overrun returns to an opaque exit 124' \
    mut_guard_budget_env_removed

# -----------------------------------------------------------------------------
# Every gate job reports the margin it had left (rustfs/gateway#217)
#
# A bare `timeout` says nothing until the moment it is fatal, and then it says only
# `exit code 124`. Both #188 and #217 were diagnosed as broken branches for days because
# of it. scripts/ci_budget.sh is the outer layer that makes the margin visible on every
# run, and check_ci_test_split.sh requires every timed command behind Test to use it.
# -----------------------------------------------------------------------------

mut_ci_target_budget_unreported() {
    replace_ci_text 'scripts/ci_budget.sh 120 "target consolidation self-test" bash scripts/test_test_target_consolidation.sh' \
        'timeout 120s bash scripts/test_test_target_consolidation.sh'
}
expect_fail check_ci_test_split.sh \
    'a gate job returning to a bare timeout, whose overrun is an unexplained exit 124' \
    mut_ci_target_budget_unreported

mut_ci_guard_shard_budget_unreported() {
    replace_ci_text 'scripts/ci_budget.sh 300 "guard mutations 1/5" env' 'timeout 300s env'
}
expect_fail check_ci_test_split.sh \
    'a guard shard returning to a bare timeout' mut_ci_guard_shard_budget_unreported

mut_ci_tsan_budget_removed() {
    replace_ci_text 'scripts/ci_budget.sh 480 "gateway TSAN" scripts/run_gateway_tsan.sh' \
        'scripts/run_gateway_tsan.sh'
}
expect_fail check_ci_test_split.sh \
    'a gate job declaring no wall-clock budget at all, so nothing reports its margin' \
    mut_ci_tsan_budget_removed

mut_guard_shard_group_duplicated() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
before = 'scripts/ci_budget.sh 300 "guard mutations 4/5" env GATEWAY_GUARD_BUDGET_SECONDS=300 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=3 bash scripts/test_guard_scripts.sh'
after = 'scripts/ci_budget.sh 300 "guard mutations 4/5" env GATEWAY_GUARD_BUDGET_SECONDS=300 GATEWAY_GUARD_SHARD_GROUPS=5 GATEWAY_GUARD_SHARD_GROUP=0 bash scripts/test_guard_scripts.sh'
if text.count(before) != 1:
    raise SystemExit("missing guard shard group mutation subject")
path.write_text(text.replace(before, after, 1))
PYEOF
}
expect_fail check_ci_test_split.sh \
    'two guard runners taking the same quarter, leaving one quarter of the suite unrun' \
    mut_guard_shard_group_duplicated

mut_guard_budget_declaration_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
# Split so this mutation's own source is not a second copy of its subject.
before = 'GUARD_BUDGET_SECONDS="${GATEWAY_GUARD' + '_BUDGET_SECONDS:-480}"'
if text.count(before) != 1:
    raise SystemExit("missing guard budget declaration mutation subject")
path.write_text(text.replace(before, "GUARD_BUDGET_SECONDS=480", 1))
PYEOF
}
expect_fail check_ci_test_split.sh \
    'the guard self-test ignoring the budget CI hands it, which is what keeps an overrun legible' \
    mut_guard_budget_declaration_removed

# -----------------------------------------------------------------------------
# rustfs/gateway#224: the pull-request body reaches the CI log, and the runner reads a log
# line beginning `::` as a workflow command. The body is therefore exported JSON-encoded,
# which puts it on one line and takes the `::` away from the start of it.
#
# check_ci_annotation_integrity.sh proves that by rendering the step's env block the way
# the runner prints it and scanning the result the way the runner reads it. These cases
# prove the guard: the workflow shape it defends, the trigger the severity bound rests on,
# the run-time invariant in its consumers, and its own model of the runner.
# -----------------------------------------------------------------------------
mut_ci_pr_body_exported_raw() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
before = "GATEWAY_PR_BODY_JSON: ${{ toJSON(github.event.pull_request.body) }}"
after = "GATEWAY_PR_BODY_JSON: ${{ github.event.pull_request.body }}"
if text.count(before) != 2:
    raise SystemExit("missing the JSON-encoded pull-request body exports")
path.write_text(text.replace(before, after))
PYEOF
}
expect_fail check_ci_annotation_integrity.sh \
    'the pull-request body exported raw, letting its author forge and suppress CI annotations' \
    mut_ci_pr_body_exported_raw \
    'would be parsed as a workflow command'

mut_ci_untrusted_title_exported_raw() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
before = "          GATEWAY_ROLE_BASE: ${{ github.event.pull_request.base.sha }}\n"
after = before + "          GATEWAY_PR_TITLE: ${{ github.event.pull_request.title }}\n"
if text.count(before) != 1:
    raise SystemExit("missing the role-verdict environment anchor")
path.write_text(text.replace(before, after, 1))
PYEOF
}
expect_fail check_ci_annotation_integrity.sh \
    'a second author-controlled field exported raw beside the encoded body' \
    mut_ci_untrusted_title_exported_raw \
    'exposes github.event.pull_request.title'

mut_ci_pr_body_export_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
before = "          GATEWAY_PR_BODY_JSON: ${{ toJSON(github.event.pull_request.body) }}\n"
if text.count(before) != 2:
    raise SystemExit("missing the JSON-encoded pull-request body exports")
path.write_text(text.replace(before, ""))
PYEOF
}
expect_fail check_ci_annotation_integrity.sh \
    'the body export disappearing, which would leave the guard with nothing to prove' \
    mut_ci_pr_body_export_removed \
    'no workflow step exports the pull-request body'

mut_ci_pull_request_target_added() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
before = "on:\n  push:\n    branches: [main]\n"
after = "on:\n  pull_request_target:\n    branches: [main]\n  push:\n    branches: [main]\n"
if text.count(before) != 1:
    raise SystemExit("missing the workflow trigger anchor")
path.write_text(text.replace(before, after, 1))
PYEOF
}
expect_fail check_ci_annotation_integrity.sh \
    'a pull_request_target trigger, which hands a fork write access and secrets' \
    mut_ci_pull_request_target_added \
    'triggers on pull_request_target'

mut_pr_body_single_line_check_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/check_role_verdicts.sh")
text = path.read_text()
before = "[[ \"$GATEWAY_PR_BODY_JSON\" != *$'\\n'* ]] ||"
after = "[[ 1 == 1 ]] ||"
if text.count(before) != 1:
    raise SystemExit("missing the single-line body invariant")
path.write_text(text.replace(before, after, 1))
PYEOF
}
expect_fail check_ci_annotation_integrity.sh \
    'a consumer dropping the run-time invariant that catches an unencoded body' \
    mut_pr_body_single_line_check_removed \
    'accepts a multi-line GATEWAY_PR_BODY_JSON'

mut_annotation_scanner_is_a_no_op() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/check_ci_annotation_integrity.sh")
text = path.read_text()
before = '    raised: list[tuple[str, str]] = []\n'
after = '    raised: list[tuple[str, str]] = []\n    return raised\n'
if text.count(before) != 1:
    raise SystemExit("missing the runner-model scanner")
path.write_text(text.replace(before, after, 1))
PYEOF
}
expect_fail_self_mutation check_ci_annotation_integrity.sh \
    'its own model of the runner reduced to a no-op, which would make both directions green forever' \
    mut_annotation_scanner_is_a_no_op

fi

if [[ "$QUIRK_LEDGER_ONLY" == 0 && "$DTO_COMPILER_ONLY" == 0 && "$BUILD_GUARDS_ONLY" == 0 && "$ERROR_STATUS_ONLY" == 0 ]]; then

# ci_budget.sh is driven directly rather than through a sandbox: its whole contract is what
# it prints and what it returns. The verdict function is pure, so the thresholds are asserted
# without burning wall-clock on sleeps the suite cannot afford.
ci_budget_verdict_case() {
    local elapsed="$1" budget="$2" expected="$3" actual
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    actual="$(bash -c "source '${SCRIPT_DIR}/ci_budget.sh'; ci_budget_verdict $elapsed $budget 80")"
    if [[ "$actual" == "$expected" ]]; then
        pass_msg "ci_budget.sh calls ${elapsed}s of ${budget}s '${expected}'"
    else
        fail_msg "ci_budget.sh called ${elapsed}s of ${budget}s '${actual}', expected '${expected}'"
    fi
}
ci_budget_verdict_case 0 100 ok
ci_budget_verdict_case 79 100 ok
ci_budget_verdict_case 80 100 warn
ci_budget_verdict_case 99 100 warn
ci_budget_verdict_case 100 100 over

ci_budget_case() {
    local desc="$1" expected_rc="$2" expected_fragment="$3"
    shift 3
    local output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    output="$("$@" 2>&1)" || rc=$?
    if [[ "$rc" -eq "$expected_rc" && "$output" == *"$expected_fragment"* ]]; then
        pass_msg "ci_budget.sh ${desc}"
    else
        fail_msg "ci_budget.sh ${desc} — rc ${rc}, expected ${expected_rc}; output: ${output}"
    fi
}
ci_budget_case 'reports the margin a passing job left' 0 'of its 100s budget' \
    bash "${SCRIPT_DIR}/ci_budget.sh" 100 'sample job' true
ci_budget_case 'preserves the exit status of the job it wraps' 7 '' \
    bash "${SCRIPT_DIR}/ci_budget.sh" 100 'sample job' bash -c 'exit 7'
ci_budget_case 'rejects a budget that is not a positive integer' 2 'positive integer' \
    bash "${SCRIPT_DIR}/ci_budget.sh" 0 'sample job' true
ci_budget_case 'rejects an empty label, which an overrun could not name' 2 'label must not be empty' \
    bash "${SCRIPT_DIR}/ci_budget.sh" 100 '' true

# The 124 is produced by a stub on PATH on purpose. The unit under test is ci_budget.sh's
# handling of an exhausted budget, not GNU timeout's ability to report one, and a stub keeps
# the case honest on macOS, where timeout(1) does not exist at all and the case would
# otherwise quietly assert nothing.
ci_budget_timeout_case() {
    local stub output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    stub="$(mktemp -d "${TMPDIR:-/tmp}/gateway-ci-budget-stub.XXXXXX")"
    printf '#!/usr/bin/env bash\nexit 124\n' >"${stub}/timeout"
    chmod +x "${stub}/timeout"
    output="$(PATH="${stub}:${PATH}" bash "${SCRIPT_DIR}/ci_budget.sh" 100 'sample job' true 2>&1)" || rc=$?
    rm -rf "$stub"
    if [[ "$rc" -eq 124 && "$output" == *'OUT OF TIME'* && "$output" == *'::error'* ]]; then
        pass_msg 'ci_budget.sh turns an exhausted budget into an OUT OF TIME diagnosis and an annotation'
    else
        fail_msg "ci_budget.sh did not diagnose an exhausted budget — rc ${rc}: ${output}"
    fi
}
ci_budget_timeout_case

# A budget nothing can enforce is a check that cannot fail. Off CI that degrades to measurement
# with a warning; on CI it must be a hard error instead.
ci_budget_missing_enforcer_case() {
    local empty output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    empty="$(mktemp -d "${TMPDIR:-/tmp}/gateway-ci-budget-empty.XXXXXX")"
    # The interpreter is named absolutely because the emptied PATH cannot resolve `bash` either,
    # and a 127 here would look like the refusal this case is trying to observe.
    output="$(PATH="$empty" CI=true "$BASH" "${SCRIPT_DIR}/ci_budget.sh" 100 'sample job' true 2>&1)" || rc=$?
    rm -rf "$empty"
    if [[ "$rc" -eq 2 && "$output" == *'no budget could be enforced'* ]]; then
        pass_msg 'ci_budget.sh refuses to report a margin CI could not enforce'
    else
        fail_msg "ci_budget.sh accepted an unenforceable budget on CI — rc ${rc}: ${output}"
    fi
}
ci_budget_missing_enforcer_case

mut_config_snapshot_case_identity_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/service_config.rs")
old = "async fn c_lim_0005_hot_update_does_not_tear_an_inflight_request() {"
new = "async fn hot_update_does_not_tear_an_inflight_request() {"
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("c-lim-0005 test identity anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'c-lim-0005 losing its executable runtime identity' mut_config_snapshot_case_identity_removed \
    'c-lim-0005 active runtime evidence is missing or duplicated'

mut_config_snapshot_case_disabled() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/service_config.rs")
old = "#[tokio::test]\nasync fn c_lim_0005_hot_update_does_not_tear_an_inflight_request() {"
new = "#[cfg(any())]\n#[tokio::test]\nasync fn c_lim_0005_hot_update_does_not_tear_an_inflight_request() {"
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("c-lim-0005 active-test anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'c-lim-0005 being disabled by cfg' mut_config_snapshot_case_disabled \
    'c-lim-0005 must be one unconditional tokio test'

mut_config_snapshot_current_request_widened() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/service_config.rs")
old = "assert_eq!(first.status(), http::StatusCode::PAYLOAD_TOO_LARGE);"
new = "assert_eq!(first.status(), http::StatusCode::OK);"
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("c-lim-0005 current-request assertion anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'c-lim-0005 losing the current-request snapshot direction' mut_config_snapshot_current_request_widened \
    "c-lim-0005 runtime evidence drifted at 'assert_eq!(first.status(), http::StatusCode::PAYLOAD_TOO_LARGE);'"

mut_config_snapshot_next_request_stale() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/service_config.rs")
old = "assert_eq!(second.status(), http::StatusCode::OK);"
new = "assert_eq!(second.status(), http::StatusCode::PAYLOAD_TOO_LARGE);"
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("c-lim-0005 next-request assertion anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'c-lim-0005 losing the next-request replacement direction' mut_config_snapshot_next_request_stale \
    "c-lim-0005 runtime evidence drifted at 'assert_eq!(second.status(), http::StatusCode::OK);'"

mut_request_cancellation_capture_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
subject = "        let request_cancellation = request.extensions().get::<tokio::sync::watch::Receiver<bool>>().cloned();\n"
replacement = "        let request_cancellation = None;\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique request-cancellation capture subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'request entry dropping the server cancellation signal' mut_request_cancellation_capture_removed \
    'shared request entry does not carry cancellation beside its captured configuration'

mut_request_cancellation_store_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text()
subject = "        self.request_cancellation = request_cancellation;\n"
replacement = "        self.request_cancellation = None;\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique request-cancellation store subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'the request snapshot refusing the captured cancellation signal' mut_request_cancellation_store_removed \
    'request cancellation does not cross every typed snapshot stage'

mut_request_cancellation_stage_propagation_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text()
subject = "            request_cancellation: self.request_cancellation,\n"
replacement = "            request_cancellation: None,\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique request-cancellation propagation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'a typed request stage dropping cancellation' mut_request_cancellation_stage_propagation_removed \
    'request cancellation does not cross every typed snapshot stage'

mut_extension_config_load() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/src/ext/mod.rs")
text = path.read_text()
addition = """

#[allow(dead_code)]
fn c_lim_0041_illicit_config_load(store: &crate::config::ConfigStore) {
    let _snapshot = store.load_full();
}
"""
if "c_lim_0041_illicit_config_load" in text:
    raise SystemExit("c-lim-0041 mutation anchor is not unique")
path.write_text(text + addition)
PYEOF
}
expect_fail check_config_load_once.sh \
    'c-lim-0041 adding a hot-configuration load inside the extension tree' mut_extension_config_load \
    'crates/gateway/src/ext/mod.rs:'

mut_second_config_load() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let snapshot = self.inner.config.load_full();",
    "let snapshot = self.inner.config.load_full();\n        let _torn = self.inner.config.load_full();",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'c-lim-0041 adding a second hot-configuration read in the request pipeline' mut_second_config_load

mut_pipeline_config_rcu_added() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
subject = "        let snapshot = self.inner.config.load_full();\n"
replacement = subject + "        let _torn = self.inner.config.rcu(Arc::clone);\n"
if text.count(subject) != 2:
    raise SystemExit("request-entry assembly snapshot anchors drifted")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second pipeline snapshot read through the partial-update primitive' mut_pipeline_config_rcu_added

mut_request_entry_routing_snapshot_borrowed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
subject = "        let snapshot = self.inner.config.load_full();\n"
replacement = "        let snapshot = self.inner.config.load();\n"
if text.count(subject) != 2:
    raise SystemExit("request-entry assembly snapshot anchors drifted")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'the dynamic request entry losing its owned assembly snapshot' mut_request_entry_routing_snapshot_borrowed \
    'dynamic and monomorphic request entries must each capture one owned assembly snapshot'

mut_pipeline_routing_reload_added() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
subject = "        let request_cancellation = request.extensions().get::<tokio::sync::watch::Receiver<bool>>().cloned();\n"
replacement = "        let _torn_assembly = self.inner.config.load_full();\n" + subject
if text.count(subject) != 1:
    raise SystemExit("shared request cancellation anchor drifted")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'a later pipeline stage reloading the assembly snapshot' mut_pipeline_routing_reload_added

mut_request_snapshot_settings_detached() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
subject = "self.call_with_mode(request, mode, Arc::clone(&snapshot.config), runtime)"
replacement = "self.call_with_mode(request, mode, Arc::new(crate::ServiceConfig::new(0)), runtime)"
if text.count(subject) != 2:
    raise SystemExit("request assembly handoff anchors drifted")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'request settings detached from their middleware generation' mut_request_snapshot_settings_detached \
    'request settings and middleware must come from the same entry snapshot'

mut_aliased_second_config_load() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let snapshot = self.inner.config.load_full();",
    "let snapshot = self.inner.config.load_full();\n        let config_store = &self.inner.config;\n        let _torn = config_store.load_full();",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through an aliased store' mut_aliased_second_config_load

mut_as_ref_second_config_load() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let snapshot = self.inner.config.load_full();",
    "let snapshot = self.inner.config.load_full();\n        let _torn = self.inner.config.as_ref().load_full();",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through Arc::as_ref' mut_as_ref_second_config_load

mut_guarded_config_load() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let snapshot = self.inner.config.load_full();",
    "let snapshot = self.inner.config.load_full();\n        let _torn = self.inner.config.load();",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through ArcSwap::load' mut_guarded_config_load

mut_ufcs_config_load_full() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let snapshot = self.inner.config.load_full();",
    "let snapshot = self.inner.config.load_full();\n        let _torn = arc_swap::ArcSwapAny::load_full(self.inner.config.as_ref());",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through UFCS load_full' mut_ufcs_config_load_full

mut_ufcs_config_load() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let snapshot = self.inner.config.load_full();",
    "let snapshot = self.inner.config.load_full();\n        let _torn = arc_swap::ArcSwapAny::load(self.inner.config.as_ref());",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through UFCS load' mut_ufcs_config_load

mut_import_aliased_config_load_full() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let snapshot = self.inner.config.load_full();",
    "let snapshot = self.inner.config.load_full();\n        use arc_swap::ArcSwapAny as Swap;\n        let _torn = Swap::load_full(self.inner.config.as_ref());",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through an imported type alias' mut_import_aliased_config_load_full

mut_type_aliased_config_load() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let snapshot = self.inner.config.load_full();",
    "let snapshot = self.inner.config.load_full();\n        type ConfigStoreAlias = arc_swap::ArcSwapAny<Arc<crate::config::AssemblySnapshot>>;\n        let _torn = ConfigStoreAlias::load(self.inner.config.as_ref());",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through a type alias' mut_type_aliased_config_load

mut_config_load_function_item() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let snapshot = self.inner.config.load_full();",
    "let snapshot = self.inner.config.load_full();\n        use arc_swap::ArcSwapAny as Swap;\n        let read = Swap::load_full;\n        let _torn = read(self.inner.config.as_ref());",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through a function item' mut_config_load_function_item

mut_config_load_allowlist_deleted() {
    rm -f scripts/config_load_allowlist.txt
}
expect_fail check_config_load_once.sh \
    'the config-load allowlist being absent' mut_config_load_allowlist_deleted

# The allowlist anchors each load by file, enclosing item and line text. gateway#707 and #724 each
# went red because an unrelated edit above an allowed load moved its line number.
mut_config_load_test_inserted_above() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/ext/governor/default.rs")
text = path.read_text()
subject = "mod tests {\n"
if text.count(subject) != 1 or ".load(" not in text.split(subject, 1)[1]:
    raise SystemExit("missing mutation subject: a test module holding an allowed load")
addition = "    // Inserted above every allowed load in this module.\n\n    #[test]\n    fn shifts_the_loads_below() {\n        assert_eq!(1 + 1, 2);\n    }\n\n"
path.write_text(text.replace(subject, subject + addition, 1))
PYEOF
}
expect_guard_pass check_config_load_once.sh \
    'a test inserted above an allowed load, moving its line number' mut_config_load_test_inserted_above

mut_config_load_lines_removed_above() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
subject = "    /// Answers one request.\n    ///\n"
if text.count(subject) != 1 or "self.inner.config.load_full()" not in text.split(subject, 1)[1]:
    raise SystemExit("missing mutation subject: documentation above the request-entry snapshots")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_guard_pass check_config_load_once.sh \
    'documentation removed above the request-entry snapshot loads' mut_config_load_lines_removed_above

# The same line text in another item is a new site, not the listed one.
mut_config_load_copied_to_new_item() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
subject = "impl S3Service {\n"
listed = "        let snapshot = self.inner.config.load();\n"
if text.count(subject) != 1 or listed not in text:
    raise SystemExit("missing mutation subject: an allowed S3Service snapshot load")
addition = "    #[allow(dead_code)]\n    fn illicit_snapshot(&self) {\n" + listed + "        drop(snapshot);\n    }\n\n"
path.write_text(text.replace(subject, subject + addition, 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'an allowed load line copied into a new unlisted function' mut_config_load_copied_to_new_item \
    'unlisted load at crates/gateway/src/service.rs:'

# Moving a load keeps its file, its line text and the count; only the item path sees it arrive
# somewhere the reviewed entry did not name.
mut_config_load_moved_to_other_item() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
listed = "        let snapshot = self.inner.config.load();\n"
source = listed + "        f.debug_struct(\"S3Service\")"
target = "    pub fn limits(&self) -> &Limits {\n"
if text.count(source) != 1 or text.count(target) != 1:
    raise SystemExit("missing mutation subject: the Debug snapshot load and the limits() accessor")
text = text.replace(source, "        let snapshot = self.inner.config.as_ref();\n        f.debug_struct(\"S3Service\")", 1)
path.write_text(text.replace(target, target + listed + "        drop(snapshot);\n", 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'an allowed load moved into another function of the same file' mut_config_load_moved_to_other_item \
    'unlisted load at crates/gateway/src/service.rs:'

mut_config_load_entry_orphaned() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
subject = "        let snapshot = self.inner.config.load();\n        snapshot.runtime().routing.dispatch.names()"
if text.count(subject) != 1:
    raise SystemExit("missing mutation subject: the operations() snapshot load")
path.write_text(text.replace(subject, "        let snapshot = self.inner.config.as_ref();\n        snapshot.runtime().routing.dispatch.names()", 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'an allowlist entry left behind after its load is removed' mut_config_load_entry_orphaned \
    'allowlist entry matches no load site: crates/gateway/src/service.rs'

mut_config_load_entry_ambiguous() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
load = "        let snapshot = self.inner.config.load();\n"
subject = load + "        snapshot.runtime().routing.dispatch.names()"
if text.count(subject) != 1:
    raise SystemExit("missing mutation subject: the operations() snapshot load")
path.write_text(text.replace(subject, load + subject, 1))
PYEOF
}
expect_fail check_config_load_once.sh \
    'one allowlist entry matching a second identical load in the same function' mut_config_load_entry_ambiguous \
    'is listed 1 time(s) but matches 2 site(s)'

# Two genuinely identical loads in one item are listed twice; one entry must not cover both.
mut_config_load_repeated_entry_collapsed() {
    python3 - <<'PYEOF'
from collections import Counter
from pathlib import Path

path = Path("scripts/config_load_allowlist.txt")
lines = path.read_text().splitlines(keepends=True)
repeated = [line for line, count in Counter(lines).items() if count == 2 and not line.startswith("#")]
if not repeated:
    raise SystemExit("missing mutation subject: an allowlist entry listed for two identical sites")
lines.remove(repeated[0])
path.write_text("".join(lines))
PYEOF
}
expect_fail check_config_load_once.sh \
    'an entry for two identical loads collapsed into one' mut_config_load_repeated_entry_collapsed \
    'is listed 1 time(s) but matches 2 site(s)'

mut_config_load_entry_malformed() {
    printf 'crates/gateway/src/service.rs:1\n' >>scripts/config_load_allowlist.txt
}
expect_fail check_config_load_once.sh \
    'a line-number allowlist entry' mut_config_load_entry_malformed \
    'is not `FILE | ITEM PATH | LINE TEXT`'

# Listing a second load in a request entry satisfies the inventory; it must still be refused.
mut_request_entry_second_listed_load() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
subject = "        let runtime = snapshot.runtime();\n        let mode = DynamicMode {\n"
if text.count(subject) != 1:
    raise SystemExit("missing mutation subject: the dynamic request entry")
added = "        let _torn = self.inner.config.load();\n"
path.write_text(text.replace(subject, subject.replace("        let mode", added + "        let mode", 1), 1))
allowlist = Path("scripts/config_load_allowlist.txt")
allowlist.write_text(
    allowlist.read_text() + "crates/gateway/src/service.rs | impl S3Service / fn call | let _torn = self.inner.config.load();\n"
)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a request entry with a second, allowlisted snapshot load' mut_request_entry_second_listed_load \
    'each request entry must allowlist exactly one assembly snapshot load'

mut_config_snapshot_stage_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace("let config = state.config.decoded();", "let config = state.config;", 1)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a real request path dropping the decoded snapshot stage' mut_config_snapshot_stage_deleted

# Each load-then-store rewrite also re-anchors its load allowlist entry, as an author would, so the
# load inventory passes and only the write-primitive rule can see that a partial update may now
# overwrite a concurrent one.
reanchor_config_load_entry() {
    python3 - "$@" <<'PYEOF'
from pathlib import Path
import sys

file, old, new = sys.argv[1:]
path = Path("scripts/config_load_allowlist.txt")
lines = path.read_text().splitlines(keepends=True)
suffix = " | " + " ".join(old.split()) + "\n"
matches = [index for index, line in enumerate(lines) if line.startswith(file + " | ") and line.endswith(suffix)]
if len(matches) != 1:
    raise SystemExit(f"missing mutation subject: one allowlist entry for {old!r} in {file}")
lines[matches[0]] = lines[matches[0]][: -len(suffix)] + " | " + " ".join(new.split()) + "\n"
path.write_text("".join(lines))
PYEOF
}

mut_settings_update_load_then_store() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/config.rs")
text = path.read_text()
subject = "        self.store.rcu(|current| {\n"
if text.count(subject) != 1:
    raise SystemExit("missing mutation subject: the settings update's rcu")
path.write_text(text.replace(subject, "        let current = self.store.load_full(); self.store.store({\n", 1))
PYEOF
    reanchor_config_load_entry crates/gateway/src/config.rs \
        'self.store.rcu(|current| {' 'let current = self.store.load_full(); self.store.store({'
}
expect_fail check_config_load_once.sh \
    'a settings update that loads then stores and can overwrite a concurrent registry update' \
    mut_settings_update_load_then_store \
    'every ConfigStore write except the one complete replacement must be an rcu'

mut_registry_update_ufcs_store() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service/update.rs")
text = path.read_text()
subject = "        self.inner.config.rcu(|current| {\n"
if text.count(subject) != 1:
    raise SystemExit("missing mutation subject: the registry update's rcu")
replacement = "        let current = self.inner.config.load_full(); arc_swap::ArcSwapAny::store(&self.inner.config, {\n"
path.write_text(text.replace(subject, replacement, 1))
PYEOF
    reanchor_config_load_entry crates/gateway/src/service/update.rs 'self.inner.config.rcu(|current| {' \
        'let current = self.inner.config.load_full(); arc_swap::ArcSwapAny::store(&self.inner.config, {'
}
expect_fail check_config_load_once.sh \
    'a registry update storing through UFCS and able to overwrite a concurrent settings update' \
    mut_registry_update_ufcs_store \
    'every ConfigStore write except the one complete replacement must be an rcu'

mut_tsan_instrumentation_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("scripts/run_gateway_tsan.sh")
path.write_text(path.read_text().replace("RUSTFLAGS='-Zsanitizer=thread'", "RUSTFLAGS=''", 1))
PYEOF
}
expect_fail check_gateway_tsan_wiring.sh \
    'the TSAN runner losing sanitizer instrumentation' mut_tsan_instrumentation_deleted

mut_tsan_build_std_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("scripts/run_gateway_tsan.sh")
path.write_text(path.read_text().replace(" test -Zbuild-std ", " test ", 1))
PYEOF
}
expect_fail check_gateway_tsan_wiring.sh \
    'the TSAN runner using an uninstrumented standard library' mut_tsan_build_std_deleted

mut_tsan_thread_count_reduced() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/tests/service_concurrency.rs")
path.write_text(path.read_text().replace("const THREADS: usize = 100;", "const THREADS: usize = 99;", 1))
PYEOF
}
expect_fail check_gateway_tsan_wiring.sh \
    'the concurrency case being reduced to 99 OS threads' mut_tsan_thread_count_reduced

mut_tsan_ci_call_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path(".github/workflows/ci.yml")
path.write_text(path.read_text().replace("scripts/run_gateway_tsan.sh", "cargo test -p rustfs-gateway", 1))
PYEOF
}
expect_fail check_gateway_tsan_wiring.sh \
    'CI no longer invoking the TSAN runner' mut_tsan_ci_call_deleted

mut_tsan_aggregate_drops_tsan() {
    replace_ci_text ', gateway-tsan, docs, examples]' ', docs, examples]'
}
expect_fail check_gateway_tsan_wiring.sh \
    'the required aggregate no longer waiting for TSAN' \
    mut_tsan_aggregate_drops_tsan

mut_default_security_doc_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/policy.rs")
text = path.read_text().replace("/// # Security\n", "", 1)
path.write_text(text)
PYEOF
}
expect_fail check_default_doc.sh \
    'a Default implementation losing its security consequences' mut_default_security_doc_deleted

mut_derived_default_security_doc_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/host.rs")
text = path.read_text().replace("/// # Security\n", "", 1)
path.write_text(text)
PYEOF
}
expect_fail check_default_doc.sh \
    'a derived extension default losing its security consequences' mut_derived_default_security_doc_deleted

mut_undocumented_derived_default_added() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/observer.rs")
text = path.read_text()
text += "\n#[derive(Default)]\npub struct UndocumentedObserverDefault;\n"
path.write_text(text)
PYEOF
}
expect_fail check_default_doc.sh \
    'a newly derived extension default without security documentation' mut_undocumented_derived_default_added

mut_inline_undocumented_derived_default_added() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/observer.rs")
text = path.read_text()
text += "\n#[derive(Default)] pub struct InlineUndocumentedDefault;\n"
path.write_text(text)
PYEOF
}
expect_fail check_default_doc.sh \
    'an inline derived extension default without security documentation' mut_inline_undocumented_derived_default_added

mut_default_doc_subject_deleted() {
    rm -f crates/gateway/src/ext/policy.rs
}
expect_fail check_default_doc.sh \
    "a documented Default implementation's source being absent" mut_default_doc_subject_deleted

# Fault-inject the real make_sandbox function. Each mode must fail without publishing a sandbox or
# leaving its derived list, archive, or partially initialized directory behind.
expect_sandbox_setup_failure() {
    local mode="$1" probe_root rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    probe_root="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-fault.XXXXXX")"
    mkdir -p "$probe_root/repo" "$probe_root/tmp"
    (
        cd "$probe_root/repo"
        git init -q .
        printf 'sandbox fault probe\n' >tracked.txt
        git add tracked.txt
        git -c user.name=t -c user.email=t@t commit -qm base
    )
    (
        local real_git real_tar sandbox_rc=0
        real_git="$(command -v git)"
        real_tar="$(command -v tar)"
        REPO_ROOT="$probe_root/repo"
        TMPDIR="$probe_root/tmp"
        SANDBOX=""

        git() {
            local argument
            if [[ "$mode" == list-failure && "$1" == ls-files ]]; then
                return 71
            fi
            if [[ "$mode" == commit-failure ]]; then
                for argument in "$@"; do
                    if [[ "$argument" == commit ]]; then
                        return 72
                    fi
                done
            fi
            command "$real_git" "$@"
        }
        tar() {
            if [[ "$mode" == create-failure && "$1" == -cf ]]; then
                return 73
            fi
            if [[ "$mode" == extract-failure && "$1" == -xf ]]; then
                return 74
            fi
            command "$real_tar" "$@"
        }

        make_sandbox || sandbox_rc=$?
        [[ "$sandbox_rc" -ne 0 && -z "$SANDBOX" ]] || exit 1
        shopt -s nullglob dotglob
        leftovers=("$TMPDIR"/*)
        [[ "${#leftovers[@]}" -eq 0 ]]
    ) || rc=$?
    rm -rf "$probe_root"
    if [[ "$rc" -eq 0 ]]; then
        pass_msg "make_sandbox fails closed and cleans up: ${mode}"
    else
        fail_msg "make_sandbox leaked state or reported success: ${mode}"
    fi
}

expect_sandbox_setup_failure list-failure
expect_sandbox_setup_failure create-failure
expect_sandbox_setup_failure extract-failure
expect_sandbox_setup_failure commit-failure

mut_guard_sandbox_archive_restored_to_stream() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
start = text.index('    list="${dir}.files"')
end = text.index('    if ! (cd "$dir" && git init -q .); then', start)
stream = '''    (cd "$REPO_ROOT" && tar -cf - -T "$list") | (cd "$dir" && tar -xf -)
    rm -f "$list"
'''
path.write_text(text[:start] + stream + text[end:])
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'make_sandbox restoring the streaming tar pipeline' mut_guard_sandbox_archive_restored_to_stream

mut_guard_sandbox_archive_not_derived_from_unique_dir() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = '    archive="${dir}.tar"\n'
path.write_text(text.replace(old, '    archive="${TMPDIR:-/tmp}/gateway-guard-archive.tar"\n', 1))
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'make_sandbox using a fixed archive path' mut_guard_sandbox_archive_not_derived_from_unique_dir

mut_guard_sandbox_archive_list_not_fail_closed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = '''    if ! (
        cd "$REPO_ROOT" &&
            git ls-files >"$list" &&
            git ls-files --others --exclude-standard >>"$list" &&
            sort -u -o "$list" "$list"
    ); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
'''
new = '''    (
        cd "$REPO_ROOT" &&
            git ls-files >"$list" &&
            git ls-files --others --exclude-standard >>"$list" &&
            sort -u -o "$list" "$list"
    ) || true
'''
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'file-list creation ignoring a producer failure' mut_guard_sandbox_archive_list_not_fail_closed

mut_guard_sandbox_archive_create_not_fail_closed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = '''    if ! (cd "$REPO_ROOT" && tar -cf "$archive" -T "$list"); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
'''
path.write_text(text.replace(old, '    (cd "$REPO_ROOT" && tar -cf "$archive" -T "$list") || true\n', 1))
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'archive creation ignoring a producer failure' mut_guard_sandbox_archive_create_not_fail_closed

mut_guard_sandbox_archive_extract_leaks_partial_state() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = '''    if ! (cd "$dir" && tar -xf "$archive"); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
'''
new = '''    if ! (cd "$dir" && tar -xf "$archive"); then
        return 1
    fi
'''
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'archive extraction leaking partial state' mut_guard_sandbox_archive_extract_leaks_partial_state

mut_guard_sandbox_archive_cleanup_commented_out() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = '        rm -f "$list" "$archive" || true\n'
new = '        # rm -f "$list" "$archive" || true\n'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'a cleanup command being replaced by a comment' mut_guard_sandbox_archive_cleanup_commented_out

mut_guard_sandbox_archive_commit_not_fail_closed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = '''    if ! (cd "$dir" && git -c user.name=t -c user.email=t@t commit -qm base >/dev/null 2>&1); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
'''
new = '    (cd "$dir" && git -c user.name=t -c user.email=t@t commit -qm base >/dev/null 2>&1) || true\n'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'sandbox base commit ignoring failure' mut_guard_sandbox_archive_commit_not_fail_closed

mut_xtask_autotests_restored() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("autotests = false\n", "autotests = true\n", 1))
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'restoring xtask implicit test discovery' mut_xtask_autotests_restored

mut_xtask_autobins_restored() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("autobins = false\n", "autobins = true\n", 1))
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'restoring xtask implicit bin discovery' mut_xtask_autobins_restored

mut_xtask_autoexamples_restored() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("autoexamples = false\n", "autoexamples = true\n", 1))
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'restoring xtask implicit example discovery' mut_xtask_autoexamples_restored

mut_xtask_autobenches_restored() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("autobenches = false\n", "autobenches = true\n", 1))
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'restoring xtask implicit bench discovery' mut_xtask_autobenches_restored

mut_xtask_explicit_bin_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/Cargo.toml")
text = path.read_text()
entry = '''[[bin]]
name = "xtask"
path = "src/main.rs"

'''
if text.count(entry) != 1:
    raise SystemExit("xtask explicit bin target is missing")
path.write_text(text.replace(entry, "", 1))
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'removing the explicit xtask bin target' mut_xtask_explicit_bin_removed

mut_xtask_integration_target_renamed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/Cargo.toml")
text = path.read_text()
path.write_text(text.replace('name = "xtask-integration"\n', 'name = "integration"\n', 1))
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'renaming the workspace-unique xtask integration target' mut_xtask_integration_target_renamed

mut_xtask_implicit_library_added() {
    cp xtask/src/main.rs xtask/src/lib.rs
}
expect_fail check_xtask_test_target_consolidation.sh \
    'adding an implicit xtask library target' mut_xtask_implicit_library_added

mut_xtask_bench_target_added() {
    cat >>xtask/Cargo.toml <<'TOMLEOF'

[[bench]]
name = "unexpected-bench"
path = "src/main.rs"
TOMLEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'adding an xtask bench target outside the exact feedback scope' mut_xtask_bench_target_added

mut_xtask_registration_omitted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/tests/integration.rs")
text = path.read_text()
path.write_text(text.replace('#[path = "cli_contract.rs"]\nmod cli_contract;\n', '', 1))
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'an omitted xtask integration registration' mut_xtask_registration_omitted

mut_xtask_registration_duplicated() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/tests/integration.rs")
text = path.read_text()
entry = '#[path = "cli_contract.rs"]\nmod cli_contract;\n'
path.write_text(text.replace(entry, entry + entry, 1))
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'a duplicated xtask integration registration' mut_xtask_registration_duplicated

mut_xtask_source_unregistered() {
    cp xtask/tests/cli_contract.rs xtask/tests/unregistered_contract.rs
}
expect_fail check_xtask_test_target_consolidation.sh \
    'a new unregistered xtask integration source' mut_xtask_source_unregistered

mut_xtask_source_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/tests/cli_contract.rs")
path.write_text("#![cfg(any())]\n" + path.read_text())
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'a registered xtask source disabled by file cfg' mut_xtask_source_disabled

mut_xtask_source_symlinked() {
    rm xtask/tests/cli_contract.rs
    ln -s why_contract.rs xtask/tests/cli_contract.rs
}
expect_fail check_xtask_test_target_consolidation.sh \
    'a registered xtask source replaced by a symlink' mut_xtask_source_symlinked

mut_xtask_extra_test_target() {
    cat >>xtask/Cargo.toml <<'TOMLEOF'

[[test]]
name = "duplicate"
path = "tests/integration.rs"
TOMLEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'a second explicit xtask test target' mut_xtask_extra_test_target

mut_xtask_example_reuses_source() {
    cat >>xtask/Cargo.toml <<'TOMLEOF'

[[example]]
name = "duplicate-contract"
path = "tests/cli_contract.rs"
test = true
TOMLEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'an example target reusing an xtask test source' mut_xtask_example_reuses_source

mut_xtask_path_reuses_source() {
    cat >>xtask/src/main.rs <<'RUSTEOF'

#[cfg(test)]
#[path = "../tests/cli_contract.rs"]
mod duplicate_contract;
RUSTEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'a path attribute reusing an xtask test source' mut_xtask_path_reuses_source

mut_xtask_include_reuses_source() {
    cat >>xtask/src/main.rs <<'RUSTEOF'

#[cfg(test)]
mod duplicate_contract {
    include!("../tests/cli_contract.rs");
}
RUSTEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'an include reusing an xtask test source' mut_xtask_include_reuses_source

mut_xtask_lifetimes_surround_path_reuse() {
    cat >>xtask/src/main.rs <<'RUSTEOF'

fn before_path<'a>() {} #[cfg(test)] #[path = "../tests/cli_contract.rs"] mod duplicate_contract; fn after_path<'b>() {}
RUSTEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'lifetimes surrounding an active path reuse' mut_xtask_lifetimes_surround_path_reuse

mut_xtask_lifetimes_surround_include_reuse() {
    cat >>xtask/src/main.rs <<'RUSTEOF'

fn before_include<'a>() {} #[cfg(test)] mod duplicate_contract { include!("../tests/cli_contract.rs"); } fn after_include<'b>() {}
RUSTEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'lifetimes surrounding an active include reuse' mut_xtask_lifetimes_surround_include_reuse

mut_xtask_path_include_token_decoys() {
    cat >>xtask/src/main.rs <<'RUSTEOF'

// #[path = "../tests/cli_contract.rs"]
const PATH_DECOY: &str = "#[path = \"../tests/cli_contract.rs\"]";
const INCLUDE_DECOY: &str = "include!(\"../tests/cli_contract.rs\")";
const CHAR_DECOY: char = '#';
const BYTE_CHAR_DECOY: u8 = b'!';
fn lifetime_control<'a>(value: &'a str) -> &'a str { value }
RUSTEOF
}
expect_guard_pass check_xtask_test_target_consolidation.sh \
    'comment, string, char, byte-char, and lifetime token decoys' mut_xtask_path_include_token_decoys

mut_xtask_explicit_build_reuses_source() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("build = false\n", 'build = "tests/cli_contract.rs"\n', 1))
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'an explicit build target reusing an xtask test source' mut_xtask_explicit_build_reuses_source

mut_xtask_default_build_symlink_reuses_source() {
    ln -s tests/cli_contract.rs xtask/build.rs
}
expect_fail check_xtask_test_target_consolidation.sh \
    'the default build target symlinking an xtask test source' mut_xtask_default_build_symlink_reuses_source

mut_xtask_default_build_includes_source() {
    cat >xtask/build.rs <<'RUSTEOF'
include!("tests/cli_contract.rs");
RUSTEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'the default build target including an xtask test source' mut_xtask_default_build_includes_source

mut_sig_autotests_restored() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("autotests = false\n", "autotests = true\n", 1))
PYEOF
}
expect_fail check_sig_test_target_consolidation.sh \
    'restoring sig implicit test discovery' mut_sig_autotests_restored

mut_sig_registration_omitted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/integration.rs")
text = path.read_text()
path.write_text(text.replace('#[path = "canonical_request.rs"]\nmod canonical_request;\n', '', 1))
PYEOF
}
expect_fail check_sig_test_target_consolidation.sh \
    'an omitted sig integration registration' mut_sig_registration_omitted

mut_sig_registration_duplicated() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/integration.rs")
text = path.read_text()
entry = '#[path = "canonical_request.rs"]\nmod canonical_request;\n'
path.write_text(text.replace(entry, entry + entry, 1))
PYEOF
}
expect_fail check_sig_test_target_consolidation.sh \
    'a duplicated sig integration registration' mut_sig_registration_duplicated

mut_http_autotests_restored() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("autotests = false\n", "autotests = true\n", 1))
PYEOF
}
expect_fail check_http_test_target_consolidation.sh \
    'restoring http implicit test discovery' mut_http_autotests_restored

mut_http_registration_omitted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/integration.rs")
text = path.read_text()
path.write_text(text.replace('#[path = "host_ambiguity.rs"]\nmod host_ambiguity;\n', '', 1))
PYEOF
}
expect_fail check_http_test_target_consolidation.sh \
    'an omitted http integration registration' mut_http_registration_omitted

mut_http_fixture_registration_omitted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/integration.rs")
text = path.read_text()
path.write_text(text.replace('#[path = "support/mod.rs"]\nmod support;\n', '', 1))
PYEOF
}
expect_fail check_http_test_target_consolidation.sh \
    'the http harness no longer registering its fixture module' mut_http_fixture_registration_omitted

mut_http_suite_redeclares_the_fixture_module() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/http/tests/host_ambiguity.rs")
text = path.read_text()
path.write_text(text.replace("use crate::support::", "mod support;\nuse crate::support::", 1))
PYEOF
}
expect_fail check_http_test_target_consolidation.sh \
    'an http suite declaring the harness-owned fixture module itself' mut_http_suite_redeclares_the_fixture_module

mut_sig_source_unregistered() {
    cp crates/sig/tests/canonical_request.rs crates/sig/tests/unregistered_contract.rs
}
expect_fail check_sig_test_target_consolidation.sh \
    'a new unregistered sig integration source' mut_sig_source_unregistered

mut_sig_source_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/canonical_request.rs")
path.write_text("#![cfg(any())]\n" + path.read_text())
PYEOF
}
expect_fail check_sig_test_target_consolidation.sh \
    'a registered sig source disabled by file cfg' mut_sig_source_disabled

mut_sig_source_symlinked() {
    rm crates/sig/tests/canonical_request.rs
    ln -s timing.rs crates/sig/tests/canonical_request.rs
}
expect_fail check_sig_test_target_consolidation.sh \
    'a registered sig source replaced by a symlink' mut_sig_source_symlinked

mut_sig_extra_test_target() {
    cat >>crates/sig/Cargo.toml <<'TOMLEOF'

[[test]]
name = "duplicate"
path = "tests/integration.rs"
TOMLEOF
}
expect_fail check_sig_test_target_consolidation.sh \
    'a second explicit sig test target' mut_sig_extra_test_target

mut_sig_example_reuses_source() {
    cat >>crates/sig/Cargo.toml <<'TOMLEOF'

[[example]]
name = "duplicate-contract"
path = "tests/canonical_request.rs"
test = true
TOMLEOF
}
expect_fail check_sig_test_target_consolidation.sh \
    'an example target reusing a sig test source' mut_sig_example_reuses_source

mut_sig_path_reuses_source() {
    cat >>crates/sig/src/lib.rs <<'RUSTEOF'

#[cfg(test)]
#[path = "../tests/canonical_request.rs"]
mod duplicate_contract;
RUSTEOF
}
expect_fail check_sig_test_target_consolidation.sh \
    'a path attribute reusing a sig test source' mut_sig_path_reuses_source

mut_sig_include_reuses_source() {
    cat >>crates/sig/src/lib.rs <<'RUSTEOF'

#[cfg(test)]
mod duplicate_contract {
    include!("../tests/canonical_request.rs");
}
RUSTEOF
}
expect_fail check_sig_test_target_consolidation.sh \
    'an include reusing a sig test source' mut_sig_include_reuses_source

mut_sig_shared_fixture_loaded_twice() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/security_floor.rs")
text = path.read_text()
old = "use crate::security_floor_fixtures::*;"
new = "mod security_floor_fixtures;\nuse security_floor_fixtures::*;"
if text.count(old) != 1:
    raise SystemExit("the shared fixture import anchor is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_test_target_consolidation.sh \
    'a sig integration source loading the shared fixture as a second module' mut_sig_shared_fixture_loaded_twice

mut_server_autotests_restored() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/server/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("autotests = false\n", "autotests = true\n", 1))
PYEOF
}
expect_fail check_server_test_target_consolidation.sh \
    'restoring server implicit test discovery' mut_server_autotests_restored

mut_server_registration_omitted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/server/tests/integration.rs")
text = path.read_text()
text = text.replace('#[path = "lingering_close.rs"]\nmod lingering_close;\n', '', 1)
path.write_text(text)
PYEOF
}
expect_fail check_server_test_target_consolidation.sh \
    'an omitted server integration registration' mut_server_registration_omitted

fi

if [[ "$QUIRK_LEDGER_ONLY" == 1 ]]; then

# The protected quirk ledger has independent negative controls for its counts, source union,
# dimensions, capability exclusions, production consumers, bilateral backlinks and generated ID
# sets. None of these controls runs codegen or Cargo.
QUIRK_LEDGER_DIAGNOSTICS=$(cat <<'DIAGEOF'
mut_quirk_ledger_classification_count	q-timestamp-0012: unknown classification
mut_quirk_ledger_duplicate_source	q-restore-header-absence-0127: multiple typed sources
mut_quirk_ledger_typed_contract_proof_removed	ledger typed_contracts: expected 160, found 159
mut_quirk_ledger_dimension_count	ledger dimensions: expected 179, found 178
mut_quirk_ledger_misbound_emitter_dimension	q-restore-header-absence-0127: expected one declared emitter binding, found 0
mut_quirk_ledger_capability_exclusion	capability exclusions must remain typed contract sources
mut_quirk_ledger_mutable_consumer	q-empty-0002: mutable source is claimed by no operation overlay
mut_quirk_ledger_runtime_consumer	q-restore-header-absence-0127: emitted constants lack one production consumer identity
mut_quirk_ledger_cfg_disabled_consumer	q-restore-header-absence-0127: emitted constants lack one production consumer identity
mut_quirk_ledger_cfg_attr_disabled_consumer	q-restore-header-absence-0127: emitted constants lack one production consumer identity
mut_quirk_ledger_codegen_consumer_decoy	q-restore-root-namespace-0137: emitted constants lack one production consumer identity
mut_quirk_ledger_direct_case_comment_decoy	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_string_decoy	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_cfg_disabled	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_cfg_attr_disabled	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_ignored	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_cfg_attr_ignored	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_should_panic	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_inert_body_string	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_ordinary_function	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_shadowed_macro	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_forward_backlink	q-restore-header-absence-0127 -> c-select-restore-0019: missing unique backlink
mut_quirk_ledger_reverse_backlink	c-select-restore-0040 -> q-restore-header-absence-0127: missing unique source backlink
mut_quirk_ledger_spec_id_set	spec/quirks id set drifted:
mut_quirk_ledger_signature_host_consumer	q-sig-canonical-host-raw-0156: emitted constants lack one production consumer identity
mut_quirk_ledger_signature_path_consumer	q-sig-raw-path-fallback-0157: emitted constants lack one production consumer identity
mut_quirk_ledger_signature_payload_consumer	q-sig-payload-token-verbatim-0158: emitted constants lack one production consumer identity
mut_quirk_ledger_sigv2_mutable_contract_consumer	q-sig-v2-included-query: emitted constants lack one production consumer identity
mut_quirk_ledger_sigv2_expires_consumer	q-sig-v2-expires-absolute: emitted constants lack one production consumer identity
mut_quirk_ledger_sigv2_query_consumer	q-sig-v2-query-not-covered: emitted constants lack one production consumer identity
DIAGEOF
)
if ! python3 - "${GATEWAY_GUARD_SCRIPT_SOURCE:-$0}" <<'PYEOF'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text()
entries = re.findall(r"expect_fail check_quirk_ledger\.sh \\\n\s+'([^']+)' ([a-z0-9_]+)", text)
diagnostics = re.findall(r"^(mut_quirk_ledger_[a-z0-9_]+)\t([^\n]+)$", text, re.MULTILINE)
helpers = [helper for _, helper in entries]
if len(entries) != 30 or len(set(entries)) != 30 or len(diagnostics) != 30 or len(set(diagnostics)) != 30:
    raise SystemExit("quirk-ledger mutation manifest must contain 30 unique description/helper pairs")
if set(helpers) != {helper for helper, _ in diagnostics}:
    raise SystemExit("quirk-ledger diagnostic manifest does not match the 30 mutation helpers")
PYEOF
then
    fail_msg 'check_quirk_ledger.sh mutation manifest is missing or duplicated'
fi

QUIRK_LEDGER_PARSE_CACHE="$(mktemp "${TMPDIR:-/tmp}/gateway-quirk-ledger-cache.XXXXXX")"
rm -f "$QUIRK_LEDGER_PARSE_CACHE"
export GATEWAY_QUIRK_LEDGER_PARSE_CACHE="$QUIRK_LEDGER_PARSE_CACHE"
make_sandbox
if ! GATEWAY_CHECK_ROOT="$SANDBOX" "${SCRIPT_DIR}/check_quirk_ledger.sh" >/dev/null 2>&1; then
    fail_msg 'check_quirk_ledger.sh parse-cache baseline failed'
fi
python3 - "$QUIRK_LEDGER_PARSE_CACHE" "$SANDBOX/model/overlays/quirks/object.toml" <<'PYEOF'
import hashlib
import pathlib
import sqlite3
import sys

cache, subject = map(pathlib.Path, sys.argv[1:])
digest = hashlib.sha256(subject.read_bytes()).hexdigest()
with sqlite3.connect(cache) as connection:
    connection.execute(
        "UPDATE parse_cache SET value = 'not-json' WHERE kind = 'toml' AND hash = ?", (digest,)
    )
PYEOF
if ! GATEWAY_CHECK_ROOT="$SANDBOX" "${SCRIPT_DIR}/check_quirk_ledger.sh" >/dev/null 2>&1; then
    fail_msg 'check_quirk_ledger.sh did not repair a malformed cached row'
fi
if [[ ! -s "$QUIRK_LEDGER_PARSE_CACHE" ]]; then
    fail_msg 'check_quirk_ledger.sh parse cache was not populated'
fi
printf 'not-json\n' >"$QUIRK_LEDGER_PARSE_CACHE"
if ! GATEWAY_CHECK_ROOT="$SANDBOX" "${SCRIPT_DIR}/check_quirk_ledger.sh" >/dev/null 2>&1; then
    fail_msg 'check_quirk_ledger.sh did not rebuild a corrupt parse cache'
fi
quirk_ledger_cases_before="$cases"
mut_quirk_ledger_classification_count() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/quirks/object.toml")
text = path.read_text()
old = 'id      = "q-timestamp-0012"\nkind    = "structured_header"\nclassification = "contract"'
new = 'id      = "q-timestamp-0012"\nkind    = "structured_header"\nclassification = "unknown"'
if old not in text:
    raise SystemExit("classification mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'one protected record leaving the 101/160/89 classification ledger' mut_quirk_ledger_classification_count
if ! python3 - "$QUIRK_LEDGER_PARSE_CACHE" "$SANDBOX/model/overlays/quirks/object.toml" <<'PYEOF'
import hashlib
import pathlib
import sqlite3
import sys

cache, subject = map(pathlib.Path, sys.argv[1:])
digest = hashlib.sha256(subject.read_bytes()).hexdigest()
with sqlite3.connect(cache) as connection:
    row = connection.execute(
        "SELECT 1 FROM parse_cache WHERE kind = 'toml' AND hash = ?", (digest,)
    ).fetchone()
if row is None:
    raise SystemExit("changed content did not create a content-hash cache miss")
PYEOF
then
    fail_msg 'check_quirk_ledger.sh reused the baseline parse for changed content'
fi

mut_quirk_ledger_duplicate_source() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/quirks/select-restore.toml")
text = path.read_text()
old = 'mutation_dimension = "restore_header_absence"\ncontract_value = "omit"'
new = 'mutation_dimension = "restore_header_absence"\ncodec_value = "entity_tag"\ncontract_value = "omit"'
if old not in text:
    raise SystemExit("typed-source mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'one atom claiming two typed sources' mut_quirk_ledger_duplicate_source

mut_quirk_ledger_typed_contract_proof_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/quirks/select-restore.toml")
text = path.read_text()
old = 'mutation_dimension = "restore_header_absence"\ncontract_value = "omit"'
if text.count(old) != 1:
    raise SystemExit("typed-contract proof mutation subject is not unique")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a typed contract losing its current value and mutation dimension' mut_quirk_ledger_typed_contract_proof_removed

mut_quirk_ledger_dimension_count() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/quirks/select-restore.toml")
text = path.read_text()
old = 'mutation_dimension = "restore_header_absence"\ncontract_value = "omit"'
new = 'mutation_dimension = "restore_header_parse_grammar"\ncontract_value = "omit"'
if old not in text:
    raise SystemExit("dimension mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'the 179-dimension ledger collapsing one independent atom' mut_quirk_ledger_dimension_count

mut_quirk_ledger_misbound_emitter_dimension() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/codegen/src/emit/runtime_contracts/select_restore.rs")
text = path.read_text()
old = '''        RestoreHeaderAbsence,
        RestoreHeaderAbsence,
        RestoreHeaderAbsenceValue,'''
new = '''        RestoreHeaderParseGrammar,
        RestoreHeaderAbsence,
        RestoreHeaderAbsenceValue,'''
if text.count(old) != 1:
    raise SystemExit("emitter-dimension mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'one typed source being bound to another atom dimension by its emitter' mut_quirk_ledger_misbound_emitter_dimension

mut_quirk_ledger_capability_exclusion() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/quirks/cors.toml")
text = path.read_text()
old = 'id      = "q-cors-0006"'
new = 'id      = "q-cors-9006"'
if text.count(old) != 1:
    raise SystemExit("capability exclusion mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'the explicit two-entry CORS capability exclusion drifting' mut_quirk_ledger_capability_exclusion

mut_quirk_ledger_mutable_consumer() {
    python3 - <<'PYEOF'
import pathlib

decoy_path = None
for path in pathlib.Path("model/overlays/ops").glob("*.toml"):
    text = path.read_text()
    if '"q-empty-0002"' in text:
        path.write_text(text.replace('"q-empty-0002"', '"q-region-0003"'))
        decoy_path = path
if decoy_path is None:
    raise SystemExit("mutable-consumer mutation subject is missing")
with decoy_path.open("a") as output:
    output.write('\n# A raw TOML comment is not a consumer: "q-empty-0002"\n')
    output.write('ledger_string_decoy = "q-empty-0002"\n')
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a TOML comment replacing every parsed mutable consumer' mut_quirk_ledger_mutable_consumer

mut_quirk_ledger_runtime_consumer() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/ops/shared/restore.rs")
text = path.read_text()
old = "RESTORE_HEADER_ABSENCE"
if old not in text:
    raise SystemExit("runtime-consumer mutation subject is missing")
text = text.replace(old, "RESTORE_HEADER_ABSENCE_BROKEN")
text += '\n// A comment is not a production consumer: RESTORE_HEADER_ABSENCE\n'
text += 'const _LEDGER_STRING_DECOY: &str = "RESTORE_HEADER_ABSENCE";\n'
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'comments and strings replacing an emitted constant production use' mut_quirk_ledger_runtime_consumer

mut_quirk_ledger_cfg_disabled_consumer() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/ops/shared/restore.rs")
text = path.read_text()
old = "RESTORE_HEADER_ABSENCE"
if old not in text:
    raise SystemExit("cfg-disabled consumer mutation subject is missing")
text = text.replace(old, "RESTORE_HEADER_ABSENCE_BROKEN")
text += '''
#[cfg(any())]
fn disabled_ledger_decoy() {
    let _ = crate::contracts::RESTORE_HEADER_ABSENCE;
}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a cfg-disabled item replacing an emitted constant production use' mut_quirk_ledger_cfg_disabled_consumer

mut_quirk_ledger_cfg_attr_disabled_consumer() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/ops/shared/restore.rs")
text = path.read_text()
old = "RESTORE_HEADER_ABSENCE"
if old not in text:
    raise SystemExit("cfg_attr-disabled consumer mutation subject is missing")
text = text.replace(old, "RESTORE_HEADER_ABSENCE_BROKEN")
text += '''
#[cfg_attr(all(), cfg(any()))]
fn disabled_ledger_decoy() {
    let _ = crate::contracts::RESTORE_HEADER_ABSENCE;
}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a cfg_attr-disabled item replacing an emitted constant production use' mut_quirk_ledger_cfg_attr_disabled_consumer

mut_quirk_ledger_codegen_consumer_decoy() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/codegen/src/emit/codec/decode.rs")
text = path.read_text()
old = '"crate::contracts::RESTORE_ROOT_NAMESPACE_POLICY, crate::contracts::RestoreRootNamespacePolicy::QualifiedName"'
new = '"crate::contracts::RestoreRootNamespacePolicy::QualifiedName"'
if text.count(old) != 1:
    raise SystemExit("codegen-consumer mutation subject is not unique")
text = text.replace(old, new, 1)
text += '\n// An unrelated emitted-code string is not a live match-arm consumer.\n'
text += 'const _LEDGER_CODEGEN_DECOY: &str = "crate::contracts::RESTORE_ROOT_NAMESPACE_POLICY";\n'
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'an emitted-code policy leaving its active match arm for a string decoy' mut_quirk_ledger_codegen_consumer_decoy

mut_quirk_ledger_direct_case_comment_decoy() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("direct-case comment mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'\n// #[test]\n// fn {name}() {{ let quirk = "q-restore-header-parser-0128"; assert!(true, "{{}}", quirk); }}\n'
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a commented direct case replacing its active test function' mut_quirk_ledger_direct_case_comment_decoy

mut_quirk_ledger_direct_case_string_decoy() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("direct-case string mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'\nconst _DIRECT_CASE_DECOY: &str = r#"#[test] fn {name}() {{ let quirk = \\"q-restore-header-parser-0128\\"; assert!(true, \\"{{}}\\", quirk); }}"#;\n'
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a string direct-case decoy replacing its active test function' mut_quirk_ledger_direct_case_string_decoy

mut_quirk_ledger_direct_case_cfg_disabled() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("cfg-disabled direct-case mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'''\n#[cfg(any())]
#[test]
fn {name}() {{
    let quirk = "q-restore-header-parser-0128";
    assert!(true, "{{}}", quirk);
}}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a cfg-disabled direct case replacing its active test function' mut_quirk_ledger_direct_case_cfg_disabled

mut_quirk_ledger_direct_case_cfg_attr_disabled() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("cfg_attr-disabled direct-case mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'''\n#[cfg_attr(all(), cfg(any()))]
#[test]
fn {name}() {{
    let quirk = "q-restore-header-parser-0128";
    assert!(true, "{{}}", quirk);
}}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a cfg_attr-disabled direct case replacing its active test function' mut_quirk_ledger_direct_case_cfg_attr_disabled

mut_quirk_ledger_direct_case_ignored() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("ignored direct-case mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'''\n#[test]
#[ignore]
fn {name}() {{
    let quirk = "q-restore-header-parser-0128";
    assert!(true, "{{}}", quirk);
}}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'an ignored direct case replacing its active test function' mut_quirk_ledger_direct_case_ignored

mut_quirk_ledger_direct_case_cfg_attr_ignored() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("cfg_attr-ignored direct-case mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'''\n#[test]
#[cfg_attr(all(), ignore)]
fn {name}() {{
    let quirk = "q-restore-header-parser-0128";
    assert!(true, "{{}}", quirk);
}}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a cfg_attr-ignored direct case replacing its active test function' mut_quirk_ledger_direct_case_cfg_attr_ignored

mut_quirk_ledger_direct_case_should_panic() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("should-panic direct-case mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'''\n#[test]
#[should_panic]
fn {name}() {{
    let quirk = "q-restore-header-parser-0128";
    panic!("{{}}", quirk);
}}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a should-panic direct case replacing its active test function' mut_quirk_ledger_direct_case_should_panic

mut_quirk_ledger_direct_case_inert_body_string() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
old_binding = '    let quirk = "q-restore-header-parser-0128";'
old_assertion = '        ::core::assert_eq!(parse_restore_status(&value), None, "{}: {value:?} must be refused", quirk);'
new_assertion = '        assert_eq!(parse_restore_status(&value), None, "{value:?} must be refused");'
if text.count(old_binding) != 1 or text.count(old_assertion) != 1:
    raise SystemExit("inert direct-case string mutation subject is not unique")
text = text.replace(old_binding, '    let _ = "q-restore-header-parser-0128";', 1)
text = text.replace(old_assertion, new_assertion, 1)
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'an inert in-body string replacing an assertion-bound backlink' mut_quirk_ledger_direct_case_inert_body_string

mut_quirk_ledger_direct_case_ordinary_function() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
old_binding = '    let quirk = "q-restore-header-parser-0128";'
new_binding = '''    let quirk = "q-restore-header-parser-0128";
    fn assert_eq(_marker: &str) {}
    assert_eq(quirk);'''
old_assertion = '        ::core::assert_eq!(parse_restore_status(&value), None, "{}: {value:?} must be refused", quirk);'
new_assertion = '        assert_eq!(parse_restore_status(&value), None, "{value:?} must be refused");'
if text.count(old_binding) != 1 or text.count(old_assertion) != 1:
    raise SystemExit("ordinary-function direct-case mutation subject is not unique")
text = text.replace(old_binding, new_binding, 1)
text = text.replace(old_assertion, new_assertion, 1)
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'an ordinary function call replacing an assertion-macro backlink' mut_quirk_ledger_direct_case_ordinary_function

mut_quirk_ledger_direct_case_shadowed_macro() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
old_binding = '    let quirk = "q-restore-header-parser-0128";'
new_binding = '''    let quirk = "q-restore-header-parser-0128";
    macro_rules! assert_eq {
        ($($token:tt)*) => {};
    }'''
old_assertion = '        ::core::assert_eq!(parse_restore_status(&value), None, "{}: {value:?} must be refused", quirk);'
new_assertion = '        assert_eq!(parse_restore_status(&value), None, "{}: {value:?} must be refused", quirk);'
if text.count(old_binding) != 1 or text.count(old_assertion) != 1:
    raise SystemExit("shadowed-macro direct-case mutation subject is not unique")
text = text.replace(old_binding, new_binding, 1)
text = text.replace(old_assertion, new_assertion, 1)
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a local no-op macro replacing an absolute assertion backlink' mut_quirk_ledger_direct_case_shadowed_macro

mut_quirk_ledger_forward_backlink() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("conformance/cases/select-restore/c-select-restore-0019.toml")
text = path.read_text()
old = 'quirks = ["q-restore-header-absence-0127"]'
if old not in text:
    raise SystemExit("forward-backlink mutation subject is missing")
path.write_text(text.replace(old, 'quirks = []', 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a source-to-case backlink being removed' mut_quirk_ledger_forward_backlink

mut_quirk_ledger_reverse_backlink() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("conformance/cases/select-restore/c-select-restore-0040.toml")
text = path.read_text()
old = 'quirks = ["q-restore-select-members-0131"]'
new = 'quirks = ["q-restore-header-absence-0127", "q-restore-select-members-0131"]'
if old not in text:
    raise SystemExit("reverse-backlink mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a case naming a typed source without the reverse source backlink' mut_quirk_ledger_reverse_backlink

mut_quirk_ledger_spec_id_set() {
    mv spec/quirks/q-empty-0002.toml spec/quirks/q-empty-0002.missing
}
expect_fail check_quirk_ledger.sh \
    'one generated protected ID disappearing from the 95/160 typed set' mut_quirk_ledger_spec_id_set

mut_quirk_ledger_signature_host_consumer() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/sig/src/canonical.rs")
text = path.read_text()
old = "if SIGNATURE_CANONICAL_HOST_RAW {"
if text.count(old) != 1:
    raise SystemExit("signature host consumer mutation subject is not unique")
path.write_text(text.replace(old, "if true {", 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'the canonical-host contract losing its production consumer' mut_quirk_ledger_signature_host_consumer

mut_quirk_ledger_signature_path_consumer() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/sig/src/canonical.rs")
text = path.read_text()
old = "self.is_single() || !SIGNATURE_RAW_PATH_FALLBACK"
if text.count(old) != 1:
    raise SystemExit("signature path consumer mutation subject is not unique")
path.write_text(text.replace(old, "self.is_single() || false", 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'the raw-path contract losing its production consumer' mut_quirk_ledger_signature_path_consumer

mut_quirk_ledger_signature_payload_consumer() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/sig/src/mode.rs")
text = path.read_text()
old = "Self::Base64Sha256(digest) if SIGNATURE_PAYLOAD_TOKEN_VERBATIM =>"
if text.count(old) != 1:
    raise SystemExit("signature payload consumer mutation subject is not unique")
path.write_text(text.replace(old, "Self::Base64Sha256(digest) if true =>", 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'the payload-token contract losing its production consumer' mut_quirk_ledger_signature_payload_consumer

mut_quirk_ledger_sigv2_mutable_contract_consumer() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/sig/src/sig_v2/string_to_sign.rs")
text = path.read_text()
old = "included_query: SIGV2_INCLUDED_QUERY,"
if text.count(old) != 1:
    raise SystemExit("SigV2 included-query consumer mutation subject is not unique")
path.write_text(text.replace(old, "included_query: true,", 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'the SigV2 mutable contract losing its production consumer' mut_quirk_ledger_sigv2_mutable_contract_consumer

mut_quirk_ledger_sigv2_expires_consumer() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/sig/src/sig_v2/mod.rs")
text = path.read_text()
old = "if !SIGV2_EXPIRES_ABSOLUTE {"
if text.count(old) != 1:
    raise SystemExit("SigV2 absolute-expiry consumer mutation subject is not unique")
path.write_text(text.replace(old, "if false {", 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'the SigV2 absolute-expiry contract losing its production consumer' mut_quirk_ledger_sigv2_expires_consumer

mut_quirk_ledger_sigv2_query_consumer() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/sig/src/sig_v2/string_to_sign.rs")
text = path.read_text()
old = "query_not_covered: SIGV2_QUERY_NOT_COVERED,"
if text.count(old) != 1:
    raise SystemExit("SigV2 uncovered-query consumer mutation subject is not unique")
path.write_text(text.replace(old, "query_not_covered: true,", 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'the SigV2 uncovered-query contract losing its production consumer' mut_quirk_ledger_sigv2_query_consumer

if [[ $((cases - quirk_ledger_cases_before)) -ne 30 ]]; then
    fail_msg 'check_quirk_ledger.sh mutation census is not exactly 30 cases'
fi

unset GATEWAY_QUIRK_LEDGER_PARSE_CACHE
rm -f "$QUIRK_LEDGER_PARSE_CACHE"
QUIRK_LEDGER_PARSE_CACHE=""

fi

if [[ "$QUIRK_LEDGER_ONLY" == 0 && "$DTO_COMPILER_ONLY" == 0 && "$BUILD_GUARDS_ONLY" == 0 && "$ERROR_STATUS_ONLY" == 0 ]]; then

mut_dto_field_count_decreased() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("generated/dto/field_counts.txt")
lines = path.read_text().splitlines()
name, count = lines[0].split()
lines[0] = f"{name} {int(count) - 1}"
path.write_text("\n".join(lines) + "\n")
PYEOF
}
expect_fail check_dto_fields.sh \
    'a generated dto losing one public field' mut_dto_field_count_decreased

mut_dto_field_count_input_missing() {
    rm -f generated/dto/field_counts.txt
}
expect_fail check_dto_fields.sh \
    'the required dto field-count input being absent' mut_dto_field_count_input_missing

mut_dto_field_count_decreased_before_an_unrelated_commit() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("generated/dto/field_counts.txt")
lines = path.read_text().splitlines()
name, count = lines[0].split()
lines[0] = f"{name} {int(count) - 1}"
path.write_text("\n".join(lines) + "\n")
PYEOF
    git add generated/dto/field_counts.txt
    git -c user.name=t -c user.email=t@t commit -qm 'decrease dto field count'
    git -c user.name=t -c user.email=t@t commit --allow-empty -qm 'unrelated follow-up'
}
expect_fail_with_diagnostic check_dto_fields.sh \
    'a dto field removed in the penultimate branch commit' \
    'lost public fields' mut_dto_field_count_decreased_before_an_unrelated_commit

mut_dto_field_base_ref_missing() {
    git update-ref -d refs/remotes/origin/main
}
expect_fail_with_diagnostic check_dto_fields.sh \
    'the branch merge-base reference being unavailable' \
    'required base is unavailable: origin/main' mut_dto_field_base_ref_missing

fi

if [[ "$DTO_COMPILER_ONLY" == 1 ]]; then

mut_e0639_non_exhaustive_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/types/tests/semver_policy.rs")
text = path.read_text()
needle = "#[non_exhaustive]\n#[derive(Default)]"
if text.count(needle) != 1:
    raise SystemExit("expected exactly one non-exhaustive compiler probe")
path.write_text(text.replace(needle, "#[derive(Default)]", 1))
PYEOF
}
expect_rustc_test_fail_with_diagnostic crates/types/tests/semver_policy.rs \
    c_dto_n002_non_exhaustive_blocks_fru_across_a_crate_boundary \
    'non-exhaustive FRU unexpectedly compiled' mut_e0639_non_exhaustive_removed

mut_req_input_box_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/handler.rs")
text = path.read_text()
replacements = (
    ("    input: Box<O::Input>,", "    input: O::Input,"),
    ("            input: Box::new(input),", "            input,"),
    ("        *self.input", "        self.input"),
)
for old, new in replacements:
    if old not in text:
        raise SystemExit(f"boxed request mutation subject is missing: {old}")
    text = text.replace(old, new)
path.write_text(text)
PYEOF
}
expect_cargo_test_fail_with_diagnostic rustfs-gateway-core integration \
    dto_cold_split::c_dto_n011_req_put_object_has_the_boxed_snapshot_and_stays_within_the_ceiling \
    'evaluation panicked: assertion failed: size_of::<Req<PutObject>>() == 104' mut_req_input_box_removed

fi

if [[ "$BUILD_GUARDS_ONLY" == 1 ]]; then

mut_operation_spec_builder_bypassed_by_return_literal() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/registry/reject.rs")
path.write_text(path.read_text() + '''

fn review_mutation_returns_literal() -> OperationSpec {
    OperationSpec
    {
        name: "review:Mutation",
        success_status: 200,
        required_params: &[],
        not_configured_error: None,
        auth: None,
    }
}
''')
PYEOF
}
expect_fail_and_missing_cargo check_operation_spec_builder.sh \
    'a function returning a multiline OperationSpec literal' mut_operation_spec_builder_bypassed_by_return_literal

mut_operation_spec_builder_bypassed_by_grouped_use_rename() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/registry/reject.rs")
path.write_text(path.read_text() + '''

use crate::registry::{OperationSpec as ReviewRenamedSpec};

fn review_mutation_returns_renamed_literal() -> ReviewRenamedSpec {
    ReviewRenamedSpec {
        name: "review:RenamedMutation",
        success_status: 200,
        required_params: &[],
        not_configured_error: None,
        auth: None,
    }
}
''')
PYEOF
}
expect_fail check_operation_spec_builder.sh \
    'a grouped use rename hiding an OperationSpec literal' mut_operation_spec_builder_bypassed_by_grouped_use_rename

mut_operation_spec_builder_bypassed_by_chained_type_alias() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/registry/reject.rs")
path.write_text(path.read_text() + '''

type ReviewSpecAlias = OperationSpec;
type ReviewChainedSpecAlias = ReviewSpecAlias;

fn review_mutation_returns_chained_alias_literal() -> ReviewChainedSpecAlias {
    ReviewChainedSpecAlias {
        name: "review:AliasMutation",
        success_status: 200,
        required_params: &[],
        not_configured_error: None,
        auth: None,
    }
}
''')
PYEOF
}
expect_fail check_operation_spec_builder.sh \
    'a chained type alias hiding an OperationSpec literal' mut_operation_spec_builder_bypassed_by_chained_type_alias

mut_operation_spec_builder_bypassed_by_namespace_alias() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/registry/reject.rs")
path.write_text(path.read_text() + '''

use crate::registry as ReviewRegistry;

fn review_mutation_returns_namespace_alias_literal() -> ReviewRegistry::OperationSpec {
    ReviewRegistry::OperationSpec {
        name: "review:NamespaceMutation",
        success_status: 200,
        required_params: &[],
        not_configured_error: None,
        auth: None,
    }
}
''')
PYEOF
}
expect_fail check_operation_spec_builder.sh \
    'a namespace alias hiding an OperationSpec literal' mut_operation_spec_builder_bypassed_by_namespace_alias

mut_operation_spec_builder_bypassed_by_chained_grouped_namespace_alias() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/registry/reject.rs")
path.write_text(path.read_text() + '''

use crate::{registry as ReviewGroupedRegistry};
use ReviewGroupedRegistry as ReviewChainedRegistry;

fn review_mutation_returns_chained_namespace_literal() -> ReviewChainedRegistry::OperationSpec {
    ReviewChainedRegistry::OperationSpec {
        name: "review:ChainedNamespaceMutation",
        success_status: 200,
        required_params: &[],
        not_configured_error: None,
        auth: None,
    }
}
''')
PYEOF
}
expect_fail check_operation_spec_builder.sh \
    'a grouped and chained namespace alias hiding an OperationSpec literal' \
    mut_operation_spec_builder_bypassed_by_chained_grouped_namespace_alias

# gateway#242: a standard operation that names its success status and unconfigured code by hand is
# a second authority for two values `model/overlays/**` already declares. The generated copy was the
# one nothing read, so the overlay could be flipped without changing a served byte.
mut_operation_spec_builder_restated_in_an_operation_file() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/ops/create_bucket.rs")
path.write_text(
    path.read_text().replace(
        'OperationSpec::standard("CreateBucket")',
        'OperationSpec::builder("CreateBucket", 200, None)',
    )
)
PYEOF
}
expect_fail check_operation_spec_builder.sh \
    'a standard operation restating its IR facts through the builder' \
    mut_operation_spec_builder_restated_in_an_operation_file

# The other direction: the builder is still the only constructor a dialect's vendor operation has,
# and a rule that refused it everywhere would be a rule nobody could satisfy.
mut_operation_spec_builder_used_outside_the_operation_directory() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/dialect/mod.rs")
path.write_text(
    path.read_text()
    + '''

#[cfg(test)]
fn review_vendor_specification() -> crate::registry::OperationSpec {
    crate::registry::OperationSpec::builder("review:Mutation", 200, None)
}
'''
)
PYEOF
}
expect_guard_pass check_operation_spec_builder.sh \
    'a vendor operation outside crates/core/src/ops using the builder' \
    mut_operation_spec_builder_used_outside_the_operation_directory

fi

# The error-status block is deliberately not the last block in this file, and
# check_guard_suite_tail_reachable.sh keeps it that way. Every other mode skips it, so while it was
# last, a case written at the end of the suite ran only in the `error status self-test` job and
# never in the default run: nine such cases had collected in it, none of them about an error
# status, and they are re-homed at the end of the default block below.
#
# Moving it costs no ordinal anywhere. A case ordinal is assigned by `guard_case_owned` from the
# running count of case sites the run has reached, so it depends on the order of the sites a *mode*
# executes and on nothing else. A block that mode skips contributes no site wherever it sits, and
# the error-status mode enters no other block in this file, so every mode sees the same sites in
# the same order after the move as before it. The per-group coverage proof is a statement about one
# run against itself, so it neither notices nor could have noticed.
if [[ "$ERROR_STATUS_ONLY" == 1 ]]; then

# -----------------------------------------------------------------------------
# check_error_status_total.sh — rustfs/backlog#1694
#
# The guard replaces a fallback that could not fail: a code with no row used to take a silent 400.
# Each rule is mutated separately, because one case would leave five of them as prose.
#
# Its own parallel runner, like the quirk-ledger, DTO-compiler and build-backed splits: the shared
# mutation suite is already at its eight-minute ceiling on `main` before these cases exist, and a
# case that is killed by a neighbour's budget produces no evidence at all. None of these mutations
# runs codegen or Cargo, so the split costs one runner and about a minute.
# -----------------------------------------------------------------------------

printf 'Positive control (check_error_status_total.sh must pass on the current tree)\n'
# The ordinal gate is what the group's coverage proof counts, so it is owed here exactly as it is
# owed by `expect_fail`. A mode-scoped run is single-process, so it always owns the case — but a
# site that skipped the gate would be indistinguishable from a duplicate to the proof.
error_status_positive_control() {
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    if "${SCRIPT_DIR}/check_error_status_total.sh" >/dev/null 2>&1; then
        pass_msg 'check_error_status_total.sh'
    else
        fail_msg 'check_error_status_total.sh fails on the current tree'
    fi
}
error_status_positive_control

printf '\nNegative cases (the error-status guard must fail)\n'

mut_error_status_declared_code_has_no_row() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("generated/error_codes.rs")
text = path.read_text()
old = 'pub static ERROR_CODE_OPERATIONS: &[(&str, &[&str])] = &[\n'
if old not in text:
    raise SystemExit("error-code index mutation subject is missing")
path.write_text(text.replace(old, old + '    ("CodeNobodyGaveAStatus", &["GetObject"]),\n', 1))
PYEOF
}
expect_fail check_error_status_total.sh \
    'an operation declaring a code the status authority does not map' \
    mut_error_status_declared_code_has_no_row \
    'CodeNobodyGaveAStatus'

mut_error_status_missing_error_has_no_row() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("spec/operations/PutObject.toml")
text = path.read_text()
old = 'missing_error = "MissingContentLength"'
if old not in text:
    raise SystemExit("missing_error mutation subject is missing")
path.write_text(text.replace(old, 'missing_error = "CodecCodeWithNoStatus"', 1))
PYEOF
}
expect_fail check_error_status_total.sh \
    'a codec raising a missing-member code with no status row' \
    mut_error_status_missing_error_has_no_row \
    'CodecCodeWithNoStatus'

mut_error_status_unflagged_5xx() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/error-status.toml")
text = path.read_text()
old = 'name = "InvalidArgument"\nconstant = "INVALID_ARGUMENT"\nstatus = 400'
if old not in text:
    raise SystemExit("5xx allowlist mutation subject is missing")
path.write_text(text.replace(old, 'name = "InvalidArgument"\nconstant = "INVALID_ARGUMENT"\nstatus = 500', 1))
PYEOF
}
expect_fail check_error_status_total.sh \
    'a client error typed into the 5xx band without joining the allowlist' \
    mut_error_status_unflagged_5xx \
    'server_fault'

mut_error_status_server_fault_on_a_client_error() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/error-status.toml")
text = path.read_text()
old = 'name = "InvalidArgument"\nconstant = "INVALID_ARGUMENT"\nstatus = 400'
if old not in text:
    raise SystemExit("server_fault mutation subject is missing")
path.write_text(text.replace(old, old + '\nserver_fault = true', 1))
PYEOF
}
expect_fail check_error_status_total.sh \
    'a server-fault flag outliving the 5xx status it described' \
    mut_error_status_server_fault_on_a_client_error \
    'server_fault'

mut_error_status_generated_table_edited() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("generated/error_status.rs")
text = path.read_text()
old = '    ("NoSuchKey", StatusCode::NOT_FOUND),'
if old not in text:
    raise SystemExit("generated status mutation subject is missing")
path.write_text(text.replace(old, '    ("NoSuchKey", StatusCode::FORBIDDEN),', 1))
PYEOF
}
expect_fail check_error_status_total.sh \
    'the generated table answering a status the authority does not hold' \
    mut_error_status_generated_table_edited \
    'disagree about `NoSuchKey`'

mut_error_status_custom_loses_its_status() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/types/src/scalar/error_code.rs")
text = path.read_text()
old = 'pub fn custom(code: impl Into<Cow<\'static, str>>, status: StatusCode) -> Self {'
if old not in text:
    raise SystemExit("custom-signature mutation subject is missing")
path.write_text(text.replace(old, 'pub fn custom(code: impl Into<Cow<\'static, str>>) -> Self {', 1))
PYEOF
}
expect_fail check_error_status_total.sh \
    'ErrorCode::custom going back to inventing a status for its caller' \
    mut_error_status_custom_loses_its_status \
    'name a status'

mut_error_status_second_hand_written_table() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/types/src/scalar/error_code.rs")
text = path.read_text()
old = 'use http::StatusCode;'
if old not in text:
    raise SystemExit("hand-written table mutation subject is missing")
new = old + '\n\nconst SECOND_OPINION: StatusCode = StatusCode::BAD_REQUEST;'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_error_status_total.sh \
    'a second hand-written status growing back beside the generated table' \
    mut_error_status_second_hand_written_table \
    'second hand-written answer'

mut_error_status_include_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/types/src/scalar/error_code.rs")
text = path.read_text()
old = 'include!("../../../../generated/error_status.rs");'
if old not in text:
    raise SystemExit("include mutation subject is missing")
path.write_text(text.replace(old, '// ' + old, 1))
PYEOF
}
expect_fail check_error_status_total.sh \
    'the types crate no longer reading the generated table at all' \
    mut_error_status_include_removed \
    'no longer includes the generated table'

mut_error_status_auth_code_undeclared() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/sig/src/verdict.rs")
text = path.read_text()
old = 'Self::RequestTimeTooSkewed => "RequestTimeTooSkewed",'
if old not in text:
    raise SystemExit("auth-code mutation subject is missing")
path.write_text(text.replace(old, 'Self::RequestTimeTooSkewed => "ClockIsWrongSomehow",', 1))
PYEOF
}
expect_fail check_error_status_total.sh \
    'an authentication refusal answering a code with no status row' \
    mut_error_status_auth_code_undeclared \
    'ClockIsWrongSomehow'

mut_error_status_stale_allowance() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("allowances/error-status-unreferenced.txt")
text = path.read_text()
path.write_text(text + "NoSuchKey|a row the tree reaches every day\n")
PYEOF
}
expect_fail check_error_status_total.sh \
    'the dead-code ledger excusing a row that is reached' \
    mut_error_status_stale_allowance \
    'still excuses'

mut_error_status_unlisted_dead_row() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("allowances/error-status-unreferenced.txt")
text = path.read_text()
old = "InvalidSOAPRequest|"
if old not in text:
    raise SystemExit("dead-row ledger mutation subject is missing")
kept = [line for line in text.splitlines(keepends=True) if not line.startswith(old)]
path.write_text("".join(kept))
PYEOF
}
expect_fail check_error_status_total.sh \
    'a row nothing reaches dropping off the dead-code ledger' \
    mut_error_status_unlisted_dead_row \
    'InvalidSOAPRequest'

mut_error_status_authority_removed() {
    python3 - <<'PYEOF'
import pathlib

pathlib.Path("model/overlays/error-status.toml").unlink()
PYEOF
}
expect_fail check_error_status_total.sh \
    'the authority file disappearing, which must fail rather than skip' \
    mut_error_status_authority_removed \
    'required input is missing'

# -- check_error_contract_ledger.sh ---------------------------------------------------------------
#
# The ledger maps the 24 acceptance ids of rustfs/backlog#1694 §7 to real assertions. It owes one
# death per mutation class its header names, plus one for each of the two evidence kinds it added
# over the object ledger: a Rust literal and a guard mutation. Written out rather than looped
# because each has to fail for its own diagnostic — a roll-call failure and an arithmetic failure
# read identically in a green summary, and the point of the split is that they are different
# mistakes.

mut_error_ledger_row_id_duplicated() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/check_error_contract_ledger.sh")
text = path.read_text()
old = "    'c-err-1013|negative|bound|"
new = "    'c-err-1011|negative|bound|"
if text.count(old) != 1:
    raise SystemExit("error ledger row mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
# Mutation 1: one mapping stops existing. The polarity arithmetic is deliberately left intact by
# renaming rather than deleting, so this can only be caught by the roll call.
expect_fail_self_mutation check_error_contract_ledger.sh \
    'a §7 acceptance id losing its mapping while the polarity totals still add up' \
    mut_error_ledger_row_id_duplicated

mut_error_ledger_row_polarity_flipped() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/check_error_contract_ledger.sh")
text = path.read_text()
old = "    'c-err-1013|negative|bound|"
new = "    'c-err-1013|positive|bound|"
if text.count(old) != 1:
    raise SystemExit("error ledger polarity mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
# Mutation 3: a refusal relabelled as a proof that something works.
expect_fail_self_mutation check_error_contract_ledger.sh \
    'a §7 refusal relabelled positive, moving the 9/15 split' \
    mut_error_ledger_row_polarity_flipped

mut_error_ledger_exact_message_weakened() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("conformance/cases/object/c-object-0007.toml")
text = path.read_text()
old = "<Message>The specified key does not exist.</Message>"
new = "<Message>The key was not found.</Message>"
if text.count(old) != 1:
    raise SystemExit("NoSuchKey message mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
# The rustfs/gateway#189 regression net itself: the exact AWS bytes are what caught the reworded
# not-found message, and until this ledger nothing named them.
expect_fail check_error_contract_ledger.sh \
    'the exact NoSuchKey message bytes reworded out of the case that pins them' \
    mut_error_ledger_exact_message_weakened \
    'does not contain'

mut_error_ledger_compile_fail_fixture_gutted() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/tests/compile_fail/c_err_1010_custom_code_without_a_status.rs")
text = path.read_text()
old = 'ErrorCode::custom("Foo")'
if text.count(old) != 1:
    raise SystemExit("custom-arity fixture mutation subject is not unique")
path.write_text(text.replace(old, 'ErrorCode::custom("Foo", StatusCode::BAD_REQUEST)', 1))
PYEOF
}
# A compile-fail fixture that compiles is a fixture that proves nothing, and trybuild would say so
# only when the harness runs. The ledger says so from the evidence side.
expect_fail check_error_contract_ledger.sh \
    'the one-argument call disappearing from the fixture that must not compile' \
    mut_error_ledger_compile_fail_fixture_gutted \
    'no longer contains'

mut_error_ledger_mutation_never_replayed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = "    mut_error_status_unflagged_5xx \\\n"
if text.count(old) != 1:
    raise SystemExit("5xx mutation replay subject is not unique")
path.write_text(text.replace(old, "    mut_error_status_server_fault_on_a_client_error \\\n", 1))
PYEOF
}
# The control on the control: a mutation function that no `expect_fail` line runs is a negative
# case that never executes, which reads exactly like one that passed.
expect_fail check_error_contract_ledger.sh \
    'a 5xx-allowlist mutation left defined but no longer replayed by any expect_fail line' \
    mut_error_ledger_mutation_never_replayed \
    'no expect_fail line runs it'

fi

if [[ "$QUIRK_LEDGER_ONLY" == 0 && "$DTO_COMPILER_ONLY" == 0 && "$BUILD_GUARDS_ONLY" == 0 && "$ERROR_STATUS_ONLY" == 0 ]]; then

mut_handler_context_entry_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/tests/static_dispatch.rs")
text = path.read_text()
subject = "    async fn call_with_context(\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique Handler context-entry mutation subject")
path.write_text(text.replace(subject, "    async fn call_without_context(\n", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_context_migration.sh \
    'a reviewed Handler implementation losing its context-aware entry' \
    'crates/core/tests/static_dispatch.rs Handler impl 1 is not on the reviewed two-entry migration bridge' \
    mut_handler_context_entry_removed

mut_handler_context_entry_replaced_by_decoys() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/tests/static_dispatch.rs")
text = path.read_text()
subject = "    async fn call_with_context(\n"
replacement = '''    const CONTEXT_ENTRY_DECOY: &'static str = "fn call_with_context(request)";
    // fn call_with_context(request) is not an active method.
    async fn call_without_context(
'''
if text.count(subject) != 1:
    raise SystemExit("missing unique Handler context-decoy mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_context_migration.sh \
    'comments and strings replacing a reviewed Handler context-aware entry' \
    'crates/core/tests/static_dispatch.rs Handler impl 1 is not on the reviewed two-entry migration bridge' \
    mut_handler_context_entry_replaced_by_decoys

mut_handler_context_source_dropped_before_call() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/tests/static_dispatch.rs")
text = path.read_text()
subject = '''        let (_source, context) = rustfs_gateway_core::HandlerCancellationSource::pair();
        self.call_with_context(request, context).await
'''
replacement = '''        self.call_with_context(
            request,
            rustfs_gateway_core::HandlerCancellationSource::pair().1,
        )
        .await
'''
if text.count(subject) != 1:
    raise SystemExit("missing unique Handler context-source mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_context_migration.sh \
    'the compatibility Handler entry dropping its context source before delegation' \
    'crates/core/tests/static_dispatch.rs Handler impl 1 drops or bypasses the migration context source' \
    mut_handler_context_source_dropped_before_call

mut_facade_handler_context_entry_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/handler_panic.rs")
text = path.read_text()
subject = "    async fn call_with_context("
if text.count(subject) != 1:
    raise SystemExit("missing unique facade Handler context-entry mutation subject")
path.write_text(text.replace(subject, "    async fn call_without_context(", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_context_migration.sh \
    'a facade Handler losing its explicit context-aware entry' \
    'crates/gateway/tests/handler_panic.rs Handler impl 1 is not on the reviewed facade migration bridge' \
    mut_facade_handler_context_entry_removed

mut_facade_handler_context_body_drifted() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/examples/custom_authorizer.rs")
text = path.read_text()
marker = "    async fn call_with_context("
prefix, found, suffix = text.partition(marker)
subject = "        Ok(Resp::new(PingOutput))\n"
if not found or suffix.count(subject) != 1:
    raise SystemExit("missing unique facade Handler body-drift mutation subject")
suffix = suffix.replace(subject, '        let _drift = "context only";\n' + subject, 1)
path.write_text(prefix + found + suffix)
PYEOF
}
expect_fail_with_diagnostic check_handler_context_migration.sh \
    'a facade Handler context body drifting from its legacy body' \
    'crates/gateway/examples/custom_authorizer.rs Handler impl 1 has diverged legacy and context bodies' \
    mut_facade_handler_context_body_drifted

mut_layered_backend_context_forwarding_bypassed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/dispatch.rs")
text = path.read_text()
subject = "            None => self.backend.call_with_context(request, context).await,\n"
replacement = "            None => self.backend.call(request).await,\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique layered backend context-forwarding mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_context_migration.sh \
    'the layered backend bypassing context forwarding on its direct path' \
    'crates/gateway/src/dispatch.rs Handler impl 1 does not preserve layered context forwarding' \
    mut_layered_backend_context_forwarding_bypassed

mut_context_aware_backend_deadline_observation_bypassed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/dispatch.rs")
text = path.read_text()
subject = "            assert_eq!(context.cancelled().await, rustfs_gateway_core::HandlerCancellation::Deadline);\n"
replacement = "            assert_eq!(context.cancelled().await, rustfs_gateway_core::HandlerCancellation::Signal);\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique deadline-observation mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_context_migration.sh \
    'the context-aware backend no longer observing deadline cancellation' \
    'crates/gateway/src/dispatch.rs Handler impl 2 does not observe deadline cancellation' \
    mut_context_aware_backend_deadline_observation_bypassed

mut_monomorphic_context_cancellation_observation_bypassed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/monomorphic.rs")
text = path.read_text()
subject = "        assert!(context.cancellation_reason().is_none());\n"
replacement = "        assert!(context.cancellation_reason().is_some());\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique monomorphic context-observation mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_context_migration.sh \
    'the monomorphic handler no longer inspecting its context cancellation state' \
    'crates/gateway/tests/monomorphic.rs Handler impl 1 does not inspect its context cancellation state' \
    mut_monomorphic_context_cancellation_observation_bypassed

mut_conformance_handler_context_entry_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/conformance/src/fixture/handlers_object.rs")
text = path.read_text()
subject = '''    fn call_with_context(
        &self,
        request: Req<dto::GetObject>,
'''
replacement = '''    fn call_without_context(
        &self,
        request: Req<dto::GetObject>,
'''
if text.count(subject) != 1:
    raise SystemExit("missing unique conformance Handler context-entry mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_context_migration.sh \
    'a conformance fixture Handler losing its explicit context-aware entry' \
    'crates/conformance/src/fixture/handlers_object.rs Handler impl 1 is not on the reviewed facade migration bridge' \
    mut_conformance_handler_context_entry_removed

mut_macro_handler_context_entry_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/macros/src/expand.rs")
text = path.read_text()
subject = "                fn call_with_context(\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique macro Handler context-entry mutation subject")
path.write_text(text.replace(subject, "                fn call_without_context(\n", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_context_migration.sh \
    'the Handler macro template losing its explicit context-aware entry' \
    'crates/macros/src/expand.rs Handler impl 1 is not on the reviewed facade migration bridge' \
    mut_macro_handler_context_entry_removed

mut_manual_equivalence_handler_context_entry_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/macros/tests/equivalence.rs")
text = path.read_text()
subject = '''    fn call_with_context(
        &self,
        request: Req<PutObject>,
'''
replacement = '''    fn call_without_context(
        &self,
        request: Req<PutObject>,
'''
if text.count(subject) != 1:
    raise SystemExit("missing unique manual equivalence context-entry mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_context_migration.sh \
    'a hand-written macro-equivalence Handler losing its context-aware entry' \
    'crates/macros/tests/equivalence.rs Handler impl 1 is not on the reviewed facade migration bridge' \
    mut_manual_equivalence_handler_context_entry_removed

mut_handler_deadline_class_mapping_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/registry/mod.rs")
text = path.read_text()
subject = '        "CompleteMultipartUpload" => Some(HandlerDeadlineClass::Extended),\n'
if text.count(subject) != 1:
    raise SystemExit("missing unique handler deadline mapping-removal subject")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'a standard operation losing its explicit handler deadline class' \
    'deadline-class authority differs from standard operations' \
    mut_handler_deadline_class_mapping_removed

mut_handler_deadline_extended_class_weakened() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/registry/mod.rs")
text = path.read_text()
subject = '        "CompleteMultipartUpload" => Some(HandlerDeadlineClass::Extended),\n'
replacement = '        "CompleteMultipartUpload" => Some(HandlerDeadlineClass::Standard),\n'
if text.count(subject) != 1:
    raise SystemExit("missing unique extended handler deadline mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'CompleteMultipartUpload being reduced to the ordinary handler deadline' \
    'CompleteMultipartUpload must use the Extended handler deadline' \
    mut_handler_deadline_extended_class_weakened

mut_handler_deadline_unknown_class_defaulted() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/registry/mod.rs")
text = path.read_text()
subject = "        _ => None,\n"
replacement = "        _ => Some(HandlerDeadlineClass::Standard),\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique unknown handler deadline mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'unknown operations gaining an implicit handler deadline class' \
    'deadline-class authority has an implicit wildcard class' \
    mut_handler_deadline_unknown_class_defaulted

mut_handler_deadline_registration_check_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/registry/reject.rs")
text = path.read_text()
subject = '''    if spec.deadline_class().is_none() {
        return Err(RegistryError::MissingHandlerDeadlineClass { name });
    }
'''
if text.count(subject) != 1:
    raise SystemExit("missing unique handler deadline registration mutation subject")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'shared registration no longer failing closed without a handler deadline class' \
    'shared registration does not fail closed without a handler deadline class' \
    mut_handler_deadline_registration_check_removed

mut_handler_deadline_reviewed_third_party_class_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/examples/dialect_overlay.rs")
text = path.read_text()
subject = "    .handler_deadline_class(HandlerDeadlineClass::Standard)\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique reviewed third-party deadline removal subject")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'a reviewed third-party operation losing its explicit handler deadline class' \
    'unclassified OperationSpec builder' \
    mut_handler_deadline_reviewed_third_party_class_removed

mut_handler_deadline_reviewed_third_party_class_extended() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/authz/mod.rs")
text = path.read_text()
subject = "        .handler_deadline_class(HandlerDeadlineClass::Standard)\n"
replacement = "        .handler_deadline_class(HandlerDeadlineClass::Extended)\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique reviewed third-party deadline class subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'a reviewed third-party operation gaining the extended handler deadline class' \
    'explicit OperationSpec builder does not use Standard' \
    mut_handler_deadline_reviewed_third_party_class_extended

mut_handler_deadline_second_batch_class_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/examples/custom_authorizer.rs")
text = path.read_text()
subject = "    .handler_deadline_class(HandlerDeadlineClass::Standard)\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique second-batch deadline removal subject")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'a second-batch third-party operation losing its explicit handler deadline class' \
    'unclassified OperationSpec builder' \
    mut_handler_deadline_second_batch_class_removed

mut_handler_deadline_second_batch_class_extended() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/cors_runtime.rs")
text = path.read_text()
subject = "    .handler_deadline_class(HandlerDeadlineClass::Standard)\n"
replacement = "    .handler_deadline_class(HandlerDeadlineClass::Extended)\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique second-batch deadline class subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'a second-batch third-party operation gaining the extended handler deadline class' \
    'explicit OperationSpec builder does not use Standard' \
    mut_handler_deadline_second_batch_class_extended

mut_handler_deadline_final_batch_class_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/registry/reject.rs")
text = path.read_text()
subject = "        .handler_deadline_class(HandlerDeadlineClass::Standard)\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique final-batch deadline removal subject")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'a final-batch operation losing its explicit handler deadline class' \
    'unclassified OperationSpec builder' \
    mut_handler_deadline_final_batch_class_removed

mut_handler_deadline_mixed_custom_class_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/tests/params_and_dispatch.rs")
text = path.read_text()
subject = "    .handler_deadline_class(HandlerDeadlineClass::Standard)\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique mixed custom deadline removal subject")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the mixed source losing its one explicit third-party handler deadline class' \
    'unclassified OperationSpec builder' \
    mut_handler_deadline_mixed_custom_class_removed

mut_handler_deadline_mixed_standard_override_added() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/tests/params_and_dispatch.rs")
text = path.read_text()
subject = '''static GET_OBJECT: OperationSpec = OperationSpec::builder("GetObject", 200, None)
    .required_params(&[])
'''
replacement = '''static GET_OBJECT: OperationSpec = OperationSpec::builder("GetObject", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
'''
if text.count(subject) != 1:
    raise SystemExit("missing unique mixed standard deadline override subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'a standard builder in the mixed source bypassing the central handler deadline authority' \
    'standard builder bypasses the central deadline authority' \
    mut_handler_deadline_mixed_standard_override_added

mut_handler_deadline_unclassified_source_added() {
    python3 - <<'PYEOF'
from pathlib import Path

Path("crates/core/tests/deadline_unclassified_probe.rs").write_text(
    'use rustfs_gateway_core::OperationSpec;\n'
    'static SPEC: OperationSpec = OperationSpec::builder("probe:Unclassified", 200, None).build();\n'
)
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'an unclassified builder appearing outside the reviewed source list' \
    'unclassified OperationSpec builder' \
    mut_handler_deadline_unclassified_source_added

mut_handler_deadline_classified_source_added() {
    python3 - <<'PYEOF'
from pathlib import Path

Path("crates/core/tests/deadline_classified_probe.rs").write_text(
    'use rustfs_gateway_core::{HandlerDeadlineClass, OperationSpec};\n'
    'static SPEC: OperationSpec = OperationSpec::builder("probe:Classified", 200, None)\n'
    '    .handler_deadline_class(HandlerDeadlineClass::Standard)\n'
    '    .build();\n'
)
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'a classified builder appearing without updating the repository census' \
    'repository builder census drifted' \
    mut_handler_deadline_classified_source_added

mut_handler_deadline_builder_alias_added() {
    python3 - <<'PYEOF'
from pathlib import Path

Path("crates/core/tests/deadline_alias_probe.rs").write_text(
    'use rustfs_gateway_core::{HandlerDeadlineClass, OperationSpec as Spec};\n'
    'static SPEC: Spec = Spec::builder("probe:Alias", 200, None)\n'
    '    .handler_deadline_class(HandlerDeadlineClass::Standard)\n'
    '    .build();\n'
)
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'an OperationSpec alias hiding a builder from the repository census' \
    'OperationSpec aliases are forbidden from the deadline-class census' \
    mut_handler_deadline_builder_alias_added

mut_handler_deadline_standard_default_drifted() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/config.rs")
text = path.read_text()
subject = "pub const DEFAULT_STANDARD_HANDLER_DEADLINE: Duration = Duration::from_secs(30);\n"
replacement = "pub const DEFAULT_STANDARD_HANDLER_DEADLINE: Duration = Duration::from_secs(31);\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique standard handler deadline default mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the Standard handler deadline default drifting from thirty seconds' \
    'handler deadline defaults are not Standard=30s and Extended=15m' \
    mut_handler_deadline_standard_default_drifted

mut_handler_deadline_zero_validation_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/config.rs")
text = path.read_text()
subject = '''        if extended.is_zero() {
            return Err(HandlerDeadlineConfigError::ZeroExtended);
        }
'''
if text.count(subject) != 1:
    raise SystemExit("missing unique handler deadline zero-validation mutation subject")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the Extended handler deadline accepting zero as unlimited' \
    'handler deadline configuration does not reject both zero durations' \
    mut_handler_deadline_zero_validation_removed

mut_handler_deadline_duration_mapping_crossed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/config.rs")
text = path.read_text()
subject = "            HandlerDeadlineClass::Extended => self.extended,\n"
replacement = "            HandlerDeadlineClass::Extended => self.standard,\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique handler deadline duration-mapping mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the Extended handler class using the ordinary configured duration' \
    'Extended handler deadline is not mapped to its configured duration' \
    mut_handler_deadline_duration_mapping_crossed

mut_handler_deadline_class_facade_export_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/lib.rs")
text = path.read_text()
subject = "HandlerCancellation, HandlerContext, HandlerDeadlineClass, HandlerError,"
replacement = "HandlerCancellation, HandlerContext, HandlerError,"
if text.count(subject) != 1:
    raise SystemExit("missing unique handler deadline class facade-export mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the facade losing the closed handler deadline vocabulary' \
    'facade does not export HandlerDeadlineClass' \
    mut_handler_deadline_class_facade_export_removed

mut_handler_deadline_config_facade_export_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/lib.rs")
text = path.read_text()
# Anchored on the two names and not on the line they sit on: this re-export list is rewrapped by
# rustfmt whenever a name is added to it, and a subject carrying the line break silently stops
# matching, at which point this mutation aborts and the case it belongs to never runs at all.
subject = "DEFAULT_STANDARD_HANDLER_DEADLINE, HandlerDeadlineConfig,"
replacement = "DEFAULT_STANDARD_HANDLER_DEADLINE,"
if text.count(subject) != 1:
    raise SystemExit("missing unique handler deadline config facade-export mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the facade losing validated handler deadline configuration' \
    'facade does not export HandlerDeadlineConfig' \
    mut_handler_deadline_config_facade_export_removed

mut_handler_cleanup_grace_default_drifted() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/config.rs")
text = path.read_text()
subject = "const DEFAULT_HANDLER_CLEANUP_GRACE: Duration = Duration::from_secs(1);\n"
replacement = "const DEFAULT_HANDLER_CLEANUP_GRACE: Duration = Duration::from_secs(2);\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique handler cleanup grace default mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the handler cleanup grace default drifting from one second' \
    'handler cleanup grace default is not one second' \
    mut_handler_cleanup_grace_default_drifted

mut_handler_cleanup_grace_zero_validation_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/config.rs")
text = path.read_text()
subject = '''        if cleanup_grace.is_zero() {
            return None;
        }
'''
if text.count(subject) != 1:
    raise SystemExit("missing unique handler cleanup grace validation mutation subject")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the handler cleanup grace accepting zero as an immediate drop' \
    'handler cleanup grace is not validated and stored' \
    mut_handler_cleanup_grace_zero_validation_removed

mut_handler_deadline_snapshot_duration_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/dispatch.rs")
text = path.read_text()
subject = "            let deadline = request_config.config().handler_deadline(deadline_class);\n"
replacement = "            let deadline = std::time::Duration::from_secs(30);\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique handler deadline snapshot mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'dynamic dispatch hard-coding a deadline instead of consuming the request snapshot' \
    "dynamic dispatch does not consume one request snapshot's handler deadline configuration" \
    mut_handler_deadline_snapshot_duration_removed

mut_handler_request_cancellation_snapshot_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/dispatch.rs")
text = path.read_text()
subject = "            let request_cancellation = request_config.request_cancellation();\n"
replacement = "            let request_cancellation = None;\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique dynamic request-cancellation snapshot subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'dynamic dispatch dropping the request cancellation receiver' \
    "dynamic dispatch does not consume one request snapshot's handler deadline configuration" \
    mut_handler_request_cancellation_snapshot_removed

mut_handler_request_cancellation_extract_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
subject = "        let request_cancellation = request.extensions().get::<tokio::sync::watch::Receiver<bool>>().cloned();\n"
replacement = "        let request_cancellation = None;\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique request-cancellation extraction subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the service dropping the server request-cancellation signal' \
    'the service does not extract the server request-cancellation signal' \
    mut_handler_request_cancellation_extract_removed

mut_handler_request_cancellation_stage_dropped() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text()
subject = "            request_cancellation: self.request_cancellation,\n"
replacement = "            request_cancellation: None,\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique request-cancellation stage subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'a pipeline stage dropping request cancellation' \
    'request cancellation is not carried through the typed request snapshot' \
    mut_handler_request_cancellation_stage_dropped

mut_handler_request_cancellation_poll_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/request_deadline.rs")
text = path.read_text()
subject = "            return Poll::Ready(Err(HandlerCancellation::RequestAborted));\n"
replacement = "            return Poll::Pending;\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique request-cancellation poll subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the request-cancellation receiver no longer stopping the handler' \
    'handler deadline race is missing a required poll or cancellation signal' \
    mut_handler_request_cancellation_poll_removed

mut_handler_request_abort_cleanup_mapping_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/request_deadline.rs")
text = path.read_text()
subject = "        _ => HandlerCancellationOutcome::RequestAborted { cleanup_completed },\n"
replacement = "        _ => HandlerCancellationOutcome::Expired { cleanup_completed },\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique request-abort cleanup mapping subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'request abort cleanup being reported as a deadline' \
    'request cancellation does not report bounded cleanup completion' \
    mut_handler_request_abort_cleanup_mapping_removed

mut_handler_deadline_signal_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/request_deadline.rs")
text = path.read_text()
subject = "    cancellation.cancel(reason);\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique handler deadline signal mutation subject")
path.write_text(text.replace(subject, "", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'an expired handler deadline no longer signalling its cancellation token' \
    'handler deadline race is missing a required poll or cancellation signal' \
    mut_handler_deadline_signal_removed

mut_handler_late_deadline_result_accepted() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/request_deadline.rs")
text = path.read_text()
subject = "    cancellation.cancel(reason);\n"
replacement = subject + "    return HandlerCancellationOutcome::Completed(handler.await);\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique late handler result mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'a handler result completed after its deadline becoming the response' \
    'a handler result completed after its deadline can be committed' \
    mut_handler_late_deadline_result_accepted

mut_handler_cleanup_grace_race_reversed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/request_deadline.rs")
text = path.read_text()
subject = '''        if grace.as_mut().poll(context).is_ready() {
            return Poll::Ready(false);
        }
        if handler.as_mut().poll(context).is_ready() {
            return Poll::Ready(true);
        }
'''
replacement = '''        if handler.as_mut().poll(context).is_ready() {
            return Poll::Ready(true);
        }
        if grace.as_mut().poll(context).is_ready() {
            return Poll::Ready(false);
        }
'''
if text.count(subject) != 1:
    raise SystemExit("missing unique handler cleanup race mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'handler cleanup completion winning after its grace is already exhausted' \
    'handler cleanup completion wins an exhausted grace race' \
    mut_handler_cleanup_grace_race_reversed

mut_handler_cleanup_completion_mapping_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/dispatch.rs")
text = path.read_text()
subject = "handler deadline exceeded after cleanup completed"
replacement = "handler deadline exceeded before cleanup completed"
if text.count(subject) != 2:
    raise SystemExit("missing handler cleanup completion mapping and its test oracle")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'dynamic dispatch losing the observed cleanup-completed outcome' \
    'dynamic dispatch can commit a handler result completed after its deadline' \
    mut_handler_cleanup_completion_mapping_removed

mut_dynamic_request_abort_cleanup_mapping_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/dispatch.rs")
text = path.read_text()
subject = "request ended after handler cleanup completed"
replacement = "request ended before handler cleanup completed"
if text.count(subject) != 1:
    raise SystemExit("missing unique dynamic request-abort cleanup subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'dynamic dispatch losing the request-abort cleanup result' \
    'dynamic dispatch does not classify bounded request-abort cleanup' \
    mut_dynamic_request_abort_cleanup_mapping_removed

mut_monomorphic_static_handler_injection_bypassed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/static_dispatch.rs")
text = path.read_text()
subject = "invoke_handler(backend, authorized.into_request(sse, context), request_guard)"
replacement = "invoke_handler(backend, authorized.into_request(sse, context), ())"
if text.count(subject) != 1:
    raise SystemExit("missing unique static handler injection mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_monomorphic_dispatch.sh \
    'static dispatch dropping the request state before injected handler policy' \
    'static dispatch bypasses the injected handler policy after authorization' \
    mut_monomorphic_static_handler_injection_bypassed

mut_monomorphic_handler_policy_injection_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/monomorphic.rs")
text = path.read_text()
subject = "StaticOperation::<O>::dispatch_with_handler("
replacement = "StaticOperation::<O>::dispatch("
if text.count(subject) != 1:
    raise SystemExit("missing unique monomorphic handler injection mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_monomorphic_dispatch.sh \
    'monomorphic dispatch restoring the handler call without deadline policy' \
    'monomorphic dispatch does not use the sealed handler-policy injection point' \
    mut_monomorphic_handler_policy_injection_removed

mut_monomorphic_handler_deadline_class_hardcoded() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/monomorphic.rs")
text = path.read_text()
subject = "let Some(deadline_class) = O::spec().deadline_class()"
replacement = "let Some(deadline_class) = Some(rustfs_gateway_core::HandlerDeadlineClass::Standard)"
if text.count(subject) != 1:
    raise SystemExit("missing unique monomorphic deadline class mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_monomorphic_dispatch.sh \
    'monomorphic dispatch hard-coding the Standard deadline class' \
    "monomorphic dispatch does not consume one request snapshot's handler deadline configuration" \
    mut_monomorphic_handler_deadline_class_hardcoded

mut_monomorphic_handler_deadline_snapshot_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/monomorphic.rs")
text = path.read_text()
subject = "let deadline = request_config.handler_deadline(deadline_class);"
replacement = "let deadline = std::time::Duration::from_secs(30);"
if text.count(subject) != 1:
    raise SystemExit("missing unique monomorphic deadline snapshot mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_monomorphic_dispatch.sh \
    'monomorphic dispatch hard-coding a deadline instead of using the request snapshot' \
    "monomorphic dispatch does not consume one request snapshot's handler deadline configuration" \
    mut_monomorphic_handler_deadline_snapshot_removed

mut_monomorphic_handler_deadline_signal_detached() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/monomorphic.rs")
text = path.read_text()
subject = "                            deadline_cancellation,\n"
replacement = "                            HandlerCancellationSource::pair().0,\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique monomorphic deadline signal mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_monomorphic_dispatch.sh \
    'monomorphic dispatch signalling a token the handler cannot observe' \
    "monomorphic dispatch does not consume one request snapshot's handler deadline configuration" \
    mut_monomorphic_handler_deadline_signal_detached

mut_monomorphic_request_cancellation_dropped() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/monomorphic.rs")
text = path.read_text()
subject = "                        let request_cancellation = request_config.request_cancellation();\n"
replacement = "                        let request_cancellation = None;\n"
if text.count(subject) != 1:
    raise SystemExit("missing unique monomorphic request cancellation mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_monomorphic_dispatch.sh \
    'monomorphic dispatch dropping request cancellation' \
    "monomorphic dispatch does not consume one request snapshot's handler deadline configuration" \
    mut_monomorphic_request_cancellation_dropped

mut_monomorphic_request_abort_mapping_collapsed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/monomorphic.rs")
text = path.read_text()
subject = "HandlerCancellationOutcome::RequestAborted { cleanup_completed }"
replacement = "HandlerCancellationOutcome::Expired { cleanup_completed }"
if text.count(subject) != 1:
    raise SystemExit("missing unique monomorphic request abort mapping mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_monomorphic_dispatch.sh \
    'monomorphic dispatch collapsing request abort into deadline expiry' \
    "monomorphic dispatch does not consume one request snapshot's handler deadline configuration" \
    mut_monomorphic_request_abort_mapping_collapsed

mut_monomorphic_request_abort_cleanup_mapping_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/monomorphic.rs")
text = path.read_text()
subject = "request ended after handler cleanup completed"
replacement = "request ended before handler cleanup completed"
if text.count(subject) != 1:
    raise SystemExit("missing unique monomorphic request abort cleanup mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_monomorphic_dispatch.sh \
    'monomorphic dispatch losing request-abort cleanup completion' \
    'monomorphic dispatch does not suppress and classify late handler completion' \
    mut_monomorphic_request_abort_cleanup_mapping_removed

mut_monomorphic_handler_cleanup_mapping_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/monomorphic.rs")
text = path.read_text()
subject = "handler deadline exceeded after cleanup completed"
replacement = "handler deadline exceeded before cleanup completed"
if text.count(subject) != 1:
    raise SystemExit("missing unique monomorphic cleanup mapping mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_monomorphic_dispatch.sh \
    'monomorphic dispatch losing the observed cleanup-completed outcome' \
    'monomorphic dispatch does not suppress and classify late handler completion' \
    mut_monomorphic_handler_cleanup_mapping_removed

mut_dynamic_handler_deadline_report_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/dispatch.rs")
text = path.read_text()
subject = "_request_config.record_handler_deadline(false);"
if text.count(subject) != 1:
    raise SystemExit("missing unique dynamic deadline report mutation subject")
path.write_text(text.replace(subject, "_request_config.record_handler_deadline(true);", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'dynamic dispatch reporting an exhausted cleanup grace as acknowledged' \
    'dynamic dispatch does not record acknowledged handler cleanup' \
    mut_dynamic_handler_deadline_report_removed

mut_monomorphic_handler_deadline_report_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/monomorphic.rs")
text = path.read_text()
subject = "request_config.record_handler_deadline(false);"
if text.count(subject) != 1:
    raise SystemExit("missing unique monomorphic deadline report mutation subject")
path.write_text(text.replace(subject, "request_config.record_handler_deadline(true);", 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'monomorphic dispatch reporting an exhausted cleanup grace as acknowledged' \
    'monomorphic dispatch does not record acknowledged handler cleanup' \
    mut_monomorphic_handler_deadline_report_removed

mut_handler_deadline_report_slot_fails_open() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text()
subject = "_ => Some(HandlerDeadlineReport::Unacknowledged),"
replacement = "_ => None,"
if text.count(subject) != 1:
    raise SystemExit("missing unique deadline report fail-closed mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'an unknown handler deadline report state failing open' \
    'handler deadline report slot does not fail closed on unacknowledged cleanup' \
    mut_handler_deadline_report_slot_fails_open

mut_unacknowledged_handler_deadline_keeps_connection() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
subject = "handler_deadline == Some(HandlerDeadlineReport::Unacknowledged)"
replacement = "handler_deadline == Some(HandlerDeadlineReport::Acknowledged)"
if text.count(subject) != 1:
    raise SystemExit("missing unique unacknowledged deadline connection mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'an unacknowledged handler cancellation leaving the connection reusable' \
    'an unacknowledged handler cancellation does not close the response path' \
    mut_unacknowledged_handler_deadline_keeps_connection

mut_handler_deadline_socket_evidence_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
subject = "async fn an_unacknowledged_handler_deadline_closes_the_observed_socket()"
replacement = "async fn removed_handler_deadline_socket_evidence()"
if text.count(subject) != 1:
    raise SystemExit("missing unique handler deadline socket evidence mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the real socket evidence for unacknowledged handler cancellation disappearing' \
    'handler deadline connection evidence is missing or duplicated' \
    mut_handler_deadline_socket_evidence_removed

mut_reset_cancellation_uses_orderly_close() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
subject = "socket.set_linger(Some(Duration::ZERO))"
replacement = "socket.set_linger(None)"
if text.count(subject) != 1:
    raise SystemExit("missing unique reset linger mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'c-lim-0060 replacing the TCP reset with an orderly close' \
    'c-lim-0060 does not prove reset cancellation, rollback, and permit reuse' \
    mut_reset_cancellation_uses_orderly_close

mut_reset_cancellation_loses_rollback_observation() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
subject = "backend.rollback_completed.load(Ordering::Acquire)"
replacement = "true"
if text.count(subject) != 1:
    raise SystemExit("missing unique reset rollback mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'c-lim-0060 no longer observing rollback completion' \
    'c-lim-0060 does not prove reset cancellation, rollback, and permit reuse' \
    mut_reset_cancellation_loses_rollback_observation

mut_reset_cancellation_loses_permit_reuse() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
subject = 'String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 ")'
replacement = "!response.is_empty()"
if text.count(subject) != 1:
    raise SystemExit("missing unique reset permit reuse mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'c-lim-0060 no longer proving the released permit admits a successful request' \
    'c-lim-0060 does not prove reset cancellation, rollback, and permit reuse' \
    mut_reset_cancellation_loses_permit_reuse

mut_reset_cancellation_reason_collapsed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
subject = "[HandlerCancellation::RequestAborted]"
replacement = "[HandlerCancellation::Deadline]"
if text.count(subject) != 1:
    raise SystemExit("missing unique reset reason mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'c-lim-0060 collapsing request abort into deadline cancellation' \
    'c-lim-0060 does not prove reset cancellation, rollback, and permit reuse' \
    mut_reset_cancellation_reason_collapsed

mut_handler_deadline_report_not_public() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text()
subject = "pub enum HandlerDeadlineReport {"
replacement = "pub(crate) enum HandlerDeadlineReport {"
if text.count(subject) != 1:
    raise SystemExit("missing unique public handler deadline report mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the typed handler deadline report becoming private' \
    'handler deadline report is not a public typed contract' \
    mut_handler_deadline_report_not_public

mut_handler_deadline_report_not_exported() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/lib.rs")
text = path.read_text()
subject = "pub use crate::request_config::HandlerDeadlineReport;"
replacement = "pub(crate) use crate::request_config::HandlerDeadlineReport;"
if text.count(subject) != 1:
    raise SystemExit("missing unique handler deadline report export mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the handler deadline report disappearing from the facade' \
    'facade does not export the handler deadline report' \
    mut_handler_deadline_report_not_exported

mut_observer_handler_deadline_report_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/ext/observer.rs")
text = path.read_text()
subject = "pub handler_deadline: Option<HandlerDeadlineReport>,"
replacement = "pub _handler_deadline: Option<HandlerDeadlineReport>,"
if text.count(subject) != 1:
    raise SystemExit("missing unique observer deadline report mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the request observer losing its typed handler deadline report' \
    'request observer does not expose the typed handler deadline report' \
    mut_observer_handler_deadline_report_removed

mut_handler_deadline_report_dropped_from_event() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/service.rs")
text = path.read_text()
subject = "                handler_deadline,\n                identity: outcome.identity.as_ref(),"
replacement = "                handler_deadline: None,\n                identity: outcome.identity.as_ref(),"
if text.count(subject) != 1:
    raise SystemExit("missing unique observed handler deadline mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the response observer dropping the recorded handler deadline report' \
    'response observation does not carry the request handler deadline report' \
    mut_handler_deadline_report_dropped_from_event

mut_handler_deadline_evidence_records_none() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
subject = "seen.push(event.handler_deadline);"
replacement = "seen.push(None);"
if text.count(subject) != 1:
    raise SystemExit("missing unique live deadline report recorder mutation subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'the observer evidence replacing the live deadline report with none' \
    'handler deadline observer evidence does not record the live event' \
    mut_handler_deadline_evidence_records_none

mut_unacknowledged_deadline_report_assertion_weakened() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
subject = "Some(HandlerDeadlineReport::Unacknowledged)"
replacement = "None"
if text.count(subject) != 2:
    raise SystemExit("missing exact unacknowledged deadline report assertion census")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'an unacknowledged handler deadline no longer requiring its report' \
    'handler deadline observer evidence does not distinguish all report outcomes' \
    mut_unacknowledged_deadline_report_assertion_weakened

mut_acknowledged_deadline_report_assertion_weakened() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
subject = "Some(HandlerDeadlineReport::Acknowledged)"
replacement = "None"
if text.count(subject) != 2:
    raise SystemExit("missing exact acknowledged deadline report assertion census")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'an acknowledged handler deadline no longer requiring its report' \
    'handler deadline observer evidence does not distinguish all report outcomes' \
    mut_acknowledged_deadline_report_assertion_weakened

mut_no_deadline_report_assertion_weakened() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/connection_teardown.rs")
text = path.read_text()
subject = 'recorder.seen.lock().expect("not poisoned").as_slice(), [None]'
replacement = 'recorder.seen.lock().expect("not poisoned").as_slice(), []'
if text.count(subject) != 1:
    raise SystemExit("missing unique no-deadline report assertion subject")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_handler_deadline_class.sh \
    'a completed handler no longer requiring the absence of a deadline report' \
    'handler deadline observer evidence does not distinguish all report outcomes' \
    mut_no_deadline_report_assertion_weakened

mut_signing_suite_captures_build_toolchain_cargo() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/sigsuite.rs")
text = path.read_text()
subject = '''fn suite_cargo_command() -> Command {
    Command::new("cargo")
}'''
replacement = '''fn suite_cargo_command() -> Command {
    Command::new(env!("CARGO"))
}'''
if text.count(subject) != 1:
    raise SystemExit("repository-selected signing-suite Cargo command is not unique")
path.write_text(text.replace(subject, replacement, 1))
PYEOF
}
expect_fail_with_diagnostic check_signing_suite_lock.sh \
    'the signing-suite runner capturing the build toolchain Cargo path' \
    'signing-suite runner must launch Cargo through the repository-selected rustup proxy' \
    mut_signing_suite_captures_build_toolchain_cargo

expect_signing_suite_dirty_checkout_fail() {
    local checkout output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    checkout="$(mktemp -d "${TMPDIR:-/tmp}/gateway-signing-suite-dirty.XXXXXX")"
    if ! git -C "$checkout" init -q ||
        ! git -C "$checkout" config user.name t ||
        ! git -C "$checkout" config user.email t@t; then
        rm -rf "$checkout"
        fail_msg "check_signing_suite_lock.sh dirty-checkout fixture initialization failed"
        return
    fi
    printf 'baseline\n' >"$checkout/tracked.txt"
    if ! git -C "$checkout" add tracked.txt ||
        ! git -C "$checkout" commit -qm base; then
        rm -rf "$checkout"
        fail_msg "check_signing_suite_lock.sh dirty-checkout fixture commit failed"
        return
    fi
    printf 'dirty\n' >>"$checkout/tracked.txt"
    output="$("${SCRIPT_DIR}/check_signing_suite_lock.sh" --checkout "$checkout" 2>&1)" || rc=$?
    rm -rf "$checkout"
    if [[ "$rc" -ne 0 && "$output" == *'checkout has tracked or untracked changes'* ]]; then
        pass_msg "check_signing_suite_lock.sh catches: a dirty official-suite checkout"
    else
        fail_msg "check_signing_suite_lock.sh did not reject a dirty official-suite checkout"
    fi
}
expect_signing_suite_dirty_checkout_fail

mut_signing_suite_lock_deleted() {
    rm spec/third-party/aws-signing-test-suite.lock
}
expect_fail check_signing_suite_lock.sh \
    'the protected signing-suite lock being deleted' mut_signing_suite_lock_deleted

mut_signing_suite_commit_drifted() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("spec/third-party/aws-signing-test-suite.lock")
text = path.read_text().replace(
    'commit = "cb39d6e52459b47fa8881a241ac9f78849f1bc25"',
    'commit = "0000000000000000000000000000000000000000"',
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_signing_suite_lock.sh \
    'the reviewed signing-suite commit drifting' mut_signing_suite_commit_drifted

mut_signing_suite_tree_drifted() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("spec/third-party/aws-signing-test-suite.lock")
text = path.read_text().replace(
    'v4_tree = "a40b300e3d573b47b6fc959787d1773b571f532f"',
    'v4_tree = "0000000000000000000000000000000000000000"',
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_signing_suite_lock.sh \
    'the reviewed v4 tree identity drifting' mut_signing_suite_tree_drifted

mut_signing_suite_license_drifted() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("spec/third-party/aws-signing-test-suite.lock")
text = path.read_text().replace(
    'license_blob = "67db8588217f266eb561f75fae738656325deac9"',
    'license_blob = "0000000000000000000000000000000000000000"',
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_signing_suite_lock.sh \
    'the reviewed upstream license blob drifting' mut_signing_suite_license_drifted

mut_signing_suite_retrieval_date_drifted() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("spec/third-party/aws-signing-test-suite.lock")
text = path.read_text().replace('retrieved = "2026-08-14"', 'retrieved = "unknown"', 1)
path.write_text(text)
PYEOF
}
expect_fail check_signing_suite_lock.sh \
    'the reviewed retrieval date losing its exact value' mut_signing_suite_retrieval_date_drifted

mut_signing_suite_case_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("spec/third-party/aws-signing-test-suite.lock")
text = path.read_text().replace('  "double-encode-path",\n', '', 1)
path.write_text(text)
PYEOF
}
expect_fail check_signing_suite_lock.sh \
    'one of the forty v4 cases being removed' mut_signing_suite_case_removed

mut_signing_suite_case_duplicated() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("spec/third-party/aws-signing-test-suite.lock")
text = path.read_text().replace(
    '  "double-url-encode",\n',
    '  "double-encode-path",\n',
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_signing_suite_lock.sh \
    'a duplicated v4 case replacing another case' mut_signing_suite_case_duplicated

mut_signing_suite_disposition_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("spec/third-party/aws-signing-test-suite.lock")
text = path.read_text()
prefix, marker, disposition = text.partition("v4_run_three_layer = [\n")
body, suffix_marker, suffix = disposition.partition("\n]\n\nv4_s3_negative = [\n")
if not marker or not suffix_marker or body.count('  "get-space-normalized",\n') != 1:
    raise SystemExit("missing unique v4 disposition mutation subject")
text = prefix + marker + body.replace('  "get-space-normalized",\n', '', 1) + suffix_marker + suffix
path.write_text(text)
PYEOF
}
expect_fail check_signing_suite_lock.sh \
    'a reviewed v4 disposition being removed' mut_signing_suite_disposition_removed

mut_signing_suite_provenance_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("THIRD-PARTY-NOTICES.md")
text = path.read_text().replace("## Smithy signing test suite", "## Removed signing provenance", 1)
path.write_text(text)
PYEOF
}
expect_fail check_signing_suite_lock.sh \
    'the signing-suite provenance heading being removed' mut_signing_suite_provenance_removed

mut_signing_suite_protected_row_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("AGENTS.md")
text = path.read_text()
line = '| `spec/third-party/aws-signing-test-suite.lock` | Reviewed smithy-rs signing-suite commit, license, tree identities, and complete v4/v4a case census |\n'
if text.count(line) != 1:
    raise SystemExit("missing signing-suite protected row mutation subject")
path.write_text(text.replace(line, "", 1))
PYEOF
}
expect_fail check_signing_suite_lock.sh \
    'the signing-suite lock disappearing from the protected table' \
    mut_signing_suite_protected_row_removed

# The three version mutations below read the version out of the manifest rather than naming it.
# A literal is a mutation with an expiry date: the moment the crate is bumped or the model is
# re-pinned, `str.replace` matches nothing, writes the file back unchanged, and the guard passes
# because there was nothing to catch — an `expect_fail` case that has quietly become an
# `expect_pass` one. Measured: bumping the types crate to 0.4.0 turned
# `mut_types_version_numeric_part_diverges` into a no-op. Each mutation now asserts it changed
# something, so a subject that stops existing is a loud failure rather than a silent pass.
mut_types_version_loses_model_date() {
    python3 - <<'PYEOF'
import pathlib
import re

path = pathlib.Path("crates/types/Cargo.toml")
text = path.read_text()
mutated, count = re.subn(r'(?m)^(version = "[0-9]+\.[0-9]+\.[0-9]+)\+aws\.[0-9]{4}-[0-9]{2}-[0-9]{2}"$', r'\1"', text, count=1)
if count != 1:
    raise SystemExit("missing types version model-date mutation subject")
path.write_text(mutated)
PYEOF
}
expect_fail check_version_metadata.sh \
    'the types crate version losing its AWS model date' mut_types_version_loses_model_date

mut_types_version_has_invalid_model_date() {
    python3 - <<'PYEOF'
import pathlib
import re

path = pathlib.Path("crates/types/Cargo.toml")
text = path.read_text()
mutated, count = re.subn(r'\+aws\.[0-9]{4}-[0-9]{2}-[0-9]{2}"', '+aws.2026-02-30"', text, count=1)
if count != 1:
    raise SystemExit("missing types version calendar-date mutation subject")
path.write_text(mutated)
PYEOF
}
expect_fail check_version_metadata.sh \
    'the types crate version carrying an invalid calendar date' mut_types_version_has_invalid_model_date

mut_types_version_numeric_part_diverges() {
    python3 - <<'PYEOF'
import pathlib
import re

path = pathlib.Path("crates/types/Cargo.toml")
text = path.read_text()
mutated, count = re.subn(
    r'(?m)^version = "([0-9]+)\.([0-9]+)\.([0-9]+)\+aws\.',
    lambda m: f'version = "{m.group(1)}.{int(m.group(2)) + 1}.{m.group(3)}+aws.',
    text,
    count=1,
)
if count != 1:
    raise SystemExit("missing types version numeric mutation subject")
path.write_text(mutated)
PYEOF
}
expect_fail check_version_metadata.sh \
    'the types crate numeric version diverging from the root dependency' mut_types_version_numeric_part_diverges

# -----------------------------------------------------------------------------
# The shard machinery is itself a guard, so it owes the same negative cases as
# every other guard here. Nothing below runs a real case: they run the pure
# decision functions and the isolation mechanism with synthetic inputs, so they
# cost milliseconds and cannot be timing-dependent.
# -----------------------------------------------------------------------------

# shard_case <description> <predicate> [args...]
shard_case() {
    local desc="$1"
    shift
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    if "$@"; then
        pass_msg "$desc"
    else
        fail_msg "$desc"
    fi
}

budget_verdict_is() {
    local expected="$1" elapsed="$2" stop="$3" warn="$4"
    [[ "$(guard_budget_verdict "$elapsed" "$stop" "$warn")" == "$expected" ]]
}

shard_case 'the budget verdict stays quiet while the suite has room' \
    budget_verdict_is ok 100 450 384
shard_case 'the budget verdict warns once four fifths of the budget is spent' \
    budget_verdict_is warn 384 450 384
shard_case 'the budget verdict stops the suite before timeout can kill it' \
    budget_verdict_is stop 450 450 384

# The stop reserve is a flat thirty seconds, so a small budget hands most of its clock to it. The
# quirk-ledger shards ran at 60s for months, which is 30s of working time, and stopped themselves
# on runs 33641327259 and 33646920592 with every case still printing ok. A budget below four times
# the reserve is now refused outright, before any case runs, rather than being quietly halved.
#
# Driven as a subprocess because the refusal is an `exit 1` at load time; both directions are
# asserted, since a floor that rejects everything reads exactly like one that rejects nothing.
#
# Both runs are stopped one check later by a deliberately out-of-range shard group, so neither
# executes a case and both exit 1. The rc alone therefore proves nothing — a floor that rejects
# every budget reads exactly like one that rejects none — so each case asserts which of the two
# refusals spoke.
guard_budget_floor_case() {
    local budget="$1" expected="$2" forbidden="$3" desc="$4" output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    output="$(env GATEWAY_GUARD_BUDGET_SECONDS="$budget" GATEWAY_GUARD_SHARD_GROUPS=2 \
        GATEWAY_GUARD_SHARD_GROUP=9 bash "$GUARD_SELF" 2>&1)" || rc=$?
    if [[ "$rc" -eq 1 && "$output" == *"$expected"* && "$output" != *"$forbidden"* ]]; then
        pass_msg "$desc"
    else
        fail_msg "$desc — rc ${rc}: ${output}"
    fi
}
# 119s keeps 89s of working time, one second under the quarter the reserve may cost; 120s is the
# floor itself and must be accepted, or this would be a ban rather than a floor.
guard_budget_floor_case 119 'keeps only 89s of working time' 'GATEWAY_GUARD_SHARD_GROUP must be' \
    'the suite refuses a budget the flat stop reserve would eat a quarter of'
guard_budget_floor_case 120 'GATEWAY_GUARD_SHARD_GROUP must be' 'working time' \
    'the suite accepts a budget four times its stop reserve'

shard_plan_is() {
    local expected="$1"
    shift
    [[ "$(guard_shard_plan "$@")" == "$expected" ]]
}

shard_case 'the default mode shards across the requested workers' \
    shard_plan_is 4 4 0 0 0
shard_case 'the quirk-ledger mode never shards' \
    shard_plan_is 1 4 1 0 0
shard_case 'the DTO compiler mode never shards' \
    shard_plan_is 1 4 0 1 0
shard_case 'the build-guard mode uses one worker per runner, keeping its CARGO_TARGET_DIR private' \
    shard_plan_is 1 4 0 0 1
shard_case 'the error-status mode never shards' \
    shard_plan_is 1 4 0 0 0 1

shard_of_is() {
    local expected="$1" fn="$2"
    shift 2
    [[ "$("$fn" "$@")" == "$expected" ]]
}

# shard_partition_holds <groups> <workers> <total>
# Every ordinal lands on exactly one (runner, worker) pair in range, and the runners
# get equal shares. That equal split is the whole reason a runner can prove its own
# coverage without ever seeing another runner's ledger.
shard_partition_holds() {
    local groups="$1" workers="$2" total="$3" n group worker
    local owned=()
    for ((n = 0; n < groups * workers; n++)); do
        owned[n]=0
    done
    for ((n = 1; n <= total; n++)); do
        group="$(guard_group_of "$n" "$groups")"
        worker="$(guard_worker_of "$n" "$groups" "$workers")"
        ((group >= 0 && group < groups)) || return 1
        ((worker >= 0 && worker < workers)) || return 1
        owned[group * workers + worker]=$((owned[group * workers + worker] + 1))
    done
    for ((n = 0; n < groups * workers; n++)); do
        ((owned[n] == total / (groups * workers))) || return 1
    done
}

shard_case 'the first case belongs to the first runner' \
    shard_of_is 0 guard_group_of 1 4
shard_case 'the fourth case belongs to the last of four runners' \
    shard_of_is 3 guard_group_of 4 4
shard_case 'runners stride, so the fifth case comes back to the first runner' \
    shard_of_is 0 guard_group_of 5 4
shard_case 'a runner hands its first case to its first worker' \
    shard_of_is 0 guard_worker_of 1 4 2
shard_case 'a runner strides across its own workers too' \
    shard_of_is 1 guard_worker_of 5 4 2
shard_case 'four runners of two workers split the ordinals into eight equal shares' \
    shard_partition_holds 4 2 64

# -----------------------------------------------------------------------------
# Expected diagnostics are compared as strings, which is only safe while the
# argument reaches the comparison un-executed. A double-quoted argument hands
# its backticks to command substitution: the span between them runs, its output
# replaces the span, stderr gains a "command not found", and the weakened
# remainder can still match the guard's real diagnostic — the case then proves
# less than it claims while reading green (rustfs/gateway#334). The scanner
# below reads this suite's own source and reports any double-quoted argument of
# the diagnostic-expecting helpers that contains a backtick, so the regression
# cannot return as a quoting typo. Single-quoted and $'...' arguments keep
# backticks literal and are the blessed spellings.
# -----------------------------------------------------------------------------

# diagnostic_arguments_stay_literal <path>
# Exit 0 when no expect_*_with_diagnostic argument in <path> is double-quoted
# around a backtick; exit 1 naming each offender otherwise.
diagnostic_arguments_stay_literal() {
    local subject="$1"
    python3 - "$subject" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
call_start = re.compile(r"^(expect_fail_with_diagnostic|expect_cargo_test_fail_with_diagnostic)\s")
violations = []
in_call = False
for number, line in enumerate(text.splitlines(), start=1):
    stripped = line.strip()
    if stripped.endswith("\\"):
        body = stripped[:-1]
    else:
        body = stripped
    if call_start.match(line):
        in_call = stripped.endswith("\\")
        subject = body
    elif in_call:
        subject = body
        in_call = stripped.endswith("\\")
    else:
        continue
    # Walk the line honouring single quotes: inside them, double quotes and
    # backticks are literal. `$'...'` is treated the same way.
    index = 0
    singles = 0
    while index < len(subject):
        char = subject[index]
        if char == "'":
            singles += 1
            index += 1
        elif char == '"' and singles % 2 == 0:
            end = subject.find('"', index + 1)
            if end < 0:
                end = len(subject)
            if "`" in subject[index + 1 : end]:
                violations.append((number, subject.strip()))
            index = end + 1
        else:
            index += 1
if violations:
    for number, offender in violations:
        print(f"line {number}: a double-quoted diagnostic argument contains a backtick: {offender}", file=sys.stderr)
    raise SystemExit(1)
PY
}

shard_case 'expected diagnostics keep every backtick out of double quotes' \
    diagnostic_arguments_stay_literal "${SCRIPT_DIR}/test_guard_scripts.sh"

# double_quoted_backtick_is_caught / single_quoted_backtick_is_literal
# The two directions of the scan, on synthetic sources: the exact spelling that
# silently executed on #334 must be reported, and the blessed single-quoted
# spelling of the same diagnostic must not be.
double_quoted_backtick_is_caught() {
    local tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/gateway-diag-quote.XXXXXX")"
    {
        printf '%s\n' 'expect_fail_with_diagnostic check_example.sh \'
        printf '%s\n' '    "a case whose expected diagnostic was weakened" \'
        printf '%s\n' '    "`Members:` does not name it" \'
        printf '%s\n' '    mut_noop'
    } >"$tmp"
    if diagnostic_arguments_stay_literal "$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    rm -f "$tmp"
    return 0
}

single_quoted_backtick_is_literal() {
    local tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/gateway-diag-quote.XXXXXX")"
    {
        printf '%s\n' 'expect_fail_with_diagnostic check_example.sh \'
        printf '%s\n' '    "a case whose expected diagnostic was weakened" \'
        printf '%s\n' "    '\`Members:\` does not name it' \\"
        printf '%s\n' '    mut_noop'
    } >"$tmp"
    if diagnostic_arguments_stay_literal "$tmp"; then
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

shard_case 'the diagnostic scanner catches the double-quoted backtick spelling of #334' \
    double_quoted_backtick_is_caught
shard_case 'the diagnostic scanner leaves the single-quoted spelling alone' \
    single_quoted_backtick_is_literal

# ledger_report_is <complete|defective> <considered> <groups> <group>
#                  <comma-separated ordinals per worker>...
ledger_report_is() {
    local expected="$1" considered="$2" groups="$3" group="$4"
    shift 4
    local dir spec index=0 rc=0
    dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-shard-ledger.XXXXXX")"
    for spec in "$@"; do
        printf '%s\n' ${spec//,/ } >"${dir}/ledger-${index}"
        index=$((index + 1))
    done
    guard_shard_ledger_report "$considered" "$groups" "$group" \
        "${dir}"/ledger-* >/dev/null 2>&1 || rc=$?
    rm -rf "$dir"
    if [[ "$expected" == complete ]]; then
        [[ "$rc" -eq 0 ]]
    else
        [[ "$rc" -ne 0 ]]
    fi
}

# With two runners, the first owns the odd ordinals: 1, 3, 5 and 7 out of eight,
# which its two workers take alternately as 1, 5 and 3, 7.
shard_case 'the coverage proof accepts workers that between them ran their whole runner share' \
    ledger_report_is complete 8 2 0 1,5 3,7
shard_case 'the coverage proof catches a worker that died before its last cases' \
    ledger_report_is defective 8 2 0 1,5 3
shard_case 'the coverage proof catches a case site that never learned about the shard gate' \
    ledger_report_is defective 8 2 0 1,5 1,3,7
shard_case 'the coverage proof catches a runner that ran a case belonging to another runner' \
    ledger_report_is defective 8 2 0 1,5,2 3,7
shard_case 'the coverage proof catches a ledger ordinal outside the considered range' \
    ledger_report_is defective 8 2 0 1,5,9 3,7

# shard_sandbox_isolation_contract <private|shared>
# Two concurrent workers shaped the way run_guard_shards shapes a shard: each is
# a separate process, and under `private` each derives its sandbox from its own
# TMPDIR with the same `mktemp -d` expression make_sandbox uses. Both write a
# marker, a file rendezvous makes both writes land before either read, and both
# read back. Under `private` each worker must read its own value. Under `shared`
# — one sandbox for both, which is what parallelising this suite without a
# per-process sandbox produces — exactly one worker must read the other's value,
# whichever wrote last. The rendezvous is what makes that deterministic instead
# of a race that passes by luck.
shard_sandbox_isolation_contract() {
    local mode="$1" base worker contaminated=0 spins
    base="$(mktemp -d "${TMPDIR:-/tmp}/gateway-shard-isolation.XXXXXX")"
    mkdir -p "${base}/shared"
    for worker in a b; do
        (
            sandbox="${base}/shared"
            if [[ "$mode" == private ]]; then
                mkdir -p "${base}/tmp-${worker}"
                sandbox="$(TMPDIR="${base}/tmp-${worker}" mktemp -d "${base}/tmp-${worker}/gateway-guard-test.XXXXXX")"
                printf '%s\n' "$sandbox" >"${base}/where-${worker}"
            fi
            printf '%s\n' "$worker" >"${sandbox}/marker.txt"
            : >"${base}/wrote-${worker}"
            spins=0
            while [[ ! -f "${base}/wrote-a" || ! -f "${base}/wrote-b" ]]; do
                spins=$((spins + 1))
                ((spins < 500)) || break
                sleep 0.02
            done
            cat "${sandbox}/marker.txt" >"${base}/read-${worker}"
        ) &
    done
    wait
    for worker in a b; do
        [[ -f "${base}/read-${worker}" ]] || contaminated=2
        [[ "$(cat "${base}/read-${worker}" 2>/dev/null)" == "$worker" ]] || contaminated=1
        if [[ "$mode" == private ]]; then
            # The isolation is not an accident of mktemp: it is that the worker's
            # sandbox lives under the TMPDIR the parent handed only to it.
            [[ "$(cat "${base}/where-${worker}" 2>/dev/null)" == "${base}/tmp-${worker}/"* ]] ||
                contaminated=3
        fi
    done
    rm -rf "$base"
    if [[ "$mode" == private ]]; then
        [[ "$contaminated" -eq 0 ]]
    else
        [[ "$contaminated" -eq 1 ]]
    fi
}

shard_case 'concurrent shards with private TMPDIRs never see each other sandbox writes' \
    shard_sandbox_isolation_contract private
shard_case 'one sandbox shared by concurrent shards loses a mutation, and the contract says so' \
    shard_sandbox_isolation_contract shared

# --- check_form_limits.sh (rustfs/backlog#1699, POST Object form) -----------------------------

mut_form_case_identity_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/http/tests/form_limits.rs")
old = "fn c_lim_0031_a_field_after_the_file_part_is_refused()"
new = "fn a_field_after_the_file_part_is_refused()"
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("c-lim-0031 identity anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_form_limits.sh \
    'c-lim-0031 losing its executable identity' mut_form_case_identity_removed \
    'c-lim-0031 must name exactly one test function'

mut_form_case_disabled_by_cfg() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/http/tests/form_limits.rs")
old = "#[test]\nfn c_lim_0028_a_policy_ceiling_stops_the_file_at_the_policy_ceiling()"
new = "#[cfg(any())]\n#[test]\nfn c_lim_0028_a_policy_ceiling_stops_the_file_at_the_policy_ceiling()"
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("c-lim-0028 active-test anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_form_limits.sh \
    'c-lim-0028 being switched off by cfg while its name stays greppable' mut_form_case_disabled_by_cfg \
    'conditional or ignored'

mut_form_second_file_reader_door() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/http/src/form/file.rs")
old = "    /// Builds the reader. Crate-private: the ceiling has to come from `into_file`.\n"
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("FileReader constructor anchor drifted")
extra = (
    "    /// A second door.\n"
    "    #[must_use]\n"
    "    pub fn new(delimiter: &[u8]) -> Self {\n"
    "        Self::new(u64::MAX, u64::MAX, delimiter, Vec::new(), 0)\n"
    "    }\n\n"
)
path.write_text(text.replace(old, extra + old, 1))
PYEOF
}
expect_fail check_form_limits.sh \
    'a public FileReader constructor that needs no ceiling' mut_form_second_file_reader_door \
    'public `FileReader::new`'

mut_form_ceiling_no_longer_composed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/http/src/form/reader.rs")
old = "            ceiling.min(self.limits.max_file_bytes()),"
new = "            ceiling.max(self.limits.max_file_bytes()),"
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("into_file ceiling composition anchor drifted")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_form_limits.sh \
    'a policy ceiling that widens the deployment maximum instead of tightening it' \
    mut_form_ceiling_no_longer_composed \
    'composes the policy ceiling'

mut_form_unlimited_constructor_added() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/http/src/form/mod.rs")
old = "impl Default for FormLimits {"
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit("FormLimits Default anchor drifted")
extra = (
    "impl FormLimits {\n"
    "    /// Everything unbounded.\n"
    "    #[must_use]\n"
    "    pub fn unlimited_dangerous() -> Self {\n"
    "        Self::default()\n"
    "    }\n"
    "}\n\n"
)
path.write_text(text.replace(old, extra + old, 1))
PYEOF
}
expect_fail check_form_limits.sh \
    'an unlimited FormLimits constructor' mut_form_unlimited_constructor_added \
    'unlimited `FormLimits` constructor'

mut_form_evidence_file_removed() {
    rm -f crates/sig/tests/post_object_form.rs
}
expect_fail check_form_limits.sh \
    'c-lim-0002 evidence deleted, which must fail rather than skip' mut_form_evidence_file_removed \
    'required input is missing'

mut_response_header_direct_expect() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/codec/response.rs")
text = path.read_text()
text += '''

fn injected_response_header(bytes: &[u8]) -> HeaderValue {
    HeaderValue::from_bytes(bytes).expect("caller supplied a header value")
}
'''
path.write_text(text)
PYEOF
}
expect_fail check_no_response_header_unwrap.sh \
    'a response header value parsed from caller bytes with expect' \
    mut_response_header_direct_expect \
    'panic-capable response header construction'

mut_response_header_split_unwrap() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/codec/response.rs")
text = path.read_text()
text += '''

fn injected_response_header(response: &mut EncodedResponse, bytes: &[u8]) {
    let parsed = HeaderValue::from_bytes(bytes);
    response.headers.insert(http::header::CONTENT_TYPE, parsed.unwrap());
}
'''
path.write_text(text)
PYEOF
}
expect_fail check_no_response_header_unwrap.sh \
    'a fallible response header parse separated from its unwrap' \
    mut_response_header_split_unwrap \
    'panic-capable response header construction'

mut_response_header_aliased_expect() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/codec/response.rs")
text = path.read_text()
text += '''

type ResponseHeader = HeaderValue;

fn injected_response_header(bytes: &[u8]) -> ResponseHeader {
    ResponseHeader::from_bytes(bytes).expect("caller supplied a header value")
}
'''
path.write_text(text)
PYEOF
}
expect_fail check_no_response_header_unwrap.sh \
    'a response header alias hiding a panic-capable parser' \
    mut_response_header_aliased_expect \
    'panic-capable response header construction'

mut_response_header_test_expect() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/codec/response.rs")
text = path.read_text()
text += '''

#[cfg(test)]
fn injected_test_header(bytes: &[u8]) -> HeaderValue {
    HeaderValue::from_bytes(bytes).expect("the fixture supplies a header value")
}
'''
path.write_text(text)
PYEOF
}
expect_guard_pass check_no_response_header_unwrap.sh \
    'a test-only fixture may use expect on its own header bytes' \
    mut_response_header_test_expect

mut_response_header_authority_removed() {
    rm crates/core/src/codec/response.rs
}
expect_fail check_no_response_header_unwrap.sh \
    'the response-header authority disappearing instead of being scanned' \
    mut_response_header_authority_removed \
    'required input is missing'

# -- check_compat_matrix.sh / check_client_versions_pinned.sh / check_compat_table.sh ------------

mut_compat_known_fail_grew() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("compat/known-fail.txt")
text = path.read_text()
old = "boto3/range-download         rustfs/gateway#626  GetObject ignores the Range header\n"
if text.count(old) != 1:
    raise SystemExit("known-fail ratchet mutation subject is not unique")
path.write_text(text.replace(old, old + "boto3/list-pagination        rustfs/gateway#626  newly excused\n", 1))
PYEOF
}
# The whole point of the ratchet: a regression must not be silenceable by the change that caused it.
expect_fail check_compat_matrix.sh \
    'a new entry appended to the compatibility known-failure list' \
    mut_compat_known_fail_grew \
    'the list may only shrink'

mut_compat_known_fail_unowned() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("compat/known-fail.txt")
text = path.read_text()
old = "boto3/presigned-put          rustfs/gateway#628  presigned PUT is not an admitted operation"
if text.count(old) != 1:
    raise SystemExit("known-fail owner mutation subject is not unique")
path.write_text(text.replace(old, "boto3/presigned-put          later  presigned PUT is not an admitted operation", 1))
PYEOF
}
expect_fail check_compat_matrix.sh \
    'an excused compatibility failure with no owning issue' \
    mut_compat_known_fail_unowned \
    'without an <owner>/<repo>#<number> issue'

mut_compat_matrix_hand_edited() {
    python3 - <<'PYEOF'
import json
from pathlib import Path

path = Path("compat/matrix.json")
matrix = json.loads(path.read_text())
for client in matrix["clients"]:
    for row in client["scenarios"]:
        if row["status"] == "fail":
            row["status"] = "pass"
            row["verdict"] = None
            row["issue"] = None
            path.write_text(json.dumps(matrix, indent=2) + "\n")
            raise SystemExit(0)
raise SystemExit("no failing cell to promote")
PYEOF
}
# matrix.json is a generated artefact and a published promise. A hand edit that promotes a failure
# to a pass must not survive, and the counts are the part a hand edit gets wrong.
expect_fail check_compat_matrix.sh \
    'a failing compatibility cell hand-edited into a pass' \
    mut_compat_matrix_hand_edited \
    'its own cells say'

mut_compat_unsupported_without_reason() {
    python3 - <<'PYEOF'
import json
from pathlib import Path

path = Path("compat/matrix.json")
matrix = json.loads(path.read_text())
for client in matrix["clients"]:
    for row in client["scenarios"]:
        if row["status"] == "unsupported":
            row["detail"] = None
            path.write_text(json.dumps(matrix, indent=2) + "\n")
            raise SystemExit(0)
raise SystemExit("no unsupported cell to strip")
PYEOF
}
# A skip with no reason reads exactly like a pass to anything that looks only at the status.
expect_fail check_compat_matrix.sh \
    'an unsupported compatibility cell that records no reason' \
    mut_compat_unsupported_without_reason \
    'unsupported with no reason'

mut_compat_matrix_unnamed_sut() {
    python3 - <<'PYEOF'
import json
from pathlib import Path

path = Path("compat/matrix.json")
matrix = json.loads(path.read_text())
del matrix["sut"]["binary"]
path.write_text(json.dumps(matrix, indent=2) + "\n")
PYEOF
}
# A compatibility row whose system under test is unnamed cannot be re-measured, and the whole table
# then claims something about a server nobody can identify.
expect_fail check_compat_matrix.sh \
    'the compatibility manifest losing the identity of what answered it' \
    mut_compat_matrix_unnamed_sut \
    'sut block has no binary'

mut_compat_matrix_silent_provisional() {
    python3 - <<'PYEOF'
import json
from pathlib import Path

path = Path("compat/matrix.json")
matrix = json.loads(path.read_text())
matrix["sut"]["provisional_reason"] = ""
path.write_text(json.dumps(matrix, indent=2) + "\n")
PYEOF
}
# A provisional identity that stops saying why is indistinguishable from a settled one.
expect_fail check_compat_matrix.sh \
    'a provisional system under test that no longer records why' \
    mut_compat_matrix_silent_provisional \
    'provisional with no reason'

mut_compat_matrix_in_the_pr_gate() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path(".github/workflows/client-matrix.yml")
text = path.read_text()
old = "on:\n  schedule:"
if text.count(old) != 1:
    raise SystemExit("client-matrix trigger mutation subject is not unique")
path.write_text(text.replace(old, "on:\n  pull_request:\n  schedule:", 1))
PYEOF
}
# A 30-90 minute job attached to the gate is how the ten-minute budget dies.
expect_fail check_compat_matrix.sh \
    'the client matrix attached to the pull-request gate' \
    mut_compat_matrix_in_the_pr_gate \
    'cron and manual dispatch only'

mut_compat_driver_removed() {
    rm -f compat/drivers/restic/run.sh
}
expect_fail check_compat_matrix.sh \
    'a declared client losing the driver that runs it' \
    mut_compat_driver_removed \
    'has no driver'

mut_compat_client_version_floating() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("compat/versions.toml")
text = path.read_text()
old = 'version = "v0.19.1"'
if text.count(old) != 1:
    raise SystemExit("client version mutation subject is not unique")
path.write_text(text.replace(old, 'version = "latest"', 1))
PYEOF
}
expect_fail check_client_versions_pinned.sh \
    'a compatibility client left on a floating version' \
    mut_compat_client_version_floating \
    'floating version'

mut_compat_client_version_range() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("compat/versions.toml")
text = path.read_text()
old = 'version = "1.42.96"'
if text.count(old) != 1:
    raise SystemExit("client version range mutation subject is not unique")
path.write_text(text.replace(old, 'version = "^1.42"', 1))
PYEOF
}
expect_fail check_client_versions_pinned.sh \
    'a compatibility client pinned to a range rather than a version' \
    mut_compat_client_version_range \
    'version range'

mut_compat_second_version_pin() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("compat/drivers/restic/run.sh")
text = path.read_text()
old = 'scenario="${1:?scenario id required}"'
if text.count(old) != 1:
    raise SystemExit("second-pin mutation subject is not unique")
path.write_text(text.replace(old, old + "\ngo install github.com/restic/restic/cmd/restic@v0.19.0", 1))
PYEOF
}
# Two places naming a version is how the client that ran and the client that was reported drift.
expect_fail check_client_versions_pinned.sh \
    'a driver pinning a client version outside compat/versions.toml' \
    mut_compat_second_version_pin \
    'pins a client version outside compat/versions.toml'

mut_compat_readme_table_edited() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
old = "| `range-download` |"
if text.count(old) != 1:
    raise SystemExit("compatibility table mutation subject is not unique")
path.write_text(text.replace(old, "| `range-download-and-then-some` |", 1))
PYEOF
}
expect_fail check_compat_table.sh \
    'the README compatibility table edited away from the manifest' \
    mut_compat_readme_table_edited \
    'does not match compat/matrix.json'


mut_corpus_live_authorization_header() {
    python3 - <<'PYEOF'
import json
from pathlib import Path

path = Path("corpus/object/PutObject.jsonl")
lines = path.read_text().splitlines()
entry = json.loads(lines[0])
entry["headers"].append(["authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/x, Signature=live"])
lines[0] = json.dumps(entry, separators=(",", ":"))
path.write_text("\n".join(lines) + "\n")
PYEOF
}
expect_fail check_corpus_no_secrets.sh \
    'a live authorization header reaching a stored corpus bucket' \
    mut_corpus_live_authorization_header \
    'a live `authorization` header'

mut_corpus_secret_in_a_decoded_payload() {
    python3 - <<'PYEOF'
import base64
import json
from pathlib import Path

path = Path("corpus/object/PutObject.jsonl")
lines = path.read_text().splitlines()
entry = json.loads(lines[0])
planted = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
entry["chunks"] = [{"bytes_b64": base64.b64encode(planted.encode()).decode()}]
lines[0] = json.dumps(entry, separators=(",", ":"))
path.write_text("\n".join(lines) + "\n")
PYEOF
}
expect_fail check_corpus_no_secrets.sh \
    'an AWS secret access key hidden inside a base64 payload' \
    mut_corpus_secret_in_a_decoded_payload \
    'an AWS secret access key'

mut_corpus_private_key_in_prose() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("corpus/README.md")
path.write_text(path.read_text() + "\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n")
PYEOF
}
expect_fail check_corpus_no_secrets.sh \
    'a PEM private key pasted into corpus prose' \
    mut_corpus_private_key_in_prose \
    'a PEM private key'

mut_corpus_tree_removed() {
    rm -rf corpus
}
expect_fail check_corpus_no_secrets.sh \
    'the corpus tree being absent, which must fail rather than skip' \
    mut_corpus_tree_removed \
    'required input is missing'

mut_corpus_production_source() {
    python3 - <<'PYEOF'
import json
from pathlib import Path

path = Path("corpus/object/PutObject.jsonl")
lines = path.read_text().splitlines()
entry = json.loads(lines[0])
entry["src"] = "production"
lines[0] = json.dumps(entry, separators=(",", ":"))
path.write_text("\n".join(lines) + "\n")
PYEOF
}
expect_fail check_corpus_provenance.sh \
    'a corpus entry recorded from production traffic' \
    mut_corpus_production_source \
    'not on the allowlist'

mut_corpus_unpinned_client_source() {
    python3 - <<'PYEOF'
import json
from pathlib import Path

path = Path("corpus/object/PutObject.jsonl")
lines = path.read_text().splitlines()
entry = json.loads(lines[0])
entry["src"] = "client-matrix:boto3"
lines[0] = json.dumps(entry, separators=(",", ":"))
path.write_text("\n".join(lines) + "\n")
PYEOF
}
expect_fail check_corpus_provenance.sh \
    'a client-matrix source with no pinned revision' \
    mut_corpus_unpinned_client_source \
    'no pinned revision'

mut_corpus_allowlist_emptied() {
    python3 - <<'PYEOF'
import re
from pathlib import Path

path = Path("crates/corpus/src/store.rs")
text = path.read_text()
replaced, count = re.subn(
    r"pub const SOURCE_ALLOWLIST: &\[\(&str, bool\)\] = &\[.*?\n\];",
    "pub const SOURCE_ALLOWLIST: &[(&str, bool)] = &[\n];",
    text,
    flags=re.S,
)
if count != 1:
    raise SystemExit("source allowlist mutation subject is not unique")
path.write_text(replaced)
PYEOF
}
expect_fail check_corpus_provenance.sh \
    'the provenance allowlist being emptied, which would let the guard pass on anything' \
    mut_corpus_allowlist_emptied \
    'parsed as empty'

mut_corpus_unknown_system_under_test() {
    python3 - <<'PYEOF'
import json
from pathlib import Path

path = Path("corpus/object/PutObject.jsonl")
lines = path.read_text().splitlines()
entry = json.loads(lines[0])
entry["sut"] = "somebody-elses-cluster"
lines[0] = json.dumps(entry, separators=(",", ":"))
path.write_text("\n".join(lines) + "\n")
PYEOF
}
expect_fail check_corpus_provenance.sh \
    'an entry naming a system under test outside the closed vocabulary' \
    mut_corpus_unknown_system_under_test \
    'closed vocabulary'

mut_corpus_undeclared_production_recording() {
    python3 - <<'PYEOF'
import json
from pathlib import Path

path = Path("corpus/object/PutObject.jsonl")
lines = path.read_text().splitlines()
entry = json.loads(lines[0])
entry["sut"] = "rustfs-server"
lines[0] = json.dumps(entry, separators=(",", ":"))
path.write_text("\n".join(lines) + "\n")
PYEOF
}
expect_fail check_corpus_provenance.sh \
    'an entry claiming a production recording the manifest does not declare' \
    mut_corpus_undeclared_production_recording \
    'entries_from_production_server'

mut_corpus_over_hard_ceiling() {
    python3 - <<'PYEOF'
from pathlib import Path

with Path("corpus/object/oversized.bin").open("wb") as handle:
    handle.truncate(51 * 1024 * 1024)
PYEOF
}
expect_fail check_corpus_size.sh \
    'the corpus growing past its hard ceiling' \
    mut_corpus_over_hard_ceiling \
    'hard ceiling'

mut_corpus_size_limits_unreadable() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/corpus/src/store.rs")
text = path.read_text()
old = "pub const HARD_SIZE_LIMIT_BYTES: u64 = 50 * 1024 * 1024;"
if text.count(old) != 1:
    raise SystemExit("hard size limit mutation subject is not unique")
path.write_text(text.replace(old, "pub const HARD_SIZE_LIMIT_BYTES: u64 = u64::MAX;", 1))
PYEOF
}
expect_fail check_corpus_size.sh \
    'the hard ceiling becoming unreadable, which must fail rather than default' \
    mut_corpus_size_limits_unreadable \
    'cannot read HARD_SIZE_LIMIT_BYTES'

# -- re-homed from the error-status block --------------------------------------------------------
#
# These nine cases were written at the end of the file while the last block in it was
# `if [[ "$ERROR_STATUS_ONLY" == 1 ]]`, so they landed inside it. They mutate two conformance
# cases, the conformance SUT seam and the response body planner, and not one of them is an error
# status: they ran only in the `error status self-test` job, billed to a budget and named after a
# subject belonging to something else, and never in the suite the four-command gate runs. They
# pass, and they passed there before this move — what was wrong was where they sat, not what they
# assert. check_guard_suite_tail_reachable.sh now refuses the file shape that collected them.

mut_sigv2_conformance_mode_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("conformance/cases/sig/c-sig-0582.toml")
text = path.read_text()
old = 'sign = { mode = "sigv2_header", credential = "valid" }'
new = 'sign = { mode = "sigv4_header", credential = "valid" }'
if text.count(old) != 1:
    raise SystemExit("SigV2 conformance mode mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0582 losing the SigV2 runner mode it exists to exercise' \
    mut_sigv2_conformance_mode_removed \
    'lost conformance evidence'

mut_sigv2_conformance_wrong_secret_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("conformance/cases/sig/c-sig-0583.toml")
text = path.read_text()
old = 'sign = { mode = "sigv2_header", credential = "wrong_secret" }'
new = 'sign = { mode = "sigv2_header", credential = "valid" }'
if text.count(old) != 1:
    raise SystemExit("SigV2 wrong-secret mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0583 signing with the valid secret instead of the wrong one' \
    mut_sigv2_conformance_wrong_secret_removed \
    'lost conformance evidence'

# -- check_transport_shared.sh / check_caps_have_impl.sh -----------------------------------------

mut_transport_shared_reexport_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/conformance/src/sut.rs")
text = path.read_text()
old = "pub use rustfs_gateway::Transport;"
if text.count(old) != 1:
    raise SystemExit("shared Transport re-export mutation subject is not unique")
path.write_text(text.replace(old, "// shared Transport re-export removed", 1))
PYEOF
}
expect_fail check_transport_shared.sh \
    'conformance dropping the facade Transport re-export' \
    mut_transport_shared_reexport_removed \
    'does not re-export'

mut_transport_shared_duplicate_added() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/conformance/src/sut.rs")
text = path.read_text()
old = "pub use rustfs_gateway::Transport;"
if text.count(old) != 1:
    raise SystemExit("duplicate Transport mutation subject is not unique")
path.write_text(text.replace(old, old + "\npub enum Transport { Hyper, Conn }", 1))
PYEOF
}
expect_fail check_transport_shared.sh \
    'conformance restoring a second Transport enum' \
    mut_transport_shared_duplicate_added \
    'defines a second Transport enum'

mut_transport_shared_census_reduced() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/transport.rs")
text = path.read_text()
old = "pub const ALL: [Self; 2] = [Self::Hyper, Self::Conn];"
if text.count(old) != 1:
    raise SystemExit("transport census mutation subject is not unique")
path.write_text(text.replace(old, "pub const ALL: [Self; 1] = [Self::Hyper];", 1))
PYEOF
}
expect_fail check_transport_shared.sh \
    'the shared transport census dropping the self-held path' \
    mut_transport_shared_census_reduced \
    'no longer names both production paths'

mut_caps_unimplemented_advertised() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/conn/body_plan.rs")
text = path.read_text()
old = "const SUPPORTED_KERNEL_TRANSFER_CAPS: TransportCaps = TransportCaps::SENDFILE;"
if text.count(old) != 1:
    raise SystemExit("kernel capability mutation subject is not unique")
path.write_text(text.replace(old, "const SUPPORTED_KERNEL_TRANSFER_CAPS: TransportCaps = TransportCaps::SPLICE;", 1))
PYEOF
}
expect_fail check_caps_have_impl.sh \
    'the response planner advertising splice without an implementation' \
    mut_caps_unimplemented_advertised \
    'has no reviewed implementation mapping'

mut_caps_census_bypassed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/conn/body_plan.rs")
text = path.read_text()
old = "try_into_file_region_for(SUPPORTED_KERNEL_TRANSFER_CAPS)"
if text.count(old) != 1:
    raise SystemExit("capability census use mutation subject is not unique")
path.write_text(text.replace(old, "try_into_file_region_for(TransportCaps::SENDFILE)", 1))
PYEOF
}
expect_fail check_caps_have_impl.sh \
    'response planning bypassing the reviewed capability census' \
    mut_caps_census_bypassed \
    'bypasses the supported capability census'

mut_caps_server_module_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/src/lib.rs")
text = path.read_text()
old = "mod sendfile;"
if text.count(old) != 1:
    raise SystemExit("sendfile module mutation subject is not unique")
path.write_text(text.replace(old, "// sendfile module removed", 1))
PYEOF
}
expect_fail check_caps_have_impl.sh \
    'the server dropping the advertised sendfile backend module' \
    mut_caps_server_module_removed \
    'does not compile the sendfile backend'

mut_caps_platform_call_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/server/src/sendfile.rs")
text = path.read_text()
old = "nix::sys::sendfile::sendfile"
if text.count(old) < 1:
    raise SystemExit("platform sendfile mutation subject is missing")
path.write_text(text.replace(old, "nix::sys::sendfile::missing", 1))
PYEOF
}
expect_fail check_caps_have_impl.sh \
    'the advertised sendfile backend losing its platform call' \
    mut_caps_platform_call_removed \
    'a Linux or Apple sendfile implementation is missing'

# -- check_guard_suite_tail_reachable.sh ---------------------------------------------------------
#
# The guard says which block the end of this file belongs to, so no number of new cases can
# satisfy it. That is the point: a case count cannot tell a case that runs in the default suite
# from one that only ever runs in a mode-scoped shard, because the count rises either way — which
# is why rustfs/gateway#633 and #634 both record their authors finding out by grepping the run log
# for their own case descriptions, after the fact.
#
# Every refusal below exits 1, so the exit code proves nothing on its own — a guard that refused
# every suite handed to it would satisfy all five at once. Each case therefore names both the
# refusal it expects and the refusal it must not get, which is the shape gateway#640's budget-floor
# pair settled on. The accepting case is the other half: without it this would be a ban on mode
# gates rather than a rule about where the last one may sit.
#
# Each mutation writes its shell through a heredoc, which is also what the guard has to see
# through: heredoc bodies sit at column zero, so a guard reading column-zero `if`/`fi` as block
# structure would read these very fixtures as blocks of the suite itself.
guard_tail_reachable_case() {
    local expected="$1" forbidden="$2" desc="$3" mutate="$4"
    local sandbox output rc=0
    cases=$((cases + 1))
    guard_case_owned "$cases" || return 0
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    output="$(GATEWAY_CHECK_ROOT="$sandbox" \
        "${SCRIPT_DIR}/check_guard_suite_tail_reachable.sh" 2>&1)" || rc=$?
    if [[ "$rc" -eq 1 && "$output" == *"$expected"* && "$output" != *"$forbidden"* ]]; then
        pass_msg "check_guard_suite_tail_reachable.sh catches: ${desc}"
    else
        fail_msg "check_guard_suite_tail_reachable.sh did NOT catch: ${desc} — rc ${rc}: ${output}"
    fi
}

mut_guard_suite_tail_is_mode_gated() {
    cat >>scripts/test_guard_scripts.sh <<'SUITE'

if [[ "$ERROR_STATUS_ONLY" == 1 ]]; then
:
fi
SUITE
}
guard_tail_reachable_case 'a gate the default run does not enter' 'declares no mode gate' \
    'a mode-gated block written as the last block in the suite' \
    mut_guard_suite_tail_is_mode_gated

mut_guard_suite_mode_switches_renamed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = '_ONLY"'
if old not in text:
    raise SystemExit("the suite names no mode switch to rename")
path.write_text(text.replace(old, '_MODE"'))
PYEOF
}
guard_tail_reachable_case 'declares no mode gate' 'a gate the default run does not enter' \
    'a suite with no mode gate left to read, which must fail rather than pass vacuously' \
    mut_guard_suite_mode_switches_renamed

# The other half of the same fail-closed rule: a gate that is still there but spelled in a way the
# guard cannot evaluate must be refused, not skipped over in favour of the previous gate — which
# would silently report on the wrong block and let a mode-gated tail through.
mut_guard_suite_tail_gate_unreadable() {
    cat >>scripts/test_guard_scripts.sh <<'SUITE'

if [[ "$ERROR_STATUS_ONLY" == 1 ]] ||
    [[ "$BUILD_GUARDS_ONLY" == 1 ]]; then
:
fi
SUITE
}
guard_tail_reachable_case 'in a spelling this guard cannot read' 'declares no mode gate' \
    'a last mode gate spelled over two lines, which the guard must refuse rather than skip' \
    mut_guard_suite_tail_gate_unreadable

mut_guard_suite_blocks_unbalanced() {
    cat >>scripts/test_guard_scripts.sh <<'SUITE'

fi
SUITE
}
guard_tail_reachable_case 'do not nest cleanly' 'declares no mode gate' \
    'a suite whose top-level blocks no longer balance, leaving the tail undecidable' \
    mut_guard_suite_blocks_unbalanced

mut_guard_suite_tail_gate_nested() {
    cat >>scripts/test_guard_scripts.sh <<'SUITE'

if true; then
if [[ "$QUIRK_LEDGER_ONLY" == 0 && "$DTO_COMPILER_ONLY" == 0 && "$BUILD_GUARDS_ONLY" == 0 && "$ERROR_STATUS_ONLY" == 0 ]]; then
:
fi
fi
SUITE
}
guard_tail_reachable_case 'is nested inside another block' 'a gate the default run does not enter' \
    'a default-reachable last gate buried inside a block whose own condition is unread' \
    mut_guard_suite_tail_gate_nested

mut_guard_suite_tail_is_default_gated() {
    cat >>scripts/test_guard_scripts.sh <<'SUITE'

if [[ "$QUIRK_LEDGER_ONLY" == 0 && "$DTO_COMPILER_ONLY" == 0 && "$BUILD_GUARDS_ONLY" == 0 && "$ERROR_STATUS_ONLY" == 0 ]]; then
:
fi
SUITE
}
expect_guard_pass check_guard_suite_tail_reachable.sh \
    'a default-reachable block written as the last block in the suite' \
    mut_guard_suite_tail_is_default_gated

fi

guard_finish
