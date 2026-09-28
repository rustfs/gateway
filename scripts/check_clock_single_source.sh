#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_clock_single_source.sh
#
# WHAT THIS CHECKS
#   That the protocol path reads a clock in exactly two places, and that the two
#   do not read each other's:
#
#     crates/sig/src/clock.rs      the ONLY SystemTime::now() — the wall clock
#     crates/gateway/src/clock.rs  the protocol-path Instant::now() — the monotonic request clock
#     crates/server/src/io.rs      transport I/O deadlines; never visible to protocol decisions
#
#   Three assertions, all of which must hold:
#
#     1. Each of those two files really does contain its call. A guard whose
#        subject has been refactored away passes vacuously, which reads exactly
#        like a guard that checked something.
#     2. No other file under crates/*/src reads either clock.
#     3. Neither of the two reads the OTHER clock, so the wall source cannot
#        quietly acquire a monotonic reading or the reverse.
#     4. No file under crates/*/src renames either clock type (`use ... as`,
#        `type X = ...`). A renamed type reads the clock as `Wall::now()`,
#        which no textual search for the real name can see, so a rename is
#        refused outright rather than chased.
#
#   A reading is `SystemTime::now` or `Instant::now` as a path, called or not,
#   with any whitespace around `::`: `let read = Instant::now; read()` is a
#   reading too.
#
# WHY
#   Two separate rules, and both are the silent kind.
#
#   ONE READING PER REQUEST. Every time-dependent check in one admission reads
#   the same snapshot: `RequestNow` is captured once, at the top of the pipeline,
#   and passed down. A second SystemTime::now() somewhere below means the skew
#   check and the expiry check can straddle a second boundary, so a presigned URL
#   is inside its window when it is admitted and outside it when its lifetime is
#   computed — a rejection nobody can reproduce.
#
#   TWO CLOCKS, NOT ONE. Rate limiting measures elapsed time and must use the
#   monotonic source; signature expiry compares against an absolute timestamp and
#   must use the wall clock. Mixing them is steerable: an NTP step backwards makes
#   a wall-clock limiter stop refilling, a step forwards refills every bucket at
#   once, and a monotonic "expiry" has no absolute time to compare `x-amz-date`
#   against at all.
#
# WHAT IS DELIBERATELY NOT SCANNED
#   crates/conformance/** — the test harness. It times its own runs and paces its
#   own sockets, which is measurement of the suite rather than of a request, and
#   no request path passes through it. tests/ and benches/ are out of scope for
#   the same reason: a test that measures elapsed time is measuring the test.
#
# HOW TO EXEMPT
#   There is no allowance file, and adding one should be an argument on the issue
#   first. If a third clock source is genuinely needed, add it to ALLOWED below in
#   the same PR that adds the source, with the reason in the commit message.
#
# USAGE
#   scripts/check_clock_single_source.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_clock_single_source.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

cd "$ROOT_DIR"

WALL_SOURCE='crates/sig/src/clock.rs'
WALL_CALL='SystemTime::now'
MONOTONIC_SOURCE='crates/gateway/src/clock.rs'
MONOTONIC_CALL='Instant::now'
TRANSPORT_TIMER_SOURCE='crates/server/src/io.rs'

status=0

fail() {
    printf 'check_clock_single_source: %s\n' "$1" >&2
    status=1
}

# --- 1. The two subjects exist and still hold their call. --------------------
#
# `|| exit 0` would be wrong here: these files always exist, so a missing one is
# a refactor that moved the clock, not an input that has not been created yet.
for pair in "${WALL_SOURCE}|${WALL_CALL}" "${MONOTONIC_SOURCE}|${MONOTONIC_CALL}"; do
    file="${pair%%|*}"
    call="${pair##*|}"
    if [[ ! -f "$file" ]]; then
        fail "${file} does not exist; this guard's subject has moved and the guard is now checking nothing"
        continue
    fi
    if ! grep -qF "${call}(" "$file"; then
        fail "${file} no longer calls ${call}(); either the clock source moved or this guard needs updating"
    fi
done

if [[ ! -f "$TRANSPORT_TIMER_SOURCE" ]]; then
    fail "${TRANSPORT_TIMER_SOURCE} does not exist; the transport timer allowance is checking nothing"
elif ! grep -q 'struct ProgressIo' "$TRANSPORT_TIMER_SOURCE" || ! grep -qF "${MONOTONIC_CALL}(" "$TRANSPORT_TIMER_SOURCE"; then
    fail "${TRANSPORT_TIMER_SOURCE} no longer contains the transport progress timer this allowance names"
fi

# --- 2. Neither source reads the other's clock. ------------------------------
if [[ -f "$WALL_SOURCE" ]] && grep -qF "${MONOTONIC_CALL}(" "$WALL_SOURCE"; then
    fail "${WALL_SOURCE} reads the monotonic clock; the wall source must not, or expiry and rate limiting share a clock"
fi
if [[ -f "$MONOTONIC_SOURCE" ]] && grep -qF "${WALL_CALL}(" "$MONOTONIC_SOURCE"; then
    fail "${MONOTONIC_SOURCE} reads the wall clock; the monotonic source must not, or a limiter becomes steerable by NTP"
fi

# A path to either clock's `now`, called or not, whitespace-insensitive, bare or as the
# qualified `<SystemTime>::now`.
READING_PATTERN="\\b(SystemTime|Instant)[[:space:]]*>?[[:space:]]*::[[:space:]]*now\\b"
# A renamed clock type: `SystemTime as Wall`, or `type Wall = std::time::Instant;`.
RENAME_PATTERN="\\b(SystemTime|Instant)[[:space:]]+as[[:space:]]+[A-Za-z_]|\\btype[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*(<[^>]*>)?[[:space:]]*=[[:space:]]*[A-Za-z0-9_:]*\\b(SystemTime|Instant)[[:space:]]*;"

# --- 3. Nothing else on the protocol path reads either clock. ----------------
while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    case "$file" in
        crates/conformance/*) continue ;;
        "$WALL_SOURCE" | "$MONOTONIC_SOURCE" | "$TRANSPORT_TIMER_SOURCE") continue ;;
    esac
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        fail "${file}:${hit} — the protocol path reads a clock outside ${WALL_SOURCE} and ${MONOTONIC_SOURCE}"
    done < <(grep -nE "$READING_PATTERN" "$file" || true)
# The index and the working tree together, for the reason recorded in
# check_no_planning_docs.sh: a bare `git ls-files` cannot see a brand-new file, so
# a stray clock read in one would stay invisible until the commit that lands it.
done < <(git ls-files --cached --others --exclude-standard -- 'crates/*/src/*.rs' 'crates/*/src/**/*.rs' 2>/dev/null || true)

# --- 4. Nothing renames either clock type, the sources included. -------------
while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    case "$file" in
        crates/conformance/*) continue ;;
    esac
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        fail "${file}:${hit} — a renamed clock type hides every later reading from this guard; name SystemTime and Instant as themselves"
    done < <(grep -nE "$RENAME_PATTERN" "$file" || true)
done < <(git ls-files --cached --others --exclude-standard -- 'crates/*/src/*.rs' 'crates/*/src/**/*.rs' 2>/dev/null || true)

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

The pipeline takes one wall-clock reading per request and hands it down; the
limiter takes its own monotonic readings. Route the new call through
`crate::clock::Clock` (wall) or `crate::clock::MonotonicClock` (monotonic)
instead of reading a clock where you stand. See docs/capacity-planning.md and
the module documentation of crates/gateway/src/clock.rs.
EOF
fi

exit "$status"
