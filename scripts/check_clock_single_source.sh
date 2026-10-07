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

# Preserve grep's regex and symlink behavior, but pass it batches of NUL-delimited paths.
# xargs bounds each argument list; its child maps only grep's no-match status to success.
clock_inputs="$(mktemp "${TMPDIR:-/tmp}/gateway-clock-inputs.XXXXXX")"
trap 'rm -f "$clock_inputs"' EXIT

scan_clock_inputs() {
    local pattern="$1" diagnostic="$2" output rc=0 hit
    shift 2
    if ! git ls-files --cached --others --exclude-standard -z -- \
        'crates/*/src/*.rs' 'crates/*/src/**/*.rs' ':(exclude)crates/conformance/**' "$@" >"$clock_inputs"; then
        fail 'cannot scan clock inputs: Git input enumeration failed'
        return
    fi
    output="$(xargs -0 sh -c '
        pattern="$1"; shift
        [ "$#" -gt 0 ] || exit 0
        grep -nHE -- "$pattern" "$@"
        code=$?
        [ "$code" -ne 1 ] || exit 0
        exit "$code"
    ' clock-scan "$pattern" <"$clock_inputs" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        fail "cannot scan clock inputs: ${output}"
        return
    fi
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        fail "${hit} — ${diagnostic}"
    done <<<"$output"
}

# --- 3. Nothing else on the protocol path reads either clock. ----------------
scan_clock_inputs "$READING_PATTERN" \
    "the protocol path reads a clock outside ${WALL_SOURCE} and ${MONOTONIC_SOURCE}" \
    ":(exclude)${WALL_SOURCE}" ":(exclude)${MONOTONIC_SOURCE}" ":(exclude)${TRANSPORT_TIMER_SOURCE}"

# --- 4. Nothing renames either clock type, the sources included. -------------
scan_clock_inputs "$RENAME_PATTERN" \
    'a renamed clock type hides every later reading from this guard; name SystemTime and Instant as themselves'

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
