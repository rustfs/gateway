#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_policy_snapshot_once.sh
#
# WHAT THIS CHECKS
#   That the policy snapshot a request is judged against is taken in exactly
#   ONE place in the shipped pipeline.
#
#   1. `PolicySource::snapshot` is declared where this guard expects it.
#   2. Across `crates/*/src/**`, `.snapshot(` is called exactly once outside the
#      trait's own file — and that call is in the pipeline file below.
#   3. The pipeline holds the source behind a field rather than constructing one,
#      so a second stage cannot mint its own reader.
#   4. The pipeline calls it BEFORE it calls the authorizer, because a reading
#      taken after the first reader is not the reading that reader used.
#
# WHY
#   Two readings of policy inside one request are a TOCTOU window: the first
#   reader admits under the old rules, the second refuses under the new ones, or
#   the other way round — and the caller chooses when the window opens by
#   choosing when to send. Nothing in a response shows it, no conformance case
#   can express it, and the only integration test that can (`snapshot()` was
#   called once) is a test somebody has to remember to keep. This is the part
#   that does not depend on remembering.
#
#   This is the concrete instance of the Epic's `check_config_load_once.sh`,
#   which was named as a P3 guard and never written. It is scoped to policy
#   because policy is the load whose second reading is a security boundary.
#
# HOW TO EXEMPT
#   Not applicable. A second reader of policy takes the snapshot it was handed;
#   if it cannot be handed one, that is a threading problem and the fix is to
#   thread it.
#
# USAGE
#   scripts/check_policy_snapshot_once.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_policy_snapshot_once.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

cd "$ROOT_DIR"

# Named rather than discovered, for the reason every guard in this directory
# names its subject: a guard that silently finds nothing is the defect this
# repository has produced seven times.
TRAIT_FILE='crates/gateway/src/ext/policy.rs'
PIPELINE_FILE='crates/gateway/src/service.rs'
READER_FILE='crates/gateway/src/request_deadline.rs'
# The replaceable request generation the pipeline captures once at entry and reads the source from.
RUNTIME_FILE='crates/gateway/src/routing.rs'
# The field the captured generation holds the source behind.
FIELD='policy_source'

status=0

report() {
    printf '%s\n' "$1" >&2
    status=1
}

for file in "$TRAIT_FILE" "$PIPELINE_FILE" "$READER_FILE" "$RUNTIME_FILE"; do
    if [[ ! -f "$file" ]]; then
        report "check_policy_snapshot_once: ${file} does not exist; the guard cannot find the surface it is written about"
        exit 1
    fi
done

# Shipped source only. A test that reads a snapshot twice is a test *about* the
# property; the property itself is a claim about the pipeline.
#
# The `crates/*/src/` restriction is applied in the shell rather than as a
# pathspec: git switches a wildcard to pathname semantics as soon as an
# `:(exclude)` pathspec is present, so `crates/*/src/*.rs` alongside `:!:target/*`
# silently matches nothing — which is exactly the "guard reading an empty list"
# failure the count below exists to catch, arriving through the argument list.
sources=()
while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    case "$file" in
        crates/*/src/*) sources+=("$file") ;;
        *) ;;
    esac
done < <(git ls-files --cached --others --exclude-standard -- '*.rs' ':!:target/*' ':!:generated/*' ':!:*/generated/*' 2>/dev/null || true)

if [[ "${#sources[@]}" -eq 0 ]]; then
    report "check_policy_snapshot_once: no crate sources found; this guard's input is missing, which is a failure and not a skip"
    exit 1
fi

code_of() {
    awk '{ s = $0; sub(/^[ \t]+/, "", s); if (s ~ /^\/\//) { print "" } else { print $0 } }' "$1"
}

# `grep -q` closes the pipe on its first match, which kills `code_of`'s awk with
# SIGPIPE and — under `set -o pipefail` — reports the whole pipeline as failed.
# A guard built on that reads "the pattern is absent" every time the pattern is
# present, which is the wrong answer in the direction that matters. Counting
# reads the input to the end.
matches() {
    local count
    count="$(code_of "$1" | grep -cE "$2" || true)"
    [[ "$count" -gt 0 ]]
}

# -----------------------------------------------------------------------------
# Rule 1 — the trait is where this guard thinks it is.
# -----------------------------------------------------------------------------
if ! matches "$TRAIT_FILE" '^pub[ \t]+trait[ \t]+PolicySource[ \t]*:'; then
    report "check_policy_snapshot_once: no \`pub trait PolicySource\` in ${TRAIT_FILE}; the guard is reading a file that no longer declares its subject"
fi
if ! matches "$TRAIT_FILE" 'fn[ \t]+snapshot[ \t]*<'; then
    report "check_policy_snapshot_once: PolicySource in ${TRAIT_FILE} declares no \`snapshot\` method; the call-site count below would be counting nothing"
fi

# -----------------------------------------------------------------------------
# Rule 2 — exactly one call site, in the timeout helper invoked by the pipeline.
#
# The trait file itself is excluded: it holds the declaration, the blanket
# `Arc<T>` forward, and the default implementation, none of which is a reading
# taken during a request.
# -----------------------------------------------------------------------------
CALL_RE='\.snapshot[ \t]*\('
call_sites=0
for file in "${sources[@]}"; do
    [[ "$file" == "$TRAIT_FILE" ]] && continue
    hits="$(code_of "$file" | grep -cE "$CALL_RE" || true)"
    [[ "$hits" -eq 0 ]] && continue
    call_sites=$((call_sites + hits))
    if [[ "$file" != "$READER_FILE" ]]; then
        report "${file}: reads a policy snapshot; the one reading per request is taken in ${READER_FILE} and handed to every reader, because two readings are a window a caller chooses the timing of"
    elif [[ "$hits" -ne 1 ]]; then
        report "${READER_FILE}: ${hits} readings of policy in one request; there must be exactly one, and every reader must be handed it"
    fi
done

if [[ "$call_sites" -eq 0 ]]; then
    report "check_policy_snapshot_once: nothing in crates/*/src reads a policy snapshot at all; either the pipeline stopped taking one — which means no authorizer is judging against a consistent view — or this guard's pattern has stopped matching"
fi

# -----------------------------------------------------------------------------
# Rule 3 — the pipeline holds a source, it does not build one.
#
# The source lives in the replaceable generation each request captures at entry,
# so a hot update cannot hand one request two sources.
# -----------------------------------------------------------------------------
if ! matches "$RUNTIME_FILE" "${FIELD}:[ \t]*Arc<dyn[ \t]+PolicySource>"; then
    report "${RUNTIME_FILE}: no \`${FIELD}: Arc<dyn PolicySource>\` field; the source must be assembled once and held, not constructed where it is read"
fi

# -----------------------------------------------------------------------------
# Rule 4 — the reading precedes the first reader.
#
# Line order in one file is a crude test and an exact one here: both calls are
# in the same function, and a snapshot taken after the authorizer ran is not the
# snapshot the authorizer used.
# -----------------------------------------------------------------------------
snapshot_line="$(code_of "$PIPELINE_FILE" | grep -nE 'match[ \t]+policy_snapshot_with_timeout[ \t]*\(' | head -n 1 | cut -d: -f1 || true)"
authorize_line="$(code_of "$PIPELINE_FILE" | grep -nE '\.authorize_(route|input)[ \t]*\(' | head -n 1 | cut -d: -f1 || true)"
if [[ -z "$snapshot_line" ]]; then
    report "${PIPELINE_FILE}: the one policy snapshot is not awaited through the hard-timeout wrapper in the request pipeline"
elif [[ -z "$authorize_line" ]]; then
    report "${PIPELINE_FILE}: nothing calls \`authorize\`; either the pipeline no longer authorises anything, or rule 4 is comparing against nothing"
elif [[ -n "$snapshot_line" ]] && [[ "$snapshot_line" -ge "$authorize_line" ]]; then
    report "${PIPELINE_FILE}:${snapshot_line}: the policy snapshot is taken at or after the authorizer is called (line ${authorize_line}); a reading taken after the reader ran is not the reading that reader used"
fi

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

One-reading-of-policy rule violated. See rustfs/backlog#1732 (P6-02) and
crates/gateway/src/ext/policy.rs.
Every reader of policy inside one request must be handed the same snapshot. A second reading opens
a window between two readers that the caller chooses the timing of, and no response and no
conformance case can show it.
EOF
    exit "$status"
fi

printf 'OK: policy is read once per request in %s, invoked by %s (line %s), before the authorizer (line %s)\n' \
    "$READER_FILE" "$PIPELINE_FILE" "$snapshot_line" "$authorize_line"
exit 0
