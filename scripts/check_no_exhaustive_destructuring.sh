#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_exhaustive_destructuring.sh
#
# WHAT THIS CHECKS
#   That no hand-written code destructures a generated dto without a trailing
#   `..` — that is, `let Foo { a, b } = x;` rather than `let Foo { a, b, .. } = x;`.
#
# WHY
#   Exhaustive destructuring is the one pattern that a new field breaks, and it
#   is the reason dto structs cannot simply grow. AWS adds fields to the S3 model
#   every quarter; each one would turn into a compile error at every such site,
#   for no benefit, since these sites want two fields out of forty.
#
#   This is the counterpart to check_no_dto_non_exhaustive.sh. That guard keeps
#   construction additive; this one keeps consumption additive. Together they are
#   what makes "a new optional field is a minor change" true rather than aspirational.
#
#   See ADR-0004 rule P3.
#
# HOW TO EXEMPT
#   Add a line to `scripts/allowances/exhaustive-destructuring-allowances.txt`
#   in the form `<path>:<line>` with a comment giving the reason. Exhaustive
#   destructuring is occasionally right — a test that asserts the full shape of
#   a small struct, for instance — but it should be a decision, not an accident.
#
# USAGE
#   scripts/check_no_exhaustive_destructuring.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_no_exhaustive_destructuring.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ALLOWANCE_FILE="${SCRIPT_DIR}/allowances/exhaustive-destructuring-allowances.txt"
cd "$ROOT_DIR"

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

# The dto type names to look for, taken from what codegen actually emitted, so the
# guard cannot drift from the model.
#
# The layout is module-per-operation, so the real type names ARE `Input` and
# `Output`. Excluding them as "too common" — the first instinct — removes the only
# names that matter and leaves a guard that cannot fail. They are therefore matched
# only in qualified position (`...::Output {`), which is how a dto is actually named
# at a destructuring site, while a local `struct Output` in some unrelated module
# stays out of scope.
dto_names="$(git ls-files -- 'generated/dto/*' 'generated/dto/**' 2>/dev/null |
    xargs grep -ho '^pub struct [A-Za-z0-9_]*' 2>/dev/null |
    sed 's/^pub struct //' |
    grep -vxE 'Input|Output' |
    sort -u || true)"

# Flat aliases (`GetBucketLocationOutput`) are ordinary names and match unqualified.
flat_names="$(git ls-files -- 'generated/dto/flat.rs' 2>/dev/null |
    xargs grep -hoE 'as [A-Za-z0-9_]+' 2>/dev/null |
    sed 's/^as //' |
    sort -u || true)"
dto_names="$(printf '%s\n%s\n' "$dto_names" "$flat_names" | grep -v '^$' | sort -u || true)"

if [[ -z "$dto_names" ]]; then
    # Nothing generated yet: the guard has nothing to say, and saying it loudly
    # would train people to ignore it.
    exit 0
fi

pattern="$(printf '%s' "$dto_names" | paste -sd'|' -)"
# `::Input` / `::Output` in qualified position, or any of the names above.
qualified='::(Input|Output)'
pattern="(${pattern}|${qualified})"

while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    [[ -f "$file" ]] || continue
    case "$file" in
    generated/*) continue ;; # generated code is not hand-written
    esac
    while IFS=: read -r lineno text; do
        [[ -n "${lineno:-}" ]] || continue
        # A destructuring pattern with no `..` before the closing brace.
        if printf '%s' "$text" | grep -qE "(${pattern})[[:space:]]*\{[^}]*\}" &&
            ! printf '%s' "$text" | grep -qE "(${pattern})[[:space:]]*\{[^}]*\.\.[^}]*\}"; then
            if is_allowed "${file}:${lineno}"; then continue; fi
            printf '%s:%s: exhaustive destructuring of a dto; add `..` so a new field stays a minor change (ADR-0004 P3)\n' \
                "$file" "$lineno" >&2
            status=1
        fi
    done < <(grep -nE "(let|if let|while let|match)[^=]*(${pattern})[[:space:]]*\{" "$file" 2>/dev/null || true)
done < <(git ls-files -- '*.rs' 2>/dev/null || true)

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

ADR-0004 P3: destructure dto types with a trailing `..`. AWS grows these structs
on its own schedule, and an exhaustive pattern turns every addition into a
compile error at a site that wanted two fields out of forty.
EOF
fi

exit "$status"
