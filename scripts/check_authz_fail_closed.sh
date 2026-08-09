#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_authz_fail_closed.sh
#
# WHAT THIS CHECKS
#   Seven rules about the `Authorizer` extension point's contract, asserted over
#   the source rather than described in a rustdoc paragraph nobody re-reads.
#
#   1. `Decision` declares EXACTLY the three states in STATES below. A fourth
#      one is a security decision, not a refactor.
#   2. `Decision` cannot be conjured. No `impl Default for Decision`, no
#      `impl From<_> for Decision`, no `from_bool` / `from_result` constructor:
#      every one of those is a way for a verdict to exist without anyone having
#      decided anything, and `bool` in particular has no third state.
#   3. A `Decision` is INTERPRETED in exactly one file — the trait's own. Any
#      other file may produce one or pass one along; the moment a second place
#      decides what a verdict means, "Indeterminate is a refusal" is true in one
#      of them and unexamined in the other.
#   4. The interpretation is TOTAL. `Decision::settle` names all three states
#      and has no `_` arm, so a fourth state fails to compile there rather than
#      falling into whichever branch the wildcard happened to name.
#   5. `Denial` carries nothing and cannot choose its code. No fields, and no
#      constructor taking an `ErrorCode`. A policy that could answer
#      `404 NoSuchBucket` for the buckets it hides and `403` for the ones it
#      merely refuses has built an enumeration oracle out of the difference.
#   6. `AuthzAuditSink` cannot speak. Its method returns nothing and takes no
#      `&mut`, and no example ships a copy-pasteable allow-all authorizer.
#   7. The complete c-azc-0001..0030 acceptance matrix remains attached to
#      executable examples, compile-fail probes, and tests.
#
# WHY
#   rustfs's GHSA-j548-9grx-fh4f deleted a retained object because an unreadable
#   bucket record was read as "no Object Lock configured here". `Indeterminate`
#   is the shape that makes that unspellable — but only while nothing else in
#   the workspace is allowed to decide what it means. Rules 3 and 4 are that
#   "only".
#
#   Rule 6's second half is about propagation rather than about this repository:
#   an example is API, and `allow_when(|_| true)` is one paste away from a
#   production gateway with no authorisation at all.
#
# HOW TO EXEMPT
#   Not applicable. A fourth verdict state, a second interpretation site, or a
#   refusal that can choose its own code each need the argument written down in
#   an issue first — and then this guard changed in the same PR.
#
# USAGE
#   scripts/check_authz_fail_closed.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_authz_fail_closed.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

cd "$ROOT_DIR"

# The files this guard is written about. Named rather than discovered: if one
# moves, this guard must be pointed at the new home in the same change, and a
# guard that silently finds nothing is the defect this repository has produced
# seven times.
DECISION_FILE='crates/core/src/authz/mod.rs'
AUTHORIZER_FILE='crates/gateway/src/ext/authorizer.rs'
AUDIT_FILE='crates/gateway/src/ext/authz_audit.rs'
# Exactly the states `Decision` may declare, space separated and in any order.
STATES='Allow Deny Indeterminate'
# The one function permitted to turn a verdict into a continuation.
SETTLE='settle'

status=0

report() {
    printf '%s\n' "$1" >&2
    status=1
}

for file in "$DECISION_FILE" "$AUTHORIZER_FILE" "$AUDIT_FILE"; do
    if [[ ! -f "$file" ]]; then
        report "check_authz_fail_closed: ${file} does not exist; the guard cannot find the surface it is written about"
        exit 1
    fi
done

# `--cached --others --exclude-standard`, for the reason check_ct_eq.sh gives: a
# bare `git ls-files` lists only tracked files, so a brand-new module that
# interpreted a `Decision` would be invisible to this guard right up until the
# commit that added it.
sources=()
while IFS= read -r file; do
    [[ -n "$file" ]] && sources+=("$file")
done < <(git ls-files --cached --others --exclude-standard -- '*.rs' ':!:target/*' ':!:generated/*' ':!:*/generated/*' 2>/dev/null || true)

if [[ "${#sources[@]}" -eq 0 ]]; then
    report "check_authz_fail_closed: no Rust sources found; this guard's input is missing, which is a failure and not a skip"
    exit 1
fi

# Comment-only lines are blanked, keeping line numbers intact. Every rule below
# reads prose that legitimately describes what it forbids.
code_of() {
    awk '{ s = $0; sub(/^[ \t]+/, "", s); if (s ~ /^\/\//) { print "" } else { print $0 } }' "$1"
}

# Prints the body of a brace-delimited item starting at the line matching $2.
body_of() {
    code_of "$1" | awk -v start="$2" '
        BEGIN { inside = 0; depth = 0 }
        {
            line = $0
            if (inside == 0) {
                if (line ~ start) { inside = 1; depth = 0 } else { print ""; next }
            }
            opens = gsub(/\{/, "{", line)
            closes = gsub(/\}/, "}", line)
            print $0
            depth += opens - closes
            if (depth <= 0 && opens + closes > 0) { inside = 0 }
        }
    '
}

# -----------------------------------------------------------------------------
# Rule 1 — exactly the three states.
# -----------------------------------------------------------------------------
declared="$(body_of "$DECISION_FILE" '^pub[ \t]+enum[ \t]+Decision[ \t]*[{]' |
    awk '{ s = $0; sub(/^[ \t]+/, "", s); if (match(s, /^[A-Z][A-Za-z0-9_]*[ \t]*,/)) { v = substr(s, RSTART, RLENGTH); sub(/[ \t]*,$/, "", v); print v } }' |
    sort | tr '\n' ' ')"
declared="${declared% }"
expected="$(printf '%s\n' $STATES | sort | tr '\n' ' ')"
expected="${expected% }"

if [[ -z "$declared" ]]; then
    report "check_authz_fail_closed: no \`pub enum Decision\` found in ${DECISION_FILE}, or it declares no variants; the guard is reading nothing"
elif [[ "$declared" != "$expected" ]]; then
    report "${DECISION_FILE}: Decision declares [${declared}] and may declare only [${expected}]; a fourth verdict state is a security decision and needs the argument written down before the variant"
fi

# -----------------------------------------------------------------------------
# Rule 2 — a verdict cannot be conjured.
# -----------------------------------------------------------------------------
# The derive list is the attribute block immediately above the declaration, so it
# is read with a window rather than with a body scan — a body scan starts *at*
# the declaration and would never see it.
derived="$(code_of "$DECISION_FILE" | awk '
    /^#\[/ { attrs = attrs $0; next }
    /^pub[ \t]+enum[ \t]+Decision[ \t]*[{]/ { print attrs; exit }
    { attrs = "" }
')"
if [[ "$(printf '%s' "$derived" | grep -cE 'Default' || true)" -gt 0 ]]; then
    report "${DECISION_FILE}: Decision derives Default; a default verdict is a verdict nobody reached, and whichever variant is first would become the answer for every code path that forgot to decide"
fi

while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    report "${DECISION_FILE}:${hit%%:*}: Decision must not be constructible from something that is not a decision; a bool has no third state"
done < <(body_of "$DECISION_FILE" '^impl[ \t]+Decision[ \t]*[{]' | grep -nE 'fn[ \t]+(from_bool|from_result|from_option)' || true)

for file in "${sources[@]}"; do
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: an impl of Default or From for Decision; a verdict must come from a decision and from nothing else"
    done < <(code_of "$file" | grep -nE '^[ \t]*impl([ \t]*<[^>]*>)?[ \t]+(Default|From<[^>]*>)[ \t]+for[ \t]+Decision' || true)
done

# -----------------------------------------------------------------------------
# Rule 3 — one interpretation site.
#
# A match arm on a `Decision` variant is what "interpreting" looks like in
# Rust. Producing one (`Decision::Deny` as an expression) is unrestricted; it is
# reading one and branching that must have a single home. Test code is
# deliberately included: a suite that matched on a verdict would be a second
# place the meaning is written down, and the assertions in it would drift.
# -----------------------------------------------------------------------------
ARM_RE='(Decision|Self)::(Allow|Deny|Indeterminate)([ \t]*\|[ \t]*(Decision|Self)::(Allow|Deny|Indeterminate))*[ \t]*=>'
interpreters=0
for file in "${sources[@]}"; do
    hits="$(code_of "$file" | grep -cE "$ARM_RE" || true)"
    [[ "$hits" -eq 0 ]] && continue
    if [[ "$file" == "$DECISION_FILE" ]]; then
        interpreters=$((interpreters + hits))
        continue
    fi
    report "${file}: matches on a Decision variant; the meaning of a verdict is written down in ${DECISION_FILE} and nowhere else, or 'Indeterminate is a refusal' becomes true in one place and unexamined in another"
done

if [[ "$interpreters" -eq 0 ]]; then
    report "check_authz_fail_closed: no match arm on a Decision variant anywhere, including ${DECISION_FILE}; the detection pattern has stopped matching and rule 3 is checking nothing"
fi

# -----------------------------------------------------------------------------
# Rule 4 — the interpretation is total.
# -----------------------------------------------------------------------------
settle_body="$(body_of "$DECISION_FILE" "fn[ \\t]+${SETTLE}[ \\t]*[(]")"
if [[ -z "$(printf '%s' "$settle_body" | tr -d '[:space:]')" ]]; then
    report "check_authz_fail_closed: no \`fn ${SETTLE}\` in ${DECISION_FILE}; the one interpretation of a verdict has no home and rule 4 is checking nothing"
else
    for state in $STATES; do
        if [[ "$(printf '%s\n' "$settle_body" | grep -cE "Self::${state}[ \t]*(\||=>)" || true)" -eq 0 ]]; then
            report "${DECISION_FILE}: ${SETTLE} does not name Self::${state}; every state must be answered explicitly, because the one that is not is the one that falls through"
        fi
    done
    if [[ "$(printf '%s\n' "$settle_body" | grep -cE '^[ \t]*_[ \t]*=>' || true)" -gt 0 ]]; then
        report "${DECISION_FILE}: ${SETTLE} has a wildcard arm; a fourth verdict state must fail to compile here rather than inherit whichever branch the wildcard named"
    fi
fi

# -----------------------------------------------------------------------------
# Rule 5 — the refusal carries nothing and chooses nothing.
# -----------------------------------------------------------------------------
denial_decl="$(code_of "$DECISION_FILE" | grep -nE '^pub[ \t]+struct[ \t]+Denied\b' || true)"
if [[ -z "$denial_decl" ]]; then
    report "check_authz_fail_closed: no \`pub struct Denied\` in ${DECISION_FILE}; rule 5 is checking nothing"
elif [[ "$(body_of "$DECISION_FILE" '^pub[ \t]+struct[ \t]+Denied[ \t]*[{]' | grep -cE 'pub[ \t]+[a-z_][A-Za-z0-9_]*[ \t]*:|ErrorCode' || true)" -gt 0 ]]; then
    report "${DECISION_FILE}: Denied exposes a field or carries an ErrorCode; an authorization refusal may retain only its private audit decision"
fi

while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    report "${DECISION_FILE}:${hit%%:*}: a Denial constructor takes an ErrorCode; an authorisation refusal is 403 AccessDenied and nothing else, because a policy that can answer 404 for the buckets it hides has built an enumeration oracle out of the difference"
done < <(body_of "$DECISION_FILE" '^impl[ \t]+Denied[ \t]*[{]' | grep -nE 'fn[ \t]+[a-z_]+[ \t]*[(][^)]*:[ \t]*ErrorCode' || true)

# -----------------------------------------------------------------------------
# Rule 6 — the audit sink cannot speak, and no example ships an allow-all.
# -----------------------------------------------------------------------------
sink_body="$(body_of "$AUDIT_FILE" '^pub[ \t]+trait[ \t]+AuthzAuditSink[ \t]*:')"
sink_methods="$(printf '%s\n' "$sink_body" | grep -cE '^[ \t]*fn[ \t]+[a-z_]' || true)"
if [[ "$sink_methods" -eq 0 ]]; then
    report "check_authz_fail_closed: the AuthzAuditSink trait was not found in ${AUDIT_FILE}, or declares no methods; rule 6 is reading nothing"
fi
while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    report "${AUDIT_FILE}:${hit%%:*}: an AuthzAuditSink method returns a value or takes a mutable reference; a sink that can answer is a sink that can overturn a refusal, and the whole point of the hook is that it cannot"
done < <(printf '%s\n' "$sink_body" | grep -nE '^[ \t]*fn[ \t]+[a-z_].*(->|&[ \t]*mut)' || true)

ALLOW_ALL_RE='(allow_when[ \t]*\([ \t]*\|_[^|]*\|[ \t]*true|decide_with[ \t]*\([ \t]*\|_[^|]*\|[ \t]*Decision::Allow)'
examples=()
while IFS= read -r file; do
    [[ -n "$file" ]] && examples+=("$file")
done < <(printf '%s\n' "${sources[@]}" | grep -E '(^|/)examples/' || true)

if [[ "${#examples[@]}" -eq 0 ]]; then
    report "check_authz_fail_closed: no example sources found; rule 6's second half is checking nothing"
else
    for file in "${examples[@]}"; do
        while IFS= read -r hit; do
            [[ -z "$hit" ]] && continue
            report "${file}:${hit%%:*}: an example ships an unconditional allow; an example is API, and this one is a paste away from a gateway with no authorisation at all"
        done < <(code_of "$file" | grep -nE "$ALLOW_ALL_RE" || true)
    done
fi

# -----------------------------------------------------------------------------
# Rule 7 — all thirty acceptance cases remain represented by executable code.
# -----------------------------------------------------------------------------
declared_cases="$({
    for file in "${sources[@]}"; do
        grep -Eo 'c-azc-[0-9]{4}' "$file" || true
    done
} | sort -u)"
expected_cases="$(awk 'BEGIN { for (n = 1; n <= 30; n++) printf "c-azc-%04d\n", n }')"
if [[ "$declared_cases" != "$expected_cases" ]]; then
    report "check_authz_fail_closed: the executable authorization matrix is not exactly c-azc-0001 through c-azc-0030"
fi

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Authorizer fail-closed contract violated. See rustfs/backlog#1732 (P6-02) and
crates/gateway/src/ext/authorizer.rs.
The third verdict state exists so that "the policy store did not answer" cannot become "allow" by
accident. That only holds while one file decides what a verdict means, the decision is total over
every state, the refusal cannot choose its own code, and the audit hook has no way to answer back.
EOF
    exit "$status"
fi

printf 'OK: Decision is [%s], interpreted in %s alone (%s arm(s)), Denial is codeless, AuthzAuditSink is mute, %s example(s) free of allow-all\n' \
    "$declared" "$DECISION_FILE" "$interpreters" "${#examples[@]}"
exit 0
