#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_cors_credentials_exclusive.sh
#
# WHAT THIS CHECKS
#   Four rules over the CORS answer builder, `crates/core/src/cors/answer.rs`.
#
#   1. The `Access-Control-Allow-Credentials` header name is written in exactly
#      one place in the whole workspace's non-test source: that file. A second
#      writer is a second policy.
#   2. Inside that file the name appears in exactly one function body. Two is
#      how the header gets emitted from a branch the first one did not guard.
#   3. That function body does not mention `AllowOrigin::Reflected` or
#      `AllowOrigin::Wildcard`. The two wildcard forms and the credentials
#      allowance may not be reachable from one another's branch, and merging
#      the origin decision into the credentials writer is exactly the refactor
#      that reintroduces the advisory.
#   4. The file does not import the `AllowOrigin` variants unqualified
#      (`use ...AllowOrigin::*` or `use ...AllowOrigin::{...}`), because rule 3
#      matches on the qualified spelling and an unqualified `Reflected(_)`
#      would slip past it.
#
#   Rule 1 counts, so an empty or renamed file fails rather than passes: a
#   guard whose input has gone missing must go red, not quiet. Comment and
#   doc-comment lines are skipped throughout — this file documents the rule in
#   prose directly above the code, and a guard that fires on its own
#   explanation gets deleted within a week.
#
# WHY
#   GHSA-x5xv-223c-8vm7. A gateway that echoes the caller's `Origin` and also
#   answers `Access-Control-Allow-Credentials: true` has told every site on the
#   internet that it may read this user's objects with this user's session. The
#   browser enforces nothing here: it does exactly what the two headers say.
#
#   `CorsPolicy::new` refuses `CorsOrigins::Any` with credentials, and the
#   generated current contract makes wildcard origins return no credentials.
#   The typed mutation alternative is intentionally present so its cases can
#   kill the widening. This guard protects the writer boundary around both: a
#   refactor that writes the header directly inside the wildcard match fails
#   before a reviewer has to notice it.
#
# HOW TO EXEMPT
#   There is no exemption. If the answer builder has to move, move it and
#   update ANSWER_FILE below in the same commit; if a second component must
#   write the header, that component needs its own argument on the issue
#   first, not a line in an allowance file.
#
# USAGE
#   scripts/check_cors_credentials_exclusive.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_cors_credentials_exclusive.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

cd "$ROOT_DIR"

# The one file allowed to name the credentials header.
ANSWER_FILE='crates/core/src/cors/answer.rs'
# The header name, as it is spelled in source. Both the constant's identifier and the wire
# spelling, because either is a way to write the header.
CREDENTIALS_RE='ACCESS_CONTROL_ALLOW_CREDENTIALS|access-control-allow-credentials'
# The two origin forms that may never be reachable from the credentials writer.
WILDCARD_RE='AllowOrigin::Reflected|AllowOrigin::Wildcard'

status=0

report() {
    printf '%s\n' "$1" >&2
    status=1
}

if [[ ! -f "$ANSWER_FILE" ]]; then
    report "${ANSWER_FILE} does not exist; this guard's subject has moved or been deleted, and a guard with no input must fail rather than pass silently"
    exit 1
fi

# Comment lines blanked, numbering preserved. `#[cfg(test)]` is NOT skipped as a block: a rule
# that stopped at the first attribute would stop at every line after it.
strip_comments() {
    awk '{ s = $0; sub(/^[ \t]+/, "", s); if (s ~ /^\/\//) { print "" } else { print $0 } }' "$1"
}

# The same, with every `use` statement blanked as well — including the braced multi-line form a
# facade re-export is written in. Naming a constant in order to re-export it is not writing a
# header, and a guard that could not tell the difference would forbid the facade from exporting
# the item at all.
# Each `#[cfg(test)]` item blanked, and only as far as its own closing brace. The tests are where
# the forbidden combination is deliberately written down —
# `n_a_reflected_origin_never_carries_credentials` names the credentials header and
# `AllowOrigin::Reflected` in one function on purpose, because that is the assertion — and a guard
# that read its own regression tests as violations would be deleted within a week.
#
# A `#[cfg(test)]` item with no body — the `#[cfg(test)] #[path = "x.rs"] mod tests;` split used
# when a file crosses the 800-line limit — closes at its own semicolon instead, because it never
# opens a brace for the balanced form to close.
#
# Balanced rather than "to the end of the file", which is the version this was first written as.
# By convention the inline test module is the last item, so the two agree today; they stop
# agreeing the moment somebody appends anything after it, and the version that stopped at EOF
# would then be blanking production code. Two of this guard's own negative controls append at the
# end of a file, and they are the reason the difference was noticed.
strip_test_module() {
    awk '
        function delta(s,   i, c, n) {
            n = 0
            for (i = 1; i <= length(s); i++) {
                c = substr(s, i, 1)
                if (c == "{") n++
                else if (c == "}") n--
            }
            return n
        }
        {
            line = $0
            s = line
            sub(/^[ \t]+/, "", s)
            if (in_test == 0 && s ~ /^#\[cfg\(test\)\]/) {
                in_test = 1
                depth = 0
                opened = 0
            }
            if (in_test == 1) {
                d = delta(line)
                if (d > 0) { opened = 1 }
                depth += d
                print ""
                if (opened == 1 && depth <= 0) { in_test = 0 }
                # A `#[cfg(test)]` item with no body at all — `#[cfg(test)] #[path = "x.rs"] mod
                # tests;`, the split this repository uses when a file crosses 800 lines — never
                # opens a brace, so the balanced form above would never close it and everything
                # after it in the file would be blanked. That is this guard switching itself off
                # for the rest of the file. A bodyless item ends at its own semicolon.
                else if (opened == 0 && s ~ /;[ \t]*$/) { in_test = 0 }
                next
            }
            print line
        }
    ' "$1"
}

strip_comments_and_uses() {
    strip_test_module "$1" | awk '{ s = $0; sub(/^[ \t]+/, "", s); if (s ~ /^\/\//) { print "" } else { print $0 } }' | awk '
        {
            line = $0
            s = line
            sub(/^[ \t]+/, "", s)
            if (in_use == 0 && s ~ /^(pub[ \t]+)?use[ \t]/) { in_use = 1 }
            if (in_use == 1) {
                if (line ~ /;/) { in_use = 0 }
                print ""
                next
            }
            print line
        }
    '
}

# -----------------------------------------------------------------------------
# Rule 1 — one writer in the workspace.
# -----------------------------------------------------------------------------
# Keep the complete census: a producer failure must not look like a shorter source list.
if ! source_list="$(git ls-files --cached --others --exclude-standard -- '*.rs' ':!:target/*' ':!:generated/*' ':!:*/generated/*')"; then
    report 'cannot list source files for the CORS credentials guard'
    exit 1
fi
sources=()
while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    # Tests may name the header freely: asserting its absence is the point of several of them.
    case "$file" in
    *"/tests/"* | tests/*) continue ;;
    esac
    sources+=("$file")
done <<<"$source_list"

if [[ "${#sources[@]}" -eq 0 ]]; then
    report "no Rust sources are visible to this guard; it cannot have checked anything"
    exit 1
fi

# The parser below only blanks lines: it cannot create a header spelling absent from the raw
# file. Scan every eligible source once, then retain the existing parser for every candidate.
# grep's no-match status is valid; a read or tool failure is not an empty candidate set.
scan_status=0
candidates="$(grep -lE "$CREDENTIALS_RE" -- "${sources[@]}")" || scan_status=$?
if [[ "$scan_status" -gt 1 ]]; then
    report 'cannot scan every source for CORS credentials candidates'
    exit 1
fi

writers=0
while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    if ! parsed="$(strip_comments_and_uses "$file")"; then
        report "cannot parse source ${file} for CORS credentials"
        exit 1
    fi
    scan_status=0
    hits="$(grep -cE "$CREDENTIALS_RE" <<<"$parsed")" || scan_status=$?
    if [[ "$scan_status" -gt 1 ]]; then
        report "cannot scan parsed source ${file} for CORS credentials"
        exit 1
    fi
    [[ "$hits" -eq 0 ]] && continue
    if [[ "$file" == "$ANSWER_FILE" ]]; then
        writers=$((writers + 1))
        continue
    fi
    report "${file}: names the CORS credentials header outside ${ANSWER_FILE}; there is one writer of that header and this is not it"
done <<<"$candidates"

if [[ "$writers" -eq 0 ]]; then
    report "${ANSWER_FILE} never names the CORS credentials header; either the allowance was removed — in which case delete this guard deliberately — or the constant was renamed and rules 2 and 3 are now checking nothing"
fi

# -----------------------------------------------------------------------------
# Rules 2 and 3 — one function, and it does not know about the wildcard forms.
#
# awk walks the file tracking brace depth. A top-level `fn` opens a body; the body ends when the
# depth returns to the level it started at. Nested blocks inside the body are part of it, which is
# what makes "the same function" mean the same thing here as it does to a reader.
# -----------------------------------------------------------------------------
# `while read` rather than `mapfile`: this repository is developed on macOS, whose system bash is
# 3.2 and has no `mapfile`, and a guard that exits 127 on half the developers' machines is a guard
# they route around.
findings=()
while IFS= read -r finding; do
    [[ -n "$finding" ]] && findings+=("$finding")
done < <(strip_comments_and_uses "$ANSWER_FILE" | awk -v cred="$CREDENTIALS_RE" -v wild="$WILDCARD_RE" '
    function opens(s,   i, c, n) {
        n = 0
        for (i = 1; i <= length(s); i++) {
            c = substr(s, i, 1)
            if (c == "{") n++
            else if (c == "}") n--
        }
        return n
    }
    {
        line = $0
        if (in_fn == 0 && line ~ /^[ \t]*(pub([ \t]*\([^)]*\))?[ \t]+)?(const[ \t]+)?(async[ \t]+)?fn[ \t]+/) {
            name = line
            sub(/^.*fn[ \t]+/, "", name)
            sub(/[^A-Za-z0-9_].*$/, "", name)
            fn_name = name
            fn_line = NR
            depth = 0
            in_fn = 1
            saw_cred = 0
            saw_wild = 0
        }
        if (in_fn == 1) {
            if (line ~ cred) saw_cred = 1
            if (line ~ wild) saw_wild = 1
            depth += opens(line)
            if (depth <= 0 && line ~ /}/) {
                if (saw_cred == 1) {
                    print "CRED\t" fn_line "\t" fn_name "\t" saw_wild
                }
                in_fn = 0
            }
        }
    }
')

cred_functions=0
for finding in "${findings[@]}"; do
    [[ -z "$finding" ]] && continue
    IFS=$'\t' read -r _tag line name saw_wild <<<"$finding"
    cred_functions=$((cred_functions + 1))
    if [[ "$saw_wild" == "1" ]]; then
        report "${ANSWER_FILE}:${line}: fn ${name} names both the credentials header and a wildcard AllowOrigin variant; a reflected or starred origin must not be reachable from the branch that writes credentials (GHSA-x5xv-223c-8vm7)"
    fi
done

if [[ "$cred_functions" -eq 0 ]]; then
    report "${ANSWER_FILE}: no function names the credentials header, so rule 3 checked nothing; the parser or the constant's spelling has drifted"
elif [[ "$cred_functions" -gt 1 ]]; then
    report "${ANSWER_FILE}: ${cred_functions} functions name the credentials header; there is exactly one writer and a second is a second policy"
fi

# -----------------------------------------------------------------------------
# Rule 4 — the variants may not be imported unqualified.
# -----------------------------------------------------------------------------
while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    report "${ANSWER_FILE}:${hit%%:*}: AllowOrigin's variants are imported unqualified; rule 3 matches the qualified spelling, so an unqualified Reflected(_) would pass a guard that has stopped checking"
done < <(strip_comments "$ANSWER_FILE" | grep -nE '^[ \t]*(pub[ \t]+)?use[ \t]+.*AllowOrigin::' || true)

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

CORS credential exclusion violated. See rustfs/backlog#1757 and
GHSA-x5xv-223c-8vm7.

A response that echoes the caller's Origin and also says
`Access-Control-Allow-Credentials: true` lets any website read this user's
objects using this user's session. The exclusion is meant to be a property of
the code — one function writes that header, and it is only reachable from the
arm holding an origin the stored rule named literally — rather than a check
somebody remembers to make.
EOF
    exit "$status"
fi

printf 'OK: the CORS credentials header has one writer in %s, and it names no wildcard origin variant\n' "$ANSWER_FILE"
exit 0
