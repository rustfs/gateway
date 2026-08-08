#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_stage_filter_sync.sh
#
# WHAT THIS CHECKS
#   Four rules about `StageFilter`, asserted over the source rather than
#   described in a rustdoc paragraph nobody re-reads.
#
#   1. Every `StageFilter` method is SYNCHRONOUS. Neither the trait's methods
#      nor any implementation of one may be `async`, return a `Future`, a
#      `BoxFuture` or a `Pin<Box<...>>`, or `.await` anything.
#   2. No type that implements `StageFilter` holds a STORE HANDLE. Field
#      declarations in the guarded files are checked against a type-name
#      blacklist (`*Store`, `*Client`, `*Pool`, `*Backend`, `*Connection`, ...).
#      A heuristic, deliberately — but paired with rule 1 it is enough, because
#      a handle you cannot await on is a handle you cannot read through.
#   3. The trait declares EXACTLY the three seams in SEAMS below. The seam set
#      is the extension surface; adding one silently is how a position nobody
#      argued for becomes load bearing.
#   4. `WireHead` publishes no way to rewrite the method or the request target,
#      and `RoutedView` publishes no `&mut` accessor at all. Both feed decisions
#      that must have exactly one producer: the method and the target are inputs
#      to the canonical request, and the bucket and key come from the single
#      normalisation.
#
# WHY
#   `on_wire` and `on_routed` both run BEFORE authentication. A seam that could
#   await turns an unauthenticated request into work the deployment does on the
#   caller's behalf, which is an amplifier; a seam that could reach a store turns
#   it into a private-bucket enumeration oracle, because "does this bucket exist"
#   becomes answerable by timing. This is the same rule as
#   check_resolver_pure.sh's, one extension point along.
#
#   Rule 4 is the type-level half of "a filter cannot choose the target and
#   cannot change a signature's input". The `Host` header is refused at run time
#   by `FROZEN_WIRE_HEADERS` because a header name is an open set; the method and
#   the target are not reachable at all, and this guard is what keeps them that
#   way.
#
# HOW TO EXEMPT
#   Not applicable. A seam that needs to await needs an ADR revisiting ADR-0002
#   and the pre-authentication amplification argument first.
#
# USAGE
#   scripts/check_stage_filter_sync.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_stage_filter_sync.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

cd "$ROOT_DIR"

# The trait's own file. Named rather than discovered: if it moves, this guard
# must be pointed at the new home in the same change, and a guard that silently
# finds nothing is the defect this repository has produced seven times.
TRAIT_FILE='crates/gateway/src/ext/filter.rs'
# Exactly the seams the trait may declare, space separated and in any order.
SEAMS='on_wire on_routed on_response'
# Type names that mean "this value can reach storage".
STORE_NAME_RE='(Store|Storage|Repository|Connection|Pool|Backend|Database|Handle|Registry|Cache)'
# Accessors `WireHead` must not publish: they would hand a filter the two
# canonical-request inputs the frozen snapshot does not cover.
FORBIDDEN_HEAD_ACCESSORS='(fn[ \t]+method_mut|fn[ \t]+uri_mut|fn[ \t]+path_mut|fn[ \t]+query_mut|fn[ \t]+headers_mut|fn[ \t]+parts_mut|fn[ \t]+set_method|fn[ \t]+set_path|fn[ \t]+set_uri|fn[ \t]+set_query)'

status=0

report() {
    printf '%s\n' "$1" >&2
    status=1
}

# `--cached --others --exclude-standard`, for the reason check_ct_eq.sh gives:
# a bare `git ls-files` lists only tracked files, so a brand-new filter would be
# invisible to this guard right up until the commit that added it.
sources=()
while IFS= read -r file; do
    [[ -n "$file" ]] && sources+=("$file")
done < <(git ls-files --cached --others --exclude-standard -- '*.rs' ':!:target/*' ':!:generated/*' ':!:*/generated/*' 2>/dev/null || true)

if [[ "${#sources[@]}" -eq 0 ]]; then
    report "check_stage_filter_sync: no Rust sources found; this guard's input is missing, which is a failure and not a skip"
    exit 1
fi

if [[ ! -f "$TRAIT_FILE" ]]; then
    report "check_stage_filter_sync: ${TRAIT_FILE} does not exist; the guard cannot find the StageFilter trait it is written about"
    exit 1
fi

# The guarded set: the trait's file, plus every file that implements the trait.
# Discovered rather than listed, so a new implementation is guarded the moment
# it is written.
guarded=("$TRAIT_FILE")
impl_count=0
for file in "${sources[@]}"; do
    [[ "$file" == "$TRAIT_FILE" ]] && continue
    if grep -qE '^[ \t]*impl([ \t]*<[^>]*>)?[ \t]+StageFilter([ \t]*<[^>]*>)?[ \t]+for[ \t]+' "$file"; then
        guarded+=("$file")
        impl_count=$((impl_count + 1))
    fi
done

# The trait file holds the three closure adapters and the blanket `Arc<T>`
# forward; every suite that installs a filter holds another. Zero outside the
# trait file means the discovery regex has stopped matching and this guard is
# reading one file it wrote itself.
if [[ "$impl_count" -eq 0 ]]; then
    report "check_stage_filter_sync: no file outside ${TRAIT_FILE} implements StageFilter; the discovery pattern has stopped matching and this guard is checking nothing"
    exit 1
fi

# Comment-only lines are blanked, keeping line numbers intact. Rules 1, 2 and 4
# all read prose that legitimately describes what they forbid.
code_of() {
    awk '{ s = $0; sub(/^[ \t]+/, "", s); if (s ~ /^\/\//) { print "" } else { print $0 } }' "$1"
}

# -----------------------------------------------------------------------------
# Rule 1 — every seam is synchronous.
#
# The `.await` half is scoped to the *bodies* of `impl StageFilter for _` blocks,
# found by counting braces from the `impl` line. Scanning whole files would be
# wrong in the direction that matters: every suite that installs a filter is an
# `async fn` test, so a whole-file scan reports the harness and says nothing
# about the seam.
# -----------------------------------------------------------------------------
seam_alternation="$(printf '%s\n' $SEAMS | paste -sd'|' -)"

impl_bodies_of() {
    code_of "$1" | awk '
        BEGIN { depth = 0; inside = 0 }
        {
            line = $0
            if (inside == 0) {
                if (line ~ /impl([ \t]*<[^>]*>)?[ \t]+StageFilter([ \t]*<[^>]*>)?[ \t]+for[ \t]+/) {
                    inside = 1
                    depth = 0
                } else {
                    print ""
                    next
                }
            }
            opens = gsub(/\{/, "{", line)
            closes = gsub(/\}/, "}", line)
            print $0
            depth += opens - closes
            if (depth <= 0 && opens + closes > 0) { inside = 0 }
        }
    '
}

for file in "${guarded[@]}"; do
    code="$(code_of "$file")"
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: a StageFilter seam may not be async; a seam that can await lets an unauthenticated request drive work on the caller's behalf"
    done < <(printf '%s\n' "$code" | grep -nE "async[ \t]+fn[ \t]+(${seam_alternation})" || true)

    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: a StageFilter seam returns a future; the answer must be computed from the head, in constant time, with no I/O"
    done < <(printf '%s\n' "$code" | grep -nE "fn[ \t]+(${seam_alternation})[^;{]*->[^;{]*(BoxFuture|Future|Pin[ \t]*<)" || true)

    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: a StageFilter implementation awaits; nothing on the pre-authentication path may"
    done < <(impl_bodies_of "$file" | grep -nE '\.await|async[ \t]+(fn|move|block)' || true)
done

# -----------------------------------------------------------------------------
# Rule 2 — no store handle in a field.
#
# awk reports `<line>\t<field>\t<type>` for every `name: Type` field
# declaration whose type names a handle. Restricted to field position on
# purpose: `use` lines and function arguments are a different question, and a
# filter cannot hold what it is not given. Restricted to `src/` on purpose too:
# a test fixture holding a fake store is the harness, not the shipped surface.
# -----------------------------------------------------------------------------
for file in "${guarded[@]}"; do
    [[ "$file" == */src/* ]] || continue
    while IFS=$'\t' read -r line field type_name; do
        [[ -z "${line:-}" ]] && continue
        report "$(printf "%s:%s: field '%s: %s' names a store handle; a pre-authentication seam that holds one is an enumeration oracle for unauthenticated callers" \
            "$file" "$line" "$field" "$type_name")"
    done < <(code_of "$file" | awk -v store="$STORE_NAME_RE" '
        {
            s = $0
            sub(/^[ \t]+/, "", s)
            if (s == "" || s ~ /^#\[/ || s ~ /^\/\//) { next }
            # `name: Type` and never `path::to::Thing`: the character after the
            # colon may not be another colon, or every fully-qualified path in
            # the file reads as a field declaration.
            if (match(s, /^(pub([ \t]*\([^)]*\))?[ \t]+)?[a-z_][a-z0-9_]*[ \t]*:[ \t]*[^:,;=][^,;=]*/)) {
                decl = substr(s, RSTART, RLENGTH)
                name = substr(decl, 1, index(decl, ":") - 1)
                gsub(/^(pub[ \t]*(\([^)]*\))?[ \t]*)/, "", name)
                gsub(/[ \t]/, "", name)
                type_text = substr(decl, index(decl, ":") + 1)
                gsub(/^[ \t]+|[ \t]+$/, "", type_text)
                if (type_text ~ store) { print NR "\t" name "\t" type_text }
            }
        }
    ')
done

# -----------------------------------------------------------------------------
# Rule 3 — the trait declares exactly the three seams.
#
# Brace-counted from the `pub trait` line: the seams carry default bodies, so a
# scan that stopped at the first closing brace would see one seam and call the
# set complete.
# -----------------------------------------------------------------------------
declared="$(awk '
    BEGIN { inside = 0; depth = 0 }
    {
        line = $0
        if (inside == 0) {
            if (line ~ /^pub[ \t]+trait[ \t]+StageFilter[ \t]*:/) {
                inside = 1
                depth = 0
            } else {
                next
            }
        }
        s = line
        sub(/^[ \t]+/, "", s)
        if (depth == 1 && match(s, /^fn[ \t]+[a-z_][a-z0-9_]*/)) {
            name = substr(s, RSTART + 3, RLENGTH - 3)
            gsub(/[ \t]/, "", name)
            print name
        }
        opens = gsub(/\{/, "{", line)
        closes = gsub(/\}/, "}", line)
        depth += opens - closes
        if (depth <= 0 && opens + closes > 0) { inside = 0 }
    }
' "$TRAIT_FILE" | sort | tr '\n' ' ')"
declared="${declared% }"
expected="$(printf '%s\n' $SEAMS | sort | tr '\n' ' ')"
expected="${expected% }"

if [[ -z "$declared" ]]; then
    report "check_stage_filter_sync: the StageFilter trait was not found in ${TRAIT_FILE}, or declares no methods; the guard is reading nothing"
elif [[ "$declared" != "$expected" ]]; then
    report "${TRAIT_FILE}: StageFilter declares seams [${declared}] and may declare only [${expected}]; the seam set is the extension surface, and a position nobody argued for must not become load bearing by accident"
fi

# -----------------------------------------------------------------------------
# Rule 4 — the head cannot be redirected and the routed view cannot be written.
# -----------------------------------------------------------------------------
while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    report "${TRAIT_FILE}:${hit%%:*}: WireHead may not publish a way to rewrite the method or the request target; both are canonical-request inputs the frozen header snapshot does not cover"
done < <(code_of "$TRAIT_FILE" | grep -nE "$FORBIDDEN_HEAD_ACCESSORS" || true)

routed_mut="$(awk '
    BEGIN { inside = 0; depth = 0 }
    {
        line = $0
        if (inside == 0) {
            if (line ~ /^impl[ \t]+RoutedView/) {
                inside = 1
                depth = 0
            } else {
                next
            }
        }
        s = line
        sub(/^[ \t]+/, "", s)
        if (s !~ /^\/\// && s ~ /fn[ \t]+[a-z_]/ && s ~ /&[ \t]*mut/) { print NR ": " s }
        opens = gsub(/\{/, "{", line)
        closes = gsub(/\}/, "}", line)
        depth += opens - closes
        if (depth <= 0 && opens + closes > 0) { inside = 0 }
    }
' "$TRAIT_FILE")"
if [[ -n "$routed_mut" ]]; then
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${TRAIT_FILE}:${hit%%:*}: RoutedView may not publish a mutable accessor; the bucket and the key have one producer, and a seam is not a second one"
    done <<<"$routed_mut"
fi

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

StageFilter purity rule violated. See rustfs/backlog#1731 (P6-01) and docs/middleware.md.
Two of the three seams run before the request has been authenticated. Synchronous and handle-free
is what keeps an unauthenticated caller from making the deployment do I/O on their behalf; a head
that cannot be redirected and a routed view that cannot be written are what keep a filter out of
the signature and out of the target decision.
EOF
    exit "$status"
fi

printf 'OK: StageFilter is synchronous and handle-free (%s guarded file(s), %s implementation(s) outside the trait file, seams [%s])\n' \
    "${#guarded[@]}" "$impl_count" "$declared"
exit 0
