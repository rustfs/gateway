#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_resolver_pure.sh
#
# WHAT THIS CHECKS
#   Four rules about the host resolver, asserted over the source rather than
#   described in a rustdoc paragraph nobody re-reads.
#
#   1. `HostResolver::resolve` is SYNCHRONOUS. Neither the trait method nor any
#      implementation of it may be `async`, return a `Future`, a `BoxFuture` or
#      a `Pin<Box<...>>`, or `.await` anything.
#   2. No type that implements `HostResolver` holds a STORE HANDLE. Field
#      declarations in the guarded files are checked against a type-name
#      blacklist (`*Store`, `*Client`, `*Pool`, `*Backend`, `*Connection`,
#      `Arc<dyn Storage*>`, ...). A heuristic, deliberately — but paired with
#      rule 1 it is enough, because a handle you cannot await on is a handle you
#      cannot read through.
#   3. `HostQuery` declares EXACTLY the fields in QUERY_FIELDS below. It is the
#      resolver's whole input, so widening it is how a header reaches a bucket
#      decision.
#   4. No executable line in the guarded files names a forwarded header.
#      `X-Forwarded-Host` and `Forwarded` are set by every hop in front of the
#      gateway, and a resolver that read one would let any of them redirect a
#      bucket. Prose about the rule is fine; a string literal is not.
#
# WHY
#   The resolver runs BEFORE authentication. A `resolve` that could await turns
#   an unauthenticated request into work the deployment does on the caller's
#   behalf, which is an amplifier; a `resolve` that could reach a store turns it
#   into a private-bucket enumeration oracle, because "does this bucket exist"
#   is answerable by timing whether or not the answer is in the response.
#
#   Rule 3 is the type-level half of "the resolver cannot see a forwarded
#   header". The trait takes a `&HostQuery`, so the field list IS the input
#   surface: as long as it holds a host, a path and a method, no header can
#   reach a bucket decision, and no reviewer has to remember that it must not.
#
#   And rule 1 is why the resolver is the one extension point in this crate that
#   is not `-> BoxFuture` (ADR-0002). The exception has to be enforced, or the
#   next person to add an implementation writes the asynchronous one.
#
# HOW TO EXEMPT
#   Not applicable. A resolver that needs to await needs an ADR that revisits
#   ADR-0002 and the pre-authentication amplification argument first; a resolver
#   that needs a store snapshot takes it at assembly time, which is what
#   `VirtualHostStyle::new` does with its base domains.
#
# USAGE
#   scripts/check_resolver_pure.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_resolver_pure.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

cd "$ROOT_DIR"

# The trait's own file. Named rather than discovered: if it moves, this guard
# must be pointed at the new home in the same change, and a guard that silently
# finds nothing is the defect this repository has produced seven times.
TRAIT_FILE='crates/gateway/src/ext/host.rs'
# The struct whose field list is the resolver's entire input.
QUERY_TYPE='HostQuery'
# Exactly the fields it may declare, space separated and in any order.
QUERY_FIELDS='host method path'
# Type names that mean "this value can reach storage".
STORE_NAME_RE='(Store|Storage|Repository|Connection|Pool|Backend|Client|Database|Handle|Registry|Cache)'
# The forwarded headers a resolver must never consult.
FORWARDED_RE='([xX]-[fF]orwarded-|[fF]orwarded[ \t]*=|forwarded_host|FORWARDED_HOST)'

status=0

report() {
    printf '%s\n' "$1" >&2
    status=1
}

# `--cached --others --exclude-standard`, for the reason check_ct_eq.sh gives:
# a bare `git ls-files` lists only tracked files, so a brand-new resolver would
# be invisible to this guard right up until the commit that added it.
sources=()
while IFS= read -r file; do
    [[ -n "$file" ]] && sources+=("$file")
done < <(git ls-files --cached --others --exclude-standard -- '*.rs' ':!:target/*' ':!:generated/*' ':!:*/generated/*' 2>/dev/null || true)

if [[ "${#sources[@]}" -eq 0 ]]; then
    report "check_resolver_pure: no Rust sources found; this guard's input is missing, which is a failure and not a skip"
    exit 1
fi

# The guarded set: the trait's file, plus every file that implements the trait.
# Discovered rather than listed, so a new implementation is guarded the moment
# it is written.
guarded=()
if [[ ! -f "$TRAIT_FILE" ]]; then
    report "check_resolver_pure: ${TRAIT_FILE} does not exist; the guard cannot find the HostResolver trait it is written about"
    exit 1
fi
guarded+=("$TRAIT_FILE")

impl_count=0
for file in "${sources[@]}"; do
    [[ "$file" == "$TRAIT_FILE" ]] && continue
    # This exact trybuild fixture must fail compilation; it is not a runtime resolver.
    # The self-test copies it into src/ to prove discovery still rejects the same code there.
    [[ "$file" == 'crates/gateway/tests/compile_fail/c_host_0018_async_resolver.rs' ]] && continue
    if grep -qE '^[ \t]*impl([ \t]*<[^>]*>)?[ \t]+HostResolver[ \t]+for[ \t]+' "$file"; then
        guarded+=("$file")
        impl_count=$((impl_count + 1))
    fi
done

# The trait file holds `PathStyleOnly` and the blanket `Arc<T>` forward, so the
# repository always has at least one implementation outside it once a real
# resolver exists. Zero means the discovery regex stopped matching.
if [[ "$impl_count" -eq 0 ]]; then
    report "check_resolver_pure: no file outside ${TRAIT_FILE} implements HostResolver; the discovery pattern has stopped matching and this guard is checking nothing"
    exit 1
fi

# Comment-only lines are blanked, keeping line numbers intact. Rules 1, 2 and 4
# all read prose that legitimately describes what they forbid.
code_of() {
    awk '{ s = $0; sub(/^[ \t]+/, "", s); if (s ~ /^\/\//) { print "" } else { print $0 } }' "$1"
}

# -----------------------------------------------------------------------------
# Rule 1 — resolve() is synchronous.
# -----------------------------------------------------------------------------
for file in "${guarded[@]}"; do
    code="$(code_of "$file")"
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: HostResolver::resolve may not be async; a resolver that can await lets an unauthenticated request drive work on the caller's behalf"
    done < <(printf '%s\n' "$code" | grep -nE 'async[ \t]+fn[ \t]+resolve' || true)

    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: resolve() returns a future; the answer must be computed from the head, in constant time, with no I/O"
    done < <(printf '%s\n' "$code" | grep -nE 'fn[ \t]+resolve[^;{]*->[^;{]*(BoxFuture|Future|Pin[ \t]*<)' || true)

    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: a host resolver awaits; nothing on the pre-authentication path may"
    done < <(printf '%s\n' "$code" | grep -nE '\.await|async[ \t]+(fn|move|block)' || true)
done

# -----------------------------------------------------------------------------
# Rule 2 — no store handle in a field.
#
# awk reports `<line>\t<field>\t<type>` for every `name: Type` field
# declaration whose type names a handle. Restricted to field position on
# purpose: `use` lines and function arguments are a different question, and a
# resolver cannot hold what it is not given.
# -----------------------------------------------------------------------------
for file in "${guarded[@]}"; do
    while IFS=$'\t' read -r line field type_name; do
        [[ -z "${line:-}" ]] && continue
        report "$(printf "%s:%s: field '%s: %s' names a store handle; a resolver that holds one is a private-bucket enumeration oracle for unauthenticated callers" \
            "$file" "$line" "$field" "$type_name")"
    done < <(code_of "$file" | awk -v store="$STORE_NAME_RE" '
        {
            s = $0
            sub(/^[ \t]+/, "", s)
            if (s == "" || s ~ /^#\[/ || s ~ /^\/\//) { next }
            # `name: Type,` or `pub name: Type,` — a struct field, or an enum
            # variant field, which is the same reachability question.
            if (match(s, /^(pub([ \t]*\([^)]*\))?[ \t]+)?[a-z_][a-z0-9_]*[ \t]*:[ \t]*[^,;=]+/)) {
                decl = substr(s, RSTART, RLENGTH)
                split(decl, halves, ":")
                name = halves[1]
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
# Rule 3 — HostQuery declares exactly the fields it is allowed to.
# -----------------------------------------------------------------------------
declared="$(awk -v want="$QUERY_TYPE" '
    BEGIN { inside = 0 }
    {
        s = $0
        sub(/^[ \t]+/, "", s)
        if (inside == 0) {
            if (s ~ ("^(pub([ \t]*\\([^)]*\\))?[ \t]+)?struct[ \t]+" want "([ \t]*<[^>]*>)?[ \t]*\\{")) { inside = 1 }
            next
        }
        if (s ~ /^\}/) { inside = 0; next }
        if (s == "" || s ~ /^\/\// || s ~ /^#\[/) { next }
        if (match(s, /^(pub([ \t]*\([^)]*\))?[ \t]+)?[a-z_][a-z0-9_]*[ \t]*:/)) {
            decl = substr(s, RSTART, RLENGTH)
            gsub(/^(pub[ \t]*(\([^)]*\))?[ \t]*)/, "", decl)
            gsub(/[ \t:]/, "", decl)
            print decl
        }
    }
' "$TRAIT_FILE" | sort | tr '\n' ' ')"
declared="${declared% }"
expected="$(printf '%s\n' $QUERY_FIELDS | sort | tr '\n' ' ')"
expected="${expected% }"

if [[ -z "$declared" ]]; then
    report "check_resolver_pure: ${QUERY_TYPE} was not found in ${TRAIT_FILE}, or declares no fields; the guard is reading nothing"
elif [[ "$declared" != "$expected" ]]; then
    report "${TRAIT_FILE}: ${QUERY_TYPE} declares fields [${declared}] and may declare only [${expected}]; its field list is the resolver's entire input, and a header in it is a header that can redirect a bucket"
fi

# -----------------------------------------------------------------------------
# Rule 4 — no forwarded header is named in executable code.
# -----------------------------------------------------------------------------
for file in "${guarded[@]}"; do
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: a forwarded header is named in resolver code; every hop in front of the gateway can set one, so trusting it hands each of them a bucket-redirection primitive"
    done < <(code_of "$file" | grep -nE "$FORWARDED_RE" || true)
done

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Host-resolver purity rule violated. See rustfs/backlog#1737 (P6-04).
The resolver answers before the request has been authenticated. Synchronous and
handle-free is what keeps an unauthenticated caller from making the deployment
do I/O on their behalf; a closed input surface is what keeps a proxy header from
choosing the bucket. Both are properties of the code's shape, so both are checked
by reading it.
EOF
    exit "$status"
fi

printf 'OK: host resolver is pure (%s guarded file(s), %s implementation(s) outside the trait file, %s declares [%s])\n' \
    "${#guarded[@]}" "$impl_count" "$QUERY_TYPE" "$declared"
exit 0
