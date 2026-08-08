#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_single_normalization.sh
#
# WHAT THIS CHECKS
#   Four rules, all of them about there being exactly ONE place a client-chosen
#   name is turned into an ObjectKey or a BucketName.
#
#     1. The normalisation and the two floor functions are each DEFINED ONCE,
#        and in the sanctioned file (crates/types/src/scalar/naming.rs). A
#        second `fn normalize_key` or `fn floor_check_key` anywhere in the
#        workspace fails the check.
#     2. Percent-decoding is called only from an allowlisted set of files. A
#        new decode site is how a name gets decoded twice, and a doubly decoded
#        `%252e%252e` is a traversal no single-decode check would have seen.
#     3. `ObjectKey` grows no bypass: no `Deref`, no `AsRef<str>`, no
#        `From<String>`, and nothing named `new_unchecked`. Any of those hands a
#        caller a `&str` it can re-parse, join onto a path, or rebuild — which is
#        how the second normalisation is born.
#     4. No lossy UTF-8 conversion inside crates/types/src/scalar/. A lossy
#        decode turns two different client inputs into one name, so the value
#        authorisation sees is not the value the client sent.
#
#   Comment and doc-comment lines are skipped throughout: this repository
#   explains these rules in prose directly above the code they govern, and a
#   guard that fires on its own documentation is a guard somebody deletes.
#
# WHY
#   Three published RustFS advisories have one shape: the value the
#   authorisation check read was not the value the storage layer used, because
#   one of the two decoded, normalised or cleaned something the other did not.
#
#     GHSA-8r6f-hmq2-28rg  a key with a traversal reached the filesystem mapping
#     GHSA-f4vq-9ffr-m8m3  the source was authorised as a key, used as a path
#     GHSA-pq29-69jg-9mxc  an untrusted path was joined and length-checked
#
#   The difference between the two values IS the vulnerability, so the property
#   worth enforcing mechanically is not "the normalisation is correct" — that is
#   what the conformance cases are for — but "there is only one of it".
#
# HOW TO EXEMPT
#   Add the exact repository-relative path to
#   `scripts/allowances/percent-decode-allowances.txt`, with a comment saying
#   what that site decodes and why it is not a name. Nothing exempts rules 1, 3
#   or 4: those have no legitimate second instance.
#
# USAGE
#   scripts/check_single_normalization.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_single_normalization.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ALLOWANCE_FILE="${ROOT_DIR}/scripts/allowances/percent-decode-allowances.txt"

cd "$ROOT_DIR"

# The one file allowed to hold the normalisation and the floor.
NORMALISER='crates/types/src/scalar/naming.rs'
SCALAR_DIR='crates/types/src/scalar'

status=0

fail() {
    printf '%s\n' "$1" >&2
    status=1
}

# Every non-generated Rust source file in the workspace, tests included: a second
# normalisation written "only for a test fixture" is still a second normalisation, and the
# conformance fixture is where the last one was found.
sources() {
    git ls-files --cached --others --exclude-standard -- 'crates/*.rs' 'xtask/*.rs' 2>/dev/null |
        grep -v '^crates/types/generated/' |
        grep -v '^generated/' || true
}

# Strips `//` line comments and blank lines so a rule never fires on the prose explaining it.
code_lines() {
    grep -vE '^[[:space:]]*//' "$1" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Rule 1 — one definition each, in the sanctioned file.
# ---------------------------------------------------------------------------

for symbol in normalize_key floor_check_key floor_check_bucket; do
    hits=""
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        if code_lines "$file" | grep -qE "fn[[:space:]]+${symbol}[[:space:]]*\("; then
            hits="${hits}${file}
"
        fi
    done < <(sources)
    count="$(printf '%s' "$hits" | grep -c . || true)"
    if [[ "$count" -ne 1 ]]; then
        fail "single-normalisation: \`fn ${symbol}\` is defined ${count} time(s); it must be defined exactly once"
        printf '%s' "$hits" | sed 's/^/    /' >&2
    elif [[ "$(printf '%s' "$hits" | tr -d '\n')" != "$NORMALISER" ]]; then
        fail "single-normalisation: \`fn ${symbol}\` is defined in $(printf '%s' "$hits" | tr -d '\n'), not in ${NORMALISER}"
    fi
done

# ---------------------------------------------------------------------------
# Rule 2 — percent-decoding only where it is allowed.
# ---------------------------------------------------------------------------

ALLOWANCES=""
if [[ -f "$ALLOWANCE_FILE" ]]; then
    while IFS= read -r line; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | tr -d ' \t')"
        [[ -z "$line" ]] && continue
        ALLOWANCES="${ALLOWANCES}${line}
"
    done <"$ALLOWANCE_FILE"
else
    fail "single-normalisation: ${ALLOWANCE_FILE} is missing; the allowlist is the check, so an absent one fails rather than passes"
fi

is_allowed() {
    [[ -z "$ALLOWANCES" ]] && return 1
    printf '%s' "$ALLOWANCES" | grep -qxF "$1"
}

while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    if code_lines "$file" | grep -qE 'percent_decode_str[[:space:]]*\(|percent_decode[[:space:]]*\('; then
        if ! is_allowed "$file"; then
            fail "single-normalisation: ${file} percent-decodes, and is not in scripts/allowances/percent-decode-allowances.txt"
        fi
    fi
done < <(sources)

# ---------------------------------------------------------------------------
# Rule 3 — ObjectKey publishes no way back to a &str it could be rebuilt from.
# ---------------------------------------------------------------------------

while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    if code_lines "$file" | grep -qE 'impl[[:space:]]+(std::ops::)?Deref[[:space:]]+for[[:space:]]+ObjectKey'; then
        fail "single-normalisation: ${file} implements Deref for ObjectKey; a key that derefs to &str is a key the storage layer re-parses"
    fi
    if code_lines "$file" | grep -qE 'impl[[:space:]]+AsRef<str>[[:space:]]+for[[:space:]]+ObjectKey'; then
        fail "single-normalisation: ${file} implements AsRef<str> for ObjectKey; same hole as Deref, different spelling"
    fi
    if code_lines "$file" | grep -qE 'impl[[:space:]]+From<(String|&str)>[[:space:]]+for[[:space:]]+ObjectKey'; then
        fail "single-normalisation: ${file} implements From<String> for ObjectKey; an infallible constructor skips the floor entirely"
    fi
    if code_lines "$file" | grep -q 'new_unchecked'; then
        fail "single-normalisation: ${file} names new_unchecked; there is no unchecked way to build a name"
    fi
done < <(sources)

# ---------------------------------------------------------------------------
# Rule 4 — the scalar vocabulary never repairs bad bytes.
# ---------------------------------------------------------------------------

while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    case "$file" in
    "$SCALAR_DIR"/*) ;;
    *) continue ;;
    esac
    if code_lines "$file" | grep -qE 'from_utf8_lossy|decode_utf8_lossy'; then
        fail "single-normalisation: ${file} decodes lossily; U+FFFD collapses two client inputs onto one name"
    fi
done < <(sources)

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

There is exactly one place a client-chosen name becomes an ObjectKey or a
BucketName: crates/types/src/scalar/naming.rs, reached through
ObjectKey::materialize, ObjectKey::materialize_decoded and
BucketName::materialize. Route the new call site through one of those instead of
adding a second rule beside it. See rustfs/backlog#1750.
EOF
fi

exit "$status"
