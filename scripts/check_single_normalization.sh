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
#     4. No effective lossy UTF-8 conversion inside crates/types/src/scalar/.
#        The one typed mutation arm is allowed only at its exact audited line,
#        and only while the unique overlay source selects `strict`. A lossy
#        decode otherwise turns two different client inputs into one name, so
#        the value authorisation sees is not the value the client sent.
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
NAMING_OVERLAY="${ROOT_DIR}/model/overlays/quirks/naming.toml"

cd "$ROOT_DIR"

for required in git awk grep cut sort mktemp; do
    if ! command -v "$required" >/dev/null 2>&1; then
        printf 'single-normalisation: required command is missing: %s\n' "$required" >&2
        exit 1
    fi
done

# The one file allowed to hold the normalisation and the floor.
NORMALISER='crates/types/src/scalar/naming.rs'
SCALAR_DIR='crates/types/src/scalar'

status=0
fail() {
    printf '%s\n' "$1" >&2
    status=1
}

source_list="$(mktemp "${TMPDIR:-/tmp}/gateway-normalization-sources.XXXXXX")"
code_snapshot="$(mktemp "${TMPDIR:-/tmp}/gateway-normalization-code.XXXXXX")"
candidate_snapshot="$(mktemp "${TMPDIR:-/tmp}/gateway-normalization-candidates.XXXXXX")"
binary_marker="$(mktemp "${TMPDIR:-/tmp}/gateway-normalization-binary.XXXXXX")"
cleanup() { rm -f "$source_list" "$code_snapshot" "$candidate_snapshot" "$binary_marker"; }
trap cleanup EXIT

if ! git ls-files --cached --others --exclude-standard -- 'crates/*.rs' 'xtask/*.rs' >"$source_list"; then
    printf 'single-normalisation: cannot list source files\n' >&2
    exit 1
fi

sources=()
while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    case "$file" in
    crates/types/generated/* | generated/*) continue ;;
    esac
    sources+=("$file")
done <"$source_list"
if [[ "${#sources[@]}" -eq 0 ]]; then
    printf 'single-normalisation: no Rust sources found; the guard could not read the tree\n' >&2
    exit 1
fi

# Read every source once and retain its path beside each non-comment line. All later rules scan
# this one snapshot instead of starting a producer and grep process for every source file.
if ! awk '!/^[[:space:]]*\/\// { print FILENAME "\t" $0 }' "${sources[@]}" >"$code_snapshot"; then
    printf 'single-normalisation: cannot read every source file\n' >&2
    exit 1
fi

# Every ERE below requires one of these literal markers. Keep the complete path/code row:
# ungrouped alternatives in the existing patterns can also match a marker in the path.
# Rule 4's policy checks still use the full snapshot. Retain legacy binary-file behavior by
# falling back to that snapshot if any input row contains NUL, even in an unrelated line.
scan_snapshot="$candidate_snapshot"
if ! awk -v binary_marker="$binary_marker" '
    BEGIN { nul = sprintf("%c", 0) }
    length(nul) && index($0, nul) { binary = 1; exit }
    index($0, "normalize_key") || index($0, "floor_check_key") ||
    index($0, "floor_check_bucket") || index($0, "percent_decode") ||
    index($0, "ObjectKey") || index($0, "new_unchecked") ||
    index($0, "from_utf8_lossy") || index($0, "decode_utf8_lossy") { print }
    END { if (binary) print "binary" > binary_marker }
' "$code_snapshot" >"$candidate_snapshot"; then
    printf 'single-normalisation: cannot prepare candidate snapshot\n' >&2
    exit 1
fi
if [[ -s "$binary_marker" ]]; then
    scan_snapshot="$code_snapshot"
fi

matching_files() {
    local matches rc=0
    if matches="$(grep -E $'\t.*'"$1" "$scan_snapshot")"; then
        :
    else
        rc=$?
    fi
    if [[ "$rc" -eq 1 ]]; then
        return
    elif [[ "$rc" -ne 0 ]]; then
        printf 'single-normalisation: snapshot scan failed\n' >&2
        return "$rc"
    fi
    printf '%s\n' "$matches" | cut -f1 | sort -u
}

# Rule 1 — one definition each, in the sanctioned file.
for symbol in normalize_key floor_check_key floor_check_bucket; do
    hits="$(matching_files "fn[[:space:]]+${symbol}[[:space:]]*\\(")"
    count=0
    if [[ -n "$hits" ]]; then
        while IFS= read -r hit; do
            [[ -n "$hit" ]] && count=$((count + 1))
        done <<<"$hits"
    fi
    if [[ "$count" -ne 1 ]]; then
        fail "single-normalisation: \`fn ${symbol}\` is defined ${count} time(s); it must be defined exactly once"
        while IFS= read -r hit; do
            [[ -n "$hit" ]] && printf '    %s\n' "$hit" >&2
        done <<<"$hits"
    elif [[ "$hits" != "$NORMALISER" ]]; then
        fail "single-normalisation: \`fn ${symbol}\` is defined in ${hits}, not in ${NORMALISER}"
    fi
done

# Rule 2 — percent-decoding only where it is allowed.
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
    [[ -n "$ALLOWANCES" ]] && printf '%s' "$ALLOWANCES" | grep -xF "$1" >/dev/null
}

percent_hits="$(matching_files 'percent_decode_str[[:space:]]*\(|percent_decode[[:space:]]*\(')"
while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    if ! is_allowed "$file"; then
        fail "single-normalisation: ${file} percent-decodes, and is not in scripts/allowances/percent-decode-allowances.txt"
    fi
done <<<"$percent_hits"

# Rule 3 — ObjectKey publishes no way back to a &str it could be rebuilt from.
report_bypass() {
    local pattern="$1" message="$2" file files
    files="$(matching_files "$pattern")"
    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        fail "single-normalisation: ${file} ${message}"
    done <<<"$files"
}
report_bypass 'impl[[:space:]]+(std::ops::)?Deref[[:space:]]+for[[:space:]]+ObjectKey' \
    'implements Deref for ObjectKey; a key that derefs to &str is a key the storage layer re-parses'
report_bypass 'impl[[:space:]]+AsRef<str>[[:space:]]+for[[:space:]]+ObjectKey' \
    'implements AsRef<str> for ObjectKey; same hole as Deref, different spelling'
report_bypass 'impl[[:space:]]+From<(String|&str)>[[:space:]]+for[[:space:]]+ObjectKey' \
    'implements From<String> for ObjectKey; an infallible constructor skips the floor entirely'
report_bypass 'new_unchecked' 'names new_unchecked; there is no unchecked way to build a name'

# ---------------------------------------------------------------------------
# Rule 4 — the scalar vocabulary never effectively repairs bad bytes.
#
# The typed quirk table needs a real strict -> lossy mutation arm so its case can
# prove the behavior. That arm is not a general allowance: it must be the one
# exact arm in the one normalizer, selected by the one policy match, while the
# unique overlay source still says `strict`. `codegen --check` separately makes
# the generated constant agree with that source. Changing the current to lossy,
# moving the call, or adding any second lossy conversion all fail here.
# ---------------------------------------------------------------------------

strict_utf8_mutant_is_contract_gated() {
    local file="$1" lossy_lines policy_values
    [[ "$file" == "$NORMALISER" ]] || return 1
    [[ -f "$NAMING_OVERLAY" ]] || return 1

    lossy_lines="$(awk -F '\t' -v path="$file" '
        $1 == path && $0 ~ /(from_utf8_lossy|decode_utf8_lossy)/ {
            sub(/^[^\t]*\t/, "")
            sub(/^[[:space:]]*/, "")
            print
        }
    ' "$code_snapshot")"
    [[ "$lossy_lines" == 'DecodedUtf8Policy::Lossy => Ok(percent_decode_str(value).decode_utf8_lossy().into_owned()),' ]] || return 1
    [[ "$(awk -F '\t' -v path="$file" '$1 == path && index($0, "match DECODED_UTF8_POLICY {") { count++ } END { print count + 0 }' "$code_snapshot")" -eq 1 ]] || return 1

    policy_values="$(awk '
        function emit() {
            if (dimension == "decoded_utf8") print dimension "|" value
        }
        /^\[\[quirk\]\]/ {
            emit()
            dimension = ""
            value = ""
            next
        }
        /^[[:space:]]*mutation_dimension[[:space:]]*=/ {
            dimension = $0
            sub(/^[^=]*=[[:space:]]*"/, "", dimension)
            sub(/"[[:space:]]*$/, "", dimension)
        }
        /^[[:space:]]*contract_value[[:space:]]*=/ {
            value = $0
            sub(/^[^=]*=[[:space:]]*"/, "", value)
            sub(/"[[:space:]]*$/, "", value)
        }
        END { emit() }
    ' "$NAMING_OVERLAY")"
    [[ "$policy_values" == 'decoded_utf8|strict' ]]
}

lossy_hits="$(matching_files 'from_utf8_lossy|decode_utf8_lossy')"
while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    case "$file" in
    "$SCALAR_DIR"/*)
        if ! strict_utf8_mutant_is_contract_gated "$file"; then
            fail "single-normalisation: ${file} decodes lossily; U+FFFD collapses two client inputs onto one name"
        fi
        ;;
    esac
done <<<"$lossy_hits"

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
