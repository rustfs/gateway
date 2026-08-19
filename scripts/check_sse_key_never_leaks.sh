#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_sse_key_never_leaks.sh
#
# WHAT THIS CHECKS
#   Five rules over the one value in this protocol that a client hands the
#   server in cleartext and then reuses: the SSE-C customer-provided key.
#
#   1. No operation's OUTPUT binds a customer-key header. `spec/operations/*.toml`
#      is scanned section by section; a `wire_name` equal to
#      `x-amz-server-side-encryption-customer-key` or its `copy-source` twin
#      under an `[[output]]` block is a generated encoder that would write the
#      key onto a response. The `-md5` and `-algorithm` spellings are NOT
#      matched: AWS returns both and so must this gateway.
#   2. The response invariant is still wired. `crates/gateway/src/invariants.rs`
#      must name `NEVER_IN_A_RESPONSE`, and `crates/core/src/sse/headers.rs`
#      must define it as both key constants. Rule 1 governs what an encoder can
#      be generated to write; this one governs what any code at all can leave on
#      a response, and deleting the strip is the change it exists to catch.
#   3. `KeyText::expose` has exactly one call site. The key's text is carried in
#      a type with no `Debug`, no `Display` and one accessor; a second caller is
#      a second place the key becomes a `&str`, and a `&str` is one `{}` from a
#      log line. Scoped to `crates/core/src/sse/`, which is where every call has
#      to be: the accessor is `pub(super)`, so nothing outside that module tree
#      can reach it, and `crates/sig`'s unrelated `SecretBytes::expose` shares
#      the name.
#   4. Exactly one `bool::from(` under `crates/core/src/sse/`, in `key.rs`. Same
#      rule `check_ct_eq.sh` applies to `crates/sig`, applied to the other module
#      that compares bytes derived from key material: a second conversion is how
#      `a.ct_eq(&b).into() && other()` gets written, and `&&` short-circuits.
#   5. No formatting or logging macro anywhere in the workspace's non-test source
#      takes an argument naming a customer key.
#
#   Rules 1-4 count, so a renamed or deleted subject fails rather than passes
#   quietly. Comment and doc-comment lines are skipped by rules 3-5: this
#   repository explains a rule in prose directly above the code it governs, and
#   a guard that fires on its own explanation gets deleted within a week.
#
# WHY
#   `x-amz-server-side-encryption-customer-key` is a raw AES-256 key, base64'd,
#   in a request header. Three things follow, and none of them is a matter of
#   care at review time:
#
#   * echoed on a response it reaches every proxy, cache and access log between
#     here and the caller — and the caller's own logs, which is where it will
#     actually be found;
#   * interpolated into an error message it reaches whatever aggregates errors,
#     which is the shape of both RustFS advisories below;
#   * compared with `==` it leaks through timing, which is the same rule
#     `check_ct_eq.sh` enforces one crate over.
#
#   https://github.com/rustfs/rustfs/security/advisories/GHSA-8cm2-h255-v749
#   https://github.com/rustfs/rustfs/security/advisories/GHSA-333v-68xh-8mmq
#   Both were a secret reaching a log. Neither needed a subtle mistake.
#
# HOW TO EXEMPT
#   There is no exemption file, deliberately. If a subject has to move, move it
#   and update the path below in the same commit; if something genuinely needs
#   a second reader of the key, that needs an argument on the issue first.
#
# USAGE
#   scripts/check_sse_key_never_leaks.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_sse_key_never_leaks.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

cd "$ROOT_DIR"

# The module that defines the header vocabulary and the never-echoed list.
HEADERS_FILE='crates/core/src/sse/headers.rs'
# The module holding the one constant-time comparison.
KEY_FILE='crates/core/src/sse/key.rs'
# The single response invariant, which must consume the never-echoed list.
INVARIANTS_FILE='crates/gateway/src/invariants.rs'
# The directory rule 4 is scoped to.
SSE_DIR='crates/core/src/sse'
# Identifiers that name a customer key. Deliberately narrow: `key` alone is an
# object key, and `key_id` is a KMS identifier AWS echoes.
SECRET_IDENT_RE='(customer_key|customer-key|ssec_key|sse_c_key|key_text|KeyText|\.expose\(\))'

status=0

report() {
    printf '%s\n' "$1" >&2
    status=1
}

for required in "$HEADERS_FILE" "$KEY_FILE" "$INVARIANTS_FILE"; do
    if [[ ! -f "$required" ]]; then
        report "${required} does not exist; a subject of this guard has moved or been deleted, and a guard with no input must fail rather than pass silently"
        exit 1
    fi
done

# Comment lines blanked, numbering preserved.
strip_comments() {
    awk '{ s = $0; sub(/^[ \t]+/, "", s); if (s ~ /^\/\//) { print "" } else { print $0 } }' "$1"
}

# -----------------------------------------------------------------------------
# Rule 1 — no operation output binds a customer-key header.
# -----------------------------------------------------------------------------
spec_files=()
while IFS= read -r file; do
    [[ -n "$file" ]] && spec_files+=("$file")
done < <(git ls-files --cached --others --exclude-standard -- 'spec/operations/*.toml' 2>/dev/null || true)

if [[ "${#spec_files[@]}" -eq 0 ]]; then
    report "no operation specifications are visible under spec/operations; rule 1 cannot have checked anything"
else
    for file in "${spec_files[@]}"; do
        while IFS= read -r hit; do
            [[ -z "$hit" ]] && continue
            report "${file}:${hit}: an operation OUTPUT binds a customer-provided encryption key header; a response that carries the key hands it to every intermediary and every access log on the way home. Only the -algorithm and -md5 spellings may be returned"
        done < <(awk '
            /^\[\[input\]\]/ { section = "input"; next }
            /^\[\[output\]\]/ { section = "output"; next }
            /^\[/ { section = "other"; next }
            /^wire_name = "x-amz-(copy-source-)?server-side-encryption-customer-key"$/ {
                if (section == "output") { print NR }
            }
        ' "$file")
    done
fi

# -----------------------------------------------------------------------------
# Rule 2 — the never-echoed list exists, names both keys, and is consumed.
# -----------------------------------------------------------------------------
list_definition="$(strip_comments "$HEADERS_FILE" | awk '
    /NEVER_IN_A_RESPONSE/ { collecting = 1 }
    collecting == 1 { print; if (/;/) { collecting = 0 } }
')"

if [[ -z "$list_definition" ]]; then
    report "${HEADERS_FILE} no longer defines NEVER_IN_A_RESPONSE; the list the response invariant strips by has gone, so nothing removes a customer key from a response"
else
    for constant in SSEC_KEY COPY_SSEC_KEY; do
        # Word-boundary match: `SSEC_KEY` must not be satisfied by `SSEC_KEY_MD5`.
        if ! printf '%s\n' "$list_definition" | grep -E "(^|[^A-Z_])${constant}([^A-Z_]|$)" >/dev/null; then
            report "NEVER_IN_A_RESPONSE in ${HEADERS_FILE} does not list ${constant}; a CopyObject carries two independent keys and dropping either spelling echoes the one nobody was looking for"
        fi
    done
fi

# Do not use `grep -q` here: on Linux it can close the pipe after the first match, making awk exit
# with SIGPIPE under `pipefail` and turning a real match into a failed guard.
if ! strip_comments "$INVARIANTS_FILE" | grep 'NEVER_IN_A_RESPONSE' >/dev/null; then
    report "${INVARIANTS_FILE} does not consume NEVER_IN_A_RESPONSE; the one place every response passes through no longer strips the customer-key headers, so a backend that sets one puts it on the wire"
fi

# -----------------------------------------------------------------------------
# Rules 3-5 — over the workspace's Rust sources.
# -----------------------------------------------------------------------------
sources=()
while IFS= read -r file; do
    [[ -n "$file" ]] && sources+=("$file")
done < <(git ls-files --cached --others --exclude-standard -- '*.rs' ':!:target/*' ':!:generated/*' ':!:*/generated/*' 2>/dev/null || true)

if [[ "${#sources[@]}" -eq 0 ]]; then
    report "no Rust sources are visible to this guard; rules 3 to 5 cannot have checked anything"
    exit "$status"
fi

expose_call_sites=0
choice_to_bool=0

for file in "${sources[@]}"; do
    code="$(strip_comments "$file")"

    # Rules 3 and 4 — both scoped to the SSE module, for the reasons above.
    case "$file" in
    "$SSE_DIR"/*)
        hits="$(printf '%s\n' "$code" | grep -cE '\.expose\(\)' || true)"
        expose_call_sites=$((expose_call_sites + hits))
        count="$(printf '%s\n' "$code" | grep -c 'bool::from(' || true)"
        choice_to_bool=$((choice_to_bool + count))
        if [[ "$count" -gt 0 && "$file" != "$KEY_FILE" ]]; then
            report "${file}: bool::from( outside ${KEY_FILE}; a subtle::Choice turned into a bool can be short-circuited with && and stops being constant time"
        fi
        ;;
    esac

    # Rule 5 — a formatting or logging macro naming a customer key. Tests are
    # exempt: several of them assert the key's *absence* and name it to do so.
    case "$file" in
    *"/tests/"* | tests/* | */tests.rs) continue ;;
    esac
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: a formatting or logging macro names a customer-provided encryption key; GHSA-8cm2 and GHSA-333v were both a secret in a log line"
    done < <(printf '%s\n' "$code" |
        grep -nE '(format!|write!|writeln!|print!|println!|eprintln!|panic!|unreachable!|todo!|tracing::[a-z_]+!|(debug|info|warn|error|trace)!)[ \t]*\(' |
        grep -E "$SECRET_IDENT_RE" || true)
done

if [[ "$expose_call_sites" -ne 1 ]]; then
    report "KeyText::expose has ${expose_call_sites} call sites and must have exactly one; the key's text becomes a &str at each of them, and a &str is one {} away from a log line"
fi

if [[ "$choice_to_bool" -ne 1 ]]; then
    report "bool::from( appears ${choice_to_bool} times under ${SSE_DIR} and must appear exactly once, in ${KEY_FILE}; zero means the constant-time comparison has gone, more than one means a second escape hatch exists"
fi

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

The SSE-C customer key rule was broken. See rustfs/backlog#1751.
The key is a raw AES-256 key that a client sends in a request header. It must
never be echoed on a response, never reach a log line or an error message, and
never be compared with anything that short-circuits.
EOF
    exit "$status"
fi

printf 'OK: SSE-C key hygiene satisfied (%s operation specs, 1 expose call site, 1 constant-time comparison, the never-echoed list is defined and consumed)\n' \
    "${#spec_files[@]}"
exit 0
