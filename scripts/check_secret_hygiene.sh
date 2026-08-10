#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_secret_hygiene.sh
#
# WHAT THIS CHECKS
#   Six rules over the credential surface in `crates/gateway/src/ext/` — the
#   place a long-term secret, an STS session token and a derived signing key
#   are held between the credential store and the comparison.
#
#   1. Both subjects exist. `credentials.rs` defines the containers and
#      `authenticator.rs` is the one consumer; if either moves, this guard has
#      nothing to check and must say so rather than pass.
#   2. `Credentials` does not derive `Debug`, and a hand-written
#      `impl ... Debug for Credentials` exists. The redacting `Debug` is the
#      only reason a credential can appear in a diagnostic at all; deleting it
#      and letting the derive come back is the mutation this rule catches.
#   3. No `impl Display for Credentials`. A hand-written `Debug` can redact;
#      `Display` exists to render a value for a human, and there is no
#      redacting form of that worth having.
#   4. No formatting or logging macro under `crates/gateway/src/` names key
#      material (GHSA-r54g / GHSA-8cm2 / GHSA-333v — the secret in the log), and
#      no file under it names `CredentialRefusal` except the module that defines
#      it and the two export blocks. Which rule refused a credential — expired,
#      disabled, or bound to a token the request did not present — is exactly
#      the bit the uniform 403 exists to withhold. The framework's own verifier
#      consumes it through `admit(..).err()` without ever spelling the type, so
#      spelling it is the signal that something is branching on it, rendering it,
#      or writing it down.
#   5. No key material lives in a `Vec<u8>` or a `String` under
#      `crates/gateway/src/`. `zeroize` cannot reach the buffers a growing
#      `Vec` left behind.
#   6. `.expose()` — the one accessor that turns a container back into bytes —
#      has at most EXPOSE_CEILING call sites under `crates/gateway/src/`. Each
#      one is a place key material leaves its container, and a new one should
#      be a decision somebody defends rather than a line somebody adds.
#
#   Comment and doc-comment lines are skipped by rules 4-6: this repository
#   explains a rule in prose directly above the code it governs, and a guard
#   that fires on its own explanation gets deleted within a week.
#
# WHY THIS EXISTS BESIDE check_ct_eq.sh
#   `check_ct_eq.sh` rules 3-6 are scoped to `^crates/sig/src/|^crates/core/src/authn`
#   — deliberately, because outside those a `Vec<u8>` named `token` is a
#   pagination cursor. `crates/gateway/src/ext/` is outside that scope and
#   holds the same material: `Credentials` carries a `SecretBytes` and a
#   `SessionToken`, and `ChunkVerification` carries a `SigningKey`. Rules 4 and
#   5 here are the same two rules applied to the path the other guard does not
#   reach; rules 1-3 and 6 have no counterpart anywhere.
#
#   https://github.com/rustfs/rustfs/security/advisories/GHSA-r54g-49rx-98cr
#   https://github.com/rustfs/rustfs/security/advisories/GHSA-8cm2-h255-v749
#   https://github.com/rustfs/rustfs/security/advisories/GHSA-333v-68xh-8mmq
#   https://github.com/rustfs/rustfs/security/advisories/GHSA-3p3x-734c-h5vx
#
# HOW TO EXEMPT
#   There is no exemption file, deliberately. If a subject moves, move it and
#   update the path below in the same commit. A genuinely necessary new reader
#   of key material means raising EXPOSE_CEILING, which is a diff a reviewer
#   has to look at.
#
# USAGE
#   scripts/check_secret_hygiene.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_secret_hygiene.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

cd "$ROOT_DIR"

# The module that defines the credential containers.
CREDENTIALS_FILE='crates/gateway/src/ext/credentials.rs'
# Its one consumer, which holds a secret and a derived key for the length of a verification.
AUTHENTICATOR_FILE='crates/gateway/src/ext/authenticator.rs'
# The tree rules 4-6 are scoped to.
GUARDED_PATH_RE='^crates/gateway/src/'
# Identifiers that name key material. Deliberately NOT bare `key` or `token`: `access_key_id` is a
# public identifier and `continuation_token` is paging.
SECRET_IDENT_RE='(^|[^[:alnum:]_])(secret|signing_key|session_token|private_key|derived_key|passphrase|expected_signature)([^[:alnum:]]|$)'
# The only files under the guarded tree that may spell `CredentialRefusal`: the module that
# defines it, and the two export blocks that publish it for a deployment writing its own
# `Authenticator`. `SigV4Authenticator` reaches the reason through `admit(..).err()` and never
# names the type, so anything else that does is doing something with the reason.
REFUSAL_MAY_APPEAR_IN=(
    'crates/gateway/src/ext/credentials.rs'
    'crates/gateway/src/ext/mod.rs'
    'crates/gateway/src/lib.rs'
)
# How many places key material may leave its container under the guarded tree. Two are the module's
# own tests reading a fixture back; one is the chunk signer, which needs the derived key as bytes.
EXPOSE_CEILING=3

status=0

report() {
    printf '%s\n' "$1" >&2
    status=1
}

# -----------------------------------------------------------------------------
# Rule 1 — the subjects exist.
# -----------------------------------------------------------------------------
for required in "$CREDENTIALS_FILE" "$AUTHENTICATOR_FILE"; do
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
# Rule 2 — `Credentials` has a hand-written redacting Debug and no derived one.
# -----------------------------------------------------------------------------
credentials_code="$(strip_comments "$CREDENTIALS_FILE")"

if ! printf '%s\n' "$credentials_code" | grep -E '^impl ([a-z_:]+)?fmt::Debug for Credentials \{' >/dev/null; then
    report "${CREDENTIALS_FILE}: no hand-written 'impl fmt::Debug for Credentials'; the redacting Debug is the only reason a credential may appear in a diagnostic at all"
fi

# The attribute block immediately above `pub struct Credentials`, if any.
derived_on_credentials="$(printf '%s\n' "$credentials_code" | awk '
    function flush_pending() { pending = "" }
    {
        s = $0
        sub(/^[ \t]+/, "", s)
        if (s == "") { next }
        if (s ~ /^#[!]?\[/) { pending = pending " " s; next }
        if (s ~ /^(pub[ \t]+)?struct[ \t]+Credentials([ \t{<]|$)/) {
            if (pending ~ /derive[ \t]*\(/) { print NR "\t" pending }
        }
        flush_pending()
    }
')"
if printf '%s' "$derived_on_credentials" | grep -E '\b(Debug|Serialize|Deserialize|PartialEq|Eq|Clone)\b' >/dev/null; then
    report "${CREDENTIALS_FILE}: 'struct Credentials' derives a trait that prints, compares, serializes or silently copies key material: ${derived_on_credentials}"
fi

# -----------------------------------------------------------------------------
# Rule 3 — no Display for Credentials.
# -----------------------------------------------------------------------------
if printf '%s\n' "$credentials_code" | grep -E '^impl ([a-z_:]+)?Display for Credentials\b' >/dev/null; then
    report "${CREDENTIALS_FILE}: Display is implemented for Credentials; a value that renders itself for a human is a value that ends up in a log"
fi

# -----------------------------------------------------------------------------
# Rules 4-6 — scoped to the tree check_ct_eq.sh does not reach.
# -----------------------------------------------------------------------------
sources=()
while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    [[ "$file" =~ $GUARDED_PATH_RE ]] || continue
    sources+=("$file")
# `--cached --others --exclude-standard`, not a bare `git ls-files`: a brand-new file is untracked
# until it is committed, and a guard that cannot see it reports success for the wrong reason.
done < <(git ls-files --cached --others --exclude-standard -- '*.rs' ':!:target/*' ':!:generated/*' ':!:*/generated/*' 2>/dev/null || true)

if [[ "${#sources[@]}" -eq 0 ]]; then
    report "no Rust sources are visible under crates/gateway/src; rules 4-6 cannot have checked anything"
    exit 1
fi

expose_total=0
for file in "${sources[@]}"; do
    code="$(strip_comments "$file")"

    # Rule 4 — key material, or a refusal reason, inside a formatting or logging macro.
    while IFS= read -r hit; do
        [[ -n "$hit" ]] || continue
        report "${file}:${hit%%:*}: a formatting or logging macro names key material; GHSA-r54g / GHSA-8cm2 / GHSA-333v were all a secret in a log line"
    done < <(printf '%s\n' "$code" |
        grep -nE '(format!|write!|writeln!|print!|println!|eprintln!|panic!|unreachable!|todo!|tracing::[a-z_]+!|(debug|info|warn|error|trace)!)[ \t]*\(' |
        grep -iE "$SECRET_IDENT_RE" || true)

    # Rule 4b — the refusal reason does not travel. Named rather than inferred is the whole
    # signal: `admit(..).err()` yields the reason without ever spelling the type, so a file that
    # spells it is a file doing something with it.
    if printf '%s\n' "$code" | grep 'CredentialRefusal' >/dev/null; then
        allowed=0
        for permitted in "${REFUSAL_MAY_APPEAR_IN[@]}"; do
            [[ "$file" == "$permitted" ]] && allowed=1
        done
        if [[ "$allowed" -eq 0 ]]; then
            report "${file}: names CredentialRefusal; which rule refused a credential — expired, disabled, or bound to a token the request did not present — is the bit the uniform 403 exists to withhold, and it is produced and consumed in ${CREDENTIALS_FILE} without anything else naming the type"
        fi
    fi

    # Rule 5 — key material in a reallocating buffer.
    while IFS= read -r hit; do
        [[ -n "$hit" ]] || continue
        report "${file}:${hit%%:*}: key material in a Vec<u8>/String; zeroize cannot reach the buffers a growing Vec left behind — use Box<[u8]> or a fixed-size array"
    done < <(printf '%s\n' "$code" | grep -nE '(Vec<u8>|String)' | grep -iE "$SECRET_IDENT_RE" || true)

    # Rule 6 — how many places bytes leave a container.
    count="$(printf '%s\n' "$code" | grep -c '\.expose()' || true)"
    expose_total=$((expose_total + count))
done

if [[ "$expose_total" -gt "$EXPOSE_CEILING" ]]; then
    report ".expose() appears ${expose_total} times under crates/gateway/src, above the ceiling of ${EXPOSE_CEILING}; every call is a place key material becomes a plain byte slice, and a new one needs an argument on the issue rather than a raised number"
fi

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Secret hygiene rule violated. See rustfs/backlog#1736.
A credential container is only as good as the impls it does NOT have: the moment
something prints, compares or copies one, the container is decoration. The same
applies to the *reason* a credential was refused — expired, disabled, or bound to
a token the request did not present. All three are answered with one 403 on the
wire precisely so that nobody learns which; writing the distinction into a log
gives it back.
EOF
    exit "$status"
fi

printf 'OK: credential hygiene satisfied (0 violations; %s .expose() call site(s) <= %s)\n' "$expose_total" "$EXPOSE_CEILING"
exit 0
