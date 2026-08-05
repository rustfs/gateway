#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_ct_eq.sh
#
# WHAT THIS CHECKS
#   That no secret-bearing type derives `PartialEq`, `Eq` or `Debug`.
#
#   A type is treated as secret-bearing when its name contains one of:
#     Signature, Secret, SecretKey, SigningKey, SessionToken, SigningPayload
#   (see SENSITIVE_NAME_RE below). For every such `struct`/`enum`/`union`
#   declaration, the attribute block directly above it is inspected and any
#   `#[derive(...)]` listing a banned trait is reported with file:line.
#
#   Manual implementations are NOT flagged. A hand-written `impl fmt::Debug`
#   that prints `Signature(<redacted>)` is the required pattern, and a
#   hand-written `PartialEq` that delegates to `subtle::ConstantTimeEq` is the
#   whole point of the rule.
#
#   The check is a no-op that exits 0 with an explanation when no secret-bearing
#   type exists yet. `crates/s3gate-sig` is an empty shell until P2; this guard
#   is deliberately landed BEFORE the first line of signature code so that it is
#   already in CI when that code arrives, rather than being retrofitted onto a
#   codebase that already violates it.
#
# WHY
#   `#[derive(PartialEq)]` on a signature or secret compiles to a byte-wise
#   comparison that short-circuits on the first differing byte. That is a
#   textbook timing oracle: an attacker who can measure verification latency
#   recovers the expected signature byte by byte and then forges requests
#   without ever knowing the secret key.
#
#   Removing the derive does more than remove one bad comparison — it makes the
#   wrong thing UNREPRESENTABLE. With no `PartialEq` impl, `sig_a == sig_b`
#   simply does not compile, so every comparison is forced through the
#   constant-time path. The compiler, not review, becomes the enforcement.
#
#   `Debug` is banned on the same types for a different reason: a derived
#   `Debug` is how secrets end up in logs, panic messages, `tracing` spans and
#   error types. See rustfs/backlog#1724 (P0-10, first layer: deterministic
#   role duties become scripts).
#
# HOW TO EXEMPT
#   Add a line to `scripts/allowances/ct-eq-allowances.txt` (create it if
#   absent):
#
#       <path>:<TypeName>    # <why this type holds no secret material>
#
#   The only legitimate reason is a false positive on the name heuristic — for
#   example a `SignatureAlgorithm` enum that names an algorithm and carries no
#   key material. "It is more convenient in tests" is not a reason; write the
#   constant-time comparison helper instead.
#
# USAGE
#   scripts/check_ct_eq.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_ct_eq.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ALLOWANCE_FILE="${SCRIPT_DIR}/allowances/ct-eq-allowances.txt"

cd "$ROOT_DIR"

# Substring match on the type name. Kept in one place so the skill playbook and
# this guard cannot drift apart.
SENSITIVE_NAME_RE='(Signature|Secret|SecretKey|SigningKey|SessionToken|SigningPayload)'
BANNED_DERIVES='PartialEq|Eq|Debug'

status=0
sensitive_seen=0

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

sources=()
while IFS= read -r file; do
    [[ -n "$file" ]] && sources+=("$file")
done < <(git ls-files -- '*.rs' ':!:target/*' ':!:generated/*' ':!:*/generated/*' 2>/dev/null || true)

if [[ "${#sources[@]}" -eq 0 ]]; then
    printf 'check_ct_eq: no tracked Rust sources yet — nothing to check (this guard activates with the P2 signature code).\n'
    exit 0
fi

# awk scans each file, keeping the pending attribute block that precedes the
# next item declaration. Output: "<line>\t<TypeName>\t<offending derives>"
# for sensitive declarations, and "SENSITIVE" markers so the caller can tell
# "no violations" apart from "nothing to check".
for file in "${sources[@]}"; do
    while IFS=$'\t' read -r tag line type_name offenders; do
        [[ -z "${tag:-}" ]] && continue

        if [[ "$tag" == "SEEN" ]]; then
            sensitive_seen=1
            continue
        fi

        if is_allowed "${file}:${type_name}"; then
            continue
        fi

        printf "%s:%s: secret-bearing type '%s' derives %s; derive nothing that compares or prints key material — implement PartialEq via subtle::ConstantTimeEq and a redacting Debug by hand\n" \
            "$file" "$line" "$type_name" "$offenders" >&2
        status=1
    done < <(awk -v sensitive="$SENSITIVE_NAME_RE" -v banned="$BANNED_DERIVES" '
        function flush_pending() { pending = ""; pending_line = 0 }
        {
            s = $0
            sub(/^[ \t]+/, "", s)

            # Blank lines, comments and doc comments do not break an attribute block.
            if (s == "" || s ~ /^\/\//) { next }

            if (s ~ /^#[!]?\[/) {
                if (pending == "") { pending_line = NR }
                pending = pending " " s
                next
            }

            if (match(s, /^(pub([ \t]*\([^)]*\))?[ \t]+)?(struct|enum|union)[ \t]+[A-Za-z_][A-Za-z0-9_]*/)) {
                decl = substr(s, RSTART, RLENGTH)
                n = split(decl, words, /[ \t]+/)
                name = words[n]

                if (name ~ sensitive) {
                    print "SEEN\t0\t" name "\t"

                    if (pending ~ /derive[ \t]*\(/) {
                        # Collect the banned traits actually listed.
                        found = ""
                        body = pending
                        while (match(body, /derive[ \t]*\([^)]*\)/)) {
                            seg = substr(body, RSTART, RLENGTH)
                            body = substr(body, RSTART + RLENGTH)
                            m = split(seg, toks, /[^A-Za-z0-9_]+/)
                            for (i = 1; i <= m; i++) {
                                t = toks[i]
                                if (t == "derive") continue
                                if (t ~ ("^(" banned ")$")) {
                                    if (index(" " found " ", " " t " ") == 0) {
                                        found = (found == "" ? t : found ", " t)
                                    }
                                }
                            }
                        }
                        if (found != "") {
                            print "HIT\t" (pending_line ? pending_line : NR) "\t" name "\t" found
                        }
                    }
                }
            }
            flush_pending()
        }
    ' "$file")
done

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Constant-time rule violated. See rustfs/backlog#1724.
A derived PartialEq short-circuits on the first differing byte, which leaks the
expected signature through timing; a derived Debug leaks the secret into logs.
Removing the derives makes `a == b` fail to compile, which is the point: the
compiler forces every comparison through the constant-time path.
EOF
    exit "$status"
fi

if [[ "$sensitive_seen" -eq 0 ]]; then
    printf 'check_ct_eq: no secret-bearing type declarations found yet (matching /%s/).\n' "$SENSITIVE_NAME_RE"
    printf '             The guard is in place and will activate automatically when crates/s3gate-sig lands in P2.\n'
fi

exit 0
