#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_ct_eq.sh
#
# WHAT THIS CHECKS
#   Seven rules. The first two are repository-wide; the rest are scoped to the
#   crates that hold key material (`crates/sig`, and `rustfs-gateway-core`'s
#   authn modules once they exist), because outside those a `Vec<u8>` named
#   `token` is a pagination token, not a credential.
#
#   1. No secret-bearing type derives `PartialEq`, `Eq`, `Debug`, `Serialize`
#      or `Deserialize`. A type is treated as secret-bearing when its name
#      contains one of the substrings in SENSITIVE_NAME_RE below. For every
#      such `struct`/`enum`/`union` declaration, the attribute block directly
#      above it is inspected and any `#[derive(...)]` listing a banned trait is
#      reported with file:line.
#   2. No `impl Display for` a secret-bearing type. `Debug` may be implemented
#      BY HAND — a redacting `Debug` is the sanctioned pattern — but `Display`
#      has no redacting form worth having: it exists to render the value.
#   3. `bool::from(` appears at most once in the guarded crates, and only in
#      CHOICE_TO_BOOL_FILE. That is the `subtle::Choice` escape hatch; a second
#      one is how `a.ct_eq(&b).into() && other()` gets written, and `&&`
#      short-circuits.
#   4. `.unwrap_u8()` — `subtle`'s other escape hatch — appears nowhere.
#   5. No formatting or logging macro takes an argument naming key material.
#      GHSA-r54g / GHSA-8cm2 / GHSA-333v were all "the secret was in the log".
#   6. No key material lives in a `Vec<u8>` or a `String`. `zeroize` cannot
#      reach the buffers a growing `Vec` left behind, so a secret that was
#      accumulated has copies on the heap that no `Drop` will ever wipe.
#   7. Negative-case floors: the number of `compile_fail` doctests and of
#      `/// Negative` test labels in `crates/sig` may not fall below the
#      recorded baselines. Aligns with rustfs/rustfs#4815 — a negative suite
#      that is quietly emptied leaves a green check mark and no coverage.
#
#   Comment and doc-comment lines are skipped by rules 3-6. This matters: the
#   codebase explains these rules in prose right next to the code they govern
#   (`crates/stream` documents that it deliberately has no `as_any()`,
#   `secret.rs` shows `format!("{token}")` inside a `compile_fail` example), and
#   a guard that fires on its own documentation gets deleted within a week.
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
#   None of this touches MinIO CVE-2025-31489, where the signature was never
#   compared at all. That defect is answered by the type shape in
#   `crates/sig/src/verdict.rs` — `Verdict::Authenticated` requires a
#   `SignatureMatch` that only a real constant-time comparison produces — and
#   rules 3 and 7 exist to keep that shape from being hollowed out.
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
SENSITIVE_NAME_RE='(Signature|Secret|SecretKey|SigningKey|SessionToken|SigningPayload|CtBytes)'
BANNED_DERIVES='PartialEq|Eq|Debug|Serialize|Deserialize'

# Rules 3-6 apply here only. Outside these paths the identifier heuristics
# produce false positives that would train everyone to ignore the guard.
GUARDED_PATH_RE='^crates/sig/src/|^crates/core/src/authn'
# The single file allowed to turn a `subtle::Choice` into a `bool`.
CHOICE_TO_BOOL_FILE='crates/sig/src/signature.rs'
# Identifiers that name key material. Deliberately NOT bare `key` or `token`:
# `access_key_id` is a public identifier and `continuation_token` is paging.
SECRET_IDENT_RE='(secret|signing_key|session_token|private_key|derived_key|passphrase|expected_signature)'
# Baselines for rule 7. Raise them when a PR adds cases; lowering one is the
# change a reviewer must refuse to wave through. Set to the counts measured
# after P2-04 landed the security floor: a ratchet that trails the tree by 80
# cases is not a ratchet, it is a number nobody has to think about.
COMPILE_FAIL_FLOOR=25
NEGATIVE_LABEL_FLOOR=105

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

report() {
    printf '%s\n' "$1" >&2
    status=1
}

sources=()
while IFS= read -r file; do
    [[ -n "$file" ]] && sources+=("$file")
done < <(git ls-files -- '*.rs' ':!:target/*' ':!:generated/*' ':!:*/generated/*' 2>/dev/null || true)

if [[ "${#sources[@]}" -eq 0 ]]; then
    printf 'check_ct_eq: no tracked Rust sources yet — nothing to check (this guard activates with the P2 signature code).\n'
    exit 0
fi

guarded=()
for file in "${sources[@]}"; do
    if [[ "$file" =~ $GUARDED_PATH_RE ]]; then
        guarded+=("$file")
    fi
done

# -----------------------------------------------------------------------------
# Rule 1 — banned derives on secret-bearing types (repository-wide).
#
# awk scans each file, keeping the pending attribute block that precedes the
# next item declaration. Output: "<line>\t<TypeName>\t<offending derives>"
# for sensitive declarations, and "SEEN" markers so the caller can tell
# "no violations" apart from "nothing to check".
# -----------------------------------------------------------------------------
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

        report "$(printf "%s:%s: secret-bearing type '%s' derives %s; derive nothing that compares, prints or serializes key material — implement PartialEq via subtle::ConstantTimeEq and a redacting Debug by hand" \
            "$file" "$line" "$type_name" "$offenders")"
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

# -----------------------------------------------------------------------------
# Rule 2 — no `impl Display for` a secret-bearing type (repository-wide).
# A hand-written `Debug` is fine and expected; `Display` is not, because its
# whole contract is "render this value for a human", which is a log line.
# -----------------------------------------------------------------------------
for file in "${sources[@]}"; do
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        line="${hit%%:*}"
        text="${hit#*:}"
        type_name="$(printf '%s' "$text" | sed -E 's/.*for[ \t]+([A-Za-z_][A-Za-z0-9_]*).*/\1/')"
        if is_allowed "${file}:${type_name}"; then
            continue
        fi
        report "${file}:${line}: Display is implemented for secret-bearing type '${type_name}'; a value that renders itself for a human is a value that ends up in a log"
    done < <(awk -v sensitive="$SENSITIVE_NAME_RE" '
        {
            s = $0
            sub(/^[ \t]+/, "", s)
            if (s ~ /^\/\//) { next }
            if (s ~ /^impl([ \t]*<[^>]*>)?[ \t]+(core::fmt::|std::fmt::|fmt::)?Display[ \t]+for[ \t]+/) {
                if (s ~ ("for[ \t]+" sensitive)) { print NR ":" s }
            }
        }
    ' "$file")
done

# -----------------------------------------------------------------------------
# Rules 3-6 — scoped to the crates that actually hold key material.
# -----------------------------------------------------------------------------
choice_to_bool_total=0

for file in "${guarded[@]}"; do
    # Blank out comment-only lines, keeping the line numbering intact. Nothing else is skipped:
    # a rule that stopped at `#[cfg(test)]` would also stop at every line after it, which is where
    # somebody eventually appends a helper.
    code="$(awk '{ s = $0; sub(/^[ \t]+/, "", s); if (s ~ /^\/\//) { print "" } else { print $0 } }' "$file")"

    # Rule 3 — `bool::from(` count and location.
    count="$(printf '%s\n' "$code" | grep -c 'bool::from(' || true)"
    if [[ "$count" -gt 0 && "$file" != "$CHOICE_TO_BOOL_FILE" ]]; then
        while IFS= read -r hit; do
            [[ -z "$hit" ]] && continue
            report "${file}:${hit%%:*}: bool::from( outside ${CHOICE_TO_BOOL_FILE}; a subtle::Choice turned into a bool can be short-circuited with && and stops being constant time"
        done < <(printf '%s\n' "$code" | grep -n 'bool::from(' || true)
    fi
    choice_to_bool_total=$((choice_to_bool_total + count))

    # Rule 4 — subtle's other escape hatch.
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: .unwrap_u8() bypasses the constant-time wrapper; keep the value as a Choice"
    done < <(printf '%s\n' "$code" | grep -n 'unwrap_u8()' || true)

    # Rule 5 — key material inside a formatting or logging macro.
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: a formatting or logging macro names key material; GHSA-r54g / GHSA-8cm2 / GHSA-333v were all a secret in a log line"
    done < <(printf '%s\n' "$code" |
        grep -nE '(format!|write!|writeln!|print!|println!|eprintln!|panic!|unreachable!|todo!|tracing::[a-z_]+!|(debug|info|warn|error|trace)!)[ \t]*\(' |
        grep -iE "$SECRET_IDENT_RE" || true)

    # Rule 6 — key material in a reallocating buffer.
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: key material in a Vec<u8>/String; zeroize cannot reach the buffers a growing Vec left behind — use Box<[u8]> or a fixed-size array"
    done < <(printf '%s\n' "$code" | grep -nE '(Vec<u8>|String)' | grep -iE "$SECRET_IDENT_RE" || true)
done

if [[ "$choice_to_bool_total" -gt 1 ]]; then
    report "bool::from( appears ${choice_to_bool_total} times in the guarded crates; exactly one constant-time comparison may exist, in ${CHOICE_TO_BOOL_FILE}"
fi

# -----------------------------------------------------------------------------
# Rule 7 — negative-case floors.
# -----------------------------------------------------------------------------
compile_fail_count=0
negative_label_count=0
for file in "${sources[@]}"; do
    [[ "$file" == crates/sig/* ]] || continue
    n="$(grep -c '```compile_fail' "$file" || true)"
    compile_fail_count=$((compile_fail_count + n))
    n="$(grep -cE '^[ \t]*/// Negative' "$file" || true)"
    negative_label_count=$((negative_label_count + n))
done

if [[ "$compile_fail_count" -lt "$COMPILE_FAIL_FLOOR" ]]; then
    report "compile_fail doctests in crates/sig fell to ${compile_fail_count}, below the ${COMPILE_FAIL_FLOOR} baseline; a deleted compile_fail case is a deleted guarantee (rustfs/rustfs#4815)"
fi
if [[ "$negative_label_count" -lt "$NEGATIVE_LABEL_FLOOR" ]]; then
    report "'/// Negative' cases in crates/sig fell to ${negative_label_count}, below the ${NEGATIVE_LABEL_FLOOR} baseline; negative cases must outnumber positive ones"
fi

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
    printf '             The guard is in place and will activate automatically when crates/sig lands in P2.\n'
else
    printf 'OK: constant-time guards satisfied (0 violations; %s bool::from, compile_fail %s >= %s, negative cases %s >= %s)\n' \
        "$choice_to_bool_total" "$compile_fail_count" "$COMPILE_FAIL_FLOOR" "$negative_label_count" "$NEGATIVE_LABEL_FLOOR"
fi

exit 0
