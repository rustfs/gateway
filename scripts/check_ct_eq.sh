#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_ct_eq.sh
#
# WHAT THIS CHECKS
#   Eight rules. The first three are repository-wide; the rest are scoped to the
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
#   2. A hand-written `PartialEq` for a secret-bearing type calls the canonical
#      `::subtle::ConstantTimeEq::ct_eq(` authority in that same impl. Type aliases,
#      trait import aliases, comments, literals and look-alike helpers do not
#      evade the check.
#   3. No `impl Display for` a secret-bearing type. `Debug` may be implemented
#      BY HAND — a redacting `Debug` is the sanctioned pattern — but `Display`
#      has no redacting form worth having: it exists to render the value.
#   4. `bool::from(` appears at most once in the guarded crates, and only in
#      CHOICE_TO_BOOL_FILE. That is the `subtle::Choice` escape hatch; a second
#      one is how `a.ct_eq(&b).into() && other()` gets written, and `&&`
#      short-circuits.
#   5. `.unwrap_u8()` — `subtle`'s other escape hatch — appears nowhere.
#   6. No formatting or logging macro takes an argument naming key material.
#      GHSA-r54g / GHSA-8cm2 / GHSA-333v were all "the secret was in the log".
#   7. No key material lives in a `Vec<u8>` or a `String`. `zeroize` cannot
#      reach the buffers a growing `Vec` left behind, so a secret that was
#      accumulated has copies on the heap that no `Drop` will ever wipe.
#   8. Negative-case floors: the number of `compile_fail` doctests and of
#      `/// Negative` test labels in `crates/sig` may not fall below the
#      recorded baselines. Aligns with rustfs/rustfs#4815 — a negative suite
#      that is quietly emptied leaves a green check mark and no coverage.
#   9. Signature material is never compared with `==` / `!=`, in two scopes.
#      Repository-wide within the guarded crates: an equality on a line naming
#      lowercase signature or secret material (`presented_signature ==
#      expected_signature`) is a violation. And inside
#      `crates/sig/src/sig_v2/`: no `==` / `!=` at all, on anything. Rules 1
#      and 2 only stop a *derived or hand-written* `PartialEq` on a
#      secret-bearing type; they say nothing about two `String`s or two
#      `&[u8]`s being compared directly, which is the form the defect
#      actually took in s3s#616 and rustfs/rustfs#4519. SigV2 gets the
#      stricter scope because SigV2 is where the second comparison
#      historically appears: it is the algorithm with the second signature
#      width, so it is the path that grows its own comparison. Use
#      `matches!` for enums and `Signature::ct_verify` for signatures.
#
#   Comment and doc-comment lines are skipped by rules 4-7 and 9. This matters: the
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
#   rules 4 and 8 exist to keep that shape from being hollowed out.
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
ALLOWANCE_FILE="${ROOT_DIR}/scripts/allowances/ct-eq-allowances.txt"

cd "$ROOT_DIR"

fatal() {
    printf 'check_ct_eq: %s\n' "$*" >&2
    exit 1
}

command -v git >/dev/null 2>&1 || fatal 'required command is missing: git'
command -v python3 >/dev/null 2>&1 || fatal 'required command is missing: python3'

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
# Rule 9's vocabulary. Case-sensitive and lowercase on purpose: `X_AMZ_SIGNATURE`
# is the *name* of a query parameter and comparing a key against it is correct,
# while `expected_signature` is the value and comparing it is the defect.
SIGNATURE_VALUE_RE='(signature|secret|signing_key|session_token)'
# The subtree that may not compare anything at all.
NO_EQUALITY_PATH_RE='^crates/sig/src/sig_v2/'
# Baselines for rule 8. Raise them when a PR adds cases; lowering one is the
# change a reviewer must refuse to wave through. Re-measured when P2-06 landed
# the SigV2 core: a ratchet that trails the tree is not a ratchet, it is a
# number nobody has to think about.
COMPILE_FAIL_FLOOR=32
NEGATIVE_LABEL_FLOOR=186

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
    printf '%s' "$ALLOWANCES" | grep -xF "$1" >/dev/null
}

report() {
    printf '%s\n' "$1" >&2
    status=1
}

sources=()
source_inputs="$(mktemp "${TMPDIR:-/tmp}/gateway-ct-eq-sources.XXXXXX")" || fatal 'cannot create source input buffer'
partial_eq_hits="$(mktemp "${TMPDIR:-/tmp}/gateway-ct-eq-partial.XXXXXX")" || {
    rm -f "$source_inputs"
    fatal 'cannot create parser output buffer'
}
cleanup() {
    rm -f "$source_inputs" "$partial_eq_hits"
}
trap cleanup EXIT

git ls-files --cached --others --exclude-standard -z -- \
    '*.rs' ':!:target/*' ':!:generated/*' ':!:*/generated/*' >"$source_inputs" || \
    fatal 'cannot enumerate Rust source inputs'
while IFS= read -r -d '' file; do
    [[ -n "$file" ]] && sources+=("$file")
done <"$source_inputs"

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

# A hand-written PartialEq is allowed only when its own impl block performs a
# constant-time comparison. Tokenization removes comments and literals so a
# `ct_eq` decoy in prose cannot authorize an ordinary equality implementation.
if ! python3 - "$SENSITIVE_NAME_RE" "${sources[@]}" >"$partial_eq_hits" <<'PY'
import re
import sys
from pathlib import Path

sensitive = re.compile(sys.argv[1])


def tokens(source: str, label: str):
    result = []
    index = 0
    line = 1
    while index < len(source):
        if source[index].isspace():
            line += source[index] == "\n"
            index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            index = len(source) if end < 0 else end
            continue
        if source.startswith("/*", index):
            depth = 1
            index += 2
            while index < len(source) and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    line += source[index] == "\n"
                    index += 1
            if depth:
                raise ValueError(f"{label}: unterminated block comment")
            continue
        raw = re.match(r'(?:b|c)?r(#+)?"', source[index:])
        if raw:
            marker = '"' + (raw.group(1) or "")
            end = source.find(marker, index + raw.end())
            if end < 0:
                raise ValueError(f"{label}: unterminated raw string")
            segment = source[index : end + len(marker)]
            line += segment.count("\n")
            index = end + len(marker)
            continue
        if source[index] == "'":
            lifetime = re.match(r"'[A-Za-z_][A-Za-z0-9_]*", source[index:])
            if lifetime and source[index + len(lifetime.group(0)) : index + len(lifetime.group(0)) + 1] != "'":
                result.append(("'", line))
                index += 1
                continue
        quote = index + 1 if source[index] in {"b", "c"} and index + 1 < len(source) else index
        if source[quote : quote + 1] in {'"', "'"}:
            delimiter = source[quote]
            cursor = quote + 1
            while cursor < len(source):
                if source[cursor] == "\\":
                    cursor += 2
                elif source[cursor] == delimiter:
                    cursor += 1
                    break
                else:
                    line += source[cursor] == "\n"
                    cursor += 1
            else:
                raise ValueError(f"{label}: unterminated literal")
            index = cursor
            continue
        identifier = re.match(r"[A-Za-z_][A-Za-z0-9_]*", source[index:])
        if identifier:
            value = identifier.group(0)
            result.append((value, line))
            index += len(value)
            continue
        punctuation = next((item for item in ("::", "==", "!=", "->") if source.startswith(item, index)), source[index])
        result.append((punctuation, line))
        index += len(punctuation)
    return result


parsed = []
for relative in sys.argv[2:]:
    try:
        source = Path(relative).read_text(encoding="utf-8")
        stream = tokens(source, relative)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"PARSER\t{relative}\t1\t{error}")
        continue
    parsed.append((relative, stream))

use_aliases = []
type_aliases = []
for _, stream in parsed:
    index = 0
    while index < len(stream):
        value = stream[index][0]
        if value == "use":
            end = next((probe for probe in range(index + 1, len(stream)) if stream[probe][0] == ";"), len(stream))
            for probe in range(index + 1, end - 1):
                if stream[probe + 1][0] == "as":
                    use_aliases.append((stream[probe][0], stream[probe + 2][0]))
            index = end + 1
            continue
        if value == "type" and index + 1 < len(stream):
            name = stream[index + 1][0]
            end = next((probe for probe in range(index + 2, len(stream)) if stream[probe][0] == ";"), len(stream))
            equals = next((probe for probe in range(index + 2, end) if stream[probe][0] == "="), None)
            if equals is not None:
                type_aliases.append((name, {token for token, _ in stream[equals + 1 : end]}))
            index = end + 1
            continue
        index += 1

partial_eq_names = {"PartialEq"}
changed = True
while changed:
    changed = False
    for source, alias in use_aliases:
        if source in partial_eq_names and alias not in partial_eq_names:
            partial_eq_names.add(alias)
            changed = True

sensitive_names = {
    value
    for _, stream in parsed
    for value, _ in stream
    if sensitive.search(value)
}
changed = True
while changed:
    changed = False
    for alias, dependencies in type_aliases:
        if dependencies & sensitive_names and alias not in sensitive_names:
            sensitive_names.add(alias)
            changed = True


def separator(header):
    angle = 0
    for offset, value in enumerate(header):
        if value == "<":
            angle += 1
        elif value == ">" and angle:
            angle -= 1
        elif value == "for" and angle == 0:
            return offset
    return None


def trait_portion(header, split):
    start = 0
    if header[:1] == ["<"]:
        depth = 0
        for offset, value in enumerate(header):
            depth += value == "<"
            depth -= value == ">"
            if depth == 0:
                start = offset + 1
                break
    return header[start:split]


def canonical_constant_time_eq(body):
    authority = ["::", "subtle", "::", "ConstantTimeEq", "::", "ct_eq", "("]
    if body[: len(authority)] != authority or any(value in {"==", "!="} for value in body):
        return False
    depth = 1
    closing = len(authority)
    while closing < len(body) and depth:
        depth += body[closing] == "("
        depth -= body[closing] == ")"
        closing += 1
    return depth == 0 and body[closing:] == [".", "into", "(", ")"]


def canonical_partial_eq(body):
    if any(value in {"==", "!="} for value in body):
        return False
    if any(body[offset : offset + 2] == ["fn", "ne"] for offset in range(len(body) - 1)):
        return False
    methods = [offset for offset in range(len(body) - 1) if body[offset : offset + 2] == ["fn", "eq"]]
    if len(methods) != 1:
        return False
    method = methods[0]
    opening = next((offset for offset in range(method + 2, len(body)) if body[offset] == "{"), None)
    if opening is None:
        return False
    depth = 1
    closing = opening + 1
    while closing < len(body) and depth:
        depth += body[closing] == "{"
        depth -= body[closing] == "}"
        closing += 1
    return depth == 0 and canonical_constant_time_eq(body[opening + 1 : closing - 1])


def matching_delimiter(stream, opening):
    pairs = {"(": ")", "[": "]", "{": "}"}
    marker = stream[opening][0]
    if marker not in pairs:
        return None
    stack = [pairs[marker]]
    cursor = opening + 1
    while cursor < len(stream) and stack:
        value = stream[cursor][0]
        if value in pairs:
            stack.append(pairs[value])
        elif value == stack[-1]:
            stack.pop()
        cursor += 1
    return cursor if not stack else None


macro_definitions = {}
macro_sequences = {}
for relative, stream in parsed:
    index = 0
    while index + 3 < len(stream):
        if stream[index][0] == "macro_rules" and stream[index + 1][0] == "!":
            opening = index + 3
            closing = matching_delimiter(stream, opening)
            if closing is None:
                print(f"PARSER\t{relative}\t{stream[index][1]}\tunterminated macro_rules body")
                break
            name = stream[index + 2][0]
            body = [value for value, _ in stream[opening + 1 : closing - 1]]
            macro_definitions.setdefault(name, set()).update(body)
            macro_sequences.setdefault(name, []).append(body)
            index = closing
            continue
        index += 1

changed = True
while changed:
    changed = False
    for source, alias in use_aliases:
        if source in macro_definitions and alias not in macro_definitions:
            macro_definitions[alias] = set(macro_definitions[source])
            macro_sequences[alias] = list(macro_sequences[source])
            changed = True

macro_calls = {name: set() for name in macro_definitions}
for name, sequences in macro_sequences.items():
    for sequence in sequences:
        for offset in range(len(sequence) - 1):
            callee = sequence[offset]
            if sequence[offset + 1] == "!" and callee in macro_definitions:
                macro_calls[name].add(callee)

expanded_macros = {name: set(tokens) for name, tokens in macro_definitions.items()}
changed = True
while changed:
    changed = False
    for name, callees in macro_calls.items():
        expanded = set(expanded_macros[name])
        for callee in callees:
            expanded.update(expanded_macros[callee])
        if expanded != expanded_macros[name]:
            expanded_macros[name] = expanded
            changed = True

for relative, stream in parsed:
    index = 0
    while index + 2 < len(stream):
        name = stream[index][0]
        if stream[index + 1][0] != "!" or stream[index + 2][0] not in {"(", "[", "{"}:
            index += 1
            continue
        closing = matching_delimiter(stream, index + 2)
        if closing is None:
            print(f"PARSER\t{relative}\t{stream[index][1]}\tunterminated macro invocation")
            break
        arguments = {value for value, _ in stream[index + 3 : closing - 1]}
        combined = arguments | expanded_macros.get(name, set())
        for argument in arguments & expanded_macros.keys():
            combined.update(expanded_macros[argument])
        if combined & partial_eq_names and combined & sensitive_names:
            detail = next(value for value in combined if value in sensitive_names)
            print(f"MACRO\t{relative}\t{stream[index][1]}\t{detail}")
        index = closing


for relative, stream in parsed:
    index = 0
    while index < len(stream):
        if stream[index][0] != "impl":
            index += 1
            continue
        opening = next((probe for probe in range(index + 1, len(stream)) if stream[probe][0] in {"{", ";"}), None)
        if opening is None or stream[opening][0] != "{":
            index += 1
            continue
        depth = 1
        closing = opening + 1
        while closing < len(stream) and depth:
            depth += stream[closing][0] == "{"
            depth -= stream[closing][0] == "}"
            closing += 1
        if depth:
            print(f"PARSER\t{relative}\t{stream[index][1]}\tunterminated impl block")
            break
        header = [value for value, _ in stream[index + 1 : opening]]
        split = separator(header)
        if split is not None and partial_eq_names.intersection(trait_portion(header, split)):
            target = header[split + 1 :]
            if "where" in target:
                target = target[: target.index("where")]
            target_name = next((value for value in target if value in sensitive_names), None)
            body = [value for value, _ in stream[opening + 1 : closing - 1]]
            if target_name and not canonical_partial_eq(body):
                print(f"HIT\t{relative}\t{stream[index][1]}\t{target_name}")
        index = closing
PY
then
    fatal 'cannot inspect hand-written PartialEq implementations'
fi

while IFS=$'\t' read -r tag file line detail; do
    [[ -n "${tag:-}" ]] || continue
    if [[ "$tag" == "PARSER" ]]; then
        fatal "${file}:${line}: ${detail}"
    fi
    if [[ "$tag" == "MACRO" ]]; then
        report "${file}:${line}: macro expansion can generate PartialEq for secret-bearing type '${detail}'; comparison impls must remain directly inspectable (rule: AGENTS.md Expert Roles & Trigger Table)"
        continue
    fi
    if is_allowed "${file}:${detail}"; then
        continue
    fi
    report "${file}:${line}: PartialEq for secret-bearing type '${detail}' is not the canonical ::subtle::ConstantTimeEq::ct_eq(...).into() result (rule: AGENTS.md Expert Roles & Trigger Table)"
done <"$partial_eq_hits"

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
# Rule 3 — no `impl Display for` a secret-bearing type (repository-wide).
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
# Rules 4-7 — scoped to the crates that actually hold key material.
# -----------------------------------------------------------------------------
choice_to_bool_total=0

for file in "${guarded[@]}"; do
    # Blank out comment-only lines, keeping the line numbering intact. Nothing else is skipped:
    # a rule that stopped at `#[cfg(test)]` would also stop at every line after it, which is where
    # somebody eventually appends a helper.
    code="$(awk '{ s = $0; sub(/^[ \t]+/, "", s); if (s ~ /^\/\//) { print "" } else { print $0 } }' "$file")"

    # Rule 4 — `bool::from(` count and location.
    count="$(printf '%s\n' "$code" | grep -c 'bool::from(' || true)"
    if [[ "$count" -gt 0 && "$file" != "$CHOICE_TO_BOOL_FILE" ]]; then
        while IFS= read -r hit; do
            [[ -z "$hit" ]] && continue
            report "${file}:${hit%%:*}: bool::from( outside ${CHOICE_TO_BOOL_FILE}; a subtle::Choice turned into a bool can be short-circuited with && and stops being constant time"
        done < <(printf '%s\n' "$code" | grep -n 'bool::from(' || true)
    fi
    choice_to_bool_total=$((choice_to_bool_total + count))

    # Rule 5 — subtle's other escape hatch.
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: .unwrap_u8() bypasses the constant-time wrapper; keep the value as a Choice"
    done < <(printf '%s\n' "$code" | grep -n 'unwrap_u8()' || true)

    # Rule 6 — key material inside a formatting or logging macro.
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: a formatting or logging macro names key material; GHSA-r54g / GHSA-8cm2 / GHSA-333v were all a secret in a log line"
    done < <(printf '%s\n' "$code" |
        grep -nE '(format!|write!|writeln!|print!|println!|eprintln!|panic!|unreachable!|todo!|tracing::[a-z_]+!|(debug|info|warn|error|trace)!)[ \t]*\(' |
        grep -iE "$SECRET_IDENT_RE" || true)

    # Rule 7 — key material in a reallocating buffer.
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: key material in a Vec<u8>/String; zeroize cannot reach the buffers a growing Vec left behind — use Box<[u8]> or a fixed-size array"
    done < <(printf '%s\n' "$code" | grep -nE '(Vec<u8>|String)' | grep -iE "$SECRET_IDENT_RE" || true)

    # Rule 9, first scope — ordinary equality on a line naming signature material.
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        report "${file}:${hit%%:*}: == / != on signature material; ordinary equality short-circuits on the first differing byte and leaks the expected value through timing (s3s#616, rustfs/rustfs#4519) — compare through Signature::ct_verify"
    done < <(printf '%s\n' "$code" | grep -nE '(==|!=)' | grep -E "$SIGNATURE_VALUE_RE" || true)

    # Rule 9, second scope — the SigV2 subtree compares nothing directly.
    if [[ "$file" =~ $NO_EQUALITY_PATH_RE ]]; then
        while IFS= read -r hit; do
            [[ -z "$hit" ]] && continue
            report "${file}:${hit%%:*}: == / != inside ${file%%/sig_v2/*}/sig_v2/; SigV2 is the path that historically grows its own signature comparison, so this subtree compares nothing directly — use matches! for enums and Signature::ct_verify for signatures"
        done < <(printf '%s\n' "$code" | grep -nE '(==|!=)' || true)
    fi
done

if [[ "$choice_to_bool_total" -gt 1 ]]; then
    report "bool::from( appears ${choice_to_bool_total} times in the guarded crates; exactly one constant-time comparison may exist, in ${CHOICE_TO_BOOL_FILE}"
fi

# -----------------------------------------------------------------------------
# Rule 8 — negative-case floors.
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
