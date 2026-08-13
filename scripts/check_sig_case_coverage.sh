#!/usr/bin/env bash
set -euo pipefail

# WHAT: Maps every P2-01 and P2-02 acceptance id to named executable evidence.
# WHY: rustfs/backlog#1678 and rustfs/backlog#1679 require explicit cases; nearby doctests or a
# green crate suite do not prove that every listed contract still has a test.
# HOW TO EXEMPT: There is no exemption; replace a mapping only with equivalent executable evidence.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

cases=(
    'c-sig-0001|positive|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0001_empty_is_not_framed'
    'c-sig-0002|positive|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0002_hex_digest_keeps_its_signed_spelling'
    'c-sig-0003|positive|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0003_base64_digest_is_a_distinct_variant'
    'c-sig-0004|positive|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0004_unsigned_payload_is_not_framed'
    'c-sig-0005|positive|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0005_streaming_signed_is_framed'
    'c-sig-0006|positive|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0006_streaming_signed_trailer_carries_the_declaration'
    'c-sig-0007|positive|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0007_streaming_unsigned_trailer_is_framed_without_signatures'
    'c-sig-0008|positive|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0008_sigv2_signature_is_twenty_bytes'
    'c-sig-0009|negative|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0009_content_encoding_cannot_enable_framing'
    'c-sig-0010|negative|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0010_non_streaming_modes_forbid_decoded_length'
    'c-sig-0011|negative|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0011_streaming_modes_require_decoded_length'
    'c-sig-0012|negative|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0012_streaming_sigv4a_is_not_implemented'
    'c-sig-0013|negative|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0013_sigv4a_never_degrades_to_sigv4'
    'c-sig-0014|negative|crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs|let _ = left == right;'
    'c-sig-0015|negative|crates/sig/tests/compile_fail/c_sig_0015_ctbytes_debug.rs|println!'
    'c-sig-0016|negative|crates/sig/tests/compile_fail/c_sig_0016_signature_eq.rs|let _ = left == right;'
    'c-sig-0017|negative|crates/sig/tests/compile_fail/c_sig_0017_session_token_debug.rs|#[derive(Debug)]'
    'c-sig-0018|negative|crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.rs|let _ = serde_json::to_string(&token);'
    'c-sig-0019|negative|crates/sig/tests/compile_fail/c_sig_0019_sig_family_exhaustive.rs|let _ = match family'
    'c-sig-0020|negative|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0020_mixed_algorithms_are_refused'
    'c-sig-0021|negative|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0021_received_trailers_must_match_the_declaration'
    'c-sig-0022|negative|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0022_empty_trailer_declaration_is_rejected'
    'c-sig-0023|negative|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0023_too_many_trailers_are_rejected'
    'c-sig-0024|negative|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0024_wrong_length_hex_is_rejected'
    'c-sig-0025|negative|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0025_non_canonical_base64_is_rejected'
)

verification_cases=(
    'c-sig-0101|positive|crates/sig/tests/verification_proof.rs|fn c_sig_0101_equal_sigv4_signatures_produce_a_proof'
    'c-sig-0102|positive|crates/sig/tests/verification_proof.rs|fn c_sig_0102_equal_sigv2_signatures_produce_a_proof'
    'c-sig-0103|positive|crates/sig/tests/verification_proof.rs|fn c_sig_0103_exact_lowercase_hex_decodes'
    'c-sig-0104|positive|crates/sig/tests/verification_proof.rs|fn c_sig_0104_canonical_base64_decodes'
    'c-sig-0105|positive|crates/sig/tests/verification_proof.rs|fn c_sig_0105_no_credentials_is_an_anonymous_verdict'
    'c-sig-0106|positive|crates/sig/tests/verification_proof.rs|fn c_sig_0106_key_material_is_zeroized_and_never_grows'
    'c-sig-0107|negative|crates/sig/tests/verification_proof.rs|fn c_sig_0107_a_first_byte_difference_is_a_mismatch'
    'c-sig-0108|negative|crates/sig/tests/verification_proof.rs|fn c_sig_0108_a_last_byte_difference_is_the_same_mismatch'
    'c-sig-0109|negative|crates/sig/tests/verification_proof.rs|fn c_sig_0109_algorithm_families_are_never_coerced'
    'c-sig-0110|negative|crates/sig/tests/verification_proof.rs|fn c_sig_0110_a_known_key_with_a_wrong_signature_is_rejected'
    'c-sig-0111|negative|crates/sig/tests/verification_proof.rs|fn c_sig_0111_the_two_credential_rejections_differ_only_in_their_code'
    'c-sig-0112|negative|crates/sig/tests/verification_proof.rs|fn c_sig_0112_wrong_length_hex_is_rejected'
    'c-sig-0113|negative|crates/sig/tests/verification_proof.rs|fn c_sig_0113_url_safe_base64_is_rejected'
    'c-sig-0114|negative|crates/sig/tests/verification_proof.rs|fn c_sig_0114_base64_padding_must_be_exact'
    'c-sig-0115|negative|crates/sig/tests/verification_proof.rs|fn c_sig_0115_base64_whitespace_is_rejected'
    'c-sig-0116|negative|crates/sig/tests/verification_proof.rs|fn c_sig_0116_non_hex_characters_are_rejected'
    'c-sig-0117|negative|crates/sig/tests/compile_fail/c_sig_0117_authenticated_requires_proof.rs|let _ = Verdict::Authenticated { identity, scheme };'
    'c-sig-0118|negative|crates/sig/tests/compile_fail/c_sig_0118_signature_match_private.rs|let _ = SignatureMatch(());'
    'c-sig-0119|negative|crates/sig/tests/compile_fail/c_sig_0119_signature_match_no_default.rs|let _ = SignatureMatch::default();'
    'c-sig-0120|negative|crates/sig/tests/compile_fail/c_sig_0120_anonymous_ack_private.rs|let _ = AnonymousAck(());'
    'c-sig-0121|negative|crates/sig/tests/compile_fail/c_sig_0121_secret_bytes_eq.rs|let _ = left == right;'
    'c-sig-0122|negative|crates/sig/tests/compile_fail/c_sig_0122_secret_bytes_display.rs|let _ = format!'
    'c-sig-0123|negative|crates/core/tests/compile_fail/c_sig_0123_secret_bytes_serialize.rs|let _ = serde_json::to_string(&secret);'
    'c-sig-0124|negative|crates/sig/tests/compile_fail/c_sig_0124_secret_bytes_clone.rs|let _ = secret.clone();'
    'c-sig-0125|negative|crates/sig/tests/compile_fail/c_sig_0125_verification_result_must_be_used.rs|left.ct_verify(&right);'
    'c-sig-0126|negative|scripts/test_guard_scripts.sh|mut_c_sig_0126_derived_signature'
    'c-sig-0127|negative|scripts/test_guard_scripts.sh|mut_c_sig_0127_second_bool_from'
    'c-sig-0128|negative|crates/gateway/tests/credential_runtime.rs|fn c_sig_0128_request_logs_exclude_credential_material'
)

p2_03_cases=()
p2_03_manifest="${ROOT}/scripts/sig-case-coverage-p2-03.txt"
[[ -f "$p2_03_manifest" ]] || {
    printf 'check_sig_case_coverage: P2-03 case manifest is missing\n' >&2
    exit 1
}
while IFS= read -r mapping; do
    [[ -n "$mapping" ]] || {
        printf 'check_sig_case_coverage: P2-03 case manifest contains a blank row\n' >&2
        exit 1
    }
    p2_03_cases+=("$mapping")
done <"$p2_03_manifest"

[[ "${#cases[@]}" -eq 25 ]] || {
    printf 'check_sig_case_coverage: expected 25 mappings, got %s\n' "${#cases[@]}" >&2
    exit 1
}

[[ "${#verification_cases[@]}" -eq 28 ]] || {
    printf 'check_sig_case_coverage: expected 28 P2-02 mappings, got %s\n' \
        "${#verification_cases[@]}" >&2
    exit 1
}

positive=0
negative=0
expected=1
compile_fail_paths=()

command -v python3 >/dev/null 2>&1 || {
    printf 'check_sig_case_coverage: required command is missing: python3\n' >&2
    exit 1
}

evidence_requests=()

validate_rust_evidence() {
    local file="$1" kind="$2" evidence="$3" required_call="${4:-}" failure="$5"
    evidence_requests+=("${file}"$'\x1f'"${kind}"$'\x1f'"${evidence}"$'\x1f'"${required_call}"$'\x1f'"${failure}")
}

run_evidence_validations() {
    python3 - "$ROOT" "${evidence_requests[@]}" <<'PYEOF'
import re
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
requests = sys.argv[2:]
validator = r'''
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
kind = sys.argv[2]
evidence = sys.argv[3]
required_call = sys.argv[4]
source = path.read_text()

# Blank line and nested block comments plus string/character literals while preserving newlines.
# Evidence in any of those positions is data, not an executable assertion.
out = []
i = 0
depth = 0
while i < len(source):
    if depth:
        if source.startswith("/*", i):
            depth += 1
            out.extend("  ")
            i += 2
        elif source.startswith("*/", i):
            depth -= 1
            out.extend("  ")
            i += 2
        else:
            out.append("\n" if source[i] == "\n" else " ")
            i += 1
    elif source.startswith("//", i):
        while i < len(source) and source[i] != "\n":
            out.append(" ")
            i += 1
    elif source.startswith("/*", i):
        depth = 1
        out.extend("  ")
        i += 2
    elif raw := re.match(r'(?:br|r)(#{0,255})"', source[i:]):
        hashes = raw.group(1)
        closing = '"' + hashes
        end = source.find(closing, i + raw.end())
        if end == -1:
            raise SystemExit(f"{path}: unterminated raw string")
        end += len(closing)
        out.extend("\n" if char == "\n" else " " for char in source[i:end])
        i = end
    elif source[i] == '"' or source.startswith(('b"', 'c"'), i):
        quote = i if source[i] == '"' else i + 1
        end = quote + 1
        while end < len(source):
            if source[end] == "\\":
                end += 2
            elif source[end] == '"':
                end += 1
                break
            else:
                end += 1
        else:
            raise SystemExit(f"{path}: unterminated string")
        out.extend("\n" if char == "\n" else " " for char in source[i:end])
        i = end
    elif character := re.match(r"(?:b)?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^\\'\n])'", source[i:]):
        end = i + character.end()
        out.extend(" " for _ in source[i:end])
        i = end
    else:
        out.append(source[i])
        i += 1

if depth:
    raise SystemExit(f"{path}: unterminated block comment")

code = "".join(out)

def delimiter_depth(end):
    depth = {"{": 0, "(": 0, "[": 0}
    closing = {"}": "{", ")": "(", "]": "["}
    for char in code[:end]:
        if char in depth:
            depth[char] += 1
        elif char in closing:
            opener = closing[char]
            depth[opener] -= 1
    return depth

def outer_attributes(start):
    attributes = []
    position = start
    while True:
        while position and code[position - 1].isspace():
            position -= 1
        if not position or code[position - 1] != "]":
            break

        end = position
        depth = 1
        position -= 1
        while position and depth:
            position -= 1
            if code[position] == "]":
                depth += 1
            elif code[position] == "[":
                depth -= 1
        if depth:
            break

        bracket = position
        while position and code[position - 1].isspace():
            position -= 1
        if position and code[position - 1] == "!":
            position -= 1
            while position and code[position - 1].isspace():
                position -= 1
        if not position or code[position - 1] != "#":
            position = end
            break
        position -= 1
        attributes.append(code[position:end])
    attributes.reverse()
    return attributes

def top_level_function(name):
    pattern = re.compile(rf"(?m)^[ \t]*fn\s+{re.escape(name)}\s*\(\s*\)[^;{{]*\{{")
    return next(
        (
            match
            for match in pattern.finditer(code)
            if all(value == 0 for value in delimiter_depth(match.start()).values())
        ),
        None,
    )

def function_body(item):
    opening = item.end() - 1
    depth = 1
    position = opening + 1
    while position < len(code) and depth:
        if code[position] == "{":
            depth += 1
        elif code[position] == "}":
            depth -= 1
        position += 1
    if depth:
        raise SystemExit(f"{path}: function body is unterminated")
    return opening + 1, position - 1

def direct_occurrence(start, end, needle):
    position = code.find(needle, start, end)
    while position != -1:
        depth = delimiter_depth(position)
        if depth == {"{": 1, "(": 0, "[": 0} and not outer_attributes(position):
            return True
        position = code.find(needle, position + 1, end)
    return False

def direct_invocation(start, end, prefix, invocation):
    position = code.find(prefix, start, end)
    while position != -1:
        depth = delimiter_depth(position)
        statement_end = code.find(";", position, end)
        if (
            depth == {"{": 1, "(": 0, "[": 0}
            and not outer_attributes(position)
            and statement_end != -1
            and invocation in source[position : statement_end + 1]
        ):
            return True
        position = code.find(prefix, position + 1, end)
    return False

if kind == "compile":
    main = top_level_function("main")
    if main is None or outer_attributes(main.start()):
        raise SystemExit(f"{path}: no executable fn main() outside comments")
    body_start, body_end = function_body(main)
    if not direct_occurrence(body_start, body_end, evidence):
        raise SystemExit(f"{path}: mapped compile-fail evidence is not active in fn main()")
elif kind == "runtime":
    if not evidence.startswith("fn "):
        raise SystemExit(f"{path}: runtime evidence must name a function")
    function = evidence.removeprefix("fn ")
    item = top_level_function(function)
    attributes = outer_attributes(item.start()) if item is not None else []
    if len(attributes) != 1 or not re.fullmatch(r"#\s*\[\s*test\s*\]", attributes[0]):
        raise SystemExit(f"{path}: mapped function is not a real #[test] item")
elif kind == "harness":
    item = top_level_function(evidence)
    attributes = outer_attributes(item.start()) if item is not None else []
    if len(attributes) != 1 or not re.fullmatch(r"#\s*\[\s*test\s*\]", attributes[0]):
        raise SystemExit(f"{path}: compile-fail harness is not an active top-level #[test]")
    body_start, body_end = function_body(item)
    if not direct_invocation(body_start, body_end, "cases.compile_fail", required_call):
        raise SystemExit(f"{path}: compile-fail call is not active in the harness test body")
else:
    raise SystemExit(f"unknown evidence kind: {kind}")
'''

marker = "def delimiter_depth(end):"
suffix_at = validator.index(marker)
full_validator = compile(validator, "<sig-evidence>", "exec")
cached_validator = compile(validator[suffix_at:], "<sig-evidence-cached>", "exec")
views = {}

for request in requests:
    fields = request.split("\x1f")
    if len(fields) != 5:
        raise SystemExit("check_sig_case_coverage: internal evidence request is malformed")
    file, kind, evidence, required_call, failure = fields
    sys.argv = ["<sig-evidence>", file, kind, evidence, required_call]
    path = Path(file)
    if path in views:
        source, code = views[path]
        namespace = {
            "re": re,
            "source": source,
            "code": code,
            "path": path,
            "kind": kind,
            "evidence": evidence,
            "required_call": required_call,
        }
        program = cached_validator
    else:
        namespace = {}
        program = full_validator
    try:
        exec(program, namespace)
    except SystemExit as error:
        if error.code not in (None, 0):
            print(error.code, file=sys.stderr)
        print(failure, file=sys.stderr)
        raise SystemExit(1)
    views.setdefault(path, (namespace["source"], namespace["code"]))

sig = tomllib.loads((root / "crates/sig/Cargo.toml").read_text())
core = tomllib.loads((root / "crates/core/Cargo.toml").read_text())
workspace = tomllib.loads((root / "Cargo.toml").read_text())
workspace_dependencies = workspace.get("workspace", {}).get("dependencies", {})


def package_name(alias, specification):
    if isinstance(specification, str):
        return alias
    if not isinstance(specification, dict):
        raise SystemExit(f"check_sig_case_coverage: unsupported dependency specification for {alias}")
    if specification.get("workspace") is True:
        inherited = workspace_dependencies.get(alias)
        if inherited is None:
            raise SystemExit(f"check_sig_case_coverage: missing workspace dependency {alias}")
        return package_name(alias, inherited)
    return specification.get("package", alias)


def dependency_tables(manifest):
    sections = ("dependencies", "dev-dependencies", "build-dependencies")
    for section in sections:
        yield manifest.get(section, {})
    for target in manifest.get("target", {}).values():
        for section in sections:
            yield target.get(section, {})


for dependencies in dependency_tables(sig):
    for name, spec in dependencies.items():
        package = package_name(name, spec)
        if package in {"serde", "serde_json"}:
            raise SystemExit(
                f"check_sig_case_coverage: sig manifest gains serialization dependency {package}"
            )

serde_json = core.get("dev-dependencies", {}).get("serde_json")
if not isinstance(serde_json, dict) or serde_json.get("workspace") is not True:
    raise SystemExit(
        "check_sig_case_coverage: core dev tests do not enable real serde_json evidence"
    )
PYEOF
}

validate_shell_mutation() {
    local file="$1" function="$2"
    bash -n "$file" || return 1
    grep -Eq "^${function}\\(\\)[[:space:]]*\\{" "$file" || return 1
    grep -Eq "^[[:space:]]*'[^']*'[[:space:]]+${function}$" "$file" || return 1
}

for mapping in "${cases[@]}"; do
    IFS='|' read -r id polarity relative evidence <<<"$mapping"
    printf -v wanted 'c-sig-%04d' "$expected"
    [[ "$id" == "$wanted" ]] || {
        printf 'check_sig_case_coverage: expected %s, found %s\n' "$wanted" "$id" >&2
        exit 1
    }
    case "$polarity" in
        positive) positive=$((positive + 1)) ;;
        negative) negative=$((negative + 1)) ;;
        *)
            printf 'check_sig_case_coverage: %s has unknown polarity %s\n' "$id" "$polarity" >&2
            exit 1
            ;;
    esac
    file="${ROOT}/${relative}"
    [[ -f "$file" ]] || {
        printf 'check_sig_case_coverage: mapped file is missing: %s\n' "$relative" >&2
        exit 1
    }
    grep -Fq "$id" "$file" || {
        printf 'check_sig_case_coverage: %s is not named by %s\n' "$id" "$relative" >&2
        exit 1
    }
    if [[ "$relative" == crates/*/tests/compile_fail/c_sig_*.rs ]]; then
        compile_fail_paths+=("$relative")
        validate_rust_evidence "$file" compile "$evidence" '' \
            "check_sig_case_coverage: ${relative} is not an executable compile-fail fixture"
        stderr="${file%.rs}.stderr"
        [[ -f "$stderr" ]] || {
            printf 'check_sig_case_coverage: compile-fail golden is missing: %s.stderr\n' "${relative%.rs}" >&2
            exit 1
        }
        grep -Fq 'error[E' "$stderr" || {
            printf 'check_sig_case_coverage: compile-fail golden has no rustc diagnostic: %s.stderr\n' "${relative%.rs}" >&2
            exit 1
        }
        diagnostic=''
        case "$id" in
            c-sig-0014) diagnostic='`CtBytes<32>` does not implement `PartialEq`' ;;
            c-sig-0015) diagnostic='the trait `Debug` is not implemented for `CtBytes<32>`' ;;
            c-sig-0016) diagnostic='`rustfs_gateway_sig::Signature` does not implement `PartialEq`' ;;
            c-sig-0017) diagnostic='the trait `Debug` is not implemented for `SessionToken`' ;;
            c-sig-0019) diagnostic='error[E0004]: non-exhaustive patterns: `_` not covered' ;;
        esac
        if [[ -n "$diagnostic" ]] && ! grep -Fq "$diagnostic" "$stderr"; then
            printf 'check_sig_case_coverage: %s golden lost its case-specific diagnostic\n' "$id" >&2
            exit 1
        fi
    else
        validate_rust_evidence "$file" runtime "$evidence" '' \
            "check_sig_case_coverage: ${id} is not a named #[test] item in ${relative}"
    fi
    expected=$((expected + 1))
done

[[ "$positive" -eq 8 && "$negative" -eq 17 && "$negative" -ge "$positive" ]] || {
    printf 'check_sig_case_coverage: expected 8 positive and 17 negative cases, got %s/%s\n' "$positive" "$negative" >&2
    exit 1
}

[[ "${#compile_fail_paths[@]}" -eq 6 ]] || {
    printf 'check_sig_case_coverage: expected six independent compile-fail fixtures, got %s\n' "${#compile_fail_paths[@]}" >&2
    exit 1
}
[[ "$(printf '%s\n' "${compile_fail_paths[@]}" | sort -u | wc -l | tr -d ' ')" -eq 6 ]] || {
    printf 'check_sig_case_coverage: compile-fail cases must use distinct fixtures\n' >&2
    exit 1
}

positive=0
negative=0
expected=101
verification_compile_fail_paths=()

for mapping in "${verification_cases[@]}"; do
    IFS='|' read -r id polarity relative evidence <<<"$mapping"
    printf -v wanted 'c-sig-%04d' "$expected"
    [[ "$id" == "$wanted" ]] || {
        printf 'check_sig_case_coverage: expected %s, found %s\n' "$wanted" "$id" >&2
        exit 1
    }
    case "$polarity" in
        positive) positive=$((positive + 1)) ;;
        negative) negative=$((negative + 1)) ;;
        *)
            printf 'check_sig_case_coverage: %s has unknown polarity %s\n' "$id" "$polarity" >&2
            exit 1
            ;;
    esac
    file="${ROOT}/${relative}"
    [[ -f "$file" ]] || {
        printf 'check_sig_case_coverage: mapped file is missing: %s\n' "$relative" >&2
        exit 1
    }
    if [[ "$relative" == scripts/*.sh ]]; then
        validate_shell_mutation "$file" "$evidence" || {
            printf 'check_sig_case_coverage: %s is not an executable guard mutation in %s\n' \
                "$id" "$relative" >&2
            exit 1
        }
    else
        grep -Fq "$id" "$file" || {
            printf 'check_sig_case_coverage: %s is not named by %s\n' "$id" "$relative" >&2
            exit 1
        }
        if [[ "$relative" == crates/*/tests/compile_fail/c_sig_*.rs ]]; then
            verification_compile_fail_paths+=("$relative")
            validate_rust_evidence "$file" compile "$evidence" '' \
                "check_sig_case_coverage: ${relative} is not an executable compile-fail fixture"
            stderr="${file%.rs}.stderr"
            [[ -f "$stderr" ]] || {
                printf 'check_sig_case_coverage: compile-fail golden is missing: %s.stderr\n' \
                    "${relative%.rs}" >&2
                exit 1
            }
            grep -Eq '^error(\[E[0-9]+\])?:' "$stderr" || {
                printf 'check_sig_case_coverage: compile-fail golden has no rustc error: %s.stderr\n' \
                    "${relative%.rs}" >&2
                exit 1
            }
            diagnostic=''
            case "$id" in
                c-sig-0117) diagnostic='missing field `proof`' ;;
                c-sig-0118) diagnostic='cannot initialize a tuple struct which contains private fields' ;;
                c-sig-0119) diagnostic='no associated function or constant named `default` found for struct `SignatureMatch`' ;;
                c-sig-0120) diagnostic='cannot initialize a tuple struct which contains private fields' ;;
                c-sig-0121) diagnostic='binary operation `==` cannot be applied to type `SecretBytes`' ;;
                c-sig-0122) diagnostic='`SecretBytes` doesn'"'"'t implement `std::fmt::Display`' ;;
                c-sig-0123) diagnostic='the trait bound `SecretBytes: serde::Serialize` is not satisfied' ;;
                c-sig-0124) diagnostic='no method named `clone` found for struct `SecretBytes`' ;;
                c-sig-0125) diagnostic='unused `Result` that must be used' ;;
            esac
            if [[ -n "$diagnostic" ]] && ! grep -Fq "$diagnostic" "$stderr"; then
                printf 'check_sig_case_coverage: %s golden lost its case-specific diagnostic\n' \
                    "$id" >&2
                exit 1
            fi
        else
            validate_rust_evidence "$file" runtime "$evidence" '' \
                "check_sig_case_coverage: ${id} is not a named #[test] item in ${relative}"
        fi
    fi
    expected=$((expected + 1))
done

[[ "$positive" -eq 6 && "$negative" -eq 22 && "$negative" -ge "$positive" ]] || {
    printf 'check_sig_case_coverage: expected 6 positive and 22 negative P2-02 cases, got %s/%s\n' \
        "$positive" "$negative" >&2
    exit 1
}

[[ "${#verification_compile_fail_paths[@]}" -eq 9 ]] || {
    printf 'check_sig_case_coverage: expected nine P2-02 compile-fail fixtures, got %s\n' \
        "${#verification_compile_fail_paths[@]}" >&2
    exit 1
}

[[ "${#p2_03_cases[@]}" -eq 43 ]] || {
    printf 'check_sig_case_coverage: expected 43 P2-03 mappings, got %s\n' "${#p2_03_cases[@]}" >&2
    exit 1
}
positive=0
negative=0
p2_03_compile_fail_paths=()
for index in "${!p2_03_cases[@]}"; do
    IFS='|' read -r id polarity relative evidence <<<"${p2_03_cases[$index]}"
    if [[ "$index" -lt 14 ]]; then
        printf -v wanted 'c-sig-%04d' "$((201 + index))"
    else
        printf -v wanted 'c-sig-%04d' "$((230 + index - 14))"
    fi
    [[ "$id" == "$wanted" ]] || {
        printf 'check_sig_case_coverage: expected %s, found %s\n' "$wanted" "$id" >&2
        exit 1
    }
    case "$polarity" in
        positive) positive=$((positive + 1)) ;;
        negative) negative=$((negative + 1)) ;;
        *) printf 'check_sig_case_coverage: %s has unknown polarity %s\n' "$id" "$polarity" >&2; exit 1 ;;
    esac
    file="${ROOT}/${relative}"
    [[ -f "$file" ]] || {
        printf 'check_sig_case_coverage: mapped file is missing: %s\n' "$relative" >&2
        exit 1
    }
    grep -Fq "$id" "$file" || {
        printf 'check_sig_case_coverage: %s is not named by %s\n' "$id" "$relative" >&2
        exit 1
    }
    if [[ "$relative" == crates/sig/tests/compile_fail/c_sig_025[34]_*.rs ]]; then
        p2_03_compile_fail_paths+=("$relative")
        validate_rust_evidence "$file" compile "$evidence" '' \
            "check_sig_case_coverage: ${relative} is not an executable compile-fail fixture"
        stderr="${file%.rs}.stderr"
        [[ -f "$stderr" ]] || { printf 'check_sig_case_coverage: compile-fail golden is missing: %s\n' "$stderr" >&2; exit 1; }
        grep -Fq 'error[E' "$stderr" || { printf 'check_sig_case_coverage: compile-fail golden has no rustc diagnostic: %s\n' "$stderr" >&2; exit 1; }
        case "$id" in
            c-sig-0253) diagnostic='expected reference `&RawHost`' ;;
            c-sig-0254) diagnostic='no associated function or constant named `from_presented` found for struct `VerifiedScope`' ;;
        esac
        grep -Fq "$diagnostic" "$stderr" || {
            printf 'check_sig_case_coverage: %s golden lost its case-specific diagnostic\n' "$id" >&2
            exit 1
        }
    else
        function="${evidence#fn }"
        token="${id//-/_}"
        case "$id" in
            c-sig-0212|c-sig-0213|c-sig-0214) wanted_function='c_sig_official_suite' ;;
            c-sig-0244|c-sig-0245) wanted_function='c_sig_0244_and_0245_every_unsigned_amz_header_is_refused_individually' ;;
            *) wanted_function="${token}_" ;;
        esac
        if [[ "$wanted_function" == *_ ]]; then
            [[ "$function" == "$wanted_function"* ]] || {
                printf 'check_sig_case_coverage: %s is bound to the wrong executable test %s\n' "$id" "$function" >&2
                exit 1
            }
        else
            [[ "$function" == "$wanted_function" ]] || {
                printf 'check_sig_case_coverage: %s is bound to the wrong executable test %s\n' "$id" "$function" >&2
                exit 1
            }
        fi
        validate_rust_evidence "$file" runtime "$evidence" '' \
            "check_sig_case_coverage: ${id} is not a named #[test] item in ${relative}"
    fi
done
[[ "$positive" -eq 14 && "$negative" -eq 29 ]] || {
    printf 'check_sig_case_coverage: expected 14 positive and 29 negative P2-03 cases, got %s/%s\n' "$positive" "$negative" >&2
    exit 1
}
[[ "${#p2_03_compile_fail_paths[@]}" -eq 2 && "${p2_03_compile_fail_paths[0]}" != "${p2_03_compile_fail_paths[1]}" ]] || {
    printf 'check_sig_case_coverage: P2-03 compile-fail cases must use two distinct fixtures\n' >&2
    exit 1
}
[[ "$(printf '%s\n' "${verification_compile_fail_paths[@]}" | sort -u | wc -l | tr -d ' ')" -eq 9 ]] || {
    printf 'check_sig_case_coverage: P2-02 compile-fail cases must use distinct fixtures\n' >&2
    exit 1
}

manifest="${ROOT}/crates/sig/Cargo.toml"
harness="${ROOT}/crates/sig/tests/compile_fail.rs"
core_manifest="${ROOT}/crates/core/Cargo.toml"
core_harness="${ROOT}/crates/core/tests/compile_fail.rs"
grep -Fq 'trybuild = { workspace = true }' "$manifest" || {
    printf 'check_sig_case_coverage: sig manifest does not enable trybuild\n' >&2
    exit 1
}
[[ -f "$harness" ]] || {
    printf 'check_sig_case_coverage: compile-fail harness is missing\n' >&2
    exit 1
}
validate_rust_evidence "$harness" harness \
    p2_01_compile_time_boundaries_are_not_openable \
    'cases.compile_fail("tests/compile_fail/c_sig_001[4-79]_*.rs")' \
    'check_sig_case_coverage: compile-fail harness does not execute the P2-01 fixtures'
validate_rust_evidence "$harness" harness \
    p2_02_compile_time_boundaries_are_not_openable \
    'cases.compile_fail("tests/compile_fail/c_sig_01[12][0-9]_*.rs")' \
    'check_sig_case_coverage: compile-fail harness does not execute c-sig-0117 through c-sig-0125'
validate_rust_evidence "$harness" harness \
    p2_02_compile_time_boundaries_are_not_openable \
    'cases.compile_fail("tests/compile_fail/p2_02_*_cannot_*.rs")' \
    'check_sig_case_coverage: compile-fail harness does not execute the proof-token copy controls'
validate_rust_evidence "$harness" harness \
    p2_03_compile_time_boundaries_are_not_openable \
    'cases.compile_fail("tests/compile_fail/c_sig_025[34]_*.rs")' \
    'check_sig_case_coverage: compile-fail harness does not execute c-sig-0253 and c-sig-0254'
[[ -f "$core_harness" ]] || {
    printf 'check_sig_case_coverage: core signature compile-fail harness is missing\n' >&2
    exit 1
}
validate_rust_evidence "$core_harness" harness \
    compile_time_contracts_are_not_openable \
    'cases.compile_fail("tests/compile_fail/c_sig_0018_*.rs")' \
    'check_sig_case_coverage: core harness does not execute c-sig-0018'
validate_rust_evidence "$core_harness" harness \
    compile_time_contracts_are_not_openable \
    'cases.compile_fail("tests/compile_fail/c_sig_0123_*.rs")' \
    'check_sig_case_coverage: core harness does not execute c-sig-0123'

run_evidence_validations
evidence_requests=()

serialize_golden="${ROOT}/crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.stderr"
grep -Fq 'error[E0277]: the trait bound `SessionToken: serde::Serialize` is not satisfied' "$serialize_golden" || {
    printf 'check_sig_case_coverage: c-sig-0018 no longer proves SessionToken lacks Serialize\n' >&2
    exit 1
}
grep -Fq 'the trait `serde_core::ser::Serialize` is not implemented for `SessionToken`' "$serialize_golden" || {
    printf 'check_sig_case_coverage: c-sig-0018 no longer identifies the missing implementation\n' >&2
    exit 1
}
grep -Fq 'required by a bound in `serde_json::to_string`' "$serialize_golden" || {
    printf 'check_sig_case_coverage: c-sig-0018 no longer diagnoses the real serde_json call\n' >&2
    exit 1
}

secret_serialize_golden="${ROOT}/crates/core/tests/compile_fail/c_sig_0123_secret_bytes_serialize.stderr"
grep -Fq 'error[E0277]: the trait bound `SecretBytes: serde::Serialize` is not satisfied' \
    "$secret_serialize_golden" || {
    printf 'check_sig_case_coverage: c-sig-0123 no longer proves SecretBytes lacks Serialize\n' >&2
    exit 1
}
grep -Fq 'the trait `serde_core::ser::Serialize` is not implemented for `SecretBytes`' \
    "$secret_serialize_golden" || {
    printf 'check_sig_case_coverage: c-sig-0123 no longer identifies the missing implementation\n' >&2
    exit 1
}
grep -Fq 'required by a bound in `serde_json::to_string`' "$secret_serialize_golden" || {
    printf 'check_sig_case_coverage: c-sig-0123 no longer diagnoses the real serde_json call\n' >&2
    exit 1
}

proof_controls=(
    'crates/sig/tests/compile_fail/p2_02_signature_match_cannot_clone.rs|no method named `clone` found for struct `SignatureMatch`'
    'crates/sig/tests/compile_fail/p2_02_signature_match_cannot_copy.rs|use of moved value: `proof`'
    'crates/sig/tests/compile_fail/p2_02_anonymous_ack_cannot_clone.rs|no method named `clone` found for struct `AnonymousAck`'
    'crates/sig/tests/compile_fail/p2_02_anonymous_ack_cannot_copy.rs|use of moved value: `evidence`'
)
for control in "${proof_controls[@]}"; do
    IFS='|' read -r relative diagnostic <<<"$control"
    file="${ROOT}/${relative}"
    [[ -f "$file" ]] || {
        printf 'check_sig_case_coverage: proof-token control is missing: %s\n' "$relative" >&2
        exit 1
    }
    validate_rust_evidence "$file" compile 'let _ =' '' \
        "check_sig_case_coverage: proof-token control is not executable: ${relative}"
    stderr="${file%.rs}.stderr"
    [[ -f "$stderr" ]] || {
        printf 'check_sig_case_coverage: proof-token golden is missing: %s.stderr\n' \
            "${relative%.rs}" >&2
        exit 1
    }
    grep -Fq "$diagnostic" "$stderr" || {
        printf 'check_sig_case_coverage: proof-token golden lost its case-specific diagnostic: %s\n' \
            "${relative%.rs}" >&2
        exit 1
    }
done

grep -Fq 'Never run a debug build of `rustfs-gateway-sig` in production' "${ROOT}/README.md" || {
    printf 'check_sig_case_coverage: README lost the debug-build production warning\n' >&2
    exit 1
}
grep -Fq '`InvalidAccessKeyId` and' "${ROOT}/README.md" || {
    printf 'check_sig_case_coverage: README lost the T1 error-code compatibility statement\n' >&2
    exit 1
}
grep -Fq 'timing parity and rate limiting mitigate' "${ROOT}/README.md" || {
    printf 'check_sig_case_coverage: README lost the T1 mitigation statement\n' >&2
    exit 1
}
grep -Fq 'Never run a debug build of `rustfs-gateway-sig` in production' \
    "${ROOT}/docs/security-model.md" || {
    printf 'check_sig_case_coverage: security model lost the debug-build production warning\n' >&2
    exit 1
}
grep -Fq 'known key with a wrong signature answers `SignatureDoesNotMatch`' \
    "${ROOT}/docs/security-model.md" || {
    printf 'check_sig_case_coverage: security model lost the T1 error-code distinction\n' >&2
    exit 1
}
grep -Fq 'Timing parity and the mandatory' "${ROOT}/docs/security-model.md" || {
    printf 'check_sig_case_coverage: security model lost the T1 mitigation statement\n' >&2
    exit 1
}

log_capture="${ROOT}/crates/gateway/tests/credential_runtime.rs"
for evidence in \
    'let clean = run_log_capture_child(false);' \
    'let poison = run_log_capture_child(true);' \
    'credential_material_marker(&poison_log).is_some()' \
    'eprintln!("Authorization: capture-control-without-credential-material");'; do
    grep -Fq "$evidence" "$log_capture" || {
        printf 'check_sig_case_coverage: c-sig-0128 lost request-path log-capture evidence\n' >&2
        exit 1
    }
done

run_evidence_validations

printf 'OK: all 96 P2 signature cases map to executable evidence '
printf '(P2-01: 8/17; P2-02: 6/22; P2-03: 14/29)\n'
