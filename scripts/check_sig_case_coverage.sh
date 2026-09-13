#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="${BASH_SOURCE[0]%/*}"

# WHAT: Maps every P2-01 through P2-06 acceptance id to named executable evidence.
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
    'c-sig-0117|negative|crates/sig/tests/compile_fail/c_sig_0117_authenticated_requires_proof.rs|let _ = Verdict::Authenticated { identity, scheme, scope: None };'
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

p2_04_runtime_cases=()
p2_04_runtime_manifest="${ROOT}/scripts/sig-case-coverage-p2-04-runtime.txt"
[[ -f "$p2_04_runtime_manifest" ]] || {
    printf 'check_sig_case_coverage: P2-04 runtime case manifest is missing\n' >&2
    exit 1
}
while IFS= read -r mapping; do
    [[ -n "$mapping" ]] || {
        printf 'check_sig_case_coverage: P2-04 runtime manifest contains a blank row\n' >&2
        exit 1
    }
    p2_04_runtime_cases+=("$mapping")
done <"$p2_04_runtime_manifest"

p2_04_compile_fail_cases=()
p2_04_compile_fail_manifest="${ROOT}/scripts/sig-case-coverage-p2-04-compile-fail.txt"
[[ -f "$p2_04_compile_fail_manifest" ]] || {
    printf 'check_sig_case_coverage: P2-04 compile-fail case manifest is missing\n' >&2
    exit 1
}
while IFS= read -r mapping; do
    [[ -n "$mapping" ]] || {
        printf 'check_sig_case_coverage: P2-04 compile-fail manifest contains a blank row\n' >&2
        exit 1
    }
    p2_04_compile_fail_cases+=("$mapping")
done <"$p2_04_compile_fail_manifest"

p2_05_cases=()
p2_05_manifest="${ROOT}/scripts/sig-case-coverage-p2-05.txt"
[[ -f "$p2_05_manifest" ]] || {
    printf 'check_sig_case_coverage: P2-05 case manifest is missing\n' >&2
    exit 1
}
while IFS= read -r mapping; do
    [[ -n "$mapping" ]] || {
        printf 'check_sig_case_coverage: P2-05 case manifest contains a blank row\n' >&2
        exit 1
    }
    p2_05_cases+=("$mapping")
done <"$p2_05_manifest"

p2_06_cases=()
p2_06_manifest="${ROOT}/scripts/sig-case-coverage-p2-06.txt"
[[ -f "$p2_06_manifest" ]] || {
    printf 'check_sig_case_coverage: P2-06 case manifest is missing\n' >&2
    exit 1
}
while IFS= read -r mapping; do
    [[ -n "$mapping" ]] || {
        printf 'check_sig_case_coverage: P2-06 case manifest contains a blank row\n' >&2
        exit 1
    }
    p2_06_cases+=("$mapping")
done <"$p2_06_manifest"

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

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_sig_case_coverage)" || exit 1

evidence_requests=()

validate_rust_evidence() {
    local file="$1" kind="$2" evidence="$3" required_call="${4:-}" failure="$5"
    evidence_requests+=("${file}"$'\x1f'"${kind}"$'\x1f'"${evidence}"$'\x1f'"${required_call}"$'\x1f'"${failure}")
}

run_evidence_validations() {
    "$PYTHON" - "$ROOT" "${evidence_requests[@]}" <<'PYEOF'
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

# Compiled once, then matched with an offset. Cutting a fresh `source[i:]` slice copies the
# whole remainder of the file on every character, which makes an otherwise linear blanking
# pass quadratic in file length; `pattern.match(source, i)` matches at the same place without
# the copy. No pattern here carries `^`, `\A`, `\b` or a lookbehind, so anchoring at the
# offset is exactly what slicing to it already meant. `.end()` is now an absolute offset into
# `source`.
RAW_STRING_RE = re.compile(r'(?:br|r)(#{0,255})"')
CHAR_LITERAL_RE = re.compile(r"(?:b)?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^\\'\n])'")

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
    elif raw := RAW_STRING_RE.match(source, i):
        hashes = raw.group(1)
        closing = '"' + hashes
        end = source.find(closing, raw.end())
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
    elif character := CHAR_LITERAL_RE.match(source, i):
        end = character.end()
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
    pattern = re.compile(rf"(?m)^[ \t]*(?:async\s+)?fn\s+{re.escape(name)}\s*\(\s*\)[^;{{]*\{{")
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
elif kind in ("runtime", "feature_runtime"):
    if not evidence.startswith("fn "):
        raise SystemExit(f"{path}: runtime evidence must name a function")
    function = evidence.removeprefix("fn ")
    item = top_level_function(function)
    attributes = outer_attributes(item.start()) if item is not None else []
    ordinary = len(attributes) == 1 and re.fullmatch(r"#\s*\[\s*(?:tokio::)?test\s*\]", attributes[0])
    feature_gated = False
    if kind == "feature_runtime" and item is not None:
        raw_prefix = source[max(0, item.start() - 200) : item.start()]
        feature_gated = (
            len(attributes) == 2
            and re.search(
                r'#\[cfg\(feature = "dangerous-replace-signature-verifier"\)\]\s*'
                r'#\[tokio::test\]\s*$',
                raw_prefix,
            )
            is not None
        )
    if not (ordinary if kind == "runtime" else feature_gated):
        raise SystemExit(f"{path}: mapped function is not a real #[test] item")
    if required_call:
        body_start, body_end = function_body(item)
        if not direct_occurrence(body_start, body_end, required_call):
            raise SystemExit(f"{path}: mapped runtime evidence is not active in the test body")
elif kind == "split_runtime":
    if not evidence.startswith("fn "):
        raise SystemExit(f"{path}: split runtime evidence must name a function")
    function = evidence.removeprefix("fn ")
    item = top_level_function(function)
    attributes = outer_attributes(item.start()) if item is not None else []
    ordinary = len(attributes) == 1 and re.fullmatch(r"#\s*\[\s*(?:tokio::)?test\s*\]", attributes[0])
    if not ordinary:
        raise SystemExit(f"{path}: mapped split function is not a real #[test] item")
    body_start, body_end = function_body(item)
    if required_call and required_call not in code[body_start:body_end]:
        raise SystemExit(f"{path}: mapped split test lost its required active evidence")
elif kind == "nested_runtime":
    if not evidence.startswith("fn "):
        raise SystemExit(f"{path}: nested runtime evidence must name a function")
    function = evidence.removeprefix("fn ")
    pattern = re.compile(rf"(?m)^[ \t]*(?:async\s+)?fn\s+{re.escape(function)}\s*\(\s*\)[^;{{]*\{{")
    items = list(pattern.finditer(code))
    if len(items) != 1:
        raise SystemExit(f"{path}: mapped nested test is missing or ambiguous")
    item = items[0]
    attributes = outer_attributes(item.start())
    ordinary = len(attributes) == 1 and re.fullmatch(r"#\s*\[\s*(?:tokio::)?test\s*\]", attributes[0])
    if not ordinary:
        raise SystemExit(f"{path}: mapped nested function is not a real #[test] item")
    module_pattern = re.compile(r"(?m)^[ \t]*mod\s+tests\s*\{\s*$")
    containers = []
    for module in module_pattern.finditer(code):
        module_start, module_end = function_body(module)
        if module_start < item.start() < module_end:
            containers.append(module)
    if len(containers) != 1:
        raise SystemExit(f"{path}: mapped nested test is not in one direct tests module")
    module_attributes = outer_attributes(containers[0].start())
    cfg_attributes = [attribute for attribute in module_attributes if re.match(r"#\s*\[\s*cfg", attribute)]
    active_module = (
        len(cfg_attributes) == 1
        and re.fullmatch(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]", cfg_attributes[0])
        and all(
            attribute == cfg_attributes[0] or re.match(r"#\s*\[\s*allow\s*\(", attribute)
            for attribute in module_attributes
        )
    )
    direct_depth = delimiter_depth(item.start()) == {"{": 1, "(": 0, "[": 0}
    if not active_module or not direct_depth:
        raise SystemExit(f"{path}: mapped nested test is disabled or not a direct module item")
    body_start, body_end = function_body(item)
    if required_call and required_call not in code[body_start:body_end]:
        raise SystemExit(f"{path}: mapped nested test lost its required active evidence")
elif kind == "source_order":
    if code.count(evidence) != 1 or code.count(required_call) != 1:
        raise SystemExit(f"{path}: ordered production evidence is missing or ambiguous")
    if code.index(evidence) >= code.index(required_call):
        raise SystemExit(f"{path}: ordered production evidence is reversed")
elif kind == "source_literal_after":
    if code.count(evidence) != 1:
        raise SystemExit(f"{path}: production branch evidence is missing or ambiguous")
    position = code.index(evidence)
    branch_end = code.find("}", position)
    call_position = code.find("f.write_str", position, branch_end)
    if call_position == -1 or not source.startswith(required_call, call_position):
        raise SystemExit(f"{path}: production branch lost its exact literal")
elif kind == "warning_branch":
    if code.count(evidence) != 1:
        raise SystemExit(f"{path}: warning branch evidence is missing or ambiguous")
    branch_start = code.index(evidence)
    branch_end = code.find("}", branch_start)
    position = code.find("eprintln!", branch_start, branch_end)
    statement_end = code.find(";", position, branch_end) if position != -1 else -1
    statement = source[position : statement_end + 1] if statement_end != -1 else ""
    exact_warning = re.fullmatch(
        rf"eprintln!\(\s*{re.escape(required_call)}\s*\);",
        statement,
        re.DOTALL,
    )
    if position == -1 or exact_warning is None:
        raise SystemExit(f"{path}: warning branch lost its exact active diagnostic")
elif kind == "format_literal":
    if code.count("format!(") != 1:
        raise SystemExit(f"{path}: startup posture format call is missing or ambiguous")
    position = code.index("format!(")
    exact_format = re.match(
        rf"format!\(\s*{re.escape(required_call)}\s*,",
        source[position:],
        re.DOTALL,
    )
    if exact_format is None:
        raise SystemExit(f"{path}: startup posture format literal drifted")
elif kind == "format_literal_exact":
    matches = []
    # Same shape, one level out: the file tail was re-copied at every `format!(`
    # occurrence. Compiled once, matched at the occurrence offset instead.
    exact_call = re.compile(rf"format!\(\s*{re.escape(required_call)}\s*\)", re.DOTALL)
    position = code.find("format!(")
    while position != -1:
        if exact_call.match(source, position):
            matches.append(position)
        position = code.find("format!(", position + 1)
    if len(matches) != 1:
        raise SystemExit(f"{path}: dry-run posture format literal is missing or ambiguous")
elif kind == "string_match_arm":
    pattern = re.compile(
        rf"(?m)^[ \t]*{re.escape(evidence)}[ \t]*=>[ \t]*{re.escape(required_call)},[ \t]*$"
    )
    matches = []
    for match in pattern.finditer(source):
        line = code[match.start() : match.end()]
        if re.search(rf"=>[ \t]*{re.escape(required_call)},", line):
            matches.append(match.start())
    if len(matches) != 1:
        raise SystemExit(f"{path}: active floor-constructor mapping is missing or ambiguous")
elif kind == "log_render":
    if code.count("eprintln!(") != 1:
        raise SystemExit(f"{path}: startup posture log call is missing or ambiguous")
    position = code.index("eprintln!(")
    exact_log = re.match(
        r'eprintln!\(\s*"\{\}"\s*,\s*render_startup_posture\(',
        source[position:],
        re.DOTALL,
    )
    if exact_log is None:
        raise SystemExit(f"{path}: startup posture log no longer renders the live report")
elif kind in ("harness", "feature_harness"):
    item = top_level_function(evidence)
    attributes = outer_attributes(item.start()) if item is not None else []
    test_attribute = r"#\s*\[\s*test\s*\]"
    feature_attribute = r"#\s*\[\s*cfg\s*\(\s*feature\s*=\s*[^)]*\)\s*\]"
    if kind == "harness":
        valid_attributes = len(attributes) == 1 and re.fullmatch(test_attribute, attributes[0])
    else:
        raw_prefix = source[max(0, item.start() - 200) : item.start()]
        exact_feature_attributes = re.search(
            r'#\[cfg\(feature = "dangerous-replace-signature-verifier"\)\]\s*'
            r'#\[test\]\s*$',
            raw_prefix,
        )
        valid_attributes = (
            len(attributes) == 2
            and any(re.fullmatch(test_attribute, attribute) for attribute in attributes)
            and any(re.fullmatch(feature_attribute, attribute) for attribute in attributes)
            and exact_feature_attributes is not None
        )
    if not valid_attributes:
        raise SystemExit(f"{path}: compile-fail harness has the wrong test/feature attributes")
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

# Core's tests reach the real serde_json whether core depends on it for production (ADR-0019's
# SSE-KMS context validation) or only for its tests; either table carries the evidence.
serde_json = core.get("dependencies", {}).get("serde_json") or core.get("dev-dependencies", {}).get("serde_json")
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

[[ "${#p2_04_runtime_cases[@]}" -eq 46 ]] || {
    printf 'check_sig_case_coverage: expected 46 P2-04 runtime mappings, got %s\n' \
        "${#p2_04_runtime_cases[@]}" >&2
    exit 1
}
[[ "${#p2_04_compile_fail_cases[@]}" -eq 5 ]] || {
    printf 'check_sig_case_coverage: expected five P2-04 compile-fail mappings, got %s\n' \
        "${#p2_04_compile_fail_cases[@]}" >&2
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

p2_04_expected_ids=(
    c-sig-0301 c-sig-0302 c-sig-0303 c-sig-0304 c-sig-0305 c-sig-0306 c-sig-0307 c-sig-0308
    c-sig-0320 c-sig-0321 c-sig-0322 c-sig-0323 c-sig-0324 c-sig-0325 c-sig-0326 c-sig-0327
    c-sig-0328 c-sig-0329 c-sig-0330 c-sig-0331 c-sig-0332 c-sig-0333
    c-sig-0340 c-sig-0341 c-sig-0342 c-sig-0343 c-sig-0344
    c-sig-0350 c-sig-0351 c-sig-0352 c-sig-0353
    c-sig-0360 c-sig-0361 c-sig-0362 c-sig-0363 c-sig-0364 c-sig-0365 c-sig-0366
    c-sig-0370 c-sig-0371 c-sig-0372 c-sig-0373 c-sig-0374 c-sig-0375 c-sig-0378 h7-replay-hook
)
positive=0
negative=0
p2_04_evidence=()
p2_04_hard_constraints=()
for index in "${!p2_04_runtime_cases[@]}"; do
    IFS='|' read -r id polarity hard_constraint relative evidence required_call <<<"${p2_04_runtime_cases[$index]}"
    [[ "$id" == "${p2_04_expected_ids[$index]}" ]] || {
        printf 'check_sig_case_coverage: expected P2-04 %s, found %s\n' \
            "${p2_04_expected_ids[$index]}" "$id" >&2
        exit 1
    }
    case "$polarity" in
        positive) positive=$((positive + 1)) ;;
        negative) negative=$((negative + 1)) ;;
        *) printf 'check_sig_case_coverage: %s has unknown polarity %s\n' "$id" "$polarity" >&2; exit 1 ;;
    esac
    [[ "$hard_constraint" =~ ^H[1-7]$|^BOUNDARY$ ]] || {
        printf 'check_sig_case_coverage: %s has unknown security-floor constraint %s\n' \
            "$id" "$hard_constraint" >&2
        exit 1
    }
    p2_04_hard_constraints+=("$hard_constraint")
    file="${ROOT}/${relative}"
    [[ -f "$file" ]] || {
        printf 'check_sig_case_coverage: mapped file is missing: %s\n' "$relative" >&2
        exit 1
    }
    function="${evidence#fn }"
    if [[ "$id" == h7-replay-hook ]]; then
        token='h7_replay_'
    else
        token="${id//-/_}_"
    fi
    [[ "$function" == "$token"* ]] || {
        printf 'check_sig_case_coverage: %s is bound to the wrong executable test %s\n' \
            "$id" "$function" >&2
        exit 1
    }
    p2_04_evidence+=("${relative}|${evidence}")
    evidence_kind=runtime
    [[ "$id" == c-sig-0375 ]] && evidence_kind=feature_runtime
    validate_rust_evidence "$file" "$evidence_kind" "$evidence" "${required_call:-}" \
        "check_sig_case_coverage: ${id} is not a named #[test] item in ${relative}"
done
[[ "$positive" -eq 9 && "$negative" -eq 37 && "$negative" -ge "$positive" ]] || {
    printf 'check_sig_case_coverage: expected 9 positive and 37 negative P2-04 runtime cases, got %s/%s\n' \
        "$positive" "$negative" >&2
    exit 1
}
[[ "$(printf '%s\n' "${p2_04_evidence[@]}" | sort -u | wc -l | tr -d ' ')" -eq 46 ]] || {
    printf 'check_sig_case_coverage: P2-04 runtime cases must use distinct named tests\n' >&2
    exit 1
}
for hard_constraint in H1 H2 H3 H4 H5 H6 H7; do
    printf '%s\n' "${p2_04_hard_constraints[@]}" | grep -Fx "$hard_constraint" >/dev/null || {
        printf 'check_sig_case_coverage: P2-04 runtime ledger has no %s evidence\n' \
            "$hard_constraint" >&2
        exit 1
    }
done

p2_04_compile_fail_expected_ids=(
    c-sig-0345 c-sig-0346 c-sig-0354 c-sig-0376 c-sig-0377
)
p2_04_compile_fail_paths=()
for index in "${!p2_04_compile_fail_cases[@]}"; do
    IFS='|' read -r id polarity hard_constraint relative evidence diagnostic feature \
        <<<"${p2_04_compile_fail_cases[$index]}"
    [[ "$id" == "${p2_04_compile_fail_expected_ids[$index]}" ]] || {
        printf 'check_sig_case_coverage: expected P2-04 compile-fail %s, found %s\n' \
            "${p2_04_compile_fail_expected_ids[$index]}" "$id" >&2
        exit 1
    }
    [[ "$polarity" == negative ]] || {
        printf 'check_sig_case_coverage: %s must remain a negative compile-fail case\n' "$id" >&2
        exit 1
    }
    [[ "$hard_constraint" =~ ^H[1-7]$|^BOUNDARY$ ]] || {
        printf 'check_sig_case_coverage: %s has unknown compile-fail constraint %s\n' \
            "$id" "$hard_constraint" >&2
        exit 1
    }
    case "$id" in
        c-sig-0376) expected_feature='dangerous-replace-signature-verifier' ;;
        *) expected_feature='default' ;;
    esac
    [[ "$feature" == "$expected_feature" ]] || {
        printf 'check_sig_case_coverage: %s has the wrong feature boundary %s\n' "$id" "$feature" >&2
        exit 1
    }
    [[ "$relative" == crates/sig/tests/compile_fail/c_sig_${id#c-sig-}_*.rs ]] || {
        printf 'check_sig_case_coverage: %s is mapped to the wrong fixture %s\n' "$id" "$relative" >&2
        exit 1
    }
    file="${ROOT}/${relative}"
    [[ -f "$file" ]] || {
        printf 'check_sig_case_coverage: P2-04 compile-fail fixture is missing: %s\n' "$relative" >&2
        exit 1
    }
    grep -Fq "$id" "$file" || {
        printf 'check_sig_case_coverage: %s is not named by %s\n' "$id" "$relative" >&2
        exit 1
    }
    validate_rust_evidence "$file" compile "$evidence" '' \
        "check_sig_case_coverage: ${relative} is not an executable compile-fail fixture"
    stderr="${file%.rs}.stderr"
    [[ -f "$stderr" ]] || {
        printf 'check_sig_case_coverage: P2-04 compile-fail golden is missing: %s\n' \
            "${relative%.rs}.stderr" >&2
        exit 1
    }
    grep -Fq 'error[E' "$stderr" || {
        printf 'check_sig_case_coverage: P2-04 compile-fail golden has no rustc diagnostic: %s\n' \
            "${relative%.rs}.stderr" >&2
        exit 1
    }
    grep -Fq "$diagnostic" "$stderr" || {
        printf 'check_sig_case_coverage: %s golden lost its case-specific diagnostic\n' "$id" >&2
        exit 1
    }
    p2_04_compile_fail_paths+=("$relative")
done
[[ "$(printf '%s\n' "${p2_04_compile_fail_paths[@]}" | sort -u | wc -l | tr -d ' ')" -eq 5 ]] || {
    printf 'check_sig_case_coverage: P2-04 compile-fail cases must use five distinct fixtures\n' >&2
    exit 1
}

[[ "${#p2_05_cases[@]}" -eq 16 ]] || {
    printf 'check_sig_case_coverage: expected 16 P2-05 mappings, got %s\n' "${#p2_05_cases[@]}" >&2
    exit 1
}
p2_05_expected_ids=(
    c-sig-0417 c-sig-0418 c-sig-0419 c-sig-0420 c-sig-0421 c-sig-0422
    c-sig-0423 c-sig-0424 c-sig-0425 c-sig-0426 c-sig-0427 c-sig-0428
    c-sig-0429 c-sig-0430 c-sig-0431 c-sig-0432
)
positive=0
negative=0
p2_05_evidence=()
for index in "${!p2_05_cases[@]}"; do
    IFS='|' read -r id polarity relative evidence required_call secondary_call <<<"${p2_05_cases[$index]}"
    [[ "$id" == "${p2_05_expected_ids[$index]}" ]] || {
        printf 'check_sig_case_coverage: expected P2-05 %s, found %s\n' \
            "${p2_05_expected_ids[$index]}" "$id" >&2
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
    function="${evidence#fn }"
    token="${id//-/_}_"
    [[ "$function" == "$token"* ]] || {
        printf 'check_sig_case_coverage: %s is bound to the wrong executable test %s\n' \
            "$id" "$function" >&2
        exit 1
    }
    p2_05_evidence+=("${relative}|${evidence}")
    evidence_kind=nested_runtime
    [[ "$relative" == crates/gateway/tests/pipeline.rs ]] && evidence_kind=runtime
    if [[ "$relative" == crates/gateway/src/ext/authenticator_tests.rs ]]; then
        # The unit suite left authenticator.rs when P2-06's SigV2 entry point pushed that file past
        # the 800-line limit, using the `#[cfg(test)] #[path] mod tests;` split this repository
        # already uses in `crates/sig/src/signer.rs` and `crates/conformance/src/lint.rs`. The
        # module is now the file, so `nested_runtime`'s enclosing `mod tests` no longer exists —
        # and the `#[cfg(test)]` it used to observe moved to the declaration site. Asserted there,
        # adjacency included, so the suite cannot be detached from its gate or re-pointed at
        # another file.
        evidence_kind=runtime
        declaring="$(tr '\n' '\001' <"${ROOT}/crates/gateway/src/ext/authenticator.rs")"
        wanted="$(printf '#[cfg(test)]\001#[path = "authenticator_tests.rs"]\001mod tests;')"
        grep -Fq "$wanted" <<<"$declaring" || {
            printf 'check_sig_case_coverage: authenticator.rs does not declare its split unit suite under #[cfg(test)]\n' >&2
            exit 1
        }
    fi
    if [[ "$relative" == crates/sig/src/post_policy_tests.rs ]]; then
        evidence_kind=split_runtime
        declaring="$(tr '\n' '\001' <"${ROOT}/crates/sig/src/post_policy.rs")"
        wanted="$(printf '#[cfg(test)]\001#[path = "post_policy_tests.rs"]\001mod tests;')"
        grep -Fq "$wanted" <<<"$declaring" || {
            printf 'check_sig_case_coverage: post_policy.rs does not declare its split unit suite under #[cfg(test)]\n' >&2
            exit 1
        }
    fi
    validate_rust_evidence "$file" "$evidence_kind" "$evidence" "$required_call" \
        "check_sig_case_coverage: ${id} is not a named active P2-05 test in ${relative}"
    if [[ -n "${secondary_call:-}" ]]; then
        validate_rust_evidence "$file" "$evidence_kind" "$evidence" "$secondary_call" \
            "check_sig_case_coverage: ${id} lost its second active P2-05 assertion in ${relative}"
    fi
done
[[ "$positive" -eq 3 && "$negative" -eq 13 && "$negative" -gt "$positive" ]] || {
    printf 'check_sig_case_coverage: expected 3 positive and 13 negative P2-05 cases, got %s/%s\n' \
        "$positive" "$negative" >&2
    exit 1
}
[[ "$(printf '%s\n' "${p2_05_evidence[@]}" | sort -u | wc -l | tr -d ' ')" -eq 16 ]] || {
    printf 'check_sig_case_coverage: P2-05 cases must use distinct named tests\n' >&2
    exit 1
}

[[ "${#p2_06_cases[@]}" -eq 69 ]] || {
    printf 'check_sig_case_coverage: expected 69 P2-06 mappings, got %s\n' "${#p2_06_cases[@]}" >&2
    exit 1
}
p2_06_expected_ids=(
    c-sig-0501 c-sig-0502 c-sig-0503 c-sig-0504 c-sig-0505 c-sig-0506
    c-sig-0507 c-sig-0508 c-sig-0509 c-sig-0510 c-sig-0511 c-sig-0512
    c-sig-0530
    c-sig-0531 c-sig-0532 c-sig-0533 c-sig-0534 c-sig-0535 c-sig-0536
    c-sig-0537 c-sig-0538 c-sig-0539 c-sig-0540 c-sig-0541 c-sig-0542
    c-sig-0543 c-sig-0544 c-sig-0545 c-sig-0546 c-sig-0547 c-sig-0548
    c-sig-0549 c-sig-0550 c-sig-0551 c-sig-0552 c-sig-0553 c-sig-0554 c-sig-0555
    c-sig-0556 c-sig-0557 c-sig-0558 c-sig-0559 c-sig-0560 c-sig-0561
    c-sig-0562 c-sig-0563 c-sig-0564 c-sig-0565 c-sig-0566 c-sig-0567
    c-sig-0568 c-sig-0569 c-sig-0570 c-sig-0571 c-sig-0572 c-sig-0573
    c-sig-0574 c-sig-0575 c-sig-0576 c-sig-0577 c-sig-0578 c-sig-0579
    c-sig-0580 c-sig-0581 c-sig-0582 c-sig-0583 c-sig-0584 c-sig-0585
    c-sig-0586
)
positive=0
negative=0
p2_06_evidence=()
p2_06_compile_fail_paths=()
for index in "${!p2_06_cases[@]}"; do
    IFS='|' read -r id polarity relative evidence required_call <<<"${p2_06_cases[$index]}"
    [[ "$id" == "${p2_06_expected_ids[$index]}" ]] || {
        printf 'check_sig_case_coverage: expected P2-06 %s, found %s\n' \
            "${p2_06_expected_ids[$index]}" "$id" >&2
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
    p2_06_evidence+=("${relative}|${evidence}")
    if [[ "$relative" == scripts/*.sh ]]; then
        validate_shell_mutation "$file" "$evidence" || {
            printf 'check_sig_case_coverage: %s is not an executable guard mutation in %s\n' \
                "$id" "$relative" >&2
            exit 1
        }
        continue
    fi
    grep -Fq "$id" "$file" || {
        printf 'check_sig_case_coverage: %s is not named by %s\n' "$id" "$relative" >&2
        exit 1
    }
    if [[ "$relative" == conformance/cases/*.toml ]]; then
        for token in "$evidence" "$required_call"; do
            grep -Fq "$token" "$file" || {
                printf 'check_sig_case_coverage: %s lost conformance evidence `%s` in %s\n' \
                    "$id" "$token" "$relative" >&2
                exit 1
            }
        done
        continue
    fi
    if [[ "$relative" == crates/sig/tests/compile_fail/c_sig_*.rs ]]; then
        p2_06_compile_fail_paths+=("$relative")
        validate_rust_evidence "$file" compile "$evidence" '' \
            "check_sig_case_coverage: ${relative} is not an executable compile-fail fixture"
        stderr="${file%.rs}.stderr"
        [[ -f "$stderr" ]] || {
            printf 'check_sig_case_coverage: compile-fail golden is missing: %s.stderr\n' \
                "${relative%.rs}" >&2
            exit 1
        }
        diagnostic=''
        case "$id" in
            c-sig-0550) diagnostic='`rustfs_gateway_sig::Signature` does not implement `PartialEq`' ;;
            c-sig-0555) diagnostic='the trait `Debug` is not implemented for `SigV2Authorization`' ;;
        esac
        [[ -n "$diagnostic" ]] || {
            printf 'check_sig_case_coverage: %s has no pinned compile-fail diagnostic\n' "$id" >&2
            exit 1
        }
        grep -Fq "$diagnostic" "$stderr" || {
            printf 'check_sig_case_coverage: %s golden lost its case-specific diagnostic\n' "$id" >&2
            exit 1
        }
        continue
    fi
    function="${evidence#fn }"
    token="${id//-/_}_"
    [[ "$function" == "$token"* ]] || {
        printf 'check_sig_case_coverage: %s is bound to the wrong executable test %s\n' \
            "$id" "$function" >&2
        exit 1
    }
    validate_rust_evidence "$file" runtime "$evidence" "$required_call" \
        "check_sig_case_coverage: ${id} is not a named active P2-06 test in ${relative}"
done
[[ "$positive" -eq 18 && "$negative" -eq 51 && "$negative" -gt "$positive" ]] || {
    printf 'check_sig_case_coverage: expected 18 positive and 51 negative P2-06 cases, got %s/%s\n' \
        "$positive" "$negative" >&2
    exit 1
}
[[ "$(printf '%s\n' "${p2_06_evidence[@]}" | sort -u | wc -l | tr -d ' ')" -eq 69 ]] || {
    printf 'check_sig_case_coverage: P2-06 cases must use distinct named evidence\n' >&2
    exit 1
}
[[ "${#p2_06_compile_fail_paths[@]}" -eq 2 ]] || {
    printf 'check_sig_case_coverage: expected two P2-06 compile-fail fixtures, got %s\n' \
        "${#p2_06_compile_fail_paths[@]}" >&2
    exit 1
}

# The SigV2 sub-resource weakness is a deployment fact, not an implementation note: if the
# security model stops stating it, the reason SigV2 presigned is off by default is gone too.
grep -Fq 'SigV2 signs almost none of the query string' "${ROOT}/docs/security-model.md" || {
    printf 'check_sig_case_coverage: security model lost the SigV2 query-coverage statement\n' >&2
    exit 1
}
grep -Fq '`SigV2Policy::HeaderOnly` is the default' "${ROOT}/docs/security-model.md" || {
    printf 'check_sig_case_coverage: security model lost the SigV2 default-policy statement\n' >&2
    exit 1
}

grep -Fq 'Presigned URLs are replayable within their validity window.' \
    "${ROOT}/docs/security-model.md" || {
    printf 'check_sig_case_coverage: security model lost the H7 replay statement\n' >&2
    exit 1
}
grep -Fq '`ReplayNonceStore` is an opt-in single-use hook' \
    "${ROOT}/docs/security-model.md" || {
    printf 'check_sig_case_coverage: security model lost the H7 replay-hook guidance\n' >&2
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
validate_rust_evidence "$harness" harness \
    p2_04_compile_time_boundaries_are_not_openable \
    'cases.compile_fail("tests/compile_fail/c_sig_034[56]_*.rs")' \
    'check_sig_case_coverage: compile-fail harness does not execute c-sig-0345 and c-sig-0346'
validate_rust_evidence "$harness" harness \
    p2_04_compile_time_boundaries_are_not_openable \
    'cases.compile_fail("tests/compile_fail/c_sig_0354_*.rs")' \
    'check_sig_case_coverage: compile-fail harness does not execute c-sig-0354'
validate_rust_evidence "$harness" harness \
    p2_04_compile_time_boundaries_are_not_openable \
    'cases.compile_fail("tests/compile_fail/c_sig_0377_*.rs")' \
    'check_sig_case_coverage: compile-fail harness does not execute c-sig-0377'
validate_rust_evidence "$harness" feature_harness \
    p2_04_danger_ack_compile_time_boundary_is_not_openable \
    'cases.compile_fail("tests/compile_fail/c_sig_0376_*.rs")' \
    'check_sig_case_coverage: dangerous feature harness does not execute c-sig-0376'

gateway_builder="${ROOT}/crates/gateway/src/builder.rs"
gateway_service="${ROOT}/crates/gateway/src/service.rs"
gateway_dispatch="${ROOT}/crates/gateway/src/dispatch.rs"
gateway_posture="${ROOT}/crates/gateway/src/posture.rs"
xtask_main="${ROOT}/xtask/src/main.rs"
xtask_security_posture="${ROOT}/xtask/src/security_posture.rs"
validate_rust_evidence "$gateway_builder" source_order \
    'pub fn with_dangerously_replaced_signature_verifier(' \
    '_acknowledgement: DangerAck,' \
    'check_sig_case_coverage: dangerous replacement builder lost its explicit acknowledgement'
validate_rust_evidence "$gateway_builder" source_order \
    '_acknowledgement: DangerAck,' \
    'self.dangerously_replaced_signature_verifier = Some(Arc::new(verifier));' \
    'check_sig_case_coverage: dangerous replacement builder wiring is incomplete'
validate_rust_evidence "$gateway_service" source_order \
    'self.inner.floor.admit(view, M::floor(&op), now)' \
    'verifier.verify_sealed(&sealed)' \
    'check_sig_case_coverage: the replacement is not ordered after the security floor'
validate_rust_evidence "$gateway_builder" source_order \
    'let dangerously_replaced_signature_verifier = self.dangerously_replaced_signature_verifier.is_some();' \
    'SecurityPosture::new(' \
    'check_sig_case_coverage: dangerous replacement posture is not derived at assembly'
validate_rust_evidence "$gateway_builder" source_order \
    'let custom_signature_verifier = self.custom_signature_verifier.is_some();' \
    'SecurityPosture::new(' \
    'check_sig_case_coverage: custom verifier posture is not derived at assembly'
validate_rust_evidence "$gateway_builder" source_order \
    'let security_posture = SecurityPosture::new(' \
    'log_startup_posture(' \
    'check_sig_case_coverage: assembly does not emit the startup security posture'
validate_rust_evidence "$gateway_builder" source_order \
    'let dangerously_replaced_signature_verifier = self.dangerously_replaced_signature_verifier.is_some();' \
    'if dangerously_replaced_signature_verifier {' \
    'check_sig_case_coverage: dangerous replacement warning is not reached at assembly'
validate_rust_evidence "$gateway_builder" warning_branch \
    'if dangerously_replaced_signature_verifier {' \
    '"WARN: the built-in AWS signature verifier is dangerously replaced; the H1..H7 security floor remains enforced"' \
    'check_sig_case_coverage: dangerous replacement lost its exact start-up warning'
validate_rust_evidence "$gateway_posture" source_literal_after \
    'if self.dangerously_replaced_signature_verifier {' \
    'f.write_str("; AWS signature verifier: dangerously replaced")?;' \
    'check_sig_case_coverage: dangerous replacement posture display drifted'
validate_rust_evidence "$gateway_posture" source_literal_after \
    'if self.custom_signature_verifier {' \
    'f.write_str("; custom signature verifier: installed")' \
    'check_sig_case_coverage: custom verifier posture display drifted'
validate_rust_evidence "$gateway_dispatch" source_order \
    'pub(crate) fn floors(&self)' \
    'self.entries.values().map(OperationDispatch::floor)' \
    'check_sig_case_coverage: startup posture cannot enumerate registered operation floors'
validate_rust_evidence "$gateway_posture" source_order \
    '.filter(|operation| floor.admits_anonymous(operation))' \
    'format_names(&anonymous_reachable_ops)' \
    'check_sig_case_coverage: startup posture lost anonymous operation enumeration'
validate_rust_evidence "$gateway_posture" source_order \
    '.filter(|operation| !operation.privileged() && operation.allowed_schemes().allows_presigned())' \
    'format_names(&presigned_allowed_ops)' \
    'check_sig_case_coverage: startup posture lost presigned operation enumeration'
# P2-06's wiring made SigV2 a three-way policy that is actually verified, so the report names the
# policy rather than the presigned flag derived from it. `as_str()` is the switch: a report that
# printed a constant would say `HeaderOnly` while a deployment ran `HeaderAndPresigned`.
validate_rust_evidence "$gateway_posture" source_order \
    'let sigv2_policy = floor.sigv2_policy().as_str();' \
    'format!(' \
    'check_sig_case_coverage: startup posture lost the live SigV2 switch'
validate_rust_evidence "$gateway_posture" source_order \
    'let custom_verifier = if custom_signature_verifier {' \
    'let sigv2_policy = floor.sigv2_policy().as_str();' \
    'check_sig_case_coverage: startup posture lost the live custom verifier switch'
validate_rust_evidence "$gateway_posture" source_order \
    'let aws_signature_verifier = if dangerously_replaced_signature_verifier {' \
    'format!(' \
    'check_sig_case_coverage: startup posture lost the live AWS verifier switch'
validate_rust_evidence "$gateway_posture" format_literal \
    'SECURITY_POSTURE' \
    '"SECURITY_POSTURE anonymous_reachable_ops=[{}] custom_verifier={custom_verifier} sigv2_policy={sigv2_policy} presigned_allowed_ops=[{}] aws_signature_verifier={aws_signature_verifier}"' \
    'check_sig_case_coverage: startup posture output lost a required field'
validate_rust_evidence "$gateway_posture" log_render \
    'log_startup_posture' \
    'render_startup_posture' \
    'check_sig_case_coverage: startup posture is not written to the startup log'
validate_rust_evidence "$xtask_main" source_order \
    'mod security_posture;' \
    'security_posture::command(&rest),' \
    'check_sig_case_coverage: security-posture dry-run is not dispatched'
validate_rust_evidence "$xtask_security_posture" source_order \
    'if args !=' \
    'return ExitCode::from(2);' \
    'check_sig_case_coverage: security-posture accepts arguments other than --dry-run'
validate_rust_evidence "$xtask_security_posture" source_order \
    'let floors = parse_standard_floors' \
    'rustfs_gateway_core::route::ROUTES' \
    'check_sig_case_coverage: dry-run does not join real floors to the route-table inventory'
validate_rust_evidence "$xtask_security_posture" source_order \
    'rustfs_gateway_core::route::ROUTES' \
    '.filter(|row| row.handler_registration)' \
    'check_sig_case_coverage: dry-run does not exclude route-only operations from the handler inventory'
validate_rust_evidence "$xtask_security_posture" source_order \
    '.filter(|row| row.handler_registration)' \
    '.map(|row| row.operation.to_owned())' \
    'check_sig_case_coverage: dry-run does not derive handler names from real route rows'
validate_rust_evidence "$xtask_security_posture" source_order \
    'let parsed: BTreeSet<_> = floors.keys().cloned().collect();' \
    'if parsed != routed {' \
    'check_sig_case_coverage: dry-run no longer rejects operation inventory drift'
validate_rust_evidence "$xtask_security_posture" source_order \
    'std::fs::read_dir(directory)' \
    'syn::parse_file(&source)' \
    'check_sig_case_coverage: dry-run no longer parses the real operation sources'
validate_rust_evidence "$xtask_security_posture" source_order \
    'validate_operation_impl_uses_floor(&file, &path)?;' \
    'let floor_items: Vec<_>' \
    'check_sig_case_coverage: dry-run no longer proves Operation::floor returns the parsed floor'
validate_rust_evidence "$xtask_security_posture" source_order \
    'let operation_impls: Vec<_>' \
    'let floor_methods: Vec<_>' \
    'check_sig_case_coverage: dry-run no longer requires one real Operation floor method'
validate_rust_evidence "$xtask_security_posture" source_order \
    'let [syn::Stmt::Expr(syn::Expr::Reference(reference), None)]' \
    'returned.path.segments.len() != 1' \
    'check_sig_case_coverage: dry-run accepts an Operation::floor decoy binding'
validate_rust_evidence "$xtask_security_posture" source_order \
    'let syn::Expr::Call(call) = expression else {' \
    'if segments.len() != 2 || segments[0] !=' \
    'check_sig_case_coverage: dry-run accepts a non-canonical operation floor expression'
validate_rust_evidence "$xtask_security_posture" source_order \
    'let presigned = floors' \
    'floor.presigned.then_some(name.as_str())' \
    'check_sig_case_coverage: dry-run no longer derives the presigned operation list'
validate_rust_evidence "$xtask_security_posture" source_order \
    'let anonymous = floors' \
    'floor.anonymous.then_some(name.as_str())' \
    'check_sig_case_coverage: dry-run no longer derives the anonymous operation list'
validate_rust_evidence "$xtask_security_posture" string_match_arm \
    '"builtin_presigned"' \
    'true' \
    'check_sig_case_coverage: dry-run no longer recognizes the presigned floor constructor'
validate_rust_evidence "$xtask_security_posture" format_literal_exact \
    'SECURITY_POSTURE' \
    '"SECURITY_POSTURE anonymous_reachable_ops=[{anonymous}] custom_verifier=none sigv2_policy=HeaderOnly presigned_allowed_ops=[{presigned}] aws_signature_verifier=built-in"' \
    'check_sig_case_coverage: dry-run output lost a required startup-posture field'

"$PYTHON" - "$ROOT/crates/gateway/Cargo.toml" <<'PYEOF'
import sys
import tomllib
from pathlib import Path

manifest = tomllib.loads(Path(sys.argv[1]).read_text())
expected = ["rustfs-gateway-sig/dangerous-replace-signature-verifier"]
actual = manifest.get("features", {}).get("dangerous-replace-signature-verifier")
if actual != expected:
    raise SystemExit("check_sig_case_coverage: gateway dangerous replacement feature forwarding drifted")
PYEOF
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

printf 'OK: all 232 P2 signature cases map to executable evidence '
printf '(P2-01: 8/17; P2-02: 6/22; P2-03: 14/29; P2-04: 9/42; P2-05: 3/13; P2-06: 18/51)\n'
