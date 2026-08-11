#!/usr/bin/env bash
set -euo pipefail

# WHAT: Maps every P2-01 acceptance id to named executable evidence.
# WHY: rustfs/backlog#1678 requires 25 explicit cases; nearby doctests or a green crate suite do
# not prove that every listed contract still has a test.
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

[[ "${#cases[@]}" -eq 25 ]] || {
    printf 'check_sig_case_coverage: expected 25 mappings, got %s\n' "${#cases[@]}" >&2
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

validate_rust_evidence() {
    local file="$1" kind="$2" evidence="$3" required_call="${4:-}"
    python3 - "$file" "$kind" "$evidence" "$required_call" <<'PYEOF'
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
PYEOF
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
        validate_rust_evidence "$file" compile "$evidence" || {
            printf 'check_sig_case_coverage: %s is not an executable compile-fail fixture\n' "$relative" >&2
            exit 1
        }
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
        validate_rust_evidence "$file" runtime "$evidence" || {
            printf 'check_sig_case_coverage: %s is not a named #[test] item in %s\n' "$id" "$relative" >&2
            exit 1
        }
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

manifest="${ROOT}/crates/sig/Cargo.toml"
harness="${ROOT}/crates/sig/tests/compile_fail.rs"
core_manifest="${ROOT}/crates/core/Cargo.toml"
core_harness="${ROOT}/crates/core/tests/sig_compile_fail.rs"
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
    'cases.compile_fail("tests/compile_fail/c_sig_001[4-79]_*.rs")' || {
    printf 'check_sig_case_coverage: compile-fail harness does not execute the P2-01 fixtures\n' >&2
    exit 1
}
python3 - "$manifest" "$core_manifest" "${ROOT}/Cargo.toml" <<'PYEOF' || exit 1
import sys
import tomllib
from pathlib import Path

sig = tomllib.loads(Path(sys.argv[1]).read_text())
core = tomllib.loads(Path(sys.argv[2]).read_text())
workspace = tomllib.loads(Path(sys.argv[3]).read_text())
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
            raise SystemExit(f"check_sig_case_coverage: sig manifest gains serialization dependency {package}")

serde_json = core.get("dev-dependencies", {}).get("serde_json")
if not isinstance(serde_json, dict) or serde_json.get("workspace") is not True:
    raise SystemExit("check_sig_case_coverage: core dev tests do not enable real serde_json evidence")
PYEOF
[[ -f "$core_harness" ]] || {
    printf 'check_sig_case_coverage: core signature compile-fail harness is missing\n' >&2
    exit 1
}
validate_rust_evidence "$core_harness" harness \
    session_tokens_are_not_serializable \
    'cases.compile_fail("tests/compile_fail/c_sig_0018_*.rs")' || {
    printf 'check_sig_case_coverage: core harness does not execute c-sig-0018\n' >&2
    exit 1
}

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

printf 'OK: all 25 P2-01 cases map to executable evidence (8 positive, 17 negative)\n'
