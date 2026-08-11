#!/usr/bin/env bash
set -euo pipefail

# WHAT: Maps every rustfs/backlog#1706 scalar acceptance id to one atomic executable test or guard.
# WHY: P1-04 contains 71 cases, not 60; a type existing is not evidence that each protocol rule is
# observable and falsifiable. The old c-etag-0001 scalar id collided with an existing wire case, so
# its replacement is c-etag-0101.
# HOW TO EXEMPT: There is no exemption. Add a test or deterministic guard carrying the missing id.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SCALAR_TESTS_MOD="${ROOT}/crates/types/src/scalar/tests/mod.rs"

etag=(c-etag-0101 c-etag-0002 c-etag-0003 c-etag-0004 c-etag-0005)
checksum=(c-cks-0001 c-cks-0002 c-cks-0003 c-cks-0004)
timestamp=(c-ts-0001 c-ts-0002 c-ts-0003)
name=(c-name-0001 c-name-0002)
range=(c-rng-0001)
error=(c-err-0001)

for n in 001 002 003 004 005 006 007 008 009 010; do
    etag+=("c-etag-n${n}")
    checksum+=("c-cks-n${n}")
done
for n in 001 002 003 004 005 006 007; do
    timestamp+=("c-ts-n${n}")
done
for n in 001 002 003 004 005 006 007 008 009; do
    name+=("c-name-n${n}")
done
for n in 001 002 003 004 005 006 007 008; do
    range+=("c-rng-n${n}")
done
for n in 001 002 003 004 005 006 007 008 009 010 011; do
    error+=("c-err-n${n}")
done

all=("${etag[@]}" "${checksum[@]}" "${timestamp[@]}" "${name[@]}" "${range[@]}" "${error[@]}")
[[ "${#all[@]}" -eq 71 ]] || {
    printf 'check_scalar_case_coverage: expected 71 acceptance ids, got %s\n' "${#all[@]}" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || {
    printf 'check_scalar_case_coverage: required command is missing: python3\n' >&2
    exit 1
}

[[ -f "$SCALAR_TESTS_MOD" ]] || {
    printf 'check_scalar_case_coverage: scalar test module wiring is missing\n' >&2
    exit 1
}
for module in checksum_tests error_tests etag_tests name_tests range_tests timestamp_corpus_tests timestamp_tests; do
    [[ "$(grep -Fxc "mod ${module};" "$SCALAR_TESTS_MOD" || true)" -eq 1 ]] || {
        printf 'check_scalar_case_coverage: mapped test module is not wired exactly once: %s\n' "$module" >&2
        exit 1
    }
done
if grep -Eq '^[[:space:]]*#\[[[:space:]]*cfg' "$SCALAR_TESTS_MOD"; then
    printf 'check_scalar_case_coverage: mapped test module wiring must be unconditional\n' >&2
    exit 1
fi

evidence_for() {
    case "$1" in
        c-etag-n009) printf '%s|%s' 'scripts/check_etag_render.sh' 'c-etag-n009' ;;
        c-cks-n009) printf '%s|%s' 'scripts/check_checksum_dependencies.sh' 'c-cks-n009' ;;
        c-ts-0001) printf '%s|fn %s_' 'crates/types/src/scalar/tests/timestamp_corpus_tests.rs' "${1//-/_}" ;;
        c-ts-n002) printf '%s|%s' 'scripts/check_opaque_string.sh' 'c-ts-n002' ;;
        c-rng-n007) printf '%s|%s' 'conformance/cases/range/c-range-0015.toml' 'c-range-0015' ;;
        c-etag-*) printf '%s|fn %s_' 'crates/types/src/scalar/tests/etag_tests.rs' "${1//-/_}" ;;
        c-cks-*) printf '%s|fn %s_' 'crates/types/src/scalar/tests/checksum_tests.rs' "${1//-/_}" ;;
        c-ts-*) printf '%s|fn %s_' 'crates/types/src/scalar/tests/timestamp_tests.rs' "${1//-/_}" ;;
        c-name-*) printf '%s|fn %s_' 'crates/types/src/scalar/tests/name_tests.rs' "${1//-/_}" ;;
        c-rng-*) printf '%s|fn %s_' 'crates/types/src/scalar/tests/range_tests.rs' "${1//-/_}" ;;
        c-err-0001) printf '%s|fn %s_' 'crates/types/src/scalar/tests/error_tests.rs' "${1//-/_}" ;;
        c-err-n*) printf '%s|fn %s_' 'crates/core/tests/error_resolution.rs' "${1//-/_}" ;;
        *) return 1 ;;
    esac
}

validate_rust_test() {
    local file="$1" marker="$2"
    python3 - "$file" "$marker" <<'PYEOF'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
marker = sys.argv[2]
if not marker.startswith("fn "):
    raise SystemExit(f"{path}: Rust evidence must name a test function")
prefix = marker.removeprefix("fn ")
source = path.read_text()

# Blank comments and literals while preserving delimiters and byte positions. A test name in data
# or inside a macro body is not executable evidence.
out = []
i = 0
comment_depth = 0
while i < len(source):
    if comment_depth:
        if source.startswith("/*", i):
            comment_depth += 1
            out.extend("  ")
            i += 2
        elif source.startswith("*/", i):
            comment_depth -= 1
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
        comment_depth = 1
        out.extend("  ")
        i += 2
    elif raw := re.match(r'(?:br|r)(#{0,255})"', source[i:]):
        closing = '"' + raw.group(1)
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

if comment_depth:
    raise SystemExit(f"{path}: unterminated block comment")
code = "".join(out)
if re.search(r"(?m)^[ \t]*#!\s*\[\s*cfg(?:_attr)?\b", code):
    raise SystemExit(f"{path}: file-level cfg disables mapped scalar evidence")

def delimiter_depth(end):
    depth = {"{": 0, "(": 0, "[": 0}
    closing = {"}": "{", ")": "(", "]": "["}
    for char in code[:end]:
        if char in depth:
            depth[char] += 1
        elif char in closing:
            depth[closing[char]] -= 1
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
        while position and code[position - 1].isspace():
            position -= 1
        if not position or code[position - 1] != "#":
            break
        position -= 1
        attributes.append(code[position:end])
    attributes.reverse()
    return attributes

pattern = re.compile(rf"(?m)^[ \t]*fn\s+{re.escape(prefix)}[A-Za-z0-9_]*\s*\(")
active = 0
for match in pattern.finditer(code):
    if any(delimiter_depth(match.start()).values()):
        continue
    attributes = outer_attributes(match.start())
    if len(attributes) == 1 and re.fullmatch(r"#\s*\[\s*test\s*\]", attributes[0]):
        active += 1
if active != 1:
    raise SystemExit(f"{path}: {marker} has {active} active top-level #[test] matches, expected 1")
PYEOF
}

validate_toml_case() {
    local file="$1" expected_id="$2"
    python3 - "$file" "$expected_id" <<'PYEOF'
import sys
import tomllib
from pathlib import Path

path = Path(sys.argv[1])
expected = sys.argv[2]
case = tomllib.loads(path.read_text()).get("case", {})
if case.get("id") != expected:
    raise SystemExit(f"{path}: [case].id is not {expected}")
PYEOF
}

status=0
mapped=0
seen='|'
for id in "${all[@]}"; do
    if [[ "$seen" == *"|${id}|"* ]]; then
        printf 'check_scalar_case_coverage: duplicate acceptance id: %s\n' "$id" >&2
        status=1
        continue
    fi
    seen+="${id}|"
    IFS='|' read -r relative marker <<<"$(evidence_for "$id")"
    file="${ROOT}/${relative}"
    if [[ ! -f "$file" ]]; then
        printf 'check_scalar_case_coverage: %s evidence file is missing: %s\n' "$id" "$relative" >&2
        status=1
        continue
    fi
    if [[ "$relative" == *.rs ]]; then
        if ! validate_rust_test "$file" "$marker"; then
            printf 'check_scalar_case_coverage: %s has no active atomic test in %s\n' "$id" "$relative" >&2
            status=1
            continue
        fi
    elif [[ "$relative" == *.toml ]]; then
        if ! validate_toml_case "$file" "$marker"; then
            printf 'check_scalar_case_coverage: %s has no active case id in %s\n' "$id" "$relative" >&2
            status=1
            continue
        fi
    elif ! grep -Fq "$marker" "$file"; then
        printf 'check_scalar_case_coverage: %s has no atomic evidence in %s\n' "$id" "$relative" >&2
        status=1
        continue
    fi
    mapped=$((mapped + 1))
done

if [[ "$status" -ne 0 ]]; then
    printf 'check_scalar_case_coverage: %s mapped\n' "$mapped" >&2
    exit "$status"
fi
printf 'OK: all 71 scalar acceptance ids map to atomic executable evidence\n'
