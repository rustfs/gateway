#!/usr/bin/env bash
set -euo pipefail

# Public fields may be added to a generated DTO, but never silently removed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
CANDIDATE="${ROOT_DIR}/generated/dto/field_counts.txt"
AGENTS_FILE="${ROOT_DIR}/AGENTS.md"
SCRIPTS_README="${ROOT_DIR}/scripts/README.md"
MUTATION_HARNESS="${ROOT_DIR}/scripts/test_guard_scripts.sh"

if [[ "$#" -gt 1 ]]; then
    printf 'usage: check_dto_fields.sh [base-ref]\n' >&2
    exit 2
fi

for command in git mktemp python3; do
    if ! command -v "$command" >/dev/null 2>&1; then
        printf 'check_dto_fields.sh: required command is missing: %s\n' "$command" >&2
        exit 1
    fi
done

python3 - "$AGENTS_FILE" "$SCRIPTS_README" "$MUTATION_HARNESS" <<'PY'
import pathlib
import sys

agents_path, readme_path, harness_path = map(pathlib.Path, sys.argv[1:])
try:
    agents = agents_path.read_text()
    readme = readme_path.read_text()
    harness = harness_path.read_text()
except OSError as error:
    print(f"check_dto_fields.sh: required governance input is unavailable: {error}", file=sys.stderr)
    raise SystemExit(1)

protected_row = "| `generated/dto/field_counts.txt` | Public DTO field-count ratchet; a removed type or field is a breaking downstream API change |"
if agents.count(protected_row) != 1:
    print("check_dto_fields.sh: AGENTS.md must protect generated/dto/field_counts.txt exactly once", file=sys.stderr)
    raise SystemExit(1)

implemented = readme.partition("### Implemented")[2].partition("### Registered, not yet implemented (TODO)")[0]
registered = readme.partition("### Registered, not yet implemented (TODO)")[2]
row = "| `check_dto_fields.sh` | DTO public field count only grows (the `non_exhaustive` and destructuring halves are now implemented separately, see above) | P0-08 |"
if implemented.count(row) != 1 or row in registered:
    print("check_dto_fields.sh: scripts/README.md must list check_dto_fields.sh once under Implemented", file=sys.stderr)
    raise SystemExit(1)

required_mutation_fragments = (
    "\nmut_e0639_non_exhaustive_removed() {\n",
    "\nexpect_rustc_test_fail_with_diagnostic crates/types/tests/semver_policy.rs \\\n",
    "'non-exhaustive FRU unexpectedly compiled' mut_e0639_non_exhaustive_removed\n",
)
if any(harness.count(fragment) != 1 for fragment in required_mutation_fragments):
    print("check_dto_fields.sh: E0639 remove-attribute mutation harness is missing or duplicated", file=sys.stderr)
    raise SystemExit(1)
PY

if [[ ! -f "$CANDIDATE" ]]; then
    printf 'check_dto_fields.sh: required input is missing: generated/dto/field_counts.txt\n' >&2
    exit 1
fi

if [[ "$#" -eq 1 ]]; then
    baseline_ref="$1"
    if ! baseline_commit="$(git -C "$ROOT_DIR" rev-parse --verify "${baseline_ref}^{commit}" 2>/dev/null)"; then
        printf 'check_dto_fields.sh: explicit base is unavailable: %s\n' "$baseline_ref" >&2
        exit 1
    fi
else
    baseline_ref="origin/main"
    if ! git -C "$ROOT_DIR" rev-parse --verify "${baseline_ref}^{commit}" >/dev/null 2>&1; then
        printf 'check_dto_fields.sh: required base is unavailable: %s\n' "$baseline_ref" >&2
        exit 1
    fi
    if ! baseline_commit="$(git -C "$ROOT_DIR" merge-base HEAD "$baseline_ref" 2>/dev/null)" || [[ -z "$baseline_commit" ]]; then
        printf 'check_dto_fields.sh: cannot resolve merge base of HEAD and %s\n' "$baseline_ref" >&2
        exit 1
    fi
fi

previous="$(mktemp "${TMPDIR:-/tmp}/gateway-dto-fields.XXXXXX")"
trap 'rm -f "$previous"' EXIT
if ! git -C "$ROOT_DIR" show "${baseline_commit}:generated/dto/field_counts.txt" >"$previous" 2>/dev/null; then
    printf 'check_dto_fields.sh: cannot read %s:generated/dto/field_counts.txt\n' "$baseline_commit" >&2
    exit 1
fi

python3 - "$previous" "$CANDIDATE" <<'PY'
import pathlib
import re
import sys

def parse(path: pathlib.Path) -> dict[str, int]:
    result: dict[str, int] = {}
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*) ([0-9]+)", line)
        if match is None:
            raise ValueError(f"{path}:{line_number}: malformed field-count row")
        name, count = match.group(1), int(match.group(2))
        if name in result:
            raise ValueError(f"{path}:{line_number}: duplicate type {name}")
        result[name] = count
    if not result:
        raise ValueError(f"{path}: field-count input is empty")
    return result

try:
    before = parse(pathlib.Path(sys.argv[1]))
    after = parse(pathlib.Path(sys.argv[2]))
except (OSError, ValueError) as error:
    print(f"check_dto_fields.sh: {error}", file=sys.stderr)
    raise SystemExit(1)

failures = []
for name, old_count in before.items():
    new_count = after.get(name)
    if new_count is None:
        failures.append(f"{name} disappeared ({old_count} public fields removed with its type)")
    elif new_count < old_count:
        failures.append(f"{name} lost public fields ({old_count} -> {new_count})")

if failures:
    for failure in failures:
        print(f"check_dto_fields.sh: {failure}; ADR-0004 requires a planned major version", file=sys.stderr)
    raise SystemExit(1)

print(f"OK: 0 structs lost public fields (baseline: {len(before)} structs)")
PY
