#!/usr/bin/env bash
set -euo pipefail

# These guards do not need quiet grep. Ban quiet-option tokens outright so a
# future edit cannot reintroduce an early-exit consumer under `pipefail`.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if ! command -v grep >/dev/null 2>&1; then
    printf 'check_guard_grep_pipelines: required command is missing: grep\n' >&2
    exit 1
fi
if ! command -v awk >/dev/null 2>&1; then
    printf 'check_guard_grep_pipelines: required command is missing: awk\n' >&2
    exit 1
fi

targets=(
    "scripts/check_license_headers.sh"
    "scripts/check_secret_hygiene.sh"
)

quiet_flag_re="(^|[[:space:];|&(){}'\"\`])grep[[:space:]]+([^[:space:];|&(){}'\"\`]+[[:space:]]+)*(--quiet|-[A-Za-z]*q[A-Za-z]*)([[:space:];|&(){}'\"\`]|$)"
matches_file="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-grep.XXXXXX")"
normalized_file="${matches_file}.normalized"
trap 'rm -f "$matches_file" "$normalized_file"' EXIT

status=0
for file in "${targets[@]}"; do
    path="${ROOT_DIR}/${file}"
    if [[ ! -f "$path" ]]; then
        printf 'check_guard_grep_pipelines: required input is missing: %s\n' "$file" >&2
        status=1
        continue
    fi

    awk '
        {
            if (pending != "") {
                line = pending $0
                pending = ""
            } else {
                line = $0
            }
            if (sub(/\\[[:space:]]*$/, "", line)) {
                pending = line " "
                next
            }
            print line
        }
        END { if (pending != "") print pending }
    ' "$path" >"$normalized_file"

    grep_rc=0
    grep -nE "$quiet_flag_re" "$normalized_file" >"$matches_file" || grep_rc=$?
    if [[ "$grep_rc" -eq 0 ]]; then
        printf '%s: quiet grep option tokens are forbidden under pipefail:\n' "$file" >&2
        sed 's/^/  /' "$matches_file" >&2
        status=1
    elif [[ "$grep_rc" -ne 1 ]]; then
        printf 'check_guard_grep_pipelines: grep failed while scanning %s\n' "$file" >&2
        status=1
    fi
done

if [[ "$status" -ne 0 ]]; then
    printf 'Use a full-reading grep with stdout redirected, or match an already captured value.\n' >&2
fi

exit "$status"
