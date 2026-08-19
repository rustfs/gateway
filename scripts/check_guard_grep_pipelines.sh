#!/usr/bin/env bash
set -euo pipefail

# WHAT: No deterministic guard may let a quiet grep consume a pipe, and the two guards
#       that never need quiet grep at all may not name the option anywhere.
# WHY:  Quiet grep stops reading at its first match and closes the pipe. Under
#       `set -o pipefail` the producer's SIGPIPE becomes the pipeline's status, so the
#       test reads as "no match" and the guard fails on a clean tree. Measured on this
#       repository before the fix: eleven of sixty-four runs of
#       check_sig_case_coverage.sh reported missing P2-04 hard-constraint evidence that
#       was present, and one of them turned a pull request red.
# HOW TO EXEMPT: no exemption. Use a full-reading grep with stdout redirected, or match
#       an already captured value.

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

# A command may be spelled over several lines with a trailing backslash. Rejoin those
# before any pattern is applied, so a split spelling is not a way through the policy.
join_backslash_continuations() {
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
    ' "$1" >"$2"
}

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

    join_backslash_continuations "$path" "$normalized_file"

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

# The pipe hazard is not confined to the two files above, and it is the half that has
# actually cost CI cycles. Every deterministic guard is scanned for a quiet grep sitting
# on the receiving end of a pipe, whatever else it does with grep: the guards are
# discovered by glob rather than listed, so a guard added tomorrow is covered the day it
# lands.
pipeline_re="(^|[^|])\\|[[:space:]]*grep[[:space:]]+([^[:space:];|&(){}'\"\`]+[[:space:]]+)*(--quiet|-[A-Za-z]*q[A-Za-z]*)([[:space:];|&(){}'\"\`]|\$)"
piped_file="${matches_file}.piped"
trap 'rm -f "$matches_file" "$normalized_file" "$piped_file"' EXIT

shopt -s nullglob
guards=("${ROOT_DIR}"/scripts/check_*.sh)
shopt -u nullglob
if [[ "${#guards[@]}" -eq 0 ]]; then
    printf 'check_guard_grep_pipelines: required input is missing: scripts/check_*.sh\n' >&2
    exit 1
fi

for path in "${guards[@]}"; do
    file="scripts/${path##*/}"

    join_backslash_continuations "$path" "$normalized_file"

    # A pipeline may also continue over a bare trailing `|`, with the consumer on the
    # next line. `||` ends a logical branch rather than a pipe and is left alone.
    awk '
        {
            if (pending != "") {
                line = pending $0
                pending = ""
            } else {
                line = $0
            }
            if (line ~ /[^|]\|[[:space:]]*$/) {
                pending = line " "
                next
            }
            print line
        }
        END { if (pending != "") print pending }
    ' "$normalized_file" >"$piped_file"

    grep_rc=0
    grep -nE "$pipeline_re" "$piped_file" >"$matches_file" || grep_rc=$?
    if [[ "$grep_rc" -eq 0 ]]; then
        printf '%s: a quiet grep must not consume a pipe under pipefail:\n' "$file" >&2
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
