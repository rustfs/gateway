#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   Hand-written Rust files stay at or below 800 lines unless a reviewed allowance names a higher
#   ceiling, an issue URL and a reason.
# WHY
#   rustfs/backlog#1742 treats large files as a direct context-budget failure.
# HOW TO EXEMPT
#   Add `<path> <limit> <issue-url> <reason>` to allowances/file_size.txt; remove it by splitting.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ALLOWANCES="$ROOT/allowances/file_size.txt"
failures=0
used=0
max=0
allowance_paths=()
allowance_limits=()

if [[ ! -f "$ALLOWANCES" ]]; then
    printf 'check_file_size: allowances/file_size.txt is missing\n' >&2
    exit 1
fi

seen_paths=""
while read -r path limit issue reason; do
    [[ -z "${path:-}" || "$path" == \#* ]] && continue
    if [[ ! "$limit" =~ ^[0-9]+$ ]] || (( limit <= 800 )) ||
        [[ ! "$issue" =~ ^https://github\.com/rustfs/backlog/issues/[0-9]+$ ]] || [[ -z "${reason:-}" ]]; then
        printf 'check_file_size: malformed allowance for %s; need path limit issue-url reason\n' "$path" >&2
        failures=$((failures + 1))
        continue
    fi
    if grep -Fqx "$path" <<<"$seen_paths"; then
        printf 'check_file_size: duplicate allowance for %s\n' "$path" >&2
        failures=$((failures + 1))
        continue
    fi
    seen_paths+="${path}"$'\n'
    allowance_paths+=("$path")
    allowance_limits+=("$limit")
done <"$ALLOWANCES"

files=()
while IFS= read -r -d '' file; do
    files+=("$file")
done < <(find "$ROOT/crates" "$ROOT/xtask" \
    -path "$ROOT/crates/types/generated" -prune -o \
    -type f -name '*.rs' -print0)

while read -r lines file; do
    [[ "$file" == "total" ]] && continue
    relative="${file#"$ROOT"/}"
    (( lines > max )) && max=$lines
    limit=800
    allowance=""
    for index in "${!allowance_paths[@]}"; do
        if [[ "${allowance_paths[$index]}" == "$relative" ]]; then
            allowance="$relative"
            limit="${allowance_limits[$index]}"
            break
        fi
    done
    if [[ -n "$allowance" ]] && (( lines <= 800 )); then
        printf 'check_file_size: stale allowance for %s; file has only %s lines\n' "$relative" "$lines" >&2
        failures=$((failures + 1))
    elif (( lines > limit )); then
        printf 'check_file_size: %s has %s lines; limit is %s\n' "$relative" "$lines" "$limit" >&2
        failures=$((failures + 1))
    elif [[ -n "$allowance" ]]; then
        used=$((used + 1))
    fi
done < <(wc -l "${files[@]}")

while read -r path _; do
    [[ -z "${path:-}" || "$path" == \#* ]] && continue
    if [[ ! -f "$ROOT/$path" ]]; then
        printf 'check_file_size: allowance path does not exist: %s\n' "$path" >&2
        failures=$((failures + 1))
    fi
done <"$ALLOWANCES"

if (( failures > 0 )); then
    exit 1
fi
printf 'OK: max %s lines, %s allowance(s) used\n' "$max" "$used"
