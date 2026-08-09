#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$ROOT_DIR"

examples=()
while IFS= read -r file; do
    [[ -n "$file" ]] && examples+=("$file")
done < <(git ls-files --cached --others --exclude-standard -- '*/examples/*.rs' 'examples/*.rs')
if [[ "${#examples[@]}" -eq 0 ]]; then
    printf 'check_no_allow_all_in_examples: no Rust examples found\n' >&2
    exit 1
fi

pattern='allow_when[[:space:]]*\([[:space:]]*\|_.*\|[[:space:]]*true|decide_with[[:space:]]*\([[:space:]]*\|_.*\|[[:space:]]*Decision::Allow|DenyAllAuthorizer.*Decision::Allow'
for file in "${examples[@]}"; do
    if grep -nE "$pattern" "$file"; then
        printf 'check_no_allow_all_in_examples: unconditional allow in %s\n' "$file" >&2
        exit 1
    fi
done

printf 'OK: %s example source(s) contain no unconditional authorizer\n' "${#examples[@]}"
