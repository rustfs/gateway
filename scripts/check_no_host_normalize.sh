#!/usr/bin/env bash
set -euo pipefail

# WHAT: Rejects request Host or URI-authority mutation in the ring-1 server source.
# WHY: rustfs/backlog#1739 leaves host normalization in the one signed-request authority.
# EXEMPTIONS: None. A second host authority must be designed outside this crate.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
SOURCE_DIR="${ROOT_DIR}/crates/server/src"

if [[ ! -d "$SOURCE_DIR" ]]; then
    printf 'check_no_host_normalize: required source directory is missing: %s\n' "$SOURCE_DIR" >&2
    exit 1
fi

if ! command -v grep >/dev/null 2>&1; then
    printf 'check_no_host_normalize: required command is missing: grep\n' >&2
    exit 1
fi

if grep -R -n -E --include='*.rs' \
    '(headers_mut\(\).*HOST|header::HOST.*insert|uri_mut\(\).*authority|set_authority|normalize_host)' "$SOURCE_DIR"; then
    printf 'check_no_host_normalize: ring 1 must not mutate Host or URI authority\n' >&2
    exit 1
fi

printf 'OK: no host normalization in ring1\n'
