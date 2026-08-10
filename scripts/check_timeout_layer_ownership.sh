#!/usr/bin/env bash
set -euo pipefail

# WHAT: Pins the four connection-level timeout fields and rejects body/handler timeout ownership.
# WHY: rustfs/backlog#1739 assigns four of six progress layers to transport and two to the core.
# EXEMPTIONS: None. Moving ownership requires changing the task contract first.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
CONFIG="${ROOT_DIR}/crates/server/src/config.rs"
SOURCE_DIR="${ROOT_DIR}/crates/server/src"

if [[ ! -f "$CONFIG" ]]; then
    printf 'check_timeout_layer_ownership: required config is missing: %s\n' "$CONFIG" >&2
    exit 1
fi

required=(header_read_timeout write_progress_timeout keep_alive_idle connection_lifetime)
for field in "${required[@]}"; do
    if ! rg -q "pub ${field}:" "$CONFIG"; then
        printf 'check_timeout_layer_ownership: missing transport timeout field %s\n' "$field" >&2
        exit 1
    fi
done

if rg -ni '(body_read_(timeout|interval)|handler(_progress)?_timeout)' "$SOURCE_DIR"; then
    printf 'check_timeout_layer_ownership: body-read and handler-progress timeouts belong to the core\n' >&2
    exit 1
fi

printf 'OK: 4/6 timeout layers owned by rustfs-gateway-server\n'
