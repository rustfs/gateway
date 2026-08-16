#!/usr/bin/env bash
set -euo pipefail

# WHAT: Pins the three transport-owned idle timeout layers and rejects body/handler ownership.
# WHY: rustfs/backlog#1699 assigns three of six progress layers to transport; connection lifetime is an extra safety valve.
# EXEMPTIONS: None. Moving ownership requires changing the task contract first.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
CONFIG="${ROOT_DIR}/crates/server/src/config.rs"
SOURCE_DIR="${ROOT_DIR}/crates/server/src"

if [[ ! -f "$CONFIG" ]]; then
    printf 'check_timeout_layer_ownership: required config is missing: %s\n' "$CONFIG" >&2
    exit 1
fi

if ! command -v grep >/dev/null 2>&1; then
    printf 'check_timeout_layer_ownership: required command is missing: grep\n' >&2
    exit 1
fi

required=(header_read_timeout write_progress_timeout keep_alive_idle)
for field in "${required[@]}"; do
    if ! grep -q -E "pub ${field}:" "$CONFIG"; then
        printf 'check_timeout_layer_ownership: missing transport timeout field %s\n' "$field" >&2
        exit 1
    fi
done

if ! grep -q -E 'pub connection_lifetime:' "$CONFIG"; then
    printf 'check_timeout_layer_ownership: missing extra connection-lifetime safety valve\n' >&2
    exit 1
fi

if grep -R -n -i -E --include='*.rs' \
    '(first_body_byte_(timeout|idle|interval)|body_read_(timeout|idle|interval)|handler(_progress)?_(timeout|deadline)|handler_deadline)' \
    "$SOURCE_DIR"; then
    printf 'check_timeout_layer_ownership: first-body, body-read, and handler timeouts belong outside the server runtime\n' >&2
    exit 1
fi

printf 'OK: 3/6 timeout layers owned by rustfs-gateway-server; connection lifetime is an extra safety valve\n'
