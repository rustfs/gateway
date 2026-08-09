#!/usr/bin/env bash
# One ArcSwap load at request entry keeps hot configuration coherent for the whole request.
set -euo pipefail

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SOURCE_ROOT="${ROOT_DIR}/crates/gateway/src"
ALLOWLIST="${ROOT_DIR}/scripts/config_load_allowlist.txt"

fail() {
    printf 'check_config_load_once: %s\n' "$1" >&2
    exit 1
}

[[ -d "$SOURCE_ROOT" ]] || fail 'gateway source tree is missing'
[[ -f "${SOURCE_ROOT}/config.rs" ]] || fail 'the hot-configuration store is missing'
[[ -f "$ALLOWLIST" ]] || fail 'scripts/config_load_allowlist.txt is missing'

actual="$({
    cd "$ROOT_DIR"
    grep -RInE '(\.(load|load_full)|ArcSwap(Any)?::load(_full)?)\(' crates/gateway/src --include='*.rs' \
        | cut -d: -f1,2 \
        | LC_ALL=C sort
} || true)"
expected="$(grep -Ev '^[[:space:]]*(#|$)' "$ALLOWLIST" | LC_ALL=C sort)"

[[ -n "$actual" ]] || fail 'no hot-configuration load exists'
[[ "$actual" == "$expected" ]] || {
    printf 'check_config_load_once: expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    exit 1
}
[[ "$(grep -c '^crates/gateway/src/service.rs:298$' <<<"$expected")" == 1 ]] \
    || fail 'the one request-entry configuration load is not allowlisted exactly once'

printf 'OK: all load/load_full sites are frozen; one is the request-entry configuration load\n'
