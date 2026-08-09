#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
FILE='crates/gateway/src/ext/authorizer.rs'
cd "$ROOT_DIR"

if [[ ! -f "$FILE" ]]; then
    printf 'check_authz_no_default_impl: %s is missing\n' "$FILE" >&2
    exit 1
fi

methods="$({
    awk '
        /^pub trait Authorizer:/ { inside = 1 }
        inside && /fn authorize_(route|input)/ {
            method = $0
            if (method ~ /[;{]/) { print method; method = ""; collecting = 0 } else { collecting = 1 }
            next
        }
        collecting { method = method " " $0 }
        collecting && /[;{]/ { print method; method = ""; collecting = 0 }
        inside && /^}/ { exit }
    ' "$FILE"
} || true)"

for name in authorize_route authorize_input; do
    line="$(printf '%s\n' "$methods" | grep -E "fn ${name}\b" || true)"
    if [[ -z "$line" ]]; then
        printf 'check_authz_no_default_impl: Authorizer is missing %s\n' "$name" >&2
        exit 1
    fi
    if [[ "$line" == *'{'* || "$line" != *';'* ]]; then
        printf 'check_authz_no_default_impl: %s has a default body\n' "$name" >&2
        exit 1
    fi
done

if [[ "$(printf '%s\n' "$methods" | grep -cE 'fn authorize_(route|input)\b' || true)" -ne 2 ]]; then
    printf 'check_authz_no_default_impl: expected exactly two authorization methods\n' >&2
    exit 1
fi

printf 'OK: Authorizer requires authorize_route and authorize_input with no default bodies\n'
