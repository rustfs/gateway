#!/usr/bin/env bash
# Every optional extension default states its security consequence at the implementation site.
set -euo pipefail

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
EXT_DIR="${ROOT_DIR}/crates/gateway/src/ext"

fail() {
    printf 'check_default_doc: %s\n' "$1" >&2
    exit 1
}

[[ -d "$EXT_DIR" ]] || fail 'gateway extension tree is missing'

subjects=(
    'cors.rs:CorsCacheConfig'
    'credential_guard.rs:CredentialGuardConfig'
    'governor/default.rs:DefaultGovernor'
    'governor/rates.rs:GovernorRates'
    'policy.rs:PolicyTimeout'
)

derived_subjects=(
    'cors.rs:NoCors'
    'governor.rs:Unlimited'
    'host.rs:PathStyleOnly'
    'observer.rs:NoObserver'
)

checked=0
for subject in "${subjects[@]}"; do
    relative="${subject%%:*}"
    type="${subject#*:}"
    file="${EXT_DIR}/${relative}"
    [[ -f "$file" ]] || fail "${relative} is missing"
    line="$(grep -nE "^impl Default for ${type}[[:space:]]*\\{" "$file" | cut -d: -f1)"
    [[ -n "$line" ]] || fail "${relative}: Default for ${type} is missing"
    start=$((line > 8 ? line - 8 : 1))
    sed -n "${start},$((line - 1))p" "$file" | grep -qF '/// # Security' \
        || fail "${relative}:${line}: Default for ${type} has no # Security section"
    checked=$((checked + 1))
done

actual="$(grep -RhsE '^impl Default for [A-Za-z_][A-Za-z0-9_]*[[:space:]]*\{' "$EXT_DIR" --include='*.rs' | wc -l | tr -d '[:space:]')"
[[ "$actual" == "$checked" ]] || fail "found ${actual} Default implementations but documented ${checked}"

for subject in "${derived_subjects[@]}"; do
    relative="${subject%%:*}"
    type="${subject#*:}"
    file="${EXT_DIR}/${relative}"
    [[ -f "$file" ]] || fail "${relative} is missing"
    line="$(grep -nE "^pub struct ${type}([[:space:];<{]|$)" "$file" | cut -d: -f1)"
    [[ -n "$line" ]] || fail "${relative}: ${type} is missing"
    start=$((line > 12 ? line - 12 : 1))
    context="$(sed -n "${start},${line}p" "$file")"
    grep -qE '#\[derive\([^]]*Default' <<<"$context" \
        || fail "${relative}:${line}: ${type} no longer derives Default"
    grep -qF '/// # Security' <<<"$context" \
        || fail "${relative}:${line}: Default for ${type} has no # Security section"
    checked=$((checked + 1))
done

total=$((actual + ${#derived_subjects[@]}))
printf 'OK: %s/%s extension defaults document security consequences\n' "$checked" "$total"
