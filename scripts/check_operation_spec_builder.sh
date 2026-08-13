#!/usr/bin/env bash
set -euo pipefail

# REQUIRES-BUILD
# ADR-0004 P9: OperationSpec is non-exhaustive; every workspace construction site uses its builder.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if ! command -v cargo >/dev/null 2>&1; then
    printf 'check_operation_spec_builder.sh: required command is missing: cargo\n' >&2
    exit 1
fi

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT_DIR}/target}" cargo run --quiet \
    --manifest-path "${SCRIPT_DIR}/../xtask/Cargo.toml" -- \
    check-operation-spec-builder "$ROOT_DIR"
