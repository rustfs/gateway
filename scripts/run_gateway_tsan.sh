#!/usr/bin/env bash
set -euo pipefail

# Runs a-asm-0024 under Rust's real ThreadSanitizer runtime. This is separate from stable guards
# because sanitizer instrumentation requires nightly and a rebuilt standard library.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TOOLCHAIN="${GATEWAY_TSAN_TOOLCHAIN:-nightly-2026-06-18}"
TARGET="${GATEWAY_TSAN_TARGET:-$(rustc "+${TOOLCHAIN}" -vV | awk '/^host:/ { print $2 }')}"

cd "$ROOT"
RUSTFLAGS='-Zsanitizer=thread' \
RUSTDOCFLAGS='-Zsanitizer=thread' \
    cargo "+${TOOLCHAIN}" test -Zbuild-std --target "$TARGET" \
        -p rustfs-gateway --test service_concurrency -- --test-threads=1
