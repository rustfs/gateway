#!/usr/bin/env bash
set -euo pipefail

# Runs a-asm-0024 under Rust's real ThreadSanitizer runtime. This is separate from stable guards
# because sanitizer instrumentation requires nightly and a rebuilt standard library.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TOOLCHAIN="${GATEWAY_TSAN_TOOLCHAIN:-nightly-2026-06-18}"
TARGET="${GATEWAY_TSAN_TARGET:-$(rustc "+${TOOLCHAIN}" -vV | awk '/^host:/ { print $2 }')}"

cd "$ROOT"

# The test binary runs on at most four CPUs; the build around it is not restricted. The case
# still starts, and joins, one hundred OS threads that are all alive and interleaving at once.
# What changes is how many of them the host runs truly in parallel, and ThreadSanitizer's runtime
# does not survive that number growing: on the org sm-standard-4 pods, which expose 16 or 32 CPUs
# under a 15-CPU CFS quota and were never throttled (cpu.stat nr_throttled 0), the same instrumented
# binary took 60s unpinned or never finished in 240s, while pinned to 4 or 8 CPUs it finished in
# 0.21s and 0.18s (rustfs/gateway#909). Four is the vCPU count the job's runner class is named for.
TSAN_CPUS="${GATEWAY_TSAN_CPUS:-4}"
if command -v taskset >/dev/null 2>&1; then
    allowed=()
    IFS=, read -r -a ranges <<<"$(taskset -cp $$ | sed 's/.*: //')"
    for range in "${ranges[@]}"; do
        for ((cpu = ${range%-*}; cpu <= ${range#*-}; cpu++)); do
            allowed+=("$cpu")
        done
    done
    if ((${#allowed[@]} > TSAN_CPUS)); then
        chosen="$(IFS=,; printf '%s' "${allowed[*]:0:TSAN_CPUS}")"
        printf 'run_gateway_tsan: running the test binary on CPUs %s of the %s this job may use\n' \
            "$chosen" "${#allowed[@]}"
        export "CARGO_TARGET_$(printf '%s' "$TARGET" | tr 'a-z-' 'A-Z_')_RUNNER=taskset -c ${chosen}"
    fi
fi

# `--cfg gateway_tsan` compiles the dhat global allocator out of the test binary; see
# crates/gateway/tests/service_clone_allocations.rs and rustfs/gateway#958.
RUSTFLAGS='-Zsanitizer=thread --cfg gateway_tsan' \
RUSTDOCFLAGS='-Zsanitizer=thread --cfg gateway_tsan' \
    cargo "+${TOOLCHAIN}" test -Zbuild-std --target "$TARGET" \
        -p rustfs-gateway --test integration \
        service_concurrency::one_hundred_clones_answer_concurrently -- --exact --test-threads=1
