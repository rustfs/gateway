#!/usr/bin/env bash
set -euo pipefail

# Runs a-asm-0024 under Rust's real ThreadSanitizer runtime. This is separate from stable guards
# because sanitizer instrumentation requires nightly and a rebuilt standard library.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TOOLCHAIN="${GATEWAY_TSAN_TOOLCHAIN:-nightly-2026-06-18}"
TARGET="${GATEWAY_TSAN_TARGET:-$(rustc "+${TOOLCHAIN}" -vV | awk '/^host:/ { print $2 }')}"

cd "$ROOT"

# A CI pod can see more CPUs than its CFS quota allows (sm-standard-4 pods have shown 32 visible
# CPUs against a 15-CPU quota). One hundred threads spread over every visible CPU then exhaust the
# quota early in each period and are throttled together, and ThreadSanitizer's spin-then-sleep
# runtime locks convoy behind a throttled holder: the job ran its whole budget with 92 threads
# runnable and five requests answered. Pin the test to no more CPUs than the quota grants, taken
# from the CPUs this process may already use.
pin=()
if command -v taskset >/dev/null 2>&1 && [[ -r /sys/fs/cgroup/cpu.max ]]; then
    read -r quota period </sys/fs/cgroup/cpu.max
    if [[ "$quota" != max && "$period" -gt 0 ]]; then
        limit=$((quota / period))
        limit="${GATEWAY_TSAN_CPUS:-$limit}"
        allowed=()
        IFS=, read -r -a ranges <<<"$(taskset -cp $$ | sed 's/.*: //')"
        for range in "${ranges[@]}"; do
            first="${range%-*}"
            last="${range#*-}"
            for ((cpu = first; cpu <= last; cpu++)); do
                allowed+=("$cpu")
            done
        done
        if [[ "$limit" -ge 1 && "$limit" -lt "${#allowed[@]}" ]]; then
            chosen="$(IFS=,; printf '%s' "${allowed[*]:0:$limit}")"
            printf 'run_gateway_tsan: pinning to %s of %s visible CPUs (CFS quota %s/%s)\n' \
                "$limit" "${#allowed[@]}" "$quota" "$period"
            pin=(taskset -c "$chosen")
        fi
    fi
fi

RUSTFLAGS='-Zsanitizer=thread' \
RUSTDOCFLAGS='-Zsanitizer=thread' \
    ${pin[@]+"${pin[@]}"} cargo "+${TOOLCHAIN}" test -Zbuild-std --target "$TARGET" \
        -p rustfs-gateway --test integration \
        service_concurrency::one_hundred_clones_answer_concurrently -- --exact --test-threads=1
