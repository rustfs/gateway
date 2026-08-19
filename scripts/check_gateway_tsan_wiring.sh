#!/usr/bin/env bash
set -euo pipefail

# WHAT: Freezes a-asm-0024's 100-OS-thread assertion, sanitizer flags and required CI invocation.
# WHY: rustfs/backlog#1738 requires a real TSAN observation; a green job with deleted
# instrumentation or a reduced thread count would be an unfalsifiable substitute.
# HOW TO EXEMPT: There is no exemption; update the acceptance case through its design issue.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
RUNNER="${ROOT}/scripts/run_gateway_tsan.sh"
CASE="${ROOT}/crates/gateway/tests/service_concurrency.rs"
CI="${ROOT}/.github/workflows/ci.yml"

fail() {
    printf 'check_gateway_tsan_wiring: %s\n' "$1" >&2
    exit 1
}

[[ -x "$RUNNER" ]] || fail 'the TSAN runner is missing or not executable'
[[ -f "$CASE" ]] || fail 'the 100-thread acceptance test is missing'
[[ -f "$CI" ]] || fail 'the CI workflow is missing'

grep -Fq "RUSTFLAGS='-Zsanitizer=thread'" "$RUNNER" || fail 'ThreadSanitizer instrumentation is missing'
grep -Fq 'cargo "+${TOOLCHAIN}" test -Zbuild-std' "$RUNNER" || fail 'the instrumented standard-library build is missing'
grep -Fq -- '-p rustfs-gateway --test integration' "$RUNNER" \
    || fail 'the runner no longer executes the consolidated gateway integration target'
grep -Fq 'service_concurrency::one_hundred_clones_answer_concurrently -- --exact --test-threads=1' "$RUNNER" \
    || fail 'the runner no longer executes the concurrency acceptance target'

grep -Fq 'const THREADS: usize = 100;' "$CASE" || fail 'the case no longer starts exactly 100 OS threads'
grep -Fq 'std::thread::spawn' "$CASE" || fail 'the case no longer uses operating-system threads'
grep -Fq 'assert_eq!(completed.load(Ordering::SeqCst), 100' "$CASE" \
    || fail 'the case no longer asserts that all 100 threads completed'

grep -Fq 'scripts/run_gateway_tsan.sh' "$CI" || fail 'CI no longer calls the TSAN runner'
grep -Fq 'needs: [workspace-tests, signing-suite, guard-self-test, guard-self-test-2, guard-self-test-3, guard-self-test-4, target-consolidation-self-test, quirk-ledger-self-test, dto-compiler-self-test, build-guard-self-test, error-status-self-test, gateway-tsan]' "$CI" \
    || fail 'the required Test check no longer depends on the TSAN job'
grep -Fq 'test "$TSAN_RESULT" = success' "$CI" || fail 'the required Test check ignores the TSAN result'

printf 'OK: CI runs the real TSAN command over exactly 100 completed OS threads\n'
