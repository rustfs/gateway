#!/usr/bin/env bash
# a-asm-0003: the buildable minimal assembly stays within twenty effective lines.
set -euo pipefail

# =============================================================================
# check_minimal_assembly_lines.sh
#
# WHAT THIS CHECKS
#   The complete ServiceBuilder assembly shown by the minimal example is at most
#   twenty effective Rust lines. Comments and blank lines do not count.
#
# WHY
#   P7-01 promises that a consumer can assemble the facade without boilerplate.
#   Counting the marked assembly keeps the measurement on the public API while
#   leaving the example's real operation, handler, and assertions visible.
# =============================================================================

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
EXAMPLE="${ROOT_DIR}/crates/gateway/examples/minimal.rs"

[[ -f "$EXAMPLE" ]] || {
    printf 'check_minimal_assembly_lines: %s is missing\n' "$EXAMPLE" >&2
    exit 1
}

count="$({
    awk '
        /\/\/ BEGIN MINIMAL ASSEMBLY/ { begins++; inside = 1; next }
        /\/\/ END MINIMAL ASSEMBLY/ { ends++; inside = 0; next }
        inside {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            if (line != "" && line !~ /^\/\//) count++
        }
        END {
            if (begins != 1 || ends != 1 || inside != 0) exit 2
            print count + 0
        }
    ' "$EXAMPLE"
} || true)"

[[ "$count" =~ ^[0-9]+$ ]] || {
    printf 'check_minimal_assembly_lines: expected exactly one complete marker pair in %s\n' "$EXAMPLE" >&2
    exit 1
}
[[ "$count" -le 20 ]] || {
    printf 'check_minimal_assembly_lines: assembly uses %s effective lines, limit is 20\n' "$count" >&2
    exit 1
}

printf 'OK: minimal ServiceBuilder assembly uses %s/20 effective lines\n' "$count"
