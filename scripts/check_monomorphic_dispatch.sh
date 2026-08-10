#!/usr/bin/env bash
set -euo pipefail
# REQUIRES-BUILD

# WHAT: Compiles the public monomorphic parity target to LLVM IR and follows the concrete Ping
# codec/handler call chain through StaticOperation.
# WHY: rustfs/backlog#1738 a-asm-0007 and ADR-0006 require operation dispatch without stored
# Arc<dyn Fn> callbacks; source type names alone cannot prove the emitted call target.
# HOW TO EXEMPT: There is no exemption. Change the probe only with the static dispatch contract.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

if [[ -n "${GATEWAY_MONOMORPHIC_IR:-}" ]]; then
    ir="$GATEWAY_MONOMORPHIC_IR"
else
    (
        cd "$ROOT"
        cargo rustc -q -p rustfs-gateway --test monomorphic --release -- \
            --emit=llvm-ir -Cdebuginfo=1 -Copt-level=0
    )
    shopt -s nullglob
    candidates=("${CARGO_TARGET_DIR:-${ROOT}/target}"/release/deps/monomorphic-*.ll)
    if (( ${#candidates[@]} == 0 )); then
        printf 'check_monomorphic_dispatch: cargo produced no LLVM IR\n' >&2
        exit 1
    fi
    ir="${candidates[0]}"
    for candidate in "${candidates[@]:1}"; do
        if [[ "$candidate" -nt "$ir" ]]; then
            ir="$candidate"
        fi
    done
fi

if [[ ! -f "$ir" ]]; then
    printf 'check_monomorphic_dispatch: LLVM IR input is missing: %s\n' "$ir" >&2
    exit 1
fi

state="$(mktemp "${TMPDIR:-/tmp}/gateway-static-state.XXXXXX")"
decoder="$(mktemp "${TMPDIR:-/tmp}/gateway-static-decoder.XXXXXX")"
trap 'rm -f "$state" "$decoder"' EXIT

awk '
    /^define internal.*@_RNCINvMNt.*static_dispatch.*StaticOperation.*support4Ping.*8dispatch.*7Backend/ { take = 1 }
    take { print }
    take && /^}/ { exit }
' "$ir" >"$state"
awk '
    /^; rustfs_gateway_core::static_dispatch::decode::<monomorphic::support::Ping>$/ { take = 1 }
    take { print }
    take && /^}/ { exit }
' "$ir" >"$decoder"

if [[ ! -s "$state" || ! -s "$decoder" ]]; then
    printf 'check_monomorphic_dispatch: static Ping state machine or decoder was not emitted\n' >&2
    exit 1
fi

if grep -Eq 'OperationDispatch|ErasedRequest|LayeredBackend|dyn core::ops::function::Fn' "$state" "$decoder"; then
    printf 'check_monomorphic_dispatch: static codec/handler path reaches erased dispatch\n' >&2
    exit 1
fi

direct_after() {
    local file="$1"
    local comment="$2"
    local label="$3"
    if ! awk -v comment="$comment" '
        index($0, comment) { found = 1; if (getline <= 0) exit 2; if ($0 !~ /(call|invoke).*@_R/) exit 3; direct = 1 }
        END { if (!found || !direct) exit 4 }
    ' "$file"; then
        printf 'check_monomorphic_dispatch: %s is not a direct LLVM call\n' "$label" >&2
        exit 1
    fi
}

direct_after "$state" \
    '<monomorphic::support::Backend as rustfs_gateway_core::handler::Handler<monomorphic::support::Ping>>::call' \
    'concrete Handler<Ping>'
direct_after "$decoder" \
    '<monomorphic::support::Ping as rustfs_gateway_core::codec::OperationCodec>::decode' \
    'Ping OperationCodec::decode'

printf 'OK: monomorphic Ping codec and handler calls are direct in LLVM IR\n'
