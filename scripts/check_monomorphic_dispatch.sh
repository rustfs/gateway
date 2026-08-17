#!/usr/bin/env bash
set -euo pipefail
# REQUIRES-BUILD

# WHAT: Compiles the consolidated gateway integration target to LLVM IR and follows the concrete
# monomorphic Ping codec/handler call chain through StaticOperation.
# WHY: rustfs/backlog#1738 a-asm-0007 and ADR-0006 require operation dispatch without stored
# Arc<dyn Fn> callbacks; source type names alone cannot prove the emitted call target.
# HOW TO EXEMPT: There is no exemption. Change the probe only with the static dispatch contract.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

command -v python3 >/dev/null 2>&1 || {
    printf 'check_monomorphic_dispatch: required command is missing: python3\n' >&2
    exit 1
}

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
static_dispatch = root / "crates/core/src/static_dispatch.rs"
monomorphic = root / "crates/gateway/src/monomorphic.rs"
tests = root / "crates/gateway/tests/monomorphic.rs"


def fail(message: str) -> None:
    print(f"check_monomorphic_dispatch: {message}", file=sys.stderr)
    raise SystemExit(1)


for path, label in (
    (static_dispatch, "static handler dispatch"),
    (monomorphic, "monomorphic handler dispatch"),
    (tests, "monomorphic handler deadline tests"),
):
    if not path.is_file() or path.is_symlink():
        fail(f"{label} is missing or not a regular file")

try:
    static_source = static_dispatch.read_text(encoding="utf-8")
    monomorphic_source = monomorphic.read_text(encoding="utf-8")
    test_source = tests.read_text(encoding="utf-8")
except (OSError, UnicodeError) as error:
    fail(f"cannot read monomorphic deadline source: {error}")

if static_source.count("pub async fn dispatch_with_handler<") != 1:
    fail("static dispatch does not expose one sealed handler-policy injection point")
if static_source.count("invoke_handler(backend, authorized.into_request(), request_guard)") != 1:
    fail("static dispatch bypasses the injected handler policy after authorization")
if monomorphic_source.count("StaticOperation::<O>::dispatch_with_handler(") != 1:
    fail("monomorphic dispatch does not use the sealed handler-policy injection point")
for required in (
    "let Some(deadline_class) = O::spec().deadline_class()",
    "let deadline = request_config.handler_deadline(deadline_class);",
    "let cleanup_grace = request_config.handler_cleanup_grace();",
    "let (deadline_cancellation, context) = HandlerCancellationSource::pair();",
    "handler_with_deadline(call, deadline_cancellation, deadline, cleanup_grace)",
):
    if monomorphic_source.count(required) != 1:
        fail("monomorphic dispatch does not consume one request snapshot's handler deadline configuration")
for required in (
    "handler deadline exceeded after cleanup completed",
    "handler deadline exceeded before cleanup completed",
):
    if monomorphic_source.count(required) != 1:
        fail("monomorphic dispatch does not suppress and classify late handler completion")
for test_name in (
    "monomorphic_handler_deadline_signals_cleanup_and_discards_the_late_result",
    "monomorphic_handler_deadline_bounds_an_uncooperative_handler",
):
    if test_source.count(f"async fn {test_name}()") != 1:
        fail("monomorphic handler deadline executable evidence is missing or duplicated")
PY

if [[ -n "${GATEWAY_MONOMORPHIC_IR:-}" ]]; then
    ir="$GATEWAY_MONOMORPHIC_IR"
else
    (
        cd "$ROOT"
        cargo rustc -q -p rustfs-gateway --test integration --release -- \
            --emit=llvm-ir -Cdebuginfo=1 -Copt-level=0
    )
    shopt -s nullglob
    candidates=("${CARGO_TARGET_DIR:-${ROOT}/target}"/release/deps/integration-*.ll)
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
handler="$(mktemp "${TMPDIR:-/tmp}/gateway-static-handler.XXXXXX")"
trap 'rm -f "$state" "$decoder" "$handler"' EXIT

awk '
    /^define internal.*@_RNCINvMNt.*static_dispatch.*StaticOperation.*integration7support4Ping.*(8dispatch|21dispatch_with_handler).*7Backend/ { take = 1 }
    take { print }
    take && /^}/ { exit }
' "$ir" >"$state"
awk '
    /^; rustfs_gateway_core::static_dispatch::decode::<integration::support::Ping>$/ { take = 1 }
    take { print }
    take && /^}/ { exit }
' "$ir" >"$decoder"
awk '
    /^define internal.*@_RNCINvNtNt.*rustfs_gateway_core8registry8handlers21dispatch_with_context.*integration7support4Ping.*7Backend/ && $0 !~ /14LayeredBackend/ { take = 1 }
    take { print }
    take && /^}/ { exit }
' "$ir" >"$handler"

if [[ ! -s "$state" || ! -s "$decoder" || ! -s "$handler" ]]; then
    printf 'check_monomorphic_dispatch: static Ping state machine, decoder, or handler was not emitted\n' >&2
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
    '<rustfs_gateway::service::S3Service>::run::' \
    'monomorphic state transition'
direct_after "$handler" \
    '<integration::support::Backend as rustfs_gateway_core::handler::Handler<integration::support::Ping>>::call_with_context' \
    'concrete Handler<Ping>'
direct_after "$decoder" \
    '<integration::support::Ping as rustfs_gateway_core::codec::OperationCodec>::decode' \
    'Ping OperationCodec::decode'

printf 'OK: monomorphic Ping codec and handler calls are direct in LLVM IR\n'
