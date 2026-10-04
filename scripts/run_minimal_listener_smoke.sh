#!/usr/bin/env bash
set -euo pipefail

# Runs the copy-pasteable example as a real process, measures its bound socket from stdout,
# exercises one allowed and one rejected wire request, then proves SIGINT reaches graceful exit.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"
SMOKE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gateway-minimal-smoke.XXXXXX")"
LOG="${SMOKE_DIR}/minimal.log"
PROCESS_ID=""

cleanup() {
    if [[ -n "$PROCESS_ID" ]] && kill -0 "$PROCESS_ID" 2>/dev/null; then
        kill -TERM "$PROCESS_ID" 2>/dev/null || true
        wait "$PROCESS_ID" 2>/dev/null || true
    fi
    rm -rf -- "$SMOKE_DIR"
}
trap cleanup EXIT

cd "$ROOT"
python3 "${ROOT}/scripts/test_minimal_cli_refusals.py"
cargo build -p rustfs-gateway --example minimal
python3 - "${TARGET_DIR}/debug/examples/minimal" <<'PYTEST'
import subprocess
import sys

executable = sys.argv[1]
refusals = {
    "cli_refuses_missing_port_value": ["--port"],
    "cli_refuses_unknown_argument": ["--listen-everywhere"],
    "cli_refuses_missing_address_port": ["127.0.0.1"],
    "cli_refuses_out_of_range_port": ["127.0.0.1:65536"],
    "cli_refuses_extra_address": ["127.0.0.1:0", "127.0.0.1:0"],
    "cli_refuses_old_host_and_port_flags": ["--host", "127.0.0.1", "--port", "0"],
}
for name, arguments in refusals.items():
    try:
        result = subprocess.run([executable, *arguments], capture_output=True, text=True, timeout=5)
    except subprocess.TimeoutExpired:
        raise SystemExit(f"{name}: invalid arguments started a long-running listener")
    expected_error = (
        'Error: "expected at most one listen address"'
        if name == "cli_refuses_extra_address"
        else "Error: AddrParseError(Socket)"
    )
    if result.returncode != 1 or result.stdout or result.stderr.strip() != expected_error:
        raise SystemExit(f"{name}: expected argument rejection was not observed: {result}")
    print(f"OK: {name}")
PYTEST
: >"$LOG"
"${TARGET_DIR}/debug/examples/minimal" 127.0.0.1:0 >"$LOG" 2>&1 &
PROCESS_ID="$!"

ADDRESS=""
for _attempt in {1..100}; do
    ADDRESS="$(sed -n 's/^listening on http:\/\///p' "$LOG" | tail -n 1)"
    [[ -n "$ADDRESS" ]] && break
    if ! kill -0 "$PROCESS_ID" 2>/dev/null; then
        printf 'run_minimal_listener_smoke: example exited before announcing its listener\n' >&2
        sed 's/^/  /' "$LOG" >&2
        exit 1
    fi
    sleep 0.05
done

if [[ -z "$ADDRESS" ]]; then
    printf 'run_minimal_listener_smoke: example did not announce a listener within five seconds\n' >&2
    sed 's/^/  /' "$LOG" >&2
    exit 1
fi

python3 - "$ADDRESS" <<'PY'
import socket
import sys

host, port_text = sys.argv[1].rsplit(":", 1)
address = (host, int(port_text))

def exchange(request):
    with socket.create_connection(address, timeout=2) as connection:
        connection.sendall(request)
        response = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                return bytes(response)
            response.extend(chunk)

answered = exchange(
    b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)
if not answered.startswith(b"HTTP/1.1 200") or b"<Ping>2 buckets</Ping>" not in answered:
    raise SystemExit(f"allowed wire request was not answered: {answered!r}")

refused = exchange(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
if not refused.startswith(b"HTTP/1.1 403") or b"<Code>AccessDenied</Code>" not in refused:
    raise SystemExit(f"anonymous S3 request was not refused: {refused!r}")
PY

kill -INT "$PROCESS_ID"
set +e
wait "$PROCESS_ID"
STATUS="$?"
set -e
PROCESS_ID=""

if [[ "$STATUS" -ne 0 ]]; then
    printf 'run_minimal_listener_smoke: example exited with status %s after SIGINT\n' "$STATUS" >&2
    sed 's/^/  /' "$LOG" >&2
    exit 1
fi
grep -q '^shutdown: drained=0, aborted=0$' "$LOG" || {
    printf 'run_minimal_listener_smoke: graceful shutdown report is missing\n' >&2
    sed 's/^/  /' "$LOG" >&2
    exit 1
}

printf 'OK: minimal process listened at %s, served allow/refuse controls, and exited cleanly on SIGINT\n' "$ADDRESS"
