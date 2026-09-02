#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_sut_launcher.sh
#
# WHAT THIS CHECKS
#   That ci/lib/sut.sh — the one place any external suite gets a system under
#   test — behaves in both directions. Six probes:
#
#     1. a process that does bind its port    -> ready, endpoint reported
#     2. a process that exits without binding -> exit 3, and does NOT wait out
#        the whole readiness deadline
#     3. no endpoint and no command           -> exit 3, naming what is missing
#     4. an already-running endpoint          -> adopted as-is
#     5. an endpoint nothing is listening on  -> exit 3
#     6. a template with an unset placeholder -> refused, nothing written
#     7. a placeholder inside a comment line  -> left alone, not demanded
#
# WHY BOTH DIRECTIONS
#   A launcher is a one-directional control by default: the only thing anyone
#   ever tests is the happy path, and a readiness probe that returns success
#   unconditionally passes that test. It also turns every future suite run into
#   a full red against a server that was never up — and a suite-wide red is the
#   input the xfail ratchet would then be asked to absorb. AGENTS.md:
#   "A one-directional control proves nothing."
#
#   Probe 6 is the quiet one. A configuration rendered with a blank credential
#   does not fail to render; it produces a suite-wide authentication failure
#   that reads exactly like a signing defect in this repository.
#
# WHY IT IS SHARED
#   rustfs/backlog#1764 (Ceph s3-tests) and rustfs/backlog#1765 (the client
#   matrix) both need exactly this, and two copies of it would drift on the
#   first bug fix.
#
# HOW TO EXEMPT
#   None.
#
# USAGE
#   scripts/check_sut_launcher.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_sut_launcher.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
LIBRARY="${ROOT_DIR}/ci/lib/sut.sh"

if [[ ! -f "$LIBRARY" ]]; then
    printf 'check_sut_launcher: required input is missing: ci/lib/sut.sh\n' >&2
    exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/gateway-sut-check.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

status=0
fail() {
    printf 'check_sut_launcher: %s\n' "$1" >&2
    status=1
}

# A free port, claimed and released. There is an unavoidable race between releasing it
# and the probe binding it; the probes below tolerate it by failing loudly rather than
# by passing quietly, which is the only direction that matters here.
free_port() {
    python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

# --- probe 1: a process that really binds -------------------------------------------------
PORT="$(free_port)"
if out="$(
    cd "$ROOT_DIR"
    export GATEWAY_SUT_COMMAND="python3 -c \"
import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', ${PORT}))
s.listen(8)
time.sleep(30)
\""
    export GATEWAY_SUT_HOST=127.0.0.1 GATEWAY_SUT_PORT="$PORT" GATEWAY_SUT_READY_SECONDS=15
    export GATEWAY_SUT_LOG="${WORK}/bind.log"
    bash -c 'set -euo pipefail; source ci/lib/sut.sh; sut_start; printf "ENDPOINT=%s\n" "$SUT_ENDPOINT"; sut_stop' 2>&1
)"; then
    if [[ "$out" != *"ENDPOINT=http://127.0.0.1:${PORT}"* ]]; then
        fail "a listening process was started but no endpoint was reported: ${out}"
    fi
else
    fail "a process that binds its port was not detected as ready: ${out}"
fi

# --- probe 2: a process that never binds --------------------------------------------------
PORT="$(free_port)"
started="$(date +%s)"
set +e
out="$(
    cd "$ROOT_DIR"
    export GATEWAY_SUT_COMMAND="exit 7"
    export GATEWAY_SUT_HOST=127.0.0.1 GATEWAY_SUT_PORT="$PORT" GATEWAY_SUT_READY_SECONDS=20
    export GATEWAY_SUT_LOG="${WORK}/dead.log"
    bash -c 'source ci/lib/sut.sh; sut_start; printf "REACHED\n"' 2>&1
)"
code="$?"
set -e
elapsed="$(($(date +%s) - started))"
if [[ "$code" -ne 3 ]]; then
    fail "a system under test that never bound its port exited ${code}, not 3 (environment): ${out}"
fi
if [[ "$out" == *REACHED* ]]; then
    fail "sut_start returned success after the process it launched had already exited"
fi
if [[ "$elapsed" -ge 20 ]]; then
    fail "a dead process was waited out for the whole ${elapsed}s deadline instead of being noticed when it exited"
fi

# --- probe 3: nothing to launch and nothing to adopt --------------------------------------
set +e
out="$(
    cd "$ROOT_DIR"
    env -u GATEWAY_SUT_ENDPOINT -u GATEWAY_SUT_COMMAND \
        bash -c 'source ci/lib/sut.sh; sut_start; printf "REACHED\n"' 2>&1
)"
code="$?"
set -e
if [[ "$code" -ne 3 ]]; then
    fail "with neither an endpoint nor a command, sut_start exited ${code}, not 3: ${out}"
fi
if [[ "$out" != *GATEWAY_SUT_ENDPOINT* || "$out" != *GATEWAY_SUT_COMMAND* ]]; then
    fail "the no-system-under-test diagnosis does not name both ways to supply one: ${out}"
fi

# --- probes 4 and 5: an endpoint supplied from outside -------------------------------------
PORT="$(free_port)"
python3 -c "
import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', ${PORT}))
s.listen(8)
time.sleep(30)
" &
LISTENER="$!"
set +e
out="$(
    cd "$ROOT_DIR"
    export GATEWAY_SUT_ENDPOINT="http://127.0.0.1:${PORT}" GATEWAY_SUT_READY_SECONDS=15
    bash -c 'set -euo pipefail; source ci/lib/sut.sh; sut_start; printf "ENDPOINT=%s\n" "$SUT_ENDPOINT"' 2>&1
)"
code="$?"
set -e
kill "$LISTENER" 2>/dev/null || true
wait "$LISTENER" 2>/dev/null || true
if [[ "$code" -ne 0 || "$out" != *"ENDPOINT=http://127.0.0.1:${PORT}"* ]]; then
    fail "a running endpoint supplied in GATEWAY_SUT_ENDPOINT was not adopted (exit ${code}): ${out}"
fi

PORT="$(free_port)"
set +e
out="$(
    cd "$ROOT_DIR"
    export GATEWAY_SUT_ENDPOINT="http://127.0.0.1:${PORT}" GATEWAY_SUT_READY_SECONDS=2
    bash -c 'source ci/lib/sut.sh; sut_start; printf "REACHED\n"' 2>&1
)"
code="$?"
set -e
if [[ "$code" -ne 3 || "$out" == *REACHED* ]]; then
    fail "an endpoint with nothing listening on it was accepted (exit ${code}): ${out}"
fi

# --- probe 6: an unset placeholder is refused ----------------------------------------------
printf 'key = @GATEWAY_SUT_PROBE_SET@\nother = @GATEWAY_SUT_PROBE_UNSET@\n' >"${WORK}/template.conf"
set +e
out="$(
    cd "$ROOT_DIR"
    export GATEWAY_SUT_PROBE_SET=present
    env -u GATEWAY_SUT_PROBE_UNSET \
        bash -c "source ci/lib/sut.sh; sut_render '${WORK}/template.conf' '${WORK}/rendered.conf'; printf 'REACHED\n'" 2>&1
)"
code="$?"
set -e
if [[ "$code" -eq 0 || "$out" == *REACHED* ]]; then
    fail "a template with an unset placeholder was rendered anyway (exit ${code}): ${out}"
fi
if [[ -f "${WORK}/rendered.conf" ]]; then
    fail "a refused render still wrote ${WORK}/rendered.conf"
fi
if [[ "$out" != *GATEWAY_SUT_PROBE_UNSET* ]]; then
    fail "the refused render does not name the variable that was missing: ${out}"
fi

# --- probe 7: a placeholder inside a comment is documentation ------------------------------
# The real template explains its own @NAME@ syntax in its header. Substituting there made the
# first end-to-end run demand a variable called NAME, which is a configuration file refused
# because of its own comment.
printf '# the syntax is @PLACEHOLDER_NAME@\nkey = @GATEWAY_SUT_PROBE_SET@\n' >"${WORK}/commented.conf"
set +e
out="$(
    cd "$ROOT_DIR"
    export GATEWAY_SUT_PROBE_SET=present
    bash -c "source ci/lib/sut.sh; sut_render '${WORK}/commented.conf' '${WORK}/commented.out'" 2>&1
)"
code="$?"
set -e
if [[ "$code" -ne 0 ]]; then
    fail "a placeholder inside a comment line was demanded as a variable (exit ${code}): ${out}"
elif ! grep -q '@PLACEHOLDER_NAME@' "${WORK}/commented.out" 2>/dev/null; then
    fail "the comment line explaining the placeholder syntax was rewritten rather than left alone"
elif ! grep -q '^key = present$' "${WORK}/commented.out" 2>/dev/null; then
    fail "the non-comment placeholder beside a comment was not substituted"
fi

if [[ "$status" -ne 0 ]]; then
    exit 1
fi
printf 'OK: the launcher reports ready only when a port is really bound, and exits 3 with a diagnosis on every other path\n'
