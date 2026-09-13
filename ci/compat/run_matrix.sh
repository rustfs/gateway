#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# run_matrix.sh
#
# WHAT THIS DOES
#   Runs every pinned client against every abstract scenario on one freshly started system under
#   test, records what the server saw on the wire for each cell, and hands the whole thing to
#   `ci/compat/report.py`.
#
#   This is a cron job, not a pull-request gate. A full run is tens of minutes and the gate budget
#   is ten (AGENTS.md, "CI budget"); `scripts/check_compat_matrix.sh` refuses a workflow that
#   attaches the matrix to `pull_request`.
#
#   It is deliberately written for bash 3.2 — no `mapfile`, no `timeout(1)` — because a runner that
#   only works on a CI image cannot be exercised before it is pushed, and an unexercised runner is
#   where a matrix quietly stops measuring anything.
#
# USAGE
#   ci/compat/run_matrix.sh [--run-dir <dir>] [--clients a,b] [--scenarios x,y]
#
# EXIT
#   0 no regression   1 at least one regression   3 environment or driver problem
# =============================================================================

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
RUN_DIR="${GATEWAY_COMPAT_RUN_DIR:-$ROOT_DIR/target/compat}"
SCENARIO_FILTER=""
CLIENT_FILTER=""
PORT="${GATEWAY_COMPAT_PORT:-9100}"
SCENARIO_TIMEOUT="${GATEWAY_COMPAT_SCENARIO_TIMEOUT:-300}"

while [[ $# -gt 0 ]]; do
    case "$1" in
    --run-dir)
        RUN_DIR="${2:?--run-dir requires a path}"
        shift 2
        ;;
    --clients)
        CLIENT_FILTER="${2:?--clients requires a list}"
        shift 2
        ;;
    --scenarios)
        SCENARIO_FILTER="${2:?--scenarios requires a list}"
        shift 2
        ;;
    *)
        printf 'run_matrix: unknown argument %s\n' "$1" >&2
        exit 3
        ;;
    esac
done

export GATEWAY_COMPAT_ACCESS_KEY="${GATEWAY_COMPAT_ACCESS_KEY:-compatmatrixkey}"
export GATEWAY_COMPAT_SECRET_KEY="${GATEWAY_COMPAT_SECRET_KEY:-compatmatrixsecret0123456789}"
export GATEWAY_COMPAT_REGION="${GATEWAY_COMPAT_REGION:-us-east-1}"

problem() {
    printf 'run_matrix: %s\n' "$*" >&2
    exit 3
}

command -v python3 >/dev/null 2>&1 || problem 'required command is missing: python3'
[[ -n "${GATEWAY_COMPAT_SUT_BIN:-}" ]] ||
    problem 'GATEWAY_COMPAT_SUT_BIN is unset; build it with: cargo build --release -p rustfs-gateway-compat-sut'

rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR/results" "$RUN_DIR/work" "$RUN_DIR/data"
PROBE_LOG="$RUN_DIR/probe.jsonl"

# ---- capability boundary ---------------------------------------------------------------------
# The launcher prints the registry it actually built. Preflight compares it with the declared
# boundary and refuses to run on a mismatch, so a scenario is never skipped against a stale list.
"$GATEWAY_COMPAT_SUT_BIN" --print-capabilities >"$RUN_DIR/sut-capabilities.txt"

python3 "$ROOT_DIR/ci/compat/report.py" preflight \
    --versions "$ROOT_DIR/compat/versions.toml" \
    --capabilities "$ROOT_DIR/compat/capabilities.toml" \
    --sut-capabilities "$RUN_DIR/sut-capabilities.txt" || exit 3

CLIENTS="$(python3 -c 'import sys, tomllib
from pathlib import Path
print(" ".join(sorted(tomllib.loads(Path(sys.argv[1]).read_text())["clients"])))' "$ROOT_DIR/compat/versions.toml")"
SCENARIOS="$(cd "$ROOT_DIR/compat/scenarios" && ls -1 ./*.yaml | sed 's#^\./##; s#\.yaml$##' | sort | tr '\n' ' ')"

selected() {
    local filter="$1" value="$2"
    [[ -z "$filter" ]] && return 0
    [[ ",$filter," == *",$value,"* ]]
}

# ---- one server for the whole matrix ----------------------------------------------------------
# `ci/lib/sut.sh` is the launcher shared with the P8-05 external-suite runner (rustfs/backlog#1764).
# It is sourced, not executed, and it is the only place either task starts a server: two launchers
# would be two sets of readiness and shutdown bugs that disagree about what "ready" means.
#
# It refuses to run without a command because this repository had no server binary to start
# (rustfs/gateway#624). `compat-sut` is that binary, and this is where it is named.
#
# The same process also serves TLS on a second port (rustfs/gateway#719). Nothing changes for a
# driver that ignores it: `COMPAT_ENDPOINT` stays plaintext, which is where minio-go sends real
# signed chunks. Only a scenario a client can express solely over TLS — botocore sends an
# `x-amz-trailer` upload only on the unsigned-payload path, which it takes only over TLS — reaches
# for `COMPAT_TLS_ENDPOINT`, trusting `COMPAT_CA_BUNDLE`. Both listeners share one data root and one
# probe log, so a cell's evidence is read the same way whichever it used. `compat-sut` writes the
# throwaway authority and binds the TLS port before the plaintext one, so the readiness wait in
# `sut_start` covers both; the checks after it only confirm that.
TLS_PORT="${GATEWAY_COMPAT_TLS_PORT:-9443}"
TLS_AUTHORITY="$RUN_DIR/tls/ca.pem"
export GATEWAY_SUT_HOST=127.0.0.1
export GATEWAY_SUT_PORT="$PORT"
export GATEWAY_SUT_LOG="$RUN_DIR/sut.log"
export GATEWAY_SUT_COMMAND="$(printf '%q ' \
    "$GATEWAY_COMPAT_SUT_BIN" \
    --data "$RUN_DIR/data" \
    --host 127.0.0.1 \
    --port "$PORT" \
    --tls-port "$TLS_PORT" \
    --tls-self-signed "$TLS_AUTHORITY" \
    --access-key "$GATEWAY_COMPAT_ACCESS_KEY" \
    --secret-key "$GATEWAY_COMPAT_SECRET_KEY" \
    --probe-log "$PROBE_LOG")"
# shellcheck source=../lib/sut.sh
source "$ROOT_DIR/ci/lib/sut.sh"
sut_start
trap sut_stop EXIT
[[ -s "$TLS_AUTHORITY" ]] || problem "compat-sut wrote no TLS authority at $TLS_AUTHORITY"
sut_wait_ready 127.0.0.1 "$TLS_PORT" 5 || problem "the encrypted listener on port $TLS_PORT is not accepting connections"
ENDPOINT="$SUT_ENDPOINT"
export COMPAT_TLS_ENDPOINT="https://127.0.0.1:$TLS_PORT"
export COMPAT_CA_BUNDLE="$TLS_AUTHORITY"
printf 'run_matrix: system under test at %s and %s\n' "$ENDPOINT" "$COMPAT_TLS_ENDPOINT"

for client in $CLIENTS; do
    selected "$CLIENT_FILTER" "$client" || continue
    driver="$ROOT_DIR/compat/drivers/$client/run.sh"
    [[ -x "$driver" ]] || problem "client $client has no executable driver at compat/drivers/$client/run.sh"
    for scenario in $SCENARIOS; do
        selected "$SCENARIO_FILTER" "$scenario" || continue
        # A bucket per cell: a shared bucket would let one client's leftovers decide another
        # client's verdict, and the manifest would record the wrong cause.
        bucket="cm-$(printf '%s' "$client-$scenario" | tr '[:upper:]_' '[:lower:]-')"
        status="$(
            COMPAT_ACCESS_KEY="$GATEWAY_COMPAT_ACCESS_KEY" \
                COMPAT_SECRET_KEY="$GATEWAY_COMPAT_SECRET_KEY" \
                COMPAT_REGION="$GATEWAY_COMPAT_REGION" \
                python3 "$ROOT_DIR/ci/compat/run_cell.py" \
                --client "$client" \
                --scenario "$scenario" \
                --driver "$driver" \
                --scenario-file "$ROOT_DIR/compat/scenarios/$scenario.yaml" \
                --capabilities "$RUN_DIR/sut-capabilities.txt" \
                --probe-log "$PROBE_LOG" \
                --workdir "$RUN_DIR/work/$client/$scenario" \
                --bucket "$bucket" \
                --endpoint "$ENDPOINT" \
                --timeout "$SCENARIO_TIMEOUT" \
                --out "$RUN_DIR/results/$client/$scenario.json"
        )"
        printf 'run_matrix: %-8s %-26s %s\n' "$client" "$scenario" "$status"
    done
done

# The launcher stops the process with SIGTERM. Nothing is lost: the probe writes and flushes one
# line per served request, so the evidence on disk is already complete when the socket closes.
sut_stop
trap - EXIT

ALLOW_MISSING=""
if [[ -n "$CLIENT_FILTER" || -n "$SCENARIO_FILTER" ]]; then
    # A filtered run covers part of the matrix on purpose. It may not overwrite the published
    # manifest, and it may not judge the cells it never ran.
    ALLOW_MISSING="--allow-missing"
fi

SUT_VERSION="$(python3 -c 'import sys, tomllib
from pathlib import Path
print(tomllib.loads(Path(sys.argv[1]).read_text())["workspace"]["package"]["version"])' "$ROOT_DIR/Cargo.toml")"

set +e
python3 "$ROOT_DIR/ci/compat/report.py" aggregate \
    --root "$ROOT_DIR" \
    --results "$RUN_DIR/results" \
    --scenarios "$ROOT_DIR/compat/scenarios" \
    --versions "$ROOT_DIR/compat/versions.toml" \
    --capabilities "$ROOT_DIR/compat/capabilities.toml" \
    --known-fail "$ROOT_DIR/compat/known-fail.txt" \
    --out "${GATEWAY_COMPAT_MATRIX_OUT:-$ROOT_DIR/compat/matrix.json}" \
    --sut-version "$SUT_VERSION" \
    $ALLOW_MISSING
report_status=$?
set -e
exit "$report_status"
