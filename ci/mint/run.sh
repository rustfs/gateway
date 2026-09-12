#!/usr/bin/env bash
# Copyright 2026 RustFS Team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# =============================================================================
# ci/mint/run.sh — one MinIO mint run, end to end.
#
#   1. start or adopt a system under test                      (ci/lib/sut.sh)
#   2. pull the pinned image by digest for linux/amd64, and assert both
#   3. assert the image's SDK census is exactly MINT_SDKS in ci/mint/pins.env
#   4. run every SDK, named explicitly, against the system under test
#   5. copy /mint/log out of the container, then redact it and the console in place
#   6. assert the system under test survived the run
#   7. judge the per-SDK failure counts against ci/mint/baseline.txt
#
# The logic lives here rather than in workflow YAML so it can be read, grepped and run by
# hand. The workflow supplies the build, the artifact and a schedule, and nothing else.
#
# EXIT CODES
#   0 ok, 1 regression against the baseline, 2 usage, 3 environment.
#   Nothing before step 7 may exit 1: a suite that never ran is not a suite that regressed.
#
# WHAT LEAVES THIS SCRIPT
#   Only what ci/mint/report.py writes to --out: an aggregate summary, a JSON report and, in
#   record mode, a proposed baseline. The console transcript and the per-SDK logs stay in
#   --work. Third-party failure text can carry an Authorization header, a presigned query or
#   a server's signature diagnostics, so it is redacted in place, and still never uploaded.
#
# REACHING THE SYSTEM UNDER TEST FROM THE CONTAINER
#   On a Linux CI runner the container shares the runner's network namespace (`--network
#   host`) and dials the SUT on the loopback address it is bound to. Nothing listens beyond
#   loopback.
#   When the Docker daemon runs inside a VM (Colima, Docker Desktop), the container's
#   loopback is the VM's, not the host's. Keep the SUT on 127.0.0.1 and give the container
#   the VM's name for the host instead. On Colima:
#     MINT_SERVER_HOST=host.lima.internal ci/mint/run.sh --mode record
#   Measured on Colima on 2026-09-12: host.lima.internal reached a listener on the host's
#   loopback from both the host and the bridge network; 127.0.0.1 under --network host was
#   refused.
#
# THE SUITE IS NEVER VENDORED
#   It runs only as the pinned image. Its licence is Apache-2.0 and its review is in
#   THIRD-PARTY-NOTICES.md; `scripts/check_no_vendored_suites.sh` asserts none of it is
#   ever committed here.
#
# USAGE
#   ci/mint/run.sh [--mode ratchet|record] [--work <dir>] [--out <dir>]
# =============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Environment failures leave through sut_die, which owns exit 3. Usage errors are this
# script's own, and are refused before anything is started.
EXIT_USAGE=2

MODE="ratchet"
WORK_DIR=""
OUT_DIR=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
    --mode)
        MODE="${2:-}"
        shift 2
        ;;
    --work)
        WORK_DIR="${2:-}"
        shift 2
        ;;
    --out)
        OUT_DIR="${2:-}"
        shift 2
        ;;
    -h | --help)
        sed -n '17,62p' "${BASH_SOURCE[0]}"
        exit 0
        ;;
    *)
        printf 'run: unknown argument %s\n' "$1" >&2
        exit "$EXIT_USAGE"
        ;;
    esac
done
case "$MODE" in
ratchet | record) ;;
*)
    printf 'run: --mode must be ratchet or record, got %s\n' "$MODE" >&2
    exit "$EXIT_USAGE"
    ;;
esac

WORK_DIR="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/gateway-mint.XXXXXX")}"
OUT_DIR="${OUT_DIR:-${WORK_DIR}/out}"
mkdir -p "$WORK_DIR" "$OUT_DIR"

# shellcheck source=ci/lib/sut.sh
source "${ROOT_DIR}/ci/lib/sut.sh"

MINT_CONTAINER="gateway-mint-$$-${RANDOM}"
mint_cleanup() {
    docker rm -f "$MINT_CONTAINER" "${MINT_CONTAINER}-census" >/dev/null 2>&1 || true
    sut_stop
}
trap mint_cleanup EXIT

# --- the pin -----------------------------------------------------------------------------
# shellcheck source=ci/mint/pins.env
source "${ROOT_DIR}/ci/mint/pins.env"
[[ "${MINT_IMAGE:-}" =~ ^docker\.io/minio/mint@sha256:[0-9a-f]{64}$ ]] ||
    sut_die "ci/mint/pins.env must pin MINT_IMAGE as docker.io/minio/mint@sha256:<digest>, got '${MINT_IMAGE:-}'"
[[ "${MINT_PLATFORM:-}" == "linux/amd64" ]] ||
    sut_die "ci/mint/pins.env pins the linux/amd64 manifest; MINT_PLATFORM is '${MINT_PLATFORM:-}'"
read -r -a MINT_SDK_LIST <<<"${MINT_SDKS:-}"
((${#MINT_SDK_LIST[@]} > 0)) || sut_die "ci/mint/pins.env names no SDK in MINT_SDKS"
command -v docker >/dev/null 2>&1 || sut_die "docker is not installed; mint runs only as its pinned image"

# --- the configuration values --------------------------------------------------------------
# Every value the container and the SUT are given, and its default, is here. The defaults
# are for a throwaway loopback service and are not secrets; `:=` means an empty override,
# which is what an unset GitHub secret renders as, falls back to the default.
: "${MINT_ACCESS_KEY:=AKIAGATEWAYMINT00000}"
: "${MINT_SECRET_KEY:=gateway-mint-secret-for-a-throwaway-service}"
: "${MINT_REGION:=us-east-1}"
: "${MINT_SUT_HOST:=127.0.0.1}"
: "${MINT_SUT_PORT:=9200}"
: "${MINT_SUT_BINARY:=${ROOT_DIR}/target/release/compat-sut}"
: "${MINT_SERVER_HOST:=}"
: "${MINT_DOCKER_NETWORK:=host}"
: "${MINT_TEST_MODE:=core}"
case "$MINT_TEST_MODE" in
core | full) ;;
*)
    printf 'run: MINT_TEST_MODE must be core or full, got %s\n' "$MINT_TEST_MODE" >&2
    exit "$EXIT_USAGE"
    ;;
esac
export MINT_ACCESS_KEY MINT_SECRET_KEY MINT_REGION MINT_SUT_HOST MINT_SUT_PORT MINT_SUT_BINARY

# --- the system under test ---------------------------------------------------------------
# The names stay literal in the command: sut_start logs the launch shape, and expanding the
# secret here would put it in that log. bash -c expands the exported values in the child.
: "${GATEWAY_SUT_COMMAND:=\"\$MINT_SUT_BINARY\" \
    --data \"${WORK_DIR}/compat-sut-data\" \
    --host \"\$MINT_SUT_HOST\" \
    --port \"\$MINT_SUT_PORT\" \
    --region \"\$MINT_REGION\" \
    --access-key \"\$MINT_ACCESS_KEY\" \
    --secret-key \"\$MINT_SECRET_KEY\"}"
export GATEWAY_SUT_COMMAND
export GATEWAY_SUT_HOST="${GATEWAY_SUT_HOST:-$MINT_SUT_HOST}"
export GATEWAY_SUT_PORT="${GATEWAY_SUT_PORT:-$MINT_SUT_PORT}"
export GATEWAY_SUT_LOG="${GATEWAY_SUT_LOG:-${WORK_DIR}/compat-sut.log}"
sut_start
MINT_SERVER_HOST="${MINT_SERVER_HOST:-$SUT_HOST}"

# --- the image ---------------------------------------------------------------------------
printf 'run: pulling %s for %s\n' "$MINT_IMAGE" "$MINT_PLATFORM"
docker pull --quiet --platform "$MINT_PLATFORM" "$MINT_IMAGE" >/dev/null ||
    sut_die "cannot pull the pinned image ${MINT_IMAGE}"
PULLED_PLATFORM="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$MINT_IMAGE")" ||
    sut_die "cannot inspect the pulled image ${MINT_IMAGE}"
[[ "$PULLED_PLATFORM" == "$MINT_PLATFORM" ]] ||
    sut_die "the pulled image is ${PULLED_PLATFORM}, not the pinned ${MINT_PLATFORM}"

# The census is read from the image, not assumed: an SDK the image carries and the list does
# not name would silently never run, and one the list names and the image lacks would stop
# mint before the first SDK.
IMAGE_SDKS="$(docker run --rm --name "${MINT_CONTAINER}-census" --platform "$MINT_PLATFORM" --network none \
    --entrypoint /bin/ls "$MINT_IMAGE" -A /mint/run/core)" ||
    sut_die "cannot list /mint/run/core in the pinned image"
# shellcheck disable=SC2086 # one directory name per word, by construction of `ls -A`.
IMAGE_CENSUS="$(printf '%s\n' $IMAGE_SDKS | LC_ALL=C sort | tr '\n' ' ')"
PINNED_CENSUS="$(printf '%s\n' "${MINT_SDK_LIST[@]}" | LC_ALL=C sort | tr '\n' ' ')"
[[ "$IMAGE_CENSUS" == "$PINNED_CENSUS" ]] ||
    sut_die "the image's SDK census (${IMAGE_CENSUS% }) is not MINT_SDKS in ci/mint/pins.env (${PINNED_CENSUS% })"
printf 'run: the image carries exactly the %s pinned SDK(s)\n' "${#MINT_SDK_LIST[@]}"

# --- the suite ---------------------------------------------------------------------------
# Handed over as an env file rather than as arguments, so the secret never appears on a
# process command line. The file lives in the work directory with the other raw evidence.
MINT_ENV_FILE="${WORK_DIR}/mint.env"
(
    umask 077
    printf '%s=%s\n' \
        SERVER_ENDPOINT "${MINT_SERVER_HOST}:${SUT_PORT}" \
        ACCESS_KEY "$MINT_ACCESS_KEY" \
        SECRET_KEY "$MINT_SECRET_KEY" \
        SERVER_REGION "$MINT_REGION" \
        ENABLE_HTTPS 0 \
        MINT_MODE "$MINT_TEST_MODE" \
        RUN_ON_FAIL 1 >"$MINT_ENV_FILE"
)
CONSOLE="${WORK_DIR}/console.txt"
printf 'run: running %s SDK(s) in mode %s against %s:%s; the console stays in %s\n' \
    "${#MINT_SDK_LIST[@]}" "$MINT_TEST_MODE" "$MINT_SERVER_HOST" "$SUT_PORT" "$CONSOLE"
MINT_STARTED="$SECONDS"
set +e
docker run --name "$MINT_CONTAINER" \
    --platform "$MINT_PLATFORM" \
    --network "$MINT_DOCKER_NETWORK" \
    --env-file "$MINT_ENV_FILE" \
    "$MINT_IMAGE" "${MINT_SDK_LIST[@]}" >"$CONSOLE" 2>&1
MINT_STATUS="$?"
set -e
printf 'run: mint exited %s after %ss; its exit is not a verdict, the records are\n' \
    "$MINT_STATUS" "$((SECONDS - MINT_STARTED))"

# --- the evidence ------------------------------------------------------------------------
# Copied before anything judges it, and redacted before anything reads it.
MINT_LOG="${WORK_DIR}/mint-log"
rm -rf "$MINT_LOG"
docker cp "$MINT_CONTAINER:/mint/log" "$MINT_LOG" >/dev/null ||
    sut_die "cannot copy /mint/log out of ${MINT_CONTAINER}; without it this run measured nothing"
docker rm -f "$MINT_CONTAINER" >/dev/null 2>&1 || true
python3 "${ROOT_DIR}/ci/mint/report.py" redact --secret-env MINT_SECRET_KEY "$MINT_LOG" "$CONSOLE" ||
    sut_die "redaction failed; refusing to judge evidence that may still carry signing material"

# A service that died part-way makes every later SDK fail with connection refused, which
# reads exactly like an implementation that regressed.
if [[ -n "$SUT_PID" ]] && ! kill -0 "$SUT_PID" 2>/dev/null; then
    sut_die "the system under test exited during the run; nothing mint recorded after that measured it"
fi
sut_wait_ready "$SUT_HOST" "$SUT_PORT" 5 ||
    sut_die "the system under test stopped accepting connections during the run"

# --- the verdict -------------------------------------------------------------------------
REPORT_ARGS=(
    judge
    --log-dir "$MINT_LOG"
    --progress "$CONSOLE"
    --baseline "${ROOT_DIR}/ci/mint/baseline.txt"
    --sdks "${MINT_SDK_LIST[*]}"
    --image "$MINT_IMAGE"
    --markdown "${OUT_DIR}/summary.md"
    --json "${OUT_DIR}/report.json"
)
if [[ "$MODE" == "record" ]]; then
    REPORT_ARGS+=(--record "${OUT_DIR}/baseline.proposed.txt")
fi
set +e
python3 "${ROOT_DIR}/ci/mint/report.py" "${REPORT_ARGS[@]}"
REPORT_STATUS="$?"
set -e
printf 'run: report exited %s (aggregate in %s; raw evidence in %s, never for upload)\n' \
    "$REPORT_STATUS" "$OUT_DIR" "$WORK_DIR"
exit "$REPORT_STATUS"
