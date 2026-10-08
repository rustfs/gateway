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
#   2. pull the pinned image, or inspect a record-only local image ID, for linux/amd64
#   3. assert the image's SDK census is exactly MINT_SDKS in ci/mint/pins.env
#   4. run every SDK, named explicitly, against the system under test: one container over
#      plaintext, then one over the SUT's TLS listener for the SDKs in MINT_TLS_SDKS
#   5. copy /mint/log out of each container, merge the trees, then redact them and the
#      consoles in place
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
# THE TLS PASS (rustfs/gateway#719)
#   The pinned aws-sdk-java-v2 suite returns from every test without writing a record unless
#   ENABLE_HTTPS=1, so over plaintext it measures nothing. The SDKs in MINT_TLS_SDKS (default:
#   that one) run in a second container, with ENABLE_HTTPS=1, against the SUT's TLS listener
#   on MINT_SUT_TLS_PORT. compat-sut generates a throwaway authority for that listener; it is
#   copied into the container and named by SSL_CERT_FILE, and the Java suite additionally
#   trusts every certificate once ENABLE_HTTPS=1. Every other SDK stays on plaintext: moving
#   one changes which of its tests run, which is a baseline change of its own. MINT_TLS_SDKS=
#   (empty) runs every SDK over plaintext, as before the pass existed. ci/mint/report.py reads
#   each pass's console against the SDKs that pass was given.
#
# THE SUITE IS NEVER VENDORED
#   The suite runs inside an image. Component licences and reviewed provenance are in
#   THIRD-PARTY-NOTICES.md; `scripts/check_no_vendored_suites.sh` asserts that no suite
#   implementation is committed here.
#
# AGAINST AN EXTERNAL ENDPOINT (rustfs/backlog#2758, rustfs/gateway#1199)
#   --external http://host:port measures an S3 endpoint started elsewhere — a RustFS binary —
#   instead of the launcher's filesystem backend. No backend is started: `compat-sut --external`
#   is launched on MINT_SUT_HOST:MINT_SUT_PORT (and MINT_SUT_TLS_PORT for the TLS pass) and forwards
#   every request to the endpoint unchanged, so both passes, the readiness wait and the survival
#   checks below work exactly as they do for the launcher. TLS terminates at the observer. The
#   endpoint's own credentials must be given in MINT_ACCESS_KEY / MINT_SECRET_KEY; the throwaway
#   defaults belong to the launcher. Any request the observer had to answer itself, because the
#   endpoint did not, makes the run incomplete (exit 3). The report records `measured_against`
#   with the endpoint's own `Server` header, and the run is judged against the same, unchanged
#   ci/mint/baseline.txt.
#
# LOCAL IMAGE TRIALS
#   --local-image sha256:<64 lowercase hex> accepts an already built Docker image ID, in
#   either mode: the workflow passes the image ci/mint/Dockerfile built from the pinned
#   digest. It never pulls or publishes that image. The platform, full SDK census, and
#   evidence checks stay identical; the report records the local image ID, not the
#   registry manifest digest.
#
# USAGE
#   ci/mint/run.sh [--mode ratchet|record] [--work <dir>] [--out <dir>] [--local-image <id>]
#                  [--external <http://host:port>]   (or MINT_EXTERNAL_ENDPOINT)
# =============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Environment failures leave through sut_die, which owns exit 3. Usage errors are this
# script's own, and are refused before anything is started.
EXIT_USAGE=2

MODE="ratchet"
LOCAL_IMAGE=""
MINT_EXTERNAL="${MINT_EXTERNAL_ENDPOINT:-}"
WORK_DIR=""
OUT_DIR=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
    --mode)
        MODE="${2:-}"
        shift 2
        ;;
    --local-image)
        [[ "${2:-}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
            printf 'run: --local-image requires a full sha256 image ID\n' >&2
            exit "$EXIT_USAGE"
        }
        LOCAL_IMAGE="$2"
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
    --external)
        MINT_EXTERNAL="${2:-}"
        [[ -n "$MINT_EXTERNAL" ]] || {
            printf 'run: --external requires an http://host:port URL\n' >&2
            exit "$EXIT_USAGE"
        }
        shift 2
        ;;
    -h | --help)
        sed -n '17,92p' "${BASH_SOURCE[0]}"
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
# An external endpoint is measured with its own credentials, never the launcher's defaults: a run
# signed with a key the endpoint does not hold records every SDK as failing, which reads exactly
# like a regression.
if [[ -n "$MINT_EXTERNAL" && -n "${GATEWAY_SUT_ENDPOINT:-}" ]]; then
    # Adopting a running endpoint directly would put nothing in front of it to say whether an
    # answer was the endpoint's, and the runner would then refuse the run for lacking that record.
    printf 'run: --external launches its own observer; unset GATEWAY_SUT_ENDPOINT\n' >&2
    exit "$EXIT_USAGE"
fi
if [[ -n "$MINT_EXTERNAL" && ( -z "${MINT_ACCESS_KEY:-}" || -z "${MINT_SECRET_KEY:-}" ) ]]; then
    printf 'run: --external needs the endpoint'"'"'s own credentials in MINT_ACCESS_KEY and MINT_SECRET_KEY\n' >&2
    exit "$EXIT_USAGE"
fi
# Every value the container and the SUT are given, and its default, is here. The defaults
# are for a throwaway loopback service and are not secrets; `:=` means an empty override,
# which is what an unset GitHub secret renders as, falls back to the default.

WORK_DIR="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/gateway-mint.XXXXXX")}"
OUT_DIR="${OUT_DIR:-${WORK_DIR}/out}"
mkdir -p "$WORK_DIR" "$OUT_DIR"

# shellcheck source=ci/lib/sut.sh
source "${ROOT_DIR}/ci/lib/sut.sh"

MINT_CONTAINER="gateway-mint-$$-${RANDOM}"
MINT_ENV_FILE="${WORK_DIR}/mint.env"
# shellcheck disable=SC2329 # invoked by the EXIT trap below.
mint_cleanup() {
    rm -f "$MINT_ENV_FILE"
    docker rm -f "$MINT_CONTAINER" "${MINT_CONTAINER}-tls" "${MINT_CONTAINER}-census" >/dev/null 2>&1 || true
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
: "${MINT_SUT_TLS_PORT:=9243}"
# `=` and not `:=`: an explicitly empty MINT_TLS_SDKS means something, namely no TLS pass.
: "${MINT_TLS_SDKS=aws-sdk-java-v2}"
read -r -a MINT_TLS_LIST <<<"$MINT_TLS_SDKS"
for sdk in ${MINT_TLS_LIST[@]+"${MINT_TLS_LIST[@]}"}; do
    case " ${MINT_SDK_LIST[*]} " in
    *" ${sdk} "*) ;;
    *)
        printf 'run: MINT_TLS_SDKS names %s, which MINT_SDKS in ci/mint/pins.env does not\n' "$sdk" >&2
        exit "$EXIT_USAGE"
        ;;
    esac
done
MINT_PLAIN_LIST=()
for sdk in "${MINT_SDK_LIST[@]}"; do
    case " ${MINT_TLS_SDKS} " in
    *" ${sdk} "*) ;;
    *) MINT_PLAIN_LIST+=("$sdk") ;;
    esac
done
# Mint given no SDK name runs every visible one, so an empty plaintext pass would not be empty.
((${#MINT_PLAIN_LIST[@]} > 0)) || {
    printf 'run: MINT_TLS_SDKS names every pinned SDK; at least one must run over plaintext\n' >&2
    exit "$EXIT_USAGE"
}
MINT_TLS_AUTHORITY="${WORK_DIR}/tls/ca.pem"
MINT_TLS_AUTHORITY_IN_CONTAINER=/mint/compat-sut-ca.pem
export MINT_ACCESS_KEY MINT_SECRET_KEY MINT_REGION MINT_SUT_HOST MINT_SUT_PORT MINT_SUT_BINARY \
    MINT_SUT_TLS_PORT MINT_SERVER_HOST

# --- the system under test ---------------------------------------------------------------
# The names stay literal in the command: sut_start logs the launch shape, and expanding the
# secret here would put it in that log. bash -c expands the exported values in the child, so
# the embedded quotes are for that shell and not this one.
# The TLS listener is bound before the plaintext one, so sut_start's readiness wait on the
# plaintext port also covers it. A certificate for MINT_SERVER_HOST is added when the
# container dials the host by another name.
MINT_TLS_FLAGS=""
if ((${#MINT_TLS_LIST[@]} > 0)); then
    MINT_TLS_FLAGS=" --tls-port \"\$MINT_SUT_TLS_PORT\" --tls-self-signed \"${MINT_TLS_AUTHORITY}\""
    if [[ -n "$MINT_SERVER_HOST" ]]; then
        MINT_TLS_FLAGS+=" --tls-san \"\$MINT_SERVER_HOST\""
    fi
fi
REPORT_SUT_ARGS=(--sut gateway-fs)
MINT_OBSERVER_PROBE="${WORK_DIR}/observer-probe.jsonl"
if [[ -n "$MINT_EXTERNAL" ]]; then
    # The endpoint names itself once, read directly before the observer stands in front of it.
    sut_external_endpoint "$MINT_EXTERNAL"
    MINT_ENDPOINT_BUILD="$(sut_server_header "$MINT_EXTERNAL")" ||
        sut_die "the external endpoint ${MINT_EXTERNAL} did not say what it is"
    printf 'run: external endpoint %s answers as Server: %s\n' "$MINT_EXTERNAL" "${MINT_ENDPOINT_BUILD:-(none)}"
    REPORT_SUT_ARGS=(--sut external --endpoint-build "$MINT_ENDPOINT_BUILD")
    export MINT_EXTERNAL MINT_OBSERVER_PROBE
    # No data root, no credentials: the observer holds neither, and refuses both.
    # shellcheck disable=SC2089
    GATEWAY_SUT_COMMAND="${GATEWAY_SUT_COMMAND:-\"\$MINT_SUT_BINARY\" \
        --external \"\$MINT_EXTERNAL\" \
        --host \"\$MINT_SUT_HOST\" \
        --port \"\$MINT_SUT_PORT\" \
        --probe-log \"\$MINT_OBSERVER_PROBE\"${MINT_TLS_FLAGS}}"
fi
# shellcheck disable=SC2089,SC2090
: "${GATEWAY_SUT_COMMAND:=\"\$MINT_SUT_BINARY\" \
    --data \"${WORK_DIR}/compat-sut-data\" \
    --host \"\$MINT_SUT_HOST\" \
    --port \"\$MINT_SUT_PORT\" \
    --region \"\$MINT_REGION\" \
    --access-key \"\$MINT_ACCESS_KEY\" \
    --secret-key \"\$MINT_SECRET_KEY\"${MINT_TLS_FLAGS}}"
# shellcheck disable=SC2090 # the child `bash -c` in ci/lib/sut.sh is the shell that reads it.
export GATEWAY_SUT_COMMAND
export GATEWAY_SUT_HOST="${GATEWAY_SUT_HOST:-$MINT_SUT_HOST}"
export GATEWAY_SUT_PORT="${GATEWAY_SUT_PORT:-$MINT_SUT_PORT}"
export GATEWAY_SUT_LOG="${GATEWAY_SUT_LOG:-${WORK_DIR}/compat-sut.log}"
sut_start
MINT_SERVER_HOST="${MINT_SERVER_HOST:-$SUT_HOST}"
if ((${#MINT_TLS_LIST[@]} > 0)); then
    sut_wait_ready "$SUT_HOST" "$MINT_SUT_TLS_PORT" 5 ||
        sut_die "MINT_TLS_SDKS (${MINT_TLS_SDKS}) runs over the SUT's TLS listener, and nothing accepts connections on ${SUT_HOST}:${MINT_SUT_TLS_PORT}; a GATEWAY_SUT_COMMAND or GATEWAY_SUT_ENDPOINT without one needs MINT_TLS_SDKS= to run every SDK over plaintext"
fi

# --- the image ---------------------------------------------------------------------------
if [[ -n "$LOCAL_IMAGE" ]]; then
    MINT_IMAGE="$LOCAL_IMAGE"
    printf 'run: inspecting local image %s for %s\n' "$MINT_IMAGE" "$MINT_PLATFORM"
else
    printf 'run: pulling %s for %s\n' "$MINT_IMAGE" "$MINT_PLATFORM"
    docker pull --quiet --platform "$MINT_PLATFORM" "$MINT_IMAGE" >/dev/null ||
        sut_die "cannot pull the pinned image ${MINT_IMAGE}"
fi
PULLED_PLATFORM="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$MINT_IMAGE")" ||
    sut_die "cannot inspect the selected image ${MINT_IMAGE}"
[[ "$PULLED_PLATFORM" == "$MINT_PLATFORM" ]] ||
    sut_die "the selected image is ${PULLED_PLATFORM}, not the pinned ${MINT_PLATFORM}"

# The census is read from the image, not assumed: an SDK the image carries and the list does
# not name would silently never run, and one the list names and the image lacks would stop
# mint before the first SDK.
IMAGE_SDKS="$(docker run --rm --name "${MINT_CONTAINER}-census" --platform "$MINT_PLATFORM" --network none \
    --entrypoint /bin/ls "$MINT_IMAGE" -A /mint/run/core)" ||
    sut_die "cannot list /mint/run/core in the selected image"
# shellcheck disable=SC2086 # one directory name per word, by construction of `ls -A`.
IMAGE_CENSUS="$(printf '%s\n' $IMAGE_SDKS | LC_ALL=C sort | tr '\n' ' ')"
PINNED_CENSUS="$(printf '%s\n' "${MINT_SDK_LIST[@]}" | LC_ALL=C sort | tr '\n' ' ')"
[[ "$IMAGE_CENSUS" == "$PINNED_CENSUS" ]] ||
    sut_die "the image's SDK census (${IMAGE_CENSUS% }) is not MINT_SDKS in ci/mint/pins.env (${PINNED_CENSUS% })"
printf 'run: the image carries exactly the %s pinned SDK(s)\n' "${#MINT_SDK_LIST[@]}"

# --- the suite ---------------------------------------------------------------------------
# mint_pass <container> <console> <log-dir> <endpoint> <https> <sdk>...
# One container, one console, one copied /mint/log. The configuration is handed over as an
# env file rather than as arguments, so the secret never appears on a process command line.
# The file is private to this user and removed as soon as the container has been created
# from it.
mint_pass() {
    local container="$1" console="$2" log_dir="$3" endpoint="$4" https="$5"
    shift 5
    (
        umask 077
        printf '%s=%s\n' \
            SERVER_ENDPOINT "$endpoint" \
            ACCESS_KEY "$MINT_ACCESS_KEY" \
            SECRET_KEY "$MINT_SECRET_KEY" \
            SERVER_REGION "$MINT_REGION" \
            ENABLE_HTTPS "$https" \
            MINT_MODE "$MINT_TEST_MODE" \
            RUN_ON_FAIL 1 >"$MINT_ENV_FILE"
        if [[ "$https" == 1 && -s "$MINT_TLS_AUTHORITY" ]]; then
            printf '%s=%s\n' SSL_CERT_FILE "$MINT_TLS_AUTHORITY_IN_CONTAINER" >>"$MINT_ENV_FILE"
        fi
    )
    docker create --name "$container" \
        --platform "$MINT_PLATFORM" \
        --network "$MINT_DOCKER_NETWORK" \
        --env-file "$MINT_ENV_FILE" \
        "$MINT_IMAGE" "$@" >/dev/null || {
        rm -f "$MINT_ENV_FILE"
        sut_die "cannot create the mint container ${container}"
    }
    rm -f "$MINT_ENV_FILE"
    # Copied rather than bind-mounted: a daemon inside a VM cannot see a host temporary
    # directory, and `docker cp` works the same on every daemon.
    if [[ "$https" == 1 && -s "$MINT_TLS_AUTHORITY" ]]; then
        docker cp "$MINT_TLS_AUTHORITY" "${container}:${MINT_TLS_AUTHORITY_IN_CONTAINER}" >/dev/null ||
            sut_die "cannot copy the SUT's TLS authority into ${container}"
    fi
    printf 'run: running %s SDK(s) in mode %s against %s (ENABLE_HTTPS=%s); the console stays in %s\n' \
        "$#" "$MINT_TEST_MODE" "$endpoint" "$https" "$console"
    local started="$SECONDS" status
    set +e
    docker start --attach "$container" >"$console" 2>&1
    status="$?"
    set -e
    printf 'run: mint exited %s after %ss; its exit is not a verdict, the records are\n' \
        "$status" "$((SECONDS - started))"
    # Copied before anything judges it, and redacted before anything reads it.
    rm -rf "$log_dir"
    docker cp "${container}:/mint/log" "$log_dir" >/dev/null ||
        sut_die "cannot copy /mint/log out of ${container}; without it this run measured nothing"
    docker rm -f "$container" >/dev/null 2>&1 || true
}

MINT_LOG="${WORK_DIR}/mint-log"
CONSOLE="${WORK_DIR}/console.txt"
mint_pass "$MINT_CONTAINER" "$CONSOLE" "$MINT_LOG" "${MINT_SERVER_HOST}:${SUT_PORT}" 0 "${MINT_PLAIN_LIST[@]}"
MINT_REPORT_PASSES=(--pass "${MINT_PLAIN_LIST[*]}" "$CONSOLE")
MINT_CONSOLES=("$CONSOLE")
if ((${#MINT_TLS_LIST[@]} > 0)); then
    TLS_CONSOLE="${WORK_DIR}/console-tls.txt"
    TLS_LOG="${WORK_DIR}/mint-log-tls"
    mint_pass "${MINT_CONTAINER}-tls" "$TLS_CONSOLE" "$TLS_LOG" "${MINT_SERVER_HOST}:${MINT_SUT_TLS_PORT}" 1 \
        "${MINT_TLS_LIST[@]}"
    # One tree, as if one container had written it, so records are read exactly as before.
    # Both passes writing the same SDK's directory would make one of them silently win, so
    # that is refused. Mint also writes files at the top of /mint/log in every run (a combined
    # log.json, measured in https://github.com/rustfs/gateway/actions/runs/34788803143);
    # ci/mint/report.py reads only the per-SDK directories, so the TLS pass's copies are kept
    # beside the first pass's under a suffix rather than refused or dropped.
    while IFS= read -r -d '' entry; do
        name="${entry##*/}"
        if [[ -d "$entry" ]]; then
            [[ ! -e "${MINT_LOG}/${name}" ]] ||
                sut_die "both passes wrote /mint/log/${name}; refusing to judge a tree one of them overwrote"
            mv "$entry" "${MINT_LOG}/${name}"
        else
            mv "$entry" "${MINT_LOG}/${name}.tls-pass"
        fi
    done < <(find "$TLS_LOG" -mindepth 1 -maxdepth 1 -print0)
    rm -rf "$TLS_LOG"
    MINT_REPORT_PASSES+=(--pass "${MINT_TLS_LIST[*]}" "$TLS_CONSOLE")
    MINT_CONSOLES+=("$TLS_CONSOLE")
fi

# --- the evidence ------------------------------------------------------------------------
python3 "${ROOT_DIR}/ci/mint/report.py" redact --secret-env MINT_SECRET_KEY "$MINT_LOG" "${MINT_CONSOLES[@]}" ||
    sut_die "redaction failed; refusing to judge evidence that may still carry signing material"

# A service that died part-way makes every later SDK fail with connection refused, which
# reads exactly like an implementation that regressed.
if [[ -n "$SUT_PID" ]] && ! kill -0 "$SUT_PID" 2>/dev/null; then
    sut_die "the system under test exited during the run; nothing mint recorded after that measured it"
fi
sut_wait_ready "$SUT_HOST" "$SUT_PORT" 5 ||
    sut_die "the system under test stopped accepting connections during the run"
if [[ -n "$MINT_EXTERNAL" ]]; then
    # The observer stayed up; the endpoint behind it must have too, and every answer an SDK got
    # must have been the endpoint's. One `502` the observer wrote itself measured the network.
    sut_wait_ready "$SUT_EXTERNAL_HOST" "$SUT_EXTERNAL_PORT" 5 ||
        sut_die "the external endpoint ${MINT_EXTERNAL} stopped accepting connections during the run"
    [[ -f "$MINT_OBSERVER_PROBE" ]] || sut_die "the observer wrote no probe log at ${MINT_OBSERVER_PROBE}"
    UNREACHED="$(grep -c '"answered_by":"observer"' "$MINT_OBSERVER_PROBE" || true)"
    [[ "$UNREACHED" == 0 ]] ||
        sut_die "the observer could not reach ${MINT_EXTERNAL} for ${UNREACHED} request(s); nothing mint recorded is a measurement of it"
fi
if ((${#MINT_TLS_LIST[@]} > 0)); then
    sut_wait_ready "$SUT_HOST" "$MINT_SUT_TLS_PORT" 5 ||
        sut_die "the system under test's TLS listener stopped accepting connections during the run"
fi

# --- the verdict -------------------------------------------------------------------------
REPORT_ARGS=(
    judge
    --log-dir "$MINT_LOG"
    "${MINT_REPORT_PASSES[@]}"
    --baseline "${ROOT_DIR}/ci/mint/baseline.txt"
    --sdks "${MINT_SDK_LIST[*]}"
    --image "$MINT_IMAGE"
    "${REPORT_SUT_ARGS[@]}"
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
