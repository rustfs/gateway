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
# ci/s3tests/run.sh — one weekly Ceph s3-tests run, end to end.
#
#   1. start or adopt a system under test          (ci/lib/sut.sh)
#   2. render ci/s3tests/s3tests.conf.tmpl against the environment
#   3. clone ceph/s3-tests and check out the pinned commit
#   4. ASSERT the checked-out commit is exactly the pinned one
#   5. run the suite through tox with the checked-in marker filter
#   6. judge the JUnit document against ci/s3tests/xfail.txt
#
# The logic lives here rather than in workflow YAML so it can be read, grepped and run by
# hand. The workflow supplies caching, artifacts and a schedule, and nothing else.
#
# EXIT CODES
#   0 ok, 1 regression against the xfail list, 2 usage, 3 environment.
#   Nothing in steps 1-4 may exit 1: a suite that never ran is not a suite that regressed.
#
# THE SUITE IS NEVER VENDORED
#   It is cloned into a scratch directory outside the repository at run time. Its licence
#   is MIT and its provenance is recorded in docs/third-party.md;
#   `scripts/check_no_vendored_suites.sh` asserts none of it is ever committed here.
#
# USAGE
#   ci/s3tests/run.sh [--mode ratchet|record] [--work <dir>] [--out <dir>]
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
        sed -n '17,40p' "${BASH_SOURCE[0]}"
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

WORK_DIR="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/gateway-s3tests.XXXXXX")}"
OUT_DIR="${OUT_DIR:-${WORK_DIR}/out}"
mkdir -p "$WORK_DIR" "$OUT_DIR"

# shellcheck source=ci/lib/sut.sh
source "${ROOT_DIR}/ci/lib/sut.sh"
trap sut_stop EXIT

# --- the pin -----------------------------------------------------------------------------
# shellcheck source=ci/s3tests/pins.env
source "${ROOT_DIR}/ci/s3tests/pins.env"
[[ "${S3TESTS_SHA:-}" =~ ^[0-9a-f]{40}$ ]] ||
    sut_die "ci/s3tests/pins.env must pin a 40-hex commit, got '${S3TESTS_SHA:-}'"

FILTER="$(sed -e 's/#.*$//' "${ROOT_DIR}/ci/s3tests/filter.txt" | tr '\n' ' ' | tr -s ' ' | sed -e 's/^ //' -e 's/ $//')"
[[ -n "$FILTER" ]] || sut_die "ci/s3tests/filter.txt produced an empty marker expression"
printf 'run: marker filter: %s\n' "$FILTER"

# --- the configuration values --------------------------------------------------------------
# Every placeholder in ci/s3tests/s3tests.conf.tmpl gets its value here, so there is exactly
# one place to read to know what the suite was told. Each is overridable, and the workflow
# overrides the credential ones from repository secrets when they are set. The defaults are
# for a throwaway loopback service and are not secrets; `:=` means an empty override — which
# is what an unset GitHub secret renders as — falls back to the default rather than writing a
# blank credential into the configuration.
#
# The two identities MUST stay distinct: the cross-account and ACL cases measure the
# difference between them, so collapsing them makes those cases pass for the wrong reason.
: "${S3TESTS_HOST:=127.0.0.1}"
: "${S3TESTS_PORT:=9100}"
: "${S3TESTS_IS_SECURE:=False}"
: "${S3TESTS_SSL_VERIFY:=False}"
: "${S3TESTS_REGION:=us-east-1}"
# Not `: "${VAR:=...}"`: the `}` of `{random}` closes the parameter expansion, the default
# silently becomes `s3gate-{random`, and the suite then dies inside `template.format(...)`
# while importing test_s3.py — which costs ~900 of its ~955 cases and reads as a small run,
# not as an error. Measured, the first time this ran against the real suite.
if [[ -z "${S3TESTS_BUCKET_PREFIX:-}" ]]; then
    S3TESTS_BUCKET_PREFIX='s3gate-{random}-'
fi
: "${S3TESTS_LC_DEBUG_INTERVAL:=10}"
: "${S3TESTS_MAIN_ACCESS_KEY:=AKIAGATEWAYMAIN00000}"
: "${S3TESTS_MAIN_SECRET_KEY:=gateway-main-secret-for-a-throwaway-service}"
: "${S3TESTS_MAIN_DISPLAY_NAME:=s3gate-main}"
: "${S3TESTS_MAIN_USER_ID:=s3gate-main}"
: "${S3TESTS_MAIN_EMAIL:=main@s3gate.invalid}"
: "${S3TESTS_ALT_ACCESS_KEY:=AKIAGATEWAYALT000000}"
: "${S3TESTS_ALT_SECRET_KEY:=gateway-alt-secret-for-a-throwaway-service}"
: "${S3TESTS_ALT_DISPLAY_NAME:=s3gate-alt}"
: "${S3TESTS_ALT_USER_ID:=s3gate-alt}"
: "${S3TESTS_ALT_EMAIL:=alt@s3gate.invalid}"
: "${S3TESTS_TENANT_ACCESS_KEY:=AKIAGATEWAYTENANT000}"
: "${S3TESTS_TENANT_SECRET_KEY:=gateway-tenant-secret-for-a-throwaway-service}"
: "${S3TESTS_TENANT_DISPLAY_NAME:=s3gate-tenant}"
: "${S3TESTS_TENANT_USER_ID:=s3gate-tenant}"
: "${S3TESTS_TENANT_EMAIL:=tenant@s3gate.invalid}"
: "${S3TESTS_TENANT_NAME:=s3gatetenant}"
: "${S3TESTS_IAM_ROOT_ACCESS_KEY:=AKIAGATEWAYIAMROOT00}"
: "${S3TESTS_IAM_ROOT_SECRET_KEY:=gateway-iam-root-secret-for-a-throwaway-service}"
: "${S3TESTS_IAM_ROOT_ACCOUNT_ID:=S3GATE11111111111111}"
: "${S3TESTS_IAM_ALT_ROOT_ACCESS_KEY:=AKIAGATEWAYIAMALT000}"
: "${S3TESTS_IAM_ALT_ROOT_SECRET_KEY:=gateway-iam-alt-root-secret-for-a-throwaway-service}"
: "${S3TESTS_IAM_ALT_ROOT_ACCOUNT_ID:=S3GATE22222222222222}"
if [[ "$S3TESTS_MAIN_ACCESS_KEY" == "$S3TESTS_ALT_ACCESS_KEY" ]]; then
    sut_die "the main and alt identities share an access key. The cross-account and ACL cases
  are measured by the difference between them; one identity in both sections does not make
  those cases fail, it makes them pass for the wrong reason."
fi

export S3TESTS_HOST S3TESTS_PORT S3TESTS_IS_SECURE S3TESTS_SSL_VERIFY S3TESTS_REGION
export S3TESTS_BUCKET_PREFIX S3TESTS_LC_DEBUG_INTERVAL
export S3TESTS_MAIN_ACCESS_KEY S3TESTS_MAIN_SECRET_KEY S3TESTS_MAIN_DISPLAY_NAME
export S3TESTS_MAIN_USER_ID S3TESTS_MAIN_EMAIL
export S3TESTS_ALT_ACCESS_KEY S3TESTS_ALT_SECRET_KEY S3TESTS_ALT_DISPLAY_NAME
export S3TESTS_ALT_USER_ID S3TESTS_ALT_EMAIL
export S3TESTS_TENANT_ACCESS_KEY S3TESTS_TENANT_SECRET_KEY S3TESTS_TENANT_DISPLAY_NAME
export S3TESTS_TENANT_USER_ID S3TESTS_TENANT_EMAIL S3TESTS_TENANT_NAME
export S3TESTS_IAM_ROOT_ACCESS_KEY S3TESTS_IAM_ROOT_SECRET_KEY S3TESTS_IAM_ROOT_ACCOUNT_ID
export S3TESTS_IAM_ALT_ROOT_ACCESS_KEY S3TESTS_IAM_ALT_ROOT_SECRET_KEY S3TESTS_IAM_ALT_ROOT_ACCOUNT_ID

# --- the system under test ---------------------------------------------------------------
# Keep the configuration names literal in the command: sut_start logs the launch shape, and
# expanding credential values here would put workflow secrets in that log. bash -c expands the
# already-exported values only in the child that launches the compatibility SUT.
: "${GATEWAY_SUT_COMMAND:=${ROOT_DIR}/target/release/compat-sut \
    --data \"${WORK_DIR}/compat-sut-data\" \
    --host \"\$S3TESTS_HOST\" \
    --port \"\$S3TESTS_PORT\" \
    --region \"\$S3TESTS_REGION\" \
    --access-key \"\$S3TESTS_MAIN_ACCESS_KEY\" \
    --secret-key \"\$S3TESTS_MAIN_SECRET_KEY\" \
    --owner-id \"\$S3TESTS_MAIN_USER_ID\" \
    --display-name \"\$S3TESTS_MAIN_DISPLAY_NAME\" \
    --alt-access-key \"\$S3TESTS_ALT_ACCESS_KEY\" \
    --alt-secret-key \"\$S3TESTS_ALT_SECRET_KEY\" \
    --alt-owner-id \"\$S3TESTS_ALT_USER_ID\" \
    --alt-display-name \"\$S3TESTS_ALT_DISPLAY_NAME\" \
    --lc-debug-interval \"\$S3TESTS_LC_DEBUG_INTERVAL\"}"
export GATEWAY_SUT_COMMAND
export GATEWAY_SUT_HOST="${GATEWAY_SUT_HOST:-$S3TESTS_HOST}"
export GATEWAY_SUT_PORT="${GATEWAY_SUT_PORT:-$S3TESTS_PORT}"
sut_start
# The suite reaches the service through the rendered configuration, so the two must agree
# about where it is even when the endpoint was supplied rather than launched.
S3TESTS_HOST="$SUT_HOST"
S3TESTS_PORT="$SUT_PORT"
export S3TESTS_HOST S3TESTS_PORT

CONF="${WORK_DIR}/s3tests.conf"
sut_render "${ROOT_DIR}/ci/s3tests/s3tests.conf.tmpl" "$CONF"

# --- the suite ---------------------------------------------------------------------------
SUITE_DIR="${WORK_DIR}/s3-tests"
if [[ ! -d "${SUITE_DIR}/.git" ]]; then
    git clone --quiet "$S3TESTS_REPOSITORY" "$SUITE_DIR" ||
        sut_die "cannot clone ${S3TESTS_REPOSITORY}"
fi
git -C "$SUITE_DIR" fetch --quiet origin "$S3TESTS_SHA" 2>/dev/null ||
    git -C "$SUITE_DIR" fetch --quiet origin ||
    sut_die "cannot fetch ${S3TESTS_SHA} from ${S3TESTS_REPOSITORY}"
git -C "$SUITE_DIR" checkout --quiet --detach "$S3TESTS_SHA" ||
    sut_die "cannot check out the pinned commit ${S3TESTS_SHA}"

# Assert the pin rather than trusting the checkout. A `git checkout` that silently landed
# somewhere else would make every subsequent weekly result incomparable with the last one,
# and nothing downstream would say so.
CHECKED_OUT="$(git -C "$SUITE_DIR" rev-parse HEAD)"
if [[ "$CHECKED_OUT" != "$S3TESTS_SHA" ]]; then
    sut_die "the suite is at ${CHECKED_OUT} but ci/s3tests/pins.env pins ${S3TESTS_SHA}"
fi
printf 'run: ceph/s3-tests is at the pinned commit %s\n' "$CHECKED_OUT"

JUNIT="${OUT_DIR}/s3tests-junit.xml"
COLLECT_LOG="${OUT_DIR}/collected.txt"

command -v tox >/dev/null 2>&1 || sut_die "tox is not installed; the suite is run through its own tox environment"

# Collection is reported separately so the summary can state how many cases the filter
# actually selected. A filter that silently selects nothing is the failure mode that makes
# an all-green report meaningless.
(
    cd "$SUITE_DIR"
    S3TEST_CONF="$CONF" S3_USE_SIGV4=1 tox -- --collect-only -q -m "$FILTER"
) >"$COLLECT_LOG" 2>&1 || true
# Two independent readings of the same number: pytest's own trailing "N tests collected"
# line, and a count of the collected node ids. If the first is absent the format changed,
# and falling back to the second is better than reporting a zero nobody would question.
COLLECTED="$(sed -nE 's/^([0-9]+)(\/[0-9]+)? +tests? +collected.*/\1/p' "$COLLECT_LOG" | tail -n 1)"
if [[ -z "$COLLECTED" ]]; then
    COLLECTED="$(grep -cE '::test_' "$COLLECT_LOG" || true)"
fi
printf 'run: the filter selected %s case(s)\n' "$COLLECTED"
# Measured at the pinned commit with the checked-in filter: 740 of 1053, 313 deselected. The
# floor is below that and far above what a broken configuration yields, because the failure
# this catches is silent — a section missing from the rendered configuration raises inside a
# module import, every case in that module vanishes, and pytest reports a small green run
# rather than an error. Measured once at 55 of 1053, from one absent option.
# The suite is pinned, so this number only moves when somebody removes an exclusion, which
# only ever raises it.
if [[ "${COLLECTED:-0}" -lt "${S3TESTS_MINIMUM_CASES:-700}" ]]; then
    printf 'run: the last 40 lines of the collection log follow\n' >&2
    tail -n 40 "$COLLECT_LOG" | sed 's/^/  /' >&2
    sut_die "collection selected ${COLLECTED} case(s), fewer than the ${S3TESTS_MINIMUM_CASES:-700} a
  working checkout of this suite must yield. Something is wrong with the checkout, the
  configuration or the filter — not with the implementation."
fi

set +e
(
    cd "$SUITE_DIR"
    S3TEST_CONF="$CONF" S3_USE_SIGV4=1 tox -- -m "$FILTER" --junitxml="$JUNIT"
)
SUITE_STATUS="$?"
set -e
printf 'run: pytest exited %s\n' "$SUITE_STATUS"
[[ -f "$JUNIT" ]] || sut_die "the suite produced no JUnit document at ${JUNIT}"

# --- the verdict -------------------------------------------------------------------------
REPORT_ARGS=(
    --junit "$JUNIT"
    --xfail "${ROOT_DIR}/ci/s3tests/xfail.txt"
    --markdown "${OUT_DIR}/summary.md"
    --json "${OUT_DIR}/report.json"
)
if [[ "$MODE" == "record" ]]; then
    REPORT_ARGS+=(--record "${OUT_DIR}/xfail.proposed.txt")
fi
set +e
python3 "${ROOT_DIR}/ci/s3tests/report.py" "${REPORT_ARGS[@]}"
REPORT_STATUS="$?"
set -e
printf 'run: report exited %s (artifacts in %s)\n' "$REPORT_STATUS" "$OUT_DIR"
exit "$REPORT_STATUS"
