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
# ci/lib/sut.sh — the one place an external suite gets a system under test.
#
# WHAT THIS IS RESPONSIBLE FOR
#   Producing an endpoint an external suite can be pointed at, waiting until it
#   actually accepts connections, rendering a suite configuration template
#   against the environment, and tearing the process down again.
#
# WHAT IT IS NOT RESPONSIBLE FOR
#   Running any suite, interpreting any result, or knowing anything about
#   s3-tests, mint, or a client matrix. It is shared on purpose: rustfs/backlog#1764
#   and rustfs/backlog#1765 both need exactly this and must not grow two of it.
#
# THE ONE RULE THAT MATTERS
#   A system under test that never came up must NOT look like a failing
#   implementation. Every failure path here exits 3 — the environment code the
#   conformance runner and ci/s3tests/report.py already use — and says which
#   half broke. A suite that records "everything failed" against a dead server
#   poisons the baseline it is measured against ever afterwards.
#
# USAGE
#   source ci/lib/sut.sh
#   sut_start                    # sets SUT_ENDPOINT, SUT_HOST, SUT_PORT
#   trap sut_stop EXIT
#   sut_render <template> <out>  # @NAME@ -> $NAME, refusing unset names
#   sut_external_endpoint <url>  # validate and wait for an endpoint started elsewhere
#   sut_server_header <url>      # that endpoint's own Server header, or nothing
#
# ENVIRONMENT
#   GATEWAY_SUT_ENDPOINT   an already-running `http://host:port` to use as-is.
#                          This is how the workflow is driven against a service
#                          started elsewhere.
#   GATEWAY_SUT_COMMAND    the command line to launch instead of the default.
#   GATEWAY_SUT_HOST/PORT  where the launched process is expected to listen.
#   GATEWAY_SUT_READY_SECONDS  readiness deadline (default 60).
#   GATEWAY_SUT_LOG        where the launched process's output is written.
# =============================================================================

# Environment failures leave with this code everywhere in this repository:
# 0 ok, 1 regression, 2 usage, 3 environment.
SUT_EXIT_ENVIRONMENT=3

SUT_PID=""
SUT_ENDPOINT=""
SUT_HOST=""
SUT_PORT=""
SUT_LOG=""

sut_die() {
    printf 'sut: %s\n' "$*" >&2
    exit "$SUT_EXIT_ENVIRONMENT"
}

# sut_wait_ready <host> <port> <deadline-seconds> [pid]
# Polls a TCP connect until it succeeds. If a pid is given and that process has
# already exited, this stops immediately rather than burning the whole deadline
# waiting for a listener that will never appear.
sut_wait_ready() {
    local host="$1" port="$2" deadline="$3" pid="${4:-}"
    local waited=0
    while ((waited < deadline * 10)); do
        if python3 - "$host" "$port" <<'PY'
import socket
import sys

try:
    with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1):
        pass
except OSError:
    raise SystemExit(1)
raise SystemExit(0)
PY
        then
            return 0
        fi
        if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
            printf 'sut: the system under test exited before it accepted a connection\n' >&2
            return 1
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
    printf 'sut: %s:%s did not accept a connection within %ss\n' "$host" "$port" "$deadline" >&2
    return 1
}

# sut_render <template> <output>
# Replaces every @NAME@ with the environment value of NAME. An unset or empty
# name is refused: a configuration silently rendered with a blank credential
# produces a suite-wide red that reads exactly like an implementation defect.
sut_render() {
    local template="$1" output="$2"
    [[ -f "$template" ]] || sut_die "configuration template is missing: $template"
    python3 - "$template" "$output" <<'PY' || exit "$SUT_EXIT_ENVIRONMENT"
import os
import re
import sys

template, output = sys.argv[1], sys.argv[2]
with open(template, encoding="utf-8") as handle:
    text = handle.read()

missing = []


def substitute(match: "re.Match[str]") -> str:
    name = match.group(1)
    value = os.environ.get(name)
    if not value:
        missing.append(name)
        return ""
    return value


# A comment line is documentation, not configuration. Substituting inside one makes the
# template's own explanation of its placeholder syntax a missing variable — measured, the
# first time this ran end to end.
lines = []
for line in text.splitlines(keepends=True):
    if line.lstrip().startswith(("#", ";")):
        lines.append(line)
    else:
        lines.append(re.sub(r"@([A-Z][A-Z0-9_]*)@", substitute, line))
rendered = "".join(lines)
if missing:
    unique = sorted(set(missing))
    print(f"sut: the configuration template needs these unset variables: {', '.join(unique)}", file=sys.stderr)
    raise SystemExit(1)
with open(output, "w", encoding="utf-8") as handle:
    handle.write(rendered)
print(f"sut: rendered {output}")
PY
}

# sut_external_endpoint <url>
# Validates an external endpoint the way `compat-sut --external` will parse it — `http://host:port`
# and nothing else — waits until it accepts connections, and sets SUT_EXTERNAL_HOST/PORT. Refusing
# here, before an observer is launched, names the operator's URL as the problem rather than leaving
# the observer's own refusal in a log nobody reads.
SUT_EXTERNAL_HOST=""
SUT_EXTERNAL_PORT=""
sut_external_endpoint() {
    local url="$1" authority
    authority="${url#http://}"
    [[ "$authority" != "$url" ]] || sut_die "an external endpoint must be an http://host:port URL, got ${url}"
    authority="${authority%/}"
    [[ "$authority" =~ ^[^/?#@]+:[0-9]+$ ]] || sut_die "an external endpoint must be http://host:port with no path, got ${url}"
    SUT_EXTERNAL_HOST="${authority%:*}"
    SUT_EXTERNAL_PORT="${authority##*:}"
    sut_wait_ready "$SUT_EXTERNAL_HOST" "$SUT_EXTERNAL_PORT" "${GATEWAY_SUT_READY_SECONDS:-60}" ||
        sut_die "the external endpoint ${url} is not accepting connections"
}

# sut_server_header <url>
# Prints the `Server` header of one unsigned `HEAD /` answered by <url>, or nothing when the answer
# carries none. Any status counts — an unsigned request is refused, and the refusal still names the
# server — but no answer at all exits 3: an endpoint that cannot say what it is has not been measured.
sut_server_header() {
    python3 - "$1" <<'PY' || exit "$SUT_EXIT_ENVIRONMENT"
import http.client
import sys
import urllib.parse

url = urllib.parse.urlsplit(sys.argv[1])
try:
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
    connection.request("HEAD", "/")
    server = connection.getresponse().getheader("Server")
except OSError as error:
    print(f"sut: {sys.argv[1]} did not answer HEAD /: {error}", file=sys.stderr)
    raise SystemExit(1)
# The value is echoed into a CI log line and a manifest. One line of printable characters, so a
# folded or control-laden header cannot start a line of its own (a `::` workflow command) there.
print(" ".join("".join(ch if ch.isprintable() else " " for ch in (server or "")).split())[:200])
PY
}

# sut_start
# Produces SUT_ENDPOINT one of two ways, and exits 3 if it cannot.
sut_start() {
    if [[ -n "${GATEWAY_SUT_ENDPOINT:-}" ]]; then
        local authority="${GATEWAY_SUT_ENDPOINT#http://}"
        [[ "$authority" != "$GATEWAY_SUT_ENDPOINT" ]] ||
            sut_die "GATEWAY_SUT_ENDPOINT must be an absolute http:// URL, got ${GATEWAY_SUT_ENDPOINT}"
        authority="${authority%/}"
        SUT_HOST="${authority%%:*}"
        SUT_PORT="${authority##*:}"
        [[ "$SUT_PORT" =~ ^[0-9]+$ ]] || sut_die "GATEWAY_SUT_ENDPOINT has no port: ${GATEWAY_SUT_ENDPOINT}"
        SUT_ENDPOINT="http://${SUT_HOST}:${SUT_PORT}"
        sut_wait_ready "$SUT_HOST" "$SUT_PORT" "${GATEWAY_SUT_READY_SECONDS:-60}" ||
            sut_die "the endpoint supplied in GATEWAY_SUT_ENDPOINT is not accepting connections"
        printf 'sut: using the supplied endpoint %s\n' "$SUT_ENDPOINT"
        return 0
    fi

    if [[ -z "${GATEWAY_SUT_COMMAND:-}" ]]; then
        # There IS a runnable server in this repository now — compat/sut, the `compat-sut`
        # binary — but this library still refuses to guess a command line. Saying so is the
        # whole point: a launcher that quietly produced no endpoint would hand the suite a
        # connection-refused for every case and call it a result, and one that guessed a
        # command would hand it a service configured with credentials the suite does not
        # hold. The caller names the command, and names it once.
        sut_die "no system under test. Set GATEWAY_SUT_ENDPOINT to an already-running S3
  service, or GATEWAY_SUT_COMMAND to a command that starts one and listens on
  GATEWAY_SUT_HOST:GATEWAY_SUT_PORT. This repository ships one: build it with
  \`cargo build --release -p rustfs-gateway-compat-sut\` and launch \`target/release/compat-sut\`
  with --data, --host, --port and the credential flags the suite is configured with
  (\`compat-sut --print-capabilities\` lists what it registers)."
    fi

    SUT_HOST="${GATEWAY_SUT_HOST:-127.0.0.1}"
    SUT_PORT="${GATEWAY_SUT_PORT:-9100}"
    SUT_LOG="${GATEWAY_SUT_LOG:-${TMPDIR:-/tmp}/gateway-sut.log}"
    printf 'sut: launching %s\n' "$GATEWAY_SUT_COMMAND"
    # shellcheck disable=SC2086 # the operator supplies a command line, not one word.
    bash -c "$GATEWAY_SUT_COMMAND" >"$SUT_LOG" 2>&1 &
    SUT_PID="$!"
    if ! sut_wait_ready "$SUT_HOST" "$SUT_PORT" "${GATEWAY_SUT_READY_SECONDS:-60}" "$SUT_PID"; then
        printf 'sut: the last 40 lines of %s follow\n' "$SUT_LOG" >&2
        tail -n 40 "$SUT_LOG" 2>/dev/null | sed 's/^/  /' >&2 || true
        sut_stop
        sut_die "the system under test never became reachable"
    fi
    SUT_ENDPOINT="http://${SUT_HOST}:${SUT_PORT}"
    printf 'sut: %s is up (pid %s)\n' "$SUT_ENDPOINT" "$SUT_PID"
}

# sut_stop
# Idempotent. Safe as an EXIT trap even when sut_start never launched anything.
sut_stop() {
    [[ -n "$SUT_PID" ]] || return 0
    if kill -0 "$SUT_PID" 2>/dev/null; then
        kill -TERM "$SUT_PID" 2>/dev/null || true
        wait "$SUT_PID" 2>/dev/null || true
    fi
    SUT_PID=""
}
