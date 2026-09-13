#!/usr/bin/env bash
# Shared driver helpers.
#
# A driver translates one abstract scenario into one client's commands and prints exactly one
# result object on stdout:
#
#   {"scenario": "<id>", "status": "pass"|"fail"|"unsupported", "detail": "<text>",
#    "evidence": {...}}
#
# `unsupported` is a first-class status and never a failure: a client that has no way to express a
# scenario has told us nothing about the server, and recording that as a failure would pollute the
# manifest and stop the ratchet from ever moving. It is also not a pass — the summary counts it
# separately and the README table prints it as a skip with its reason.
#
# Everything a driver writes to stderr is captured by the runner and attached to the result, so
# diagnostics belong there rather than on stdout, which must hold the result object and nothing
# else.
#
# The endpoint is `COMPAT_ENDPOINT`, plaintext, and every scenario uses it unless the client can
# express that scenario only over TLS. For those, the runner also exports `COMPAT_TLS_ENDPOINT`
# (`https://`, the same server, data root and probe log) and `COMPAT_CA_BUNDLE`, the PEM authority
# that is the only thing a driver may trust for it. Never disable verification instead: a client
# that skips it is a different client from the one the manifest names.

emit() {
    local scenario="$1" status="$2" detail="${3:-}"
    COMPAT_EMIT_SCENARIO="$scenario" COMPAT_EMIT_STATUS="$status" COMPAT_EMIT_DETAIL="$detail" \
        python3 -c 'import json, os; print(json.dumps({"scenario": os.environ["COMPAT_EMIT_SCENARIO"], "status": os.environ["COMPAT_EMIT_STATUS"], "detail": os.environ["COMPAT_EMIT_DETAIL"], "evidence": {}}))'
}

unsupported() {
    emit "$1" unsupported "$2"
    exit 0
}

require_env() {
    local name
    for name in "$@"; do
        if [[ -z "${!name:-}" ]]; then
            printf 'driver: required environment variable %s is unset\n' "$name" >&2
            exit 64
        fi
    done
}
