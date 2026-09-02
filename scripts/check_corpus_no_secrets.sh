#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_corpus_no_secrets.sh
#
# WHAT THIS CHECKS
#   Nothing under `corpus/` carries credential material: no live `authorization`,
#   `cookie`, `x-amz-security-token` or SSE-C customer key; no presigned
#   `X-Amz-Signature`/`X-Amz-Credential`; no AWS secret access key, PEM private key,
#   JSON Web Token, SigV4 signature or credential assignment, in a header value, a
#   request target, or a base64 payload once it is decoded. It reports file and line.
#
# WHY
#   rustfs/backlog#1763 names credential leakage as the task's top risk: a corpus that
#   contains a real credential is an irreversible repository leak, and `git rm` does not
#   undo it. `rustfs-gateway-corpus`'s own gate refuses such an entry at ingest — but a
#   guard that shares an implementation with the thing it guards fails in exactly the
#   places that implementation is wrong, and a file can reach `corpus/` by hand, by
#   merge, or by a `--force` nobody reviewed. This scanner is written independently, in
#   a different language, from the same rules, and runs in CI and pre-commit both. Its
#   value is the disagreement it can produce, not the agreement.
#
# HOW TO EXEMPT
#   There is no exemption. Remove the material, or replace the field with the fixed
#   `__REDACTED__` placeholder and list its name in the entry's `redacted` array.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

command -v python3 >/dev/null 2>&1 || {
    printf 'check_corpus_no_secrets: required command is missing: python3\n' >&2
    exit 1
}

if [[ ! -d "${ROOT_DIR}/corpus" ]]; then
    printf 'check_corpus_no_secrets: required input is missing: corpus/\n' >&2
    exit 1
fi

python3 "${SCRIPT_DIR}/lib/corpus_secret_scan.py" "$ROOT_DIR"
