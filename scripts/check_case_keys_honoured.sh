#!/usr/bin/env bash
set -euo pipefail

# REQUIRES-BUILD
#   This guard compiles and runs the workspace, so it does not belong in CI's
#   `static` job, which is documented as everything deterministic and
#   sub-second. `.github/workflows/ci.yml` reads this marker to decide which job
#   runs it; the split is declared here rather than remembered there, so a guard
#   that starts needing a build cannot silently make the fast job slow.

# =============================================================================
# check_case_keys_honoured.sh
#
# WHAT THIS CHECKS
#   That every key `conformance/case.schema.json` declares is one the
#   conformance harness actually reads — or is written down in
#   `crates/conformance/src/keys.rs::DECLARED` with the reason it is not.
#
#   It runs the whole corpus and then audits the ledger the run filled:
#
#     * a schema key nothing read and nothing declared          -> FAIL
#     * a recorded name the schema does not declare             -> FAIL
#     * a DECLARED entry for a key the schema dropped           -> FAIL
#     * a DECLARED entry the ledger contradicts                 -> FAIL
#     * one source location claiming more than one key          -> FAIL
#     * "unreachable behind X" where X is itself unread          -> FAIL
#     * "unexercised by the corpus" where a case now writes it   -> FAIL
#
# WHY
#   The schema is frozen and enumerates every key a case may write, so a key
#   nothing reads is a key a case can declare into the void. That has happened
#   six times in this suite: a hard-coded `Outcome::Response`, a constant
#   `request_progress`, a `sign_request` that dropped the query tamper, a
#   `contains_utf8` compared against unredacted bytes, and — found by this
#   guard's first run — `setup.buckets[].object_lock` and
#   `connection.pipeline`, both parsed, schema-checked and then dropped. Every
#   one of them produced a green case that measured something other than what
#   it said it measured.
#
#   This guard is a Rust test rather than shell, and that is deliberate:
#   "the harness reads this key" is not a textual property. `region` appears
#   all over `inprocess.rs` and is `sign.region`; the identically spelled
#   `setup.buckets[].region` was read by nothing. Grep cannot tell them apart,
#   and a guard that cannot tell them apart is the same defect one level up.
#   The proof is dynamic: reading a key is what records it, and the field
#   fetched is derived from the name recorded.
#
# HOW TO EXEMPT
#   Add the key to `DECLARED` in `crates/conformance/src/keys.rs` with a
#   disposition (`Inert`, `Unhonoured`, `BehindRefusal`, `Unexercised`) and a
#   reason a maintainer can act on. `Unhonoured` also puts a warning on every
#   case that declares the key, so the gap shows up on the affected case.
#   An entry the schema does not declare, or one the ledger shows as read,
#   fails this guard — the list cannot rot in either direction.
#
# USAGE
#   scripts/check_case_keys_honoured.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_case_keys_honoured.sh
#
#   GATEWAY_CHECK_ROOT selects the CORPUS to audit; the harness that is
#   audited is always the one next to this script, because auditing a harness
#   means compiling and running it and a sandbox has no build cache. That is
#   what makes the self-test in test_guard_scripts.sh affordable: it mutates
#   the schema in the sandbox and this guard runs the real binary against it.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CORPUS_DIR="${GATEWAY_CHECK_ROOT:-$REPO_DIR}/conformance"

if [[ ! -f "${CORPUS_DIR}/case.schema.json" ]]; then
    printf 'check_case_keys_honoured: no corpus at %s\n' "$CORPUS_DIR" >&2
    exit 1
fi

cd "$REPO_DIR"

output=""
status=0
output="$(RUSTFS_GATEWAY_CONFORMANCE_ROOT="$CORPUS_DIR" \
    cargo run -q -p rustfs-gateway-conformance --no-default-features --bin rustfs-gateway-conformance -- audit-keys 2>&1)" || status=$?

if [[ "$status" -ne 0 ]]; then
    printf '%s\n' "$output" >&2
    printf '\ncheck_case_keys_honoured: FAILED\n' >&2
    printf 'A key the frozen schema declares is not read by the harness, or an entry in\n' >&2
    printf 'crates/conformance/src/keys.rs::DECLARED no longer tells the truth.\n' >&2
    exit 1
fi

printf 'check_case_keys_honoured: ok\n'
# Not `| head -1`: under `pipefail` the reader closes the pipe as soon as it has
# its line, and a `printf` that has not finished writing dies of SIGPIPE. Being
# the last command, its status becomes the guard's, so a passing audit exits 1 —
# and which side wins the race depends on machine load, so it passes locally.
printf '%s\n' "${output%%$'\n'*}"
