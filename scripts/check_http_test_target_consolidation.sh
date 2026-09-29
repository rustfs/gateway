#!/usr/bin/env bash
set -euo pipefail
# The `http` crate's twenty integration sources link as one Cargo test target (rustfs/gateway#277
# phase 2). `tests/support/` is the harness-owned fixture module every suite reaches through
# `crate::support`; a suite that declares `mod support;` itself would link a second copy.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_TEST_TARGET_CRATE=crates/http \
GATEWAY_TEST_TARGET_MODULES=accepted_transport_extensions,allocation_budget,boundary_guards,checksum_arbitration,chunked_decode_replay,form_allocations,form_grammar,form_legacy_edges,form_limits,framing_smuggling,header_accept_replay,header_and_query,host_ambiguity,ingest_chunk_rss,ingest_chunk_rules,ingest_framing,ingest_known_answer,ingest_perf_gates,ingest_verify,reject_wording \
GATEWAY_TEST_TARGET_FIXTURES=support=support/mod.rs \
    exec "${SCRIPT_DIR}/check_xtask_test_target_consolidation.sh"
