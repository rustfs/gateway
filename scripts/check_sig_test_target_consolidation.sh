#!/usr/bin/env bash
set -euo pipefail

# Keep sig integration contracts in one active Cargo target so all-target clippy stays inside the
# repository's 30-second feedback budget. There are no exemptions.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_TEST_TARGET_CRATE=crates/sig \
GATEWAY_TEST_TARGET_MODULES=canonical_request,compile_fail,effective_host,frozen_dimensions,post_form_replay,post_object_form,security_floor,security_floor_presigned,security_floor_schemes,sig_v2,sig_v2_admission,signer_roundtrip,timing,verification_proof \
    exec "${SCRIPT_DIR}/check_xtask_test_target_consolidation.sh"
