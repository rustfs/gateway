#!/usr/bin/env bash
set -euo pipefail

# Keep ext-field integration contracts in one active Cargo target so all-target clippy stays inside the
# repository's 30-second feedback budget. There are no exemptions.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_TEST_TARGET_CRATE=spikes/ext-field \
GATEWAY_TEST_TARGET_MODULES=roundtrip,security,unknown_elements \
    exec "${SCRIPT_DIR}/check_xtask_test_target_consolidation.sh"
