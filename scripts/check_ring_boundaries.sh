#!/usr/bin/env bash
set -euo pipefail

# Checks the permanent ring-0/1 prohibition and the one dated compat-s3s
# exception from AGENTS.md. Parsing lives with the internal DAG guard so renamed,
# workspace-inherited and target-specific dependencies have one interpretation.
# There is no allowance for a dependency cycle.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_LAYER_MODE=ring exec "${SCRIPT_DIR}/check_layer_dependencies.sh"
