#!/usr/bin/env bash
set -euo pipefail

# WHAT: Keeps the P3-04 acceptance command as an executable alias of the stronger shared-trailer
# guard, which also rejects RwLock, OnceCell, OnceLock, and aliases of those wrappers.
# WHY: A mutex-only grep would miss the other shared slots that recreate the same early-read race.
# HOW TO EXEMPT: There is no exemption; trailer ownership stays inside an EOF event.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec /bin/bash "${SCRIPT_DIR}/check_no_shared_trailers.sh"
