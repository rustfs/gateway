#!/usr/bin/env bash
# P7-03: conformance must consume the facade's transport vocabulary instead of cloning it.
set -euo pipefail

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SUT="${ROOT_DIR}/crates/conformance/src/sut.rs"
FACADE="${ROOT_DIR}/crates/gateway/src/transport.rs"

fail() {
    printf 'check_transport_shared: %s\n' "$1" >&2
    exit 1
}

[[ -f "$SUT" ]] || fail 'conformance SUT seam is missing'
[[ -f "$FACADE" ]] || fail 'facade transport vocabulary is missing'

grep -F 'pub use rustfs_gateway::Transport;' "$SUT" >/dev/null \
    || fail 'conformance does not re-export the facade Transport type'
! grep -Eq '^pub enum Transport[[:space:]]*\{' "$SUT" \
    || fail 'conformance defines a second Transport enum'
grep -F 'pub const ALL: [Self; 2] = [Self::Hyper, Self::Conn];' "$FACADE" >/dev/null \
    || fail 'the shared transport census no longer names both production paths'

printf 'OK: conformance and the facade share one two-path Transport type\n'
