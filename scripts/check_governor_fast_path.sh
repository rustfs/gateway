#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
SOURCE="${ROOT_DIR}/crates/gateway/src/ext/governor/default.rs"
BUILDER="${ROOT_DIR}/crates/gateway/src/builder.rs"
SERVICE="${ROOT_DIR}/crates/gateway/src/service.rs"
INTERFACE="${ROOT_DIR}/crates/gateway/src/ext/governor.rs"

status=0

fail() {
    printf 'check_governor_fast_path: %s\n' "$1" >&2
    status=1
}

if [[ ! -f "$SOURCE" || ! -f "$BUILDER" || ! -f "$SERVICE" || ! -f "$INTERFACE" ]]; then
    fail 'a governor guard subject is missing'
    exit "$status"
fi

fast_path="$(sed -n '/pub fn try_acquire_sync/,/^    }/p' "$SOURCE")"
if [[ -z "$fast_path" ]]; then
    fail 'DefaultGovernor::try_acquire_sync is missing'
else
    if grep -Eq 'Box::|Vec::|format!|to_owned\(|\.clone\(' <<<"$fast_path"; then
        fail 'the synchronous decision path contains an allocating operation'
    fi
    auth_line="$(grep -nF 'ClassKind::Authenticated => return Some(Lease::admit())' <<<"$fast_path" | cut -d: -f1)"
    clock_line="$(grep -nF 'self.clock.monotonic()' <<<"$fast_path" | cut -d: -f1)"
    if [[ -z "$auth_line" || -z "$clock_line" || "$auth_line" -ge "$clock_line" ]]; then
        fail 'authenticated traffic no longer returns before the clock and address locks'
    fi
fi

shards="$(sed -n 's/^const CLIENT_SHARDS: usize = \([0-9][0-9]*\);$/\1/p' "$SOURCE")"
if [[ -z "$shards" || "$shards" -le 1 ]]; then
    fail 'the client map is not split across more than one shard'
fi

grep -qF 'aggregate: AtomicMeter' "$SOURCE" || fail 'the aggregate meter is no longer atomic'
grep -qF 'credential_lookup: AtomicMeter' "$SOURCE" || fail 'the credential class meter is no longer atomic'
grep -qF 'entries: HashMap::with_capacity(capacity)' "$SOURCE" \
    || fail 'the client map is no longer preallocated outside the decision path'
grep -qF 'LayeredGovernor::new(framework_governor, user)' "$BUILDER" \
    || fail 'a user governor no longer remains ANDed with the framework governor'
grep -qF 'request.extensions().get::<ClientAddr>()' "$SERVICE" \
    || fail 'the client address no longer comes from transport extensions'
if grep -qiF 'x-forwarded-for' "$SERVICE"; then
    fail 'the service reads an untrusted forwarding header for governor input'
fi
grep -qF 'pub(crate) const fn new(' "$INTERFACE" \
    || fail 'GovernorRequest construction is no longer framework-owned'
if grep -Eq '^[[:space:]]+pub (operation|bucket|declared_body_bytes|identity|client_addr|kind):' "$INTERFACE"; then
    fail 'GovernorRequest exposes writable framework-owned fields'
fi

exit "$status"
