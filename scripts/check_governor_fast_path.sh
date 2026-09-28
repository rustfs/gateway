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
fi
# c-lim-0004: the object-safe boundary decides through the synchronous path and nothing else.
boundary="$(sed -n '/^impl Governor for DefaultGovernor {$/,/^}$/p' "$SOURCE")"
if ! grep -qF 'let decided = self.try_acquire_sync(request).ok_or(());' <<<"$boundary"; then
    fail 'c-lim-0004 the Governor boundary no longer decides through try_acquire_sync'
fi

# c-gov-0012: a load refusal logs nothing request-derived, because the governor logs nothing.
for governor_source in "$INTERFACE" "$SOURCE" "$(dirname "$SOURCE")/meter.rs" "$(dirname "$SOURCE")/rates.rs"; do
    if [[ ! -f "$governor_source" ]]; then
        fail "governor source ${governor_source#"$ROOT_DIR"/} is missing"
    elif grep -nE '\b(e?println|e?print|dbg|tracing::[a-z_]+|log::[a-z_]+|trace|debug|info|warn|error)!' "$governor_source" >/dev/null; then
        fail "c-gov-0012 ${governor_source#"$ROOT_DIR"/} logs; a refusal for load must not interpolate request-derived content anywhere"
    fi
done

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
governor_request_interface="$(sed -n "/^impl<'a> GovernorRequest<'a> {$/,/^}$/p" "$INTERFACE")"
grep -qF 'pub(crate) const fn new(' <<<"$governor_request_interface" \
    || fail 'GovernorRequest construction is no longer framework-owned'
if grep -Eq '^[[:space:]]+pub (operation|bucket|declared_body_bytes|identity|client_addr|kind):' "$INTERFACE"; then
    fail 'GovernorRequest exposes writable framework-owned fields'
fi

if [[ "$status" == 0 ]]; then
    printf 'OK: c-lim-0004 binds the admitted governor path to the synchronous nonallocating implementation\n'
fi
exit "$status"
