#!/usr/bin/env bash
set -euo pipefail

# WHAT: Pins the three transport-owned idle timeout layers and rejects body/handler ownership.
# WHY: rustfs/backlog#1699 assigns three of six progress layers to transport; connection lifetime is an extra safety valve.
# EXEMPTIONS: None. Moving ownership requires changing the task contract first.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
CONFIG="${ROOT_DIR}/crates/server/src/config.rs"
SOURCE_DIR="${ROOT_DIR}/crates/server/src"
TLS_EVIDENCE="${ROOT_DIR}/crates/server/tests/tls_h2.rs"

if [[ ! -f "$CONFIG" ]]; then
    printf 'check_timeout_layer_ownership: required config is missing: %s\n' "$CONFIG" >&2
    exit 1
fi

if [[ ! -f "$TLS_EVIDENCE" || -L "$TLS_EVIDENCE" ]]; then
    printf 'check_timeout_layer_ownership: c-lim-0062 TLS evidence is missing or not a regular file\n' >&2
    exit 1
fi

if ! command -v grep >/dev/null 2>&1; then
    printf 'check_timeout_layer_ownership: required command is missing: grep\n' >&2
    exit 1
fi

required=(header_read_timeout write_progress_timeout keep_alive_idle)
for field in "${required[@]}"; do
    if ! grep -q -E "pub ${field}:" "$CONFIG"; then
        printf 'check_timeout_layer_ownership: missing transport timeout field %s\n' "$field" >&2
        exit 1
    fi
done

if ! grep -q -E 'pub connection_lifetime:' "$CONFIG"; then
    printf 'check_timeout_layer_ownership: missing extra connection-lifetime safety valve\n' >&2
    exit 1
fi

if grep -R -n -i -E --include='*.rs' \
    '(first_body_byte_(timeout|idle|interval)|body_read_(timeout|idle|interval)|handler(_progress)?_(timeout|deadline)|handler_deadline)' \
    "$SOURCE_DIR"; then
    printf 'check_timeout_layer_ownership: first-body, body-read, and handler timeouts belong outside the server runtime\n' >&2
    exit 1
fi

python3 - "$TLS_EVIDENCE" <<'PY'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(
    r"#\[tokio::test\]\s+async fn c_lim_0062_a_srv_0015_per_ip_half_open_limit_and_header_deadline_recover\(\)\s*\{",
    source,
)
if match is None:
    raise SystemExit("check_timeout_layer_ownership: c-lim-0062 executable TLS evidence is missing")
if not source[:match.start()].rstrip().endswith("}"):
    raise SystemExit("check_timeout_layer_ownership: c-lim-0062 is disabled or survives only as a decoy")

depth = 1
cursor = match.end()
while cursor < len(source) and depth:
    depth += (source[cursor] == "{") - (source[cursor] == "}")
    cursor += 1
if depth:
    raise SystemExit("check_timeout_layer_ownership: c-lim-0062 test body is unterminated")
body = source[match.end():cursor - 1]
if re.search(r"#\s*\[\s*cfg(?:_attr)?\b", body):
    raise SystemExit("check_timeout_layer_ownership: c-lim-0062 evidence is conditionally disabled")
required = (
    "server_config.max_connections_per_ip = Some(2);",
    "server_config.header_read_timeout = Duration::from_millis(50);",
    "metrics.per_ip_rejections() != 1",
    "assert_eq!(tls.handshake_count(), 2",
    "metrics.active_connections() != 0",
    "tls_connect(local_addr, certificate).await",
    "request_keep_alive(&mut recovered).await.starts_with(",
)
missing = [fragment for fragment in required if fragment not in body]
if missing:
    raise SystemExit(
        "check_timeout_layer_ownership: c-lim-0062 does not prove both rejection and deadline recovery: "
        + ", ".join(missing)
    )
PY

printf 'OK: 3/6 timeout layers owned by rustfs-gateway-server; connection lifetime is an extra safety valve\n'
