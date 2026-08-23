#!/usr/bin/env bash
# a-asm-0018: a second hot configuration load or a missing real pipeline stage is a violation.
# One ArcSwap load at request entry keeps hot configuration coherent for the whole request.
set -euo pipefail

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SOURCE_ROOT="${ROOT_DIR}/crates/gateway/src"
ALLOWLIST="${ROOT_DIR}/scripts/config_load_allowlist.txt"
RUNTIME_EVIDENCE="${ROOT_DIR}/crates/gateway/tests/service_config.rs"

fail() {
    printf 'check_config_load_once: %s\n' "$1" >&2
    exit 1
}

[[ -d "$SOURCE_ROOT" ]] || fail 'gateway source tree is missing'
[[ -f "${SOURCE_ROOT}/config.rs" ]] || fail 'the hot-configuration store is missing'
[[ -f "$ALLOWLIST" ]] || fail 'scripts/config_load_allowlist.txt is missing'
[[ -f "$RUNTIME_EVIDENCE" ]] || fail 'c-lim-0005 runtime evidence is missing'

actual="$({
    cd "$ROOT_DIR"
    grep -RInE '(\.|::)(load|load_full)([^[:alnum:]_]|$)' crates/gateway/src --include='*.rs' \
        | cut -d: -f1,2 \
        | LC_ALL=C sort
} || true)"
expected="$(grep -Ev '^[[:space:]]*(#|$)' "$ALLOWLIST" | LC_ALL=C sort)"

[[ -n "$actual" ]] || fail 'no hot-configuration load exists'
[[ "$actual" == "$expected" ]] || {
    printf 'check_config_load_once: expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    exit 1
}
[[ "$(grep -c '^crates/gateway/src/service.rs:313$' <<<"$expected")" == 1 ]] \
    || fail 'the one request-entry configuration load is not allowlisted exactly once'

stages="$(grep -oE '\.(accepted|routed|governed|authenticated|route_authorized|body_read|decoded|input_authorized)\(' \
    "${SOURCE_ROOT}/service.rs" | tr -d '.(')"
expected_stages="$(printf '%s\n' accepted routed governed authenticated route_authorized body_read decoded input_authorized)"
[[ "$stages" == "$expected_stages" ]] \
    || fail 'the real S3Service path no longer consumes the snapshot through all eight stages in order'

python3 - "${SOURCE_ROOT}/service.rs" "${SOURCE_ROOT}/request_config.rs" <<'PY'
from pathlib import Path
import sys

service = Path(sys.argv[1]).read_text(encoding="utf-8")
request_config = Path(sys.argv[2]).read_text(encoding="utf-8")
capture = """        let request_cancellation = request.extensions().get::<tokio::sync::watch::Receiver<bool>>().cloned();
        let config = RequestConfig::enter(config).with_request_cancellation(request_cancellation);
"""
if service.count(capture) != 1:
    raise SystemExit("check_config_load_once: request entry does not capture cancellation beside its one snapshot")
for fragment in (
    "request_cancellation: Option<tokio::sync::watch::Receiver<bool>>,",
    "self.request_cancellation = request_cancellation;",
    "request_cancellation: self.request_cancellation,",
):
    if request_config.count(fragment) != 1:
        raise SystemExit("check_config_load_once: request cancellation does not cross every typed snapshot stage")
PY

python3 - "$RUNTIME_EVIDENCE" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
signature = "async fn c_lim_0005_hot_update_does_not_tear_an_inflight_request() {"
if text.count(signature) != 1:
    raise SystemExit("check_config_load_once: c-lim-0005 active runtime evidence is missing or duplicated")

lines = text.splitlines()
index = lines.index(signature)
attributes = []
cursor = index - 1
while cursor >= 0 and lines[cursor].startswith("#["):
    attributes.append(lines[cursor])
    cursor -= 1
if attributes != ["#[tokio::test]"]:
    raise SystemExit("check_config_load_once: c-lim-0005 must be one unconditional tokio test")
if cursor < 0 or "c-lim-0005" not in lines[cursor]:
    raise SystemExit("check_config_load_once: c-lim-0005 runtime evidence lost its case identity")

end_marker = "\n}\n\n/// Regression: reconfiguring a builder"
start = text.index(signature)
end = text.find(end_marker, start)
if end < 0:
    raise SystemExit("check_config_load_once: c-lim-0005 runtime evidence has no bounded function body")
body = text[start:end]
required = (
    "wired().config(ServiceConfig::new(8))",
    "UpdatingFilter::new(handle.clone(), ServiceConfig::new(32))",
    "assert_eq!(first.status(), http::StatusCode::PAYLOAD_TOO_LARGE);",
    "assert_eq!(second.status(), http::StatusCode::OK);",
)
for fragment in required:
    if body.count(fragment) != 1:
        raise SystemExit(f"check_config_load_once: c-lim-0005 runtime evidence drifted at {fragment!r}")
if "#[cfg" in body:
    raise SystemExit("check_config_load_once: c-lim-0005 runtime evidence is conditionally disabled")
PY

printf 'OK: c-lim-0005 observes one request snapshot; c-lim-0041 locks the sole request-entry load\n'
