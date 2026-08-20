#!/usr/bin/env bash
set -euo pipefail

# WHAT: Pins the three transport-owned idle timeout layers, rejects body/handler ownership, and keeps
#       the write-progress layer's thousand-slow-reader load evidence executable.
# WHY: rustfs/backlog#1699 assigns three of six progress layers to transport; connection lifetime is an extra safety valve.
# EXEMPTIONS: None. Moving ownership requires changing the task contract first.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
CONFIG="${ROOT_DIR}/crates/server/src/config.rs"
SOURCE_DIR="${ROOT_DIR}/crates/server/src"
TLS_EVIDENCE="${ROOT_DIR}/crates/server/tests/tls_h2.rs"
LOAD_EVIDENCE="${ROOT_DIR}/crates/server/tests/server_load.rs"

if [[ ! -f "$CONFIG" ]]; then
    printf 'check_timeout_layer_ownership: required config is missing: %s\n' "$CONFIG" >&2
    exit 1
fi

if [[ ! -f "$TLS_EVIDENCE" || -L "$TLS_EVIDENCE" ]]; then
    printf 'check_timeout_layer_ownership: c-lim-0062 TLS evidence is missing or not a regular file\n' >&2
    exit 1
fi

if [[ ! -f "$LOAD_EVIDENCE" || -L "$LOAD_EVIDENCE" ]]; then
    printf 'check_timeout_layer_ownership: c-lim-0061 load evidence is missing or not a regular file\n' >&2
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

python3 - "$LOAD_EVIDENCE" <<'PY'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
mixed_match = re.search(
    r"#\[tokio::test\]\s+"
    r"async fn c_lim_0006_a_srv_0008_one_thousand_connections_stay_inside_the_rss_budget\(\)\s*\{",
    source,
)
if mixed_match is None:
    raise SystemExit("check_timeout_layer_ownership: c-lim-0006 executable load evidence is missing")
depth = 1
cursor = mixed_match.end()
while cursor < len(source) and depth:
    depth += (source[cursor] == "{") - (source[cursor] == "}")
    cursor += 1
if depth:
    raise SystemExit("check_timeout_layer_ownership: c-lim-0006 test body is unterminated")
mixed_body = source[mixed_match.end() : cursor - 1]
if re.search(r"#\s*\[\s*cfg(?:_attr)?\b", mixed_body):
    raise SystemExit("check_timeout_layer_ownership: c-lim-0006 evidence is conditionally disabled")
mixed_required = (
    "growth <= budget + budget / 2,",
    "for _ in 1..WAVES {",
    "let tail_mean = tail_growth / (WAVES - 1);",
    "let ballast_seen = resident_growth_ps_can_see()",
    "if ballast_seen < BALLAST_BYTES / BALLAST_SHARE_SEEN {",
    "if first_growth < MIN_SCALE {",
    "let reuse_ceiling = first_growth / TAIL_SHARE_OF_FIRST;",
    "tail_mean <= reuse_ceiling,",
)
mixed_missing = [fragment for fragment in mixed_required if fragment not in mixed_body]
if mixed_missing:
    raise SystemExit(
        "check_timeout_layer_ownership: c-lim-0006 does not prove bounded multi-wave reuse with a working RSS instrument: "
        + ", ".join(mixed_missing)
    )
if "REUSE_SLACK" in mixed_body:
    raise SystemExit("check_timeout_layer_ownership: c-lim-0006 returned to a hardcoded single-wave RSS ceiling")

match = re.search(
    r'#\[tokio::test\(flavor = "multi_thread", worker_threads = 4\)\]\s+'
    r"async fn c_lim_0061_a_srv_0026_one_thousand_slow_readers_close_without_starving_healthy_traffic\(\)\s*\{",
    source,
)
if match is None:
    raise SystemExit("check_timeout_layer_ownership: c-lim-0061 executable load evidence is missing")
preceding = [line for line in source[: match.start()].rstrip().splitlines() if line.strip()]
while preceding and preceding[-1].lstrip().startswith("///"):
    preceding.pop()
if not preceding or not preceding[-1].rstrip().endswith("}"):
    raise SystemExit("check_timeout_layer_ownership: c-lim-0061 is disabled or survives only as a decoy")

depth = 1
cursor = match.end()
while cursor < len(source) and depth:
    depth += (source[cursor] == "{") - (source[cursor] == "}")
    cursor += 1
if depth:
    raise SystemExit("check_timeout_layer_ownership: c-lim-0061 test body is unterminated")
body = source[match.end() : cursor - 1]
if re.search(r"#\s*\[\s*cfg(?:_attr)?\b", body):
    raise SystemExit("check_timeout_layer_ownership: c-lim-0061 evidence is conditionally disabled")
required = (
    # Two listeners built the same way, so that the parked readers are the only difference between
    # the loaded one and the control its latency is measured against.
    "let (loaded_runtime, loaded) = server_on_own_runtime(",
    "let (control_runtime, control) = server_on_own_runtime(",
    # Both directions of the latency observation, sampled in lock-step rather than one taken
    # several seconds of unrelated host activity away from the other.
    "paired_probe_p99(control.local_addr, loaded.local_addr, PROBES, PROBE_CEILING)",
    "loaded_probes.p99 <= ceiling,",
    # A stalled probe is charged the ceiling and the ceiling lands in the tail the rank discards,
    # so the percentile alone cannot see a handful of unanswered probes.
    "loaded_probes.stalled <= control_probes.stalled,",
    # A host that cannot answer the idle control listener is skipped with its reason, not passed on
    # two saturated percentiles that compare equal because both were charged the ceiling.
    "if control_probes.stalled > 0 {",
    # Resident memory while the wave is parked, and again across the identical waves that follow.
    "parked_growth <= parked_budget,",
    "tail_mean <= reuse_ceiling,",
    # More than one further wave, so that the claim is a trend and not one reading, and the tail is
    # averaged over samples rather than resting on whichever way a single one happened to round.
    "for _ in 1..WAVES {",
    # The ceiling is derived from the first wave's own growth. A constant here is what made this
    # case fail one run in three on healthy trees: 8 MiB is the noise floor of a `ps` reading taken
    # across a thousand connections, so a hardcoded bound measures the host and not the server.
    "let reuse_ceiling = first_growth / TAIL_SHARE_OF_FIRST;",
    # A host whose first wave shows no scale is reported, not passed against a ceiling near zero.
    "if first_growth < MIN_SCALE {",
    # The positive control for `ps` itself, and the gate that keeps the reuse assertion from
    # running where it could not go red. On macOS a resident-set delta cannot see retained memory
    # at all, so without this the whole reading is a green line that had no other option.
    "let ballast_seen = resident_growth_ps_can_see()",
    "if ballast_seen < BALLAST_BYTES / BALLAST_SHARE_SEEN {",
    "let first_closure = retire_slow_readers(first_wave, &loaded.metrics).await;",
    "closures.push(retire_slow_readers(wave, &loaded.metrics).await);",
)
# The harness races the write-progress deadline for every connection's first byte, and a reader it
# loses that race for reports end of file rather than a byte. Tolerating that silently would let a
# wave that never opened a single window still be timed as though it had, so the count is bounded.
stall = re.search(r"async fn stall_slow_readers\(.*?\n\}\n", source, re.S)
if stall is None:
    raise SystemExit("check_timeout_layer_ownership: c-lim-0061 slow-reader stall helper is missing")
for fragment in (
    "retired_early <= requested / EARLY_RETIREMENT_SHARE,",
    # Each reader driven by its own task, so a thousand first bytes are waited on at once rather
    # than one behind another, which is what made the harness lose that race in the first place.
    "tokio::spawn(async move {",
):
    if fragment not in stall.group(0):
        raise SystemExit(
            "check_timeout_layer_ownership: c-lim-0061 does not bound readers retired before their first byte: "
            + fragment
        )

missing = [fragment for fragment in required if fragment not in body]
if missing:
    raise SystemExit(
        "check_timeout_layer_ownership: c-lim-0061 does not prove closure, latency and memory together: "
        + ", ".join(missing)
    )

# The two deadline settings live in the configuration both listeners share, so they are pinned
# where they are written and then followed back into the builder the case actually calls: a shared
# configuration proves nothing while nothing checks that the listeners are built out of it.
config = re.search(r"fn slow_reader_config\(\) -> ServerConfig \{(.*?)\n\}\n", source, re.S)
if config is None:
    raise SystemExit("check_timeout_layer_ownership: c-lim-0061 shared listener configuration is missing")
deadlines = (
    # The write-progress layer, and a keep-alive gap far enough away that it cannot be the layer
    # that retired the readers in its place.
    "config.write_progress_timeout = Duration::from_secs(3);",
    "config.keep_alive_idle = Duration::from_secs(60);",
)
missing = [fragment for fragment in deadlines if fragment not in config.group(1)]
if missing:
    raise SystemExit(
        "check_timeout_layer_ownership: c-lim-0061 does not pin the write-progress layer as the only "
        "one that can retire a parked reader: " + ", ".join(missing)
    )

builder = re.search(
    r"fn server_on_own_runtime\(.*?\) -> \(tokio::runtime::Runtime, RunningServer\) \{(.*?)\n\}\n",
    source,
    re.S,
)
if builder is None:
    raise SystemExit("check_timeout_layer_ownership: c-lim-0061 listener builder is missing")
if "Server::new(slow_reader_config(), service)" not in builder.group(1):
    raise SystemExit(
        "check_timeout_layer_ownership: c-lim-0061 builds its listeners from some configuration other "
        "than the one its deadlines are pinned in"
    )
if "new_multi_thread()" not in builder.group(1):
    raise SystemExit(
        "check_timeout_layer_ownership: c-lim-0061 no longer starts each listener on a worker pool of "
        "its own, so whatever starved the loaded listener would starve the control beside it"
    )
PY

printf 'OK: 3/6 timeout layers owned by rustfs-gateway-server; connection lifetime is an extra safety valve\n'
printf 'OK: c-lim-0006 observes bounded multi-wave connection memory with a working RSS instrument\n'
printf 'OK: c-lim-0061 observes write-progress closure, healthy p99 against a concurrently sampled control, and resident memory under a thousand slow readers\n'
