#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# WHAT THIS CHECKS
#   The P8-01 case schema still expresses all nine day-one dimensions: timed
#   chunks, abnormal termination, mid-stream errors, clock injection,
#   connection reuse, response events, byte-exact goldens, header sets, and a
#   runner-injected transport.
#
# WHY
#   Removing one of these fields after cases exist makes the frozen format
#   unable to describe the hangs and wire-level regressions it was created for.
#
# HOW TO EXEMPT
#   There is no exemption. Changing the frozen schema uses the Breaking Change
#   process in AGENTS.md and must update this guard in the same review.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

python3 - "$REPO_DIR" <<'PYEOF'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
schema_path = root / "conformance/case.schema.json"
runner_path = root / "crates/conformance/src/cli.rs"

try:
    schema = json.loads(schema_path.read_text())
    runner = runner_path.read_text()
except (OSError, json.JSONDecodeError) as error:
    print(f"check_schema_dimensions: {error}", file=sys.stderr)
    raise SystemExit(1)

defs = schema.get("$defs", {})

def properties(name):
    node = defs.get(name, {})
    value = node.get("properties", {}) if isinstance(node, dict) else {}
    return value if isinstance(value, dict) else {}

def enum_values(owner, field):
    node = properties(owner).get(field, {})
    value = node.get("enum", []) if isinstance(node, dict) else []
    return set(value) if isinstance(value, list) else set()

def condition_requires(kind, field):
    for condition in defs.get("expect", {}).get("allOf", []):
        expected = condition.get("if", {}).get("properties", {}).get("kind", {}).get("const")
        required = condition.get("then", {}).get("required", [])
        if expected == kind and field in required:
            return True
    return False

checks = {
    "chunk arrival timing": "delay_ms" in properties("dataChunk"),
    "abnormal termination": {"close", "rst", "half_close"}.issubset(enum_values("controlChunk", "action")),
    "mid-stream error": (
        "stream_error" in enum_values("expect", "kind")
        and "body_bytes_before_error" in properties("expect")
        and condition_requires("stream_error", "body_bytes_before_error")
    ),
    "clock injection": {"fixed", "skew_ms"}.issubset(properties("clock")),
    "connection reuse": (
        "reuse" in properties("connection")
        and "exchanges" in schema.get("properties", {})
    ),
    "response events": (
        "event_stream" in enum_values("expect", "kind")
        and "events" in properties("expect")
        and condition_requires("event_stream", "events")
    ),
    "byte-exact golden": "golden" in properties("bodyExpectation"),
    "header set assertions": {"headers_exact", "headers_absent"}.issubset(properties("expect")),
    "runner-injected transport": (
        "transport" not in schema.get("properties", {})
        and "Transport::Hyper" in runner
        and "Transport::Conn" in runner
    ),
}

missing = [name for name, present in checks.items() if not present]
if missing:
    for name in missing:
        print(f"check_schema_dimensions: missing {name}", file=sys.stderr)
    raise SystemExit(1)

print("OK: 9/9 dimensions present in schema")
PYEOF
