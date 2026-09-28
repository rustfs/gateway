#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_time_gate_on_shared_runner.sh
#
# WHAT THIS CHECKS
#   Every runner this repository uses is a shared org pod, so no wall-clock number
#   may decide a CI result (rustfs/backlog#1766 a-pf-0019), and the release-mode
#   evidence and bench lanes stay out of the pull-request gate (a-pf-0021):
#
#     1. AGENTS.md states the rule.
#     2. benches/baseline.json marks wall-clock measurements, and the policy that
#        governs them, as non-blocking.
#     3. No `assert*!` in crates/*/benches/*.rs names a timing quantity
#        (elapsed, Instant, seconds, micros, nanos, as_secs...). Benches print
#        time; they assert allocations and structure.
#     4. ci.yml, the pull-request workflow, runs no `cargo bench`, no release-mode
#        test, and neither evidence suite; perf-evidence.yml and fuzz-nightly.yml
#        run on neither pull_request nor push.
#
# WHY
#   A shared runner's timing noise is tens of percent. A gate built on it fails for
#   no defect, gets rerun until green, and is then switched off — and the next
#   real regression goes through with it. The paired-control p99 ratio in
#   slow_clients.rs is not covered by rule 3: it is a ratio of two listeners probed
#   in lock-step on the same host, gated generously, and lives outside benches/.
#
# HOW TO EXEMPT
#   There is no exemption. Print the number; gate on counts, bytes or a paired
#   ratio instead.
# =============================================================================

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

python3 - "$ROOT" <<'PY'
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
failures = []


def fail(message):
    failures.append(message)


def read(relative):
    path = root / relative
    if not path.is_file():
        print(f"check_no_time_gate_on_shared_runner: required input is missing: {relative}", file=sys.stderr)
        raise SystemExit(1)
    return path.read_text(encoding="utf-8")


RULE = "No wall-clock measurement may block CI"
if RULE not in read("AGENTS.md"):
    fail(f"AGENTS.md no longer states '{RULE} ...'")

try:
    baseline = json.loads(read("benches/baseline.json"))
except json.JSONDecodeError as error:
    fail(f"benches/baseline.json is not JSON: {error}")
    baseline = {}
if baseline.get("policy", {}).get("wall_clock_measurements_block") is not False:
    fail("benches/baseline.json policy.wall_clock_measurements_block must be false")
for measurement in baseline.get("measurements", []):
    if measurement.get("kind") == "wall_clock" and measurement.get("blocking") is not False:
        fail(f"benches/baseline.json makes the wall-clock measurement {measurement.get('name')!r} blocking")

TIMING = re.compile(
    r"\b(elapsed|started|Instant|as_secs(?:_f64)?|as_millis|as_micros|as_nanos|seconds|micros|nanos|"
    r"mib_per_s|gib_per_s|throughput|per_second)\b"
)
benches = sorted(root.glob("crates/*/benches/*.rs"))
if not benches:
    fail("no crates/*/benches/*.rs file exists; rule 3 has nothing to check")
for path in benches:
    text = path.read_text(encoding="utf-8")
    for match in re.finditer(r"\b(?:debug_)?assert(?:_eq|_ne)?!\s*\(", text):
        depth, index = 1, match.end()
        while index < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[index], 0)
            index += 1
        arguments = text[match.end() : index]
        timing = TIMING.search(arguments)
        if timing:
            line = text.count("\n", 0, match.start()) + 1
            fail(
                f"{path.relative_to(root)}:{line}: an assertion names the timing quantity "
                f"'{timing.group(1)}'; a bench on a shared runner may print time, never gate on it"
            )

ci = read(".github/workflows/ci.yml")
for pattern, what in (
    (r"\bcargo\s+bench\b", "cargo bench"),
    (r"\bcargo\s+test\b[^\n]*--release\b", "a release-mode cargo test"),
    (r"\bperf_evidence\b", "the perf_evidence suite"),
    (r"\bslow_clients\b", "the slow_clients suite"),
):
    if re.search(pattern, ci):
        fail(f".github/workflows/ci.yml runs {what}; release evidence and benches stay out of the PR gate")

for relative in (".github/workflows/perf-evidence.yml", ".github/workflows/fuzz-nightly.yml"):
    text = read(relative)
    head = text.split("\njobs:", 1)[0]
    triggers = re.search(r"(?ms)^on:\s*\n(.*?)(?=^\S)", head + "\nend:\n")
    block = triggers.group(1) if triggers else ""
    for event in ("pull_request", "pull_request_target", "push"):
        if re.search(rf"(?m)^\s+{event}\s*:", block):
            fail(f"{relative} runs on {event}; it belongs to the nightly lane, not the PR gate")

if failures:
    for message in failures:
        print(f"check_no_time_gate_on_shared_runner: {message}", file=sys.stderr)
    raise SystemExit(1)
print(f"OK: no wall-clock gate on shared runners ({len(benches)} bench file(s) scanned; PR gate free of release evidence)")
PY
