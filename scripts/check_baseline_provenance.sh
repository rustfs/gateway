#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_baseline_provenance.sh
#
# WHAT THIS CHECKS
#   benches/baseline.json was written by scripts/bench_baseline.py from one
#   perf-evidence workflow run and has not been edited since (rustfs/backlog#1766
#   a-pf-0023): schema 2, the generator named, a workflow-run URL on this
#   repository, a 40-hex commit, every measurement well formed, and a digest equal
#   to the one the generator computes over the rest of the file.
#
# WHY
#   A baseline is worth what its source is worth. A number typed in by hand to
#   make a comparison pass reads exactly like one a runner measured; the digest
#   makes the difference visible, and the run URL says where to go and check.
#
# HOW TO EXEMPT
#   There is no exemption. Regenerate the file from a run's micro.log artifact
#   with scripts/bench_baseline.py.
# =============================================================================

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

python3 - "$ROOT" <<'PY'
import importlib.util
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
baseline_path = root / "benches/baseline.json"
generator_path = root / "scripts/bench_baseline.py"
for path in (baseline_path, generator_path):
    if not path.is_file():
        print(f"check_baseline_provenance: required input is missing: {path.relative_to(root)}", file=sys.stderr)
        raise SystemExit(1)

spec = importlib.util.spec_from_file_location("bench_baseline", generator_path)
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)

failures = []
try:
    document = json.loads(baseline_path.read_text(encoding="utf-8"))
except json.JSONDecodeError as error:
    print(f"check_baseline_provenance: benches/baseline.json is not JSON: {error}", file=sys.stderr)
    raise SystemExit(1)

if document.get("schema_version") != 2:
    failures.append("schema_version must be 2")
source = document.get("source") or {}
if source.get("generator") != generator.GENERATOR:
    failures.append(f"source.generator must be {generator.GENERATOR}")
if not re.fullmatch(r"https://github\.com/rustfs/gateway/actions/runs/[0-9]+", str(source.get("run_url", ""))):
    failures.append("source.run_url must name a rustfs/gateway workflow run")
if not re.fullmatch(r"[0-9a-f]{40}", str(source.get("commit", ""))):
    failures.append("source.commit must be a 40-hex commit")
measurements = document.get("measurements")
if not isinstance(measurements, list) or not measurements:
    failures.append("measurements must be a non-empty list")
    measurements = []
for entry in measurements:
    if not isinstance(entry, dict) or not entry.get("name") or entry.get("kind") not in {"allocations", "size", "wall_clock", "calculator"}:
        failures.append(f"malformed measurement: {entry!r}")
if document.get("digest") != generator.digest(document):
    failures.append("digest does not match the file's contents; the baseline was edited after scripts/bench_baseline.py wrote it")

if failures:
    for message in failures:
        print(f"check_baseline_provenance: {message}", file=sys.stderr)
    raise SystemExit(1)
print(f"OK: benches/baseline.json carries {len(measurements)} measurements from {source['run_url']}")
PY
