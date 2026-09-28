#!/usr/bin/env python3
# Copyright 2026 RustFS Team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Writes benches/baseline.json from the micro-bench log of one perf-evidence workflow run.

WHAT THIS DOES
  Parses the lines the benches print ("<name>: N allocs", "<name>: N bytes (ceiling M)",
  "<name>: X ns/iteration", "<name>: X GiB/s", "checksum/<A>: calculator <target>") and writes a
  schema-2 baseline that names the workflow run, commit and runner it came from, with a SHA-256
  digest over everything else. check_baseline_provenance.sh recomputes that digest, so a
  hand-edited number fails CI (rustfs/backlog#1766 a-pf-0023).

USAGE
  scripts/bench_baseline.py --log micro.log --run-url URL --commit SHA --runner TEXT --rustc TEXT \
      --recorded-at 2026-09-28T04:00:00Z --out benches/baseline.json
  scripts/bench_baseline.py --digest benches/baseline.json   # prints the digest a file should carry
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

GENERATOR = "scripts/bench_baseline.py"
PATTERNS = (
    (re.compile(r"^([a-z0-9_/]+(?:/[A-Za-z0-9_]+)*): (\d+) allocs(?:, \d+ bytes)?(?: \(ceiling (\d+) allocs\))?"), "allocations"),
    (re.compile(r"^([a-z0-9_]+/[A-Za-z0-9_]+): (\d+) bytes \(ceiling (\d+)\)$"), "size"),
    (re.compile(r"^([a-z0-9_/]+): ([0-9.]+) (ns|us)/[^(]*\((\d+) (?:iterations|links)"), "wall_clock"),
    (re.compile(r"^([a-z0-9_/]+): ([0-9.]+) GiB/s"), "throughput"),
    (re.compile(r"^checksum/([A-Z0-9]+): calculator (\S+)$"), "calculator"),
)


def digest(document: dict) -> str:
    body = {key: value for key, value in document.items() if key != "digest"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def measurements(log: str) -> list:
    found = []
    seen = set()
    for raw in log.splitlines():
        line = raw.strip()
        for pattern, kind in PATTERNS:
            match = pattern.match(line)
            if not match:
                continue
            name = match.group(1)
            if kind == "calculator":
                name = f"checksum/{name.lower()}"
            key = (name, kind)
            if key in seen:
                break
            seen.add(key)
            if kind == "allocations":
                entry = {"name": name, "kind": kind, "value": int(match.group(2)), "unit": "heap_blocks", "blocking": True}
                if match.group(3):
                    entry["ceiling"] = int(match.group(3))
            elif kind == "size":
                entry = {"name": name, "kind": kind, "value": int(match.group(2)), "ceiling": int(match.group(3)), "unit": "bytes", "blocking": True}
            elif kind == "wall_clock":
                scale = 1.0 if match.group(3) == "ns" else 1000.0
                entry = {
                    "name": name,
                    "kind": kind,
                    "value": round(float(match.group(2)) * scale, 3),
                    "unit": "nanoseconds_per_iteration",
                    "iterations": int(match.group(4)),
                    "blocking": False,
                }
            elif kind == "throughput":
                entry = {"name": name, "kind": "wall_clock", "value": float(match.group(2)), "unit": "gibibytes_per_second", "blocking": False}
            else:
                entry = {"name": name, "kind": kind, "value": match.group(2), "unit": "crc_fast_target", "blocking": True}
            found.append(entry)
            break
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--digest", type=Path)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--run-url")
    parser.add_argument("--commit")
    parser.add_argument("--runner")
    parser.add_argument("--rustc")
    parser.add_argument("--recorded-at")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.digest:
        print(digest(json.loads(args.digest.read_text(encoding="utf-8"))))
        return 0
    missing = [name for name in ("log", "run_url", "commit", "runner", "rustc", "recorded_at", "out") if getattr(args, name) is None]
    if missing:
        parser.error(f"missing: {', '.join('--' + name.replace('_', '-') for name in missing)}")
    found = measurements(args.log.read_text(encoding="utf-8"))
    if not found:
        print("bench_baseline: the log carries no bench measurement line", file=sys.stderr)
        return 1
    document = {
        "schema_version": 2,
        "recorded_at": args.recorded_at,
        "source": {"generator": GENERATOR, "run_url": args.run_url, "commit": args.commit},
        "environment": {"runner": args.runner, "rustc": args.rustc},
        "policy": {
            "allocation_and_size_measurements_block": True,
            "wall_clock_measurements_block": False,
            "note": "Wall-clock values are review records only and are never CI thresholds.",
        },
        "measurements": found,
    }
    document["digest"] = digest(document)
    args.out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"bench_baseline: wrote {len(found)} measurements to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
