#!/usr/bin/env python3
"""Run one client against one scenario and record what the server saw while it ran.

Responsible for: deciding whether the scenario can run against the system under test's declared
capabilities (the launcher's registry; an external endpoint declares none, so nothing is skipped
before it runs and what it does not serve is read from its answers by `report.py`), executing the
driver under a wall-clock limit that a hung client cannot outlive, and
writing the cell's raw record — the driver's own result object plus the slice of the server's probe
log that belongs to this cell.
NOT responsible for: deciding pass or fail. `ci/compat/report.py` does that, so that one
implementation judges every client's wire behaviour rather than fourteen driver scripts each
judging their own.
Upstream: `ci/compat/run_matrix.sh`. Downstream: `ci/compat/report.py`.

The timeout lives here rather than in the shell because `timeout(1)` is a GNU utility that is
absent on macOS, and a matrix whose per-cell limit silently disappears on a developer's machine
would let a-cm-0019 pass for the wrong reason.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--driver", required=True)
    parser.add_argument("--scenario-file", required=True)
    parser.add_argument(
        "--capabilities",
        default="",
        help="the launcher's registry; omitted for an external endpoint, whose registry is unknown",
    )
    parser.add_argument("--probe-log", required=True)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("--out", required=True)
    arguments = parser.parse_args()

    document = yaml.safe_load(Path(arguments.scenario_file).read_text(encoding="utf-8"))
    missing = []
    if arguments.capabilities:
        declared = {
            line.strip() for line in Path(arguments.capabilities).read_text(encoding="utf-8").splitlines() if line.strip()
        }
        missing = sorted(set(document.get("requires_operations") or []) - declared)
    skip_reason = "the system under test registers no " + ", ".join(missing) if missing else ""

    probe = Path(arguments.probe_log)
    before = len(probe.read_text(encoding="utf-8", errors="replace").splitlines()) if probe.is_file() else 0

    workdir = Path(arguments.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    stdout, stderr, exit_code, timed_out = "", "", 0, False
    if not skip_reason:
        environment = dict(os.environ)
        environment.update(
            COMPAT_ENDPOINT=arguments.endpoint,
            COMPAT_BUCKET=arguments.bucket,
            COMPAT_WORKDIR=str(workdir),
        )
        try:
            completed = subprocess.run(
                [arguments.driver, arguments.scenario],
                capture_output=True,
                text=True,
                timeout=arguments.timeout,
                env=environment,
                check=False,
            )
            stdout, stderr, exit_code = completed.stdout, completed.stderr, completed.returncode
        except subprocess.TimeoutExpired as expired:
            # One client hanging must not end the matrix. The cell becomes a failure carrying the
            # limit it exceeded, and the caller moves on to the next one.
            timed_out = True
            exit_code = 124
            stdout = (expired.stdout or b"").decode("utf-8", "replace") if isinstance(expired.stdout, bytes) else (expired.stdout or "")
            stderr = (expired.stderr or b"").decode("utf-8", "replace") if isinstance(expired.stderr, bytes) else (expired.stderr or "")
        except OSError as error:
            stderr = f"the driver could not be executed: {error}"
            exit_code = 126

    after = len(probe.read_text(encoding="utf-8", errors="replace").splitlines()) if probe.is_file() else 0
    records = []
    if after > before:
        lines = probe.read_text(encoding="utf-8", errors="replace").splitlines()[before:after]
        for line in lines:
            try:
                records.append(json.loads(line))
            except ValueError:
                pass

    driver_result = None
    for line in reversed(stdout.splitlines()):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            candidate = json.loads(stripped)
        except ValueError:
            break
        if isinstance(candidate, dict) and {"scenario", "status"} <= set(candidate):
            driver_result = candidate
        break

    Path(arguments.out).parent.mkdir(parents=True, exist_ok=True)
    Path(arguments.out).write_text(
        json.dumps(
            {
                "client": arguments.client,
                "scenario": arguments.scenario,
                "driver": driver_result,
                "stdout": stdout,
                "stderr": stderr[-4000:],
                "exit_code": exit_code,
                "timed_out": timed_out,
                "timeout_seconds": arguments.timeout,
                "skipped_reason": skip_reason,
                "probe": records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    reported = "sut-unregistered" if skip_reason else (driver_result or {}).get("status", "driver-error")
    print(reported)
    return 0


if __name__ == "__main__":
    sys.exit(main())
