#!/usr/bin/env python3
"""Verify guard shard baseline-time accounting, live worker flushing, and watchdog diagnostics."""

import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import tempfile
import time


SCRIPT = Path(__file__).with_name("test_guard_scripts.sh")
SOURCE = SCRIPT.read_text(encoding="utf-8")


def extract_helpers() -> str:
    names = (
        "guard_budget_verdict",
        "guard_budget_stop",
        "guard_group_of",
        "guard_worker_of",
        "guard_case_owned",
        "guard_shard_ledger_report",
        "guard_print_elapsed",
        "run_guard_shards",
        "cleanup_sandbox",
    )
    definitions = []
    for name in names:
        match = re.search(rf"^{name}\(\) \{{\n.*?^\}}", SOURCE, re.M | re.S)
        if match is None:
            raise SystemExit(f"missing fixture helper: {name}")
        definitions.append(match.group())
    return "\n".join(definitions) + r'''
SANDBOX=""
SANDBOX_RESET_TRACKED=""
SANDBOX_RESET_UNTRACKED=""
SANDBOX_RESET_READY=0
SANDBOX_BASE=""
QUIRK_LEDGER_PARSE_CACHE=""
CT_EQ_SANDBOX=""
SEMVER_SANDBOX=""
GUARD_SHARD_COUNT="${GATEWAY_GUARD_SHARD_COUNT:-}"
GUARD_SHARD_INDEX="${GATEWAY_GUARD_SHARD_INDEX:-0}"
GUARD_SHARD_GROUPS="${GATEWAY_GUARD_SHARD_GROUPS:-1}"
GUARD_SHARD_GROUP="${GATEWAY_GUARD_SHARD_GROUP:-0}"
GUARD_SHARD_LEDGER="${GATEWAY_GUARD_SHARD_LEDGER:-}"
GUARD_SHARD_SUMMARY="${GATEWAY_GUARD_SHARD_SUMMARY:-}"
GUARD_BUDGET_SECONDS="${GATEWAY_GUARD_BUDGET_SECONDS:-480}"
GUARD_BUDGET_RESERVE_SECONDS=30
GUARD_BUDGET_STOP=$((GUARD_BUDGET_SECONDS - GUARD_BUDGET_RESERVE_SECONDS))
GUARD_BUDGET_WARN=$((GUARD_BUDGET_SECONDS * 4 / 5))
GUARD_BUDGET_ELAPSED="${GATEWAY_GUARD_BUDGET_ELAPSED:-0}"
GUARD_EXECUTED=0
make_sandbox() {
    SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/gateway-fake-baseline.XXXXXX")"
    if [[ -n "${FAKE_BASELINE_ELAPSED:-}" ]]; then
        SECONDS="$FAKE_BASELINE_ELAPSED"
    fi
}
'''


def base_env(extra: dict[str, str]) -> dict[str, str]:
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GATEWAY_GUARD_"):
            env.pop(key)
    env.update(extra)
    return env


def run_snippet(helper: Path, program: str, extra: dict[str, str], timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", 'set -euo pipefail\nsource "$HELPER"\n' + program],
        capture_output=True,
        text=True,
        env=base_env({"HELPER": str(helper), **extra}),
        timeout=timeout,
    )


def main() -> None:
    if shutil.which("bash") is None:
        raise SystemExit("bash is required")

    with tempfile.TemporaryDirectory(prefix="gateway-guard-budget-diag-") as directory:
        root = Path(directory)
        helper = root / "helpers.sh"
        helper.write_text(extract_helpers(), encoding="utf-8")

        # Negative 1: invalid GATEWAY_GUARD_BUDGET_ELAPSED fails closed before running cases.
        for bad in ("-1", "abc", "1.5"):
            res = subprocess.run(
                ["bash", str(SCRIPT)],
                capture_output=True,
                text=True,
                env=base_env({
                    "GATEWAY_GUARD_BUDGET_ELAPSED": bad,
                    "GATEWAY_GUARD_SHARD_GROUPS": "2",
                    "GATEWAY_GUARD_SHARD_GROUP": "9",
                }),
                timeout=10,
            )
            assert res.returncode == 1 and "GATEWAY_GUARD_BUDGET_ELAPSED must be a non-negative integer" in res.stderr, (
                f"invalid elapsed {bad!r} must fail closed",
                res,
            )

        # Positive 1: normal 2-worker run completes, flushes outputs, proves coverage, cleans tmp.
        ok_worker = root / "ok_worker.sh"
        ok_worker.write_text(
            '#!/bin/bash\n'
            'set -euo pipefail\n'
            'source "$HELPER"\n'
            'for ((ordinal = 1; ordinal <= 8; ordinal++)); do\n'
            '    if guard_case_owned "$ordinal"; then\n'
            '        printf "  ok   case-%s\\n" "$ordinal"\n'
            '    fi\n'
            'done\n'
            'printf "8 %s 0\\n" "$GUARD_EXECUTED" >"$GUARD_SHARD_SUMMARY"\n',
            encoding="utf-8",
        )
        ok_tmp = root / "ok-tmp"
        ok_tmp.mkdir()
        res = run_snippet(
            helper,
            'trap cleanup_sandbox EXIT\nrun_guard_shards 2\n',
            {"GUARD_SELF": str(ok_worker), "TMPDIR": str(ok_tmp)},
        )
        assert res.returncode == 0, res
        assert "8 of 8 case(s), each executed exactly once" in res.stdout, res.stdout
        assert "case-1" in res.stdout and "case-8" in res.stdout, res.stdout
        assert not list(ok_tmp.iterdir()), f"temp dirs leaked: {list(ok_tmp.iterdir())}"

        # Negative 2: parent baseline setup elapsed time is charged to workers' GUARD_BUDGET_STOP.
        charged_worker = root / "charged_worker.sh"
        charged_worker.write_text(
            '#!/bin/bash\n'
            'set -euo pipefail\n'
            'source "$HELPER"\n'
            'SECONDS=0\n'
            'for ((ordinal = 1; ordinal <= 6; ordinal++)); do\n'
            '    if ((ordinal == 3)); then SECONDS=2; fi\n'
            '    guard_case_owned "$ordinal" || :\n'
            'done\n'
            'printf "6 %s 0\\n" "$GUARD_EXECUTED" >"$GUARD_SHARD_SUMMARY"\n',
            encoding="utf-8",
        )
        charged_tmp = root / "charged-tmp"
        charged_tmp.mkdir()
        res = run_snippet(
            helper,
            'trap cleanup_sandbox EXIT\nrun_guard_shards 2\n',
            {
                "GUARD_SELF": str(charged_worker),
                "TMPDIR": str(charged_tmp),
                "GATEWAY_GUARD_BUDGET_SECONDS": "480",
                "FAKE_BASELINE_ELAPSED": "449",
            },
        )
        combined = res.stdout + res.stderr
        assert res.returncode != 0, ("worker must stop when baseline + worker seconds >= stop", res)
        assert "OUT OF TIME" in combined, combined
        assert "reached 451s of its 480s budget at case 3" in combined, combined
        assert not list(charged_tmp.iterdir()), f"temp dirs leaked: {list(charged_tmp.iterdir())}"

        # Negative 3: baseline setup already exhausting GUARD_BUDGET_STOP stops before spawning workers.
        spawn_marker = root / "worker-spawned"
        no_spawn_worker = root / "no_spawn_worker.sh"
        no_spawn_worker.write_text(
            f'#!/bin/bash\ntouch "{spawn_marker}"\n',
            encoding="utf-8",
        )
        baseline_tmp = root / "baseline-tmp"
        baseline_tmp.mkdir()
        res = run_snippet(
            helper,
            'trap cleanup_sandbox EXIT\nrun_guard_shards 2\n',
            {
                "GUARD_SELF": str(no_spawn_worker),
                "TMPDIR": str(baseline_tmp),
                "GATEWAY_GUARD_BUDGET_SECONDS": "480",
                "FAKE_BASELINE_ELAPSED": "450",
            },
        )
        assert res.returncode == 2, res
        assert "OUT OF TIME" in res.stderr and "baseline setup" in res.stderr, res.stderr
        assert not spawn_marker.exists(), "workers must not spawn after baseline already exhausted budget"
        assert not list(baseline_tmp.iterdir()), f"temp dirs leaked: {list(baseline_tmp.iterdir())}"

        # Negative 4: fast worker output flushes BEFORE a slow worker exits (no whole-group buffering).
        gate = root / "release-slow"
        stream_worker = root / "stream_worker.sh"
        stream_worker.write_text(
            '#!/bin/bash\n'
            'set -euo pipefail\n'
            'source "$HELPER"\n'
            'if [[ "$GATEWAY_GUARD_SHARD_INDEX" == 0 ]]; then\n'
            '    while [[ ! -f "$GATE_FILE" ]]; do sleep 0.05; done\n'
            'else\n'
            '    printf "FAST_WORKER_FLUSHED_EARLY\\n"\n'
            'fi\n'
            'for ((ordinal = 1; ordinal <= 4; ordinal++)); do guard_case_owned "$ordinal" || :; done\n'
            'printf "4 %s 0\\n" "$GUARD_EXECUTED" >"$GUARD_SHARD_SUMMARY"\n',
            encoding="utf-8",
        )
        stream_tmp = root / "stream-tmp"
        stream_tmp.mkdir()
        proc = subprocess.Popen(
            ["bash", "-c", 'set -euo pipefail\nsource "$HELPER"\ntrap cleanup_sandbox EXIT\nrun_guard_shards 2\n'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=base_env({
                "HELPER": str(helper),
                "GUARD_SELF": str(stream_worker),
                "TMPDIR": str(stream_tmp),
                "GATE_FILE": str(gate),
            }),
        )
        assert proc.stdout is not None
        seen = ""
        deadline = time.monotonic() + 5.0
        try:
            while time.monotonic() < deadline and "FAST_WORKER_FLUSHED_EARLY" not in seen:
                ready, _, _ = select.select([proc.stdout], [], [], 0.1)
                if ready:
                    chunk = os.read(proc.stdout.fileno(), 4096).decode("utf-8", errors="replace")
                    if not chunk:
                        break
                    seen += chunk
            flushed_before_release = "FAST_WORKER_FLUSHED_EARLY" in seen
        finally:
            gate.touch()
            rest_out, rest_err = proc.communicate(timeout=10)
        assert flushed_before_release, (
            "fast worker output was buffered until slow worker 1 exited",
            seen,
            rest_out,
            rest_err,
        )
        assert proc.returncode == 0, (seen + rest_out, rest_err)
        assert not list(stream_tmp.iterdir()), f"temp dirs leaked: {list(stream_tmp.iterdir())}"

        # Negative 5: parent watchdog stops a worker stuck mid-case before outer SIGKILL and names
        # the stalled worker, its last recorded ledger ordinal, and its partial output.
        stalled_worker = root / "stalled_worker.sh"
        stalled_worker.write_text(
            '#!/bin/bash\n'
            'set -euo pipefail\n'
            'trap "exit 143" TERM\n'
            'source "$HELPER"\n'
            'GUARD_BUDGET_STOP=10\n'
            'if [[ "$GATEWAY_GUARD_SHARD_INDEX" == 1 ]]; then\n'
            '    guard_case_owned 2 || :\n'
            '    printf "STALLED_IN_CASE_2\\n"\n'
            '    sleep 30 &\n'
            '    wait $!\n'
            'fi\n'
            'for ((ordinal = 1; ordinal <= 4; ordinal++)); do guard_case_owned "$ordinal" || :; done\n'
            'printf "4 %s 0\\n" "$GUARD_EXECUTED" >"$GUARD_SHARD_SUMMARY"\n',
            encoding="utf-8",
        )
        watchdog_tmp = root / "watchdog-tmp"
        watchdog_tmp.mkdir()
        started = time.monotonic()
        res = run_snippet(
            helper,
            'trap cleanup_sandbox EXIT\n'
            'GUARD_BUDGET_SECONDS=12\n'
            'GUARD_BUDGET_STOP=10\n'
            'SECONDS=0\n'
            'run_guard_shards 2\n',
            {
                "GUARD_SELF": str(stalled_worker),
                "TMPDIR": str(watchdog_tmp),
                "GATEWAY_GUARD_BUDGET_SECONDS": "12",
            },
            timeout=15.0,
        )
        elapsed = time.monotonic() - started
        combined = res.stdout + res.stderr
        assert res.returncode != 0, res
        assert elapsed < 10.0, f"watchdog waited {elapsed:.2f}s instead of stopping stalled worker before outer kill"
        assert "OUT OF TIME" in combined, combined
        assert "worker 2/2" in combined, combined
        assert "last recorded case 2" in combined, combined
        assert "STALLED_IN_CASE_2" in combined, combined
        assert not list(watchdog_tmp.iterdir()), f"temp dirs leaked: {list(watchdog_tmp.iterdir())}"

        # Negative 6: partial worker self-stop propagates non-zero exit and incomplete coverage.
        partial_worker = root / "partial_worker.sh"
        partial_worker.write_text(
            '#!/bin/bash\n'
            'set -euo pipefail\n'
            'source "$HELPER"\n'
            'for ((ordinal = 1; ordinal <= 6; ordinal++)); do\n'
            '    if [[ "$GATEWAY_GUARD_SHARD_INDEX" == 0 ]] && ((ordinal == 3)); then\n'
            '        SECONDS=450\n'
            '    fi\n'
            '    guard_case_owned "$ordinal" || :\n'
            'done\n'
            'printf "6 %s 0\\n" "$GUARD_EXECUTED" >"$GUARD_SHARD_SUMMARY"\n',
            encoding="utf-8",
        )
        partial_tmp = root / "partial-tmp"
        partial_tmp.mkdir()
        res = run_snippet(
            helper,
            'trap cleanup_sandbox EXIT\nrun_guard_shards 2\n',
            {"GUARD_SELF": str(partial_worker), "TMPDIR": str(partial_tmp)},
        )
        combined = res.stdout + res.stderr
        assert res.returncode != 0, res
        assert "ended without a summary" in combined and "coverage is incomplete" in combined, combined
        assert not list(partial_tmp.iterdir()), f"temp dirs leaked: {list(partial_tmp.iterdir())}"

    print("OK: guard baseline-time accounting, live worker flushing, and watchdog diagnostics verified")


if __name__ == "__main__":
    main()
