#!/usr/bin/env python3
"""Prove child signature cases partition the parent ledger and fail closed."""

import os
from pathlib import Path
import re
import subprocess
import tempfile

source = Path(__file__).with_name("test_guard_scripts.sh").read_text()
functions = []
for name in ("guard_group_of", "guard_worker_of", "guard_case_owned", "run_signature_guard_suite"):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}", source, re.M | re.S)
    assert match is not None, name
    functions.append(match.group())
program = "\n".join(functions) + """
cases=17
failures=0
GUARD_BUDGET_STOP=999999
GUARD_EXECUTED=0
GUARD_SHARD_LEDGER=""
pass_msg() { :; }
fail_msg() { failures=$((failures + 1)); }
run_signature_guard_suite
printf '%s %s' "$cases" "$failures"
"""

with tempfile.TemporaryDirectory(prefix="gateway-nested-guard-") as directory:
    root = Path(directory)
    child = root / "test_sig_case_coverage.sh"
    counter = root / "calls"
    child.write_text('''#!/bin/bash
if [[ "${1:-}" == --list ]]; then
    case "${FAULT:-}" in
        list-status) exit 1;;
        list-empty) exit 0;;
        list-gap) printf '1\\n3\\n'; exit 0;;
        list-duplicate) printf '1\\n1\\n'; exit 0;;
        list-text) printf 'bad\\n'; exit 0;;
    esac
    seq 1 29
    exit 0
fi
[[ "${1:-}" == --select ]] || exit 2
printf '%s\\n' "$2" >>"$COUNTER"
[[ "${FAULT:-}" != missing-results ]] || exit 0
printf '%s\\n' "$2" | tr ',' '\\n' >"$3"
case "${FAULT:-}" in
    empty-results) : >"$3";;
    extra-results) printf '30\\n' >>"$3";;
    duplicate-results) cat "$3" >>"$3.copy"; cat "$3.copy" >>"$3";;
esac
exit "${CHILD_STATUS:-0}"
''')
    child.chmod(0o755)

    def run(group, worker, status="0", fault=""):
        return subprocess.run(
            ["bash", "-c", program], capture_output=True, text=True,
            env=dict(os.environ, SCRIPT_DIR=directory, COUNTER=str(counter),
                     GUARD_SHARD_COUNT="8", GUARD_SHARD_GROUPS="6",
                     GUARD_SHARD_GROUP=str(group), GUARD_SHARD_INDEX=str(worker),
                     CHILD_STATUS=status, FAULT=fault),
        )

    for group in range(6):
        for worker in range(8):
            result = run(group, worker)
            assert result.returncode == 0 and result.stdout.endswith("46 0"), result
    observed = [int(case) for line in counter.read_text().splitlines() for case in line.split(',')]
    assert sorted(observed) == list(range(1, 30)), "child cases were omitted or duplicated"
    for status in ("1", "2", "124"):
        result = run(5, 2, status)
        assert result.stdout.endswith("46 1"), result
    for fault in ("list-status", "list-empty", "list-gap", "list-duplicate", "list-text",
                  "missing-results", "empty-results", "extra-results", "duplicate-results"):
        result = run(5, 2, fault=fault)
        assert result.stdout.split()[-1] == "1", (fault, result)
    child.unlink()
    assert run(5, 2).stdout.split()[-1] == "1", "missing child did not fail"
print("OK: all 29 child cases run once across 48 workers and malformed results fail closed")

# Exercise the actual child's selector without constructing repository fixtures.
child_source = Path(__file__).with_name("test_sig_case_coverage.sh").read_text()
selector = child_source[child_source.index('failures=0\n'):child_source.index('pass_msg()')]
selector += '''
for ((iteration = 0; iteration < 29; iteration++)); do
    if signature_case_owned; then printf 'ran %s\\n' "$cases"; fi
done
'''
with tempfile.TemporaryDirectory(prefix="gateway-sig-selection-") as directory:
    results = Path(directory) / "results"
    selected = subprocess.run(["bash", "-c", selector, "selector", "--select", "2,11,29", str(results)],
                              capture_output=True, text=True)
    assert selected.returncode == 0 and selected.stdout == "ran 2\nran 11\nran 29\n", selected
    assert results.read_text() == "2\n11\n29\n", "child did not record the exact selected cases"
    for indices in ("", "0", "-1", "01", "1,1", "1,", "1,x"):
        rejected = subprocess.run(["bash", "-c", selector, "selector", "--select", indices, str(results)],
                                  capture_output=True, text=True)
        assert rejected.returncode != 0, indices
    child = Path(__file__).with_name("test_sig_case_coverage.sh")
    listed = subprocess.run(["bash", str(child), "--list"], capture_output=True, text=True)
    assert listed.returncode == 0 and listed.stdout.splitlines() == [str(n) for n in range(1, 30)], listed
    unknown = subprocess.run(["bash", str(child), "--select", "30", str(results)], capture_output=True, text=True)
    assert unknown.returncode != 0 and "does not exist" in unknown.stderr, unknown
print("OK: actual child selection rejects invalid indices and lists the complete unchanged census")

# Disposable repositories must not spawn background maintenance that races their cleanup.
fixture = re.search(r"^make_sandbox\(\) \{\n.*?^\}", child_source, re.M | re.S)
assert fixture is not None
with tempfile.TemporaryDirectory(prefix="gateway-sig-fixture-") as directory:
    calls = Path(directory) / "git-calls"
    probe = '''
set -e
SANDBOX=""
git() { printf '%s\\n' "$*" >>"$GIT_CALLS"; }
tar() { :; }
''' + fixture.group() + '\nmake_sandbox\n'
    result = subprocess.run(["bash", "-c", probe], capture_output=True, text=True,
                            env=dict(os.environ, TMPDIR=directory, REPO_ROOT=directory, GIT_CALLS=str(calls)))
    assert result.returncode == 0, result
    recorded = calls.read_text().splitlines()
    assert "config maintenance.auto false" in recorded, "fixture allows background maintenance"
    assert "config gc.auto 0" in recorded, "fixture allows automatic garbage collection"
print("OK: disposable signature fixtures disable background repository maintenance")
