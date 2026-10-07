#!/usr/bin/env python3
"""Exercise the real clock guard and count completed scanner processes."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


guard = Path(__file__).with_name("check_clock_single_source.sh")
real_git = shutil.which("git")
real_grep = shutil.which("grep")
if real_git is None or real_grep is None:
    raise SystemExit("git and grep are required")

failures = []


def require(condition, message):
    if not condition:
        failures.append(message)


with tempfile.TemporaryDirectory(prefix="gateway-clock-scan-") as directory:
    root = Path(directory)
    repository, tools, events = root / "repository", root / "bin", root / "events"
    repository.mkdir()
    tools.mkdir()
    wrapper = tools / "grep"
    wrapper.write_text(r'''#!/bin/bash
if [[ "$1" == -nHE && "${CLOCK_SCAN_FAIL:-0}" == 1 ]]; then exit 2; fi
"$CLOCK_REAL_GREP" "$@"
rc=$?
printf 'grep\n' >>"$CLOCK_SCAN_EVENTS"
exit "$rc"
''')
    wrapper.chmod(0o755)
    environment = dict(os.environ, PATH=f"{tools}{os.pathsep}{os.environ['PATH']}",
                       CLOCK_REAL_GREP=real_grep, CLOCK_SCAN_EVENTS=str(events))

    def git(*arguments):
        return subprocess.run([real_git, *arguments], cwd=repository, env=environment,
                              check=True, capture_output=True, text=True)

    def write(relative, contents):
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    def count():
        return len(events.read_text().splitlines()) if events.exists() else 0

    def run(**extra):
        events.write_text("")
        result = subprocess.run(["bash", str(guard)], cwd=repository, capture_output=True,
                                text=True, env=dict(environment, GATEWAY_CHECK_ROOT=str(repository), **extra))
        return result, count()

    git("init", "-q")
    write("crates/sig/src/clock.rs", "fn wall() { SystemTime::now(); }\n")
    write("crates/gateway/src/clock.rs", "fn monotonic() { Instant::now(); }\n")
    write("crates/server/src/io.rs", "struct ProgressIo; fn timer() { Instant::now(); }\n")
    write("crates/conformance/src/probe.rs", "fn measure() { Instant::now(); }\n")
    write("crates/gateway/tests/probe.rs", "fn measure() { SystemTime::now(); }\n")
    write("crates/gateway/src/decoy.rs", "NotInstant::now(); Instant::nowish(); type Alias=NotSystemTime;\n")
    git("add", "-A")

    # Calibrate completed child observation in both directions before trusting the cost check.
    events.write_text("")
    probe = write("probe.txt", "clock\n")
    for expected in (1, 2):
        subprocess.run([str(tools / "grep"), "clock", str(probe)], env=environment,
                       check=True, capture_output=True)
        require(count() == expected, f"scanner observer did not record {expected} completed children")

    small, small_count = run()
    require(small.returncode == 0, f"healthy clock sources or excluded tests were refused: {small.stderr}")
    for index in range(200):
        write(f"crates/gateway/src/nested/ordinary_{index}.rs", "fn ordinary() {}\n")
    git("add", "-A")
    large, large_count = run()
    require(large.returncode == 0, f"ordinary runtime files were refused: {large.stderr}")
    require(large_count == small_count,
            f"scanner processes grew with the file count: {small_count} -> {large_count}")

    # Both index and working-tree inputs must still reach each pattern scan.
    for tracked in (False, True):
        for contents, diagnostic in (
            ("fn stray() { std::time::Instant :: now(); }\n", "reads a clock outside"),
            ("use std::time::SystemTime as Wall;\n", "a renamed clock type"),
            ("type Wall=SystemTime;\n", "a renamed clock type"),
            ("type Monotonic = std::time::Instant;\n", "a renamed clock type"),
        ):
            relative = "crates/gateway/src/nested/stray.rs"
            path = write(relative, contents)
            if tracked:
                git("add", "--", relative)
            result, _ = run()
            require(result.returncode != 0 and diagnostic in result.stderr and relative in result.stderr,
                    f"{'tracked' if tracked else 'untracked'} input escaped its {diagnostic} rejection: {result.returncode}, {result.stderr}")
            if tracked:
                git("rm", "-f", "--", relative)
            else:
                path.unlink()

    linked_source = write("linked.rs", "fn stray() { Instant::now(); }\n")
    for tracked in (False, True):
        relative = "crates/gateway/src/linked.rs"
        path = repository / relative
        path.symlink_to(linked_source)
        if tracked:
            git("add", "--", relative)
        result, _ = run()
        require(result.returncode != 0 and "reads a clock outside" in result.stderr,
                f"{'tracked' if tracked else 'untracked'} symlink hid a clock reading")
        if tracked:
            git("rm", "-f", "--", relative)
        else:
            path.unlink()

    result, _ = run(CLOCK_SCAN_FAIL="1")
    require(result.returncode != 0 and "cannot scan clock inputs" in result.stderr,
            "a failed scanner was accepted or rejected for the wrong reason")
    (repository / ".git").rename(repository / "saved-git")
    result, _ = run()
    require(result.returncode != 0 and "cannot scan clock inputs" in result.stderr,
            "missing Git inputs were accepted or rejected for the wrong reason")

    print(f"clock scanner processes: {small_count} with four runtime files, {large_count} with 204")

if failures:
    raise SystemExit("\n".join(failures))
print("clock scan batching: healthy scope, twelve refusals and calibrated process counts passed")
