#!/usr/bin/env python3
"""Check license-scan boundaries and observe completed scanner child processes."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


guard = Path(__file__).with_name("check_license_headers.sh")
marker = b"Licensed under the Apache License, Version 2.0"
programs = {name: shutil.which(name) for name in
            ("git", "head", "grep", "python3.13", "python3.12", "python3.11", "python3")}
if any(programs[name] is None for name in ("git", "head", "grep")):
    raise SystemExit("git, head and grep are required")
failures = []


def require(condition, message):
    if not condition:
        failures.append(message)


with tempfile.TemporaryDirectory(prefix="gateway-license-scan-") as directory:
    root = Path(directory)
    repository, tools, events = root / "repository", root / "bin", root / "events"
    repository.mkdir()
    tools.mkdir()
    for name, native in programs.items():
        if native is None:
            continue
        wrapper = tools / name
        wrapper.write_text("#!/bin/bash\n" +
                           'if [[ "${0##*/}" == git && "$1" == ls-files && "${LICENSE_ENUM_FAIL:-0}" == 1 ]]; then exit 71; fi\n' +
                           shlex.quote(native) + ' "$@"\nrc=$?\n' +
                           "printf '%s\\n' " + shlex.quote(name) + ' >>"$LICENSE_SCAN_EVENTS"\nexit "$rc"\n')
        wrapper.chmod(0o755)
    environment = dict(os.environ, PATH=f"{tools}{os.pathsep}{os.environ['PATH']}",
                       LICENSE_SCAN_EVENTS=str(events), LICENSE_ENUM_FAIL="0")
    environment.pop("GATEWAY_PYTHON", None)

    def git(*arguments):
        return subprocess.run([programs["git"], *arguments], cwd=repository, env=environment,
                              check=True, capture_output=True, text=True)

    def write(relative, contents):
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        return path

    def count():
        return len(events.read_text().splitlines()) if events.exists() else 0

    def run(**extra):
        events.write_text("")
        result = subprocess.run(["bash", str(guard)], cwd=repository, capture_output=True,
                                text=True, env=dict(environment, GATEWAY_CHECK_ROOT=str(repository), **extra))
        return result, count()

    git("init", "-q")
    source = write("crates/sample/src/lib.rs", marker + b"\n")
    write("crates/sample/src/window.rs", b"//\n" * 13 + marker + b"\n")
    write("crates/sample/src/bytes.rs", b"// \xff\n" + marker + b"\n")
    write("vendor/allowed.rs", b"// Separate upstream license.\n")
    write("scripts/allowances/license-header-allowances.txt", b"vendor/allowed.rs # Explicit fixture allowance\n")
    write("generated/output.rs", b"// Generated.\n")
    write("crates/sample/generated/output.rs", b"// Generated.\n")
    write(".gitignore", b"ignored.rs\n")
    write("ignored.rs", b"// Ignored build output.\n")
    git("add", "-A")

    events.write_text("")
    for expected in (1, 2):
        subprocess.run([str(tools / "head"), "-n", "1", str(source)], env=environment,
                       check=True, capture_output=True)
        require(count() == expected, f"scanner observer did not record {expected} completed children")

    small, small_count = run()
    require(small.returncode == 0, f"valid headers, line 14 or exclusions were refused: {small.stderr}")
    for index in range(200):
        write(f"crates/sample/src/ordinary_{index}.rs", marker + b"\n")
    git("add", "-A")
    large, large_count = run()
    require(large.returncode == 0, f"ordinary source headers were refused: {large.stderr}")
    require(large_count == small_count,
            f"scanner processes grew with the file count: {small_count} -> {large_count}")

    for tracked in (False, True):
        for contents in (b"// Missing header.\n", b"//\n" * 14 + marker + b"\n"):
            relative = "crates/sample/src/invalid.rs"
            path = write(relative, contents)
            if tracked:
                git("add", "--", relative)
            result, _ = run()
            require(result.returncode != 0 and relative in result.stderr and "first 14 lines" in result.stderr,
                    f"{'tracked' if tracked else 'untracked'} invalid header escaped its rejection")
            if tracked:
                git("rm", "-f", "--", relative)
            else:
                path.unlink()

    linked_source = write("linked.txt", b"// No header.\n")
    for tracked in (False, True):
        relative = "crates/sample/src/linked.rs"
        path = repository / relative
        path.symlink_to(linked_source)
        if tracked:
            git("add", "--", relative)
        result, _ = run()
        require(result.returncode != 0 and relative in result.stderr and "first 14 lines" in result.stderr,
                f"{'tracked' if tracked else 'untracked'} symlink hid a missing header")
        if tracked:
            git("rm", "-f", "--", relative)
        else:
            path.unlink()

    path = write("vendor/allowed.rs.extra.rs", b"// Not the allowed path.\n")
    result, _ = run()
    require(result.returncode != 0 and "vendor/allowed.rs.extra.rs" in result.stderr,
            "an allowance prefix hid another file's missing header")
    path.unlink()
    git("add", "-f", "--", "ignored.rs")
    result, _ = run()
    require(result.returncode != 0 and "ignored.rs" in result.stderr,
            "an ignored pattern hid a tracked file's missing header")
    git("rm", "-f", "--", "ignored.rs")

    result, _ = run(LICENSE_ENUM_FAIL="1")
    require(result.returncode != 0 and "cannot enumerate Rust sources" in result.stderr,
            "failed input enumeration was accepted or rejected for the wrong reason")
    (repository / ".git").rename(repository / "saved-git")
    result, _ = run()
    require(result.returncode != 0 and "cannot enumerate Rust sources" in result.stderr,
            "missing Git inputs were accepted or rejected for the wrong reason")
    print(f"license scanner processes: {small_count} with three sources, {large_count} with 203")

if failures:
    raise SystemExit("\n".join(failures))
print("license scan batching: healthy scope, ten refusals and calibrated process counts passed")
