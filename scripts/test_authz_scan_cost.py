#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Measure real authorization-guard scanner processes and preserve its source diagnostics."""

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
suite = (root / "scripts/test_guard_scripts.sh").read_text()
helper = suite.split("expect_authz_fail_minimal() {", 1)[1]
closure = re.search(r"local -a sources=\(\n(.*?)\n    \)", helper, re.S)
assert closure is not None, "authorization fixture source closure is missing"
sources = closure.group(1).split()
assert sources, "authorization fixture source closure is empty"

with tempfile.TemporaryDirectory(prefix="gateway-authz-scan-cost-") as directory:
    base = Path(directory)
    sandbox = base / "repository"
    sandbox.mkdir()
    for relative in sources:
        destination = sandbox / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, destination)
    subprocess.run(["git", "init", "-q", str(sandbox)], check=True)
    subprocess.run(["git", "-C", str(sandbox), "add", "-A"], check=True)

    tools = base / "tools"
    tools.mkdir()
    counter = base / "scanner-calls"
    for name in ("awk", "grep", "sed", "python3", "python3.11", "python3.12", "python3.13", "ruby", "perl"):
        executable = shutil.which(name)
        if executable is None:
            assert name not in ("awk", "grep"), f"required scanner is missing: {name}"
            continue
        shim = tools / name
        shim.write_text(
            "#!/bin/sh\n"
            f"printf '{name}\\n' >>\"$GATEWAY_SCANNER_CALLS\"\n"
            f"exec {shlex.quote(executable)} \"$@\"\n"
        )
        shim.chmod(0o755)
    environment = dict(os.environ, GATEWAY_CHECK_ROOT=str(sandbox),
                       GATEWAY_SCANNER_CALLS=str(counter), PATH=str(tools) + os.pathsep + os.environ["PATH"])

    def run_guard():
        counter.write_text("")
        result = subprocess.run(
            ["/bin/bash", str(root / "scripts/check_authz_fail_closed.sh")], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30,
        )
        return result, len(counter.read_text().splitlines())

    baseline, small_count = run_guard()
    assert baseline.returncode == 0, baseline.stdout
    assert small_count > 0, "scanner shims observed no work"

    probe = sandbox / "crates/gateway/src/scan_probe.rs"
    probe.write_text("// impl Default for Decision {}\n// Decision::Allow => allow(),\nfn ordinary() {}\n")
    result, _ = run_guard()
    assert result.returncode == 0, "comment-only decoys became violations: " + result.stdout

    probe.write_text("// comment keeps source line numbers\n\nimpl Default for Decision {}\n")
    result, _ = run_guard()
    assert result.returncode != 0 and "crates/gateway/src/scan_probe.rs:3: an impl of Default" in result.stdout, result.stdout

    probe.write_text("fn forbidden() {\n    Decision::Indeterminate => deny(),\n}\n")
    result, _ = run_guard()
    assert result.returncode != 0 and "crates/gateway/src/scan_probe.rs: matches on a Decision variant" in result.stdout, result.stdout
    probe.unlink()

    probe.write_text("fn forbidden() {\n    Self::Indeterminate => deny(),\n}\n")
    result, _ = run_guard()
    assert result.returncode != 0 and "crates/gateway/src/scan_probe.rs: matches on a Decision variant" in result.stdout, result.stdout
    probe.unlink()

    required = sandbox / "crates/gateway/src/ext/authz_audit.rs"
    saved = required.read_bytes()
    required.unlink()
    result, _ = run_guard()
    assert result.returncode != 0 and "authz_audit.rs does not exist" in result.stdout, result.stdout
    required.write_bytes(saved)

    probe.write_text("// c-azc-9999\n")
    result, _ = run_guard()
    assert result.returncode != 0 and "matrix is not exactly" in result.stdout, result.stdout
    probe.unlink()

    # No lexical candidates must still reach the contract diagnostic on Bash 3.2.
    saved_sources = {sandbox / relative: (sandbox / relative).read_text() for relative in sources}
    for path, text in saved_sources.items():
        text = text.replace("Decision", "Judgement")
        for variant in ("Allow", "Deny", "Indeterminate"):
            text = text.replace("Self::" + variant, "Other::" + variant)
        path.write_text(text)
    result, _ = run_guard()
    assert result.returncode != 0 and "Authorizer fail-closed contract violated" in result.stdout, result.stdout
    for path, text in saved_sources.items():
        path.write_text(text)

    # The source set grows while the scanner process census must remain bounded. Each added
    # source is untracked, so a guard that stops reading new files cannot pass the semantic probes.
    added = sandbox / "crates/gateway/src/irrelevant"
    added.mkdir()
    for index in range(100):
        (added / f"source_{index}.rs").write_text("// ordinary source\nfn harmless() {}\n")
    expanded, large_count = run_guard()
    assert expanded.returncode == 0, expanded.stdout
    assert expanded.stdout == baseline.stdout, "irrelevant sources changed the guard verdict"
    print(f"authorization scanner processes: {small_count} -> {large_count} for 100 extra sources")
    assert large_count <= small_count + 4, (
        f"scanner process count scales with source files: {small_count} -> {large_count} for 100 extra sources"
    )
print("OK: authorization scanner preserves source diagnostics with bounded subprocess growth")
