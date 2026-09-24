#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Measure policy scanner processes while preserving the one-reading diagnostics."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="gateway-policy-scan-") as directory:
    base = Path(directory)
    repository = base / "repository"
    repository.mkdir()
    names = ("ext/policy.rs", "service.rs", "request_deadline.rs", "routing.rs")
    for name in names:
        relative = Path("crates/gateway/src") / name
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, destination)
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(["git", "-C", str(repository), "add", "-A"], check=True)
    counter = base / "calls"
    tools = base / "tools"
    tools.mkdir()
    for name in ("awk", "grep"):
        executable = shutil.which(name)
        assert executable is not None, f"missing scanner: {name}"
        shim = tools / name
        shim.write_text(f'#!/bin/sh\nprintf "{name}\\n" >> "$GATEWAY_SCANNER_CALLS"\nexec {shlex.quote(executable)} "$@"\n')
        shim.chmod(0o755)
    environment = dict(os.environ, GATEWAY_CHECK_ROOT=str(repository), GATEWAY_SCANNER_CALLS=str(counter),
                       PATH=str(tools) + os.pathsep + os.environ["PATH"])

    def run():
        counter.write_text("")
        result = subprocess.run(["/bin/bash", str(root / "scripts/check_policy_snapshot_once.sh")],
                                env=environment, capture_output=True, text=True, timeout=30)
        return result, len(counter.read_text().splitlines())

    baseline, before = run()
    assert baseline.returncode == 0, baseline.stderr
    assert before > 0, "scanner counter observed no work"
    probe = repository / "crates/gateway/src/untracked.rs"
    probe.write_text("// source.snapshot(None);\nfn harmless() {}\n")
    result, _ = run()
    assert result.returncode == 0, result.stderr
    probe.write_text("fn duplicate() { source.snapshot \t(None); }\n")
    result, _ = run()
    assert result.returncode != 0 and "untracked.rs: reads a policy snapshot" in result.stderr, result.stderr
    probe.unlink()
    foreign = repository / "crates/other/src/reader.rs"
    foreign.parent.mkdir(parents=True)
    foreign.write_text("fn duplicate() { source.snapshot(None); }\n")
    result, _ = run()
    assert result.returncode != 0 and "crates/other/src/reader.rs: reads a policy snapshot" in result.stderr, result.stderr
    foreign.unlink()

    reader = repository / "crates/gateway/src/request_deadline.rs"
    original = reader.read_text()
    assert original.count("source.snapshot(identity)") == 1, "reader fixture changed"
    reader.write_text(original.replace("source.snapshot(identity)", "source.read(identity)"))
    result, _ = run()
    assert result.returncode != 0 and "snapshot at all" in result.stderr, result.stderr
    reader.write_text(original + "\nfn again() { source.snapshot(None); }\n")
    result, _ = run()
    assert result.returncode != 0 and "2 readings of policy" in result.stderr, result.stderr
    reader.write_text(original)

    # Exercise an actually empty prefilter result, including on macOS Bash 3.2.
    saved_sources = {repository / "crates/gateway/src" / name: (repository / "crates/gateway/src" / name).read_text()
                     for name in names}
    for path, text in saved_sources.items():
        path.write_text(text.replace(".snapshot", ".read"))
    result, _ = run()
    assert result.returncode != 0 and "snapshot at all" in result.stderr, result.stderr
    for path, text in saved_sources.items():
        path.write_text(text)

    trait = repository / "crates/gateway/src/ext/policy.rs"
    original_trait = trait.read_text()
    trait.write_text(original_trait + "\nfn forward() { source.snapshot(None); }\n")
    result, _ = run()
    assert result.returncode == 0, "trait forwarding must remain excluded: " + result.stderr
    trait.unlink()
    result, _ = run()
    assert result.returncode != 0 and "policy.rs does not exist" in result.stderr, result.stderr
    trait.write_text(original_trait)

    added = repository / "crates/gateway/src/irrelevant"
    added.mkdir()
    for index in range(100):
        (added / f"file_{index}.rs").write_text("fn ordinary() {}\n")
    expanded, after = run()
    assert expanded.returncode == 0, expanded.stderr
    assert expanded.stdout == baseline.stdout, "irrelevant files changed the verdict"
    print(f"policy scanner processes: {before} -> {after} for 100 extra sources")
    assert after <= before + 2, f"scanner processes scale with irrelevant sources: {before} -> {after}"
print("OK: policy scanner retains source diagnostics with bounded process growth")
