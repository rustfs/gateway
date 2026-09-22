#!/usr/bin/env python3
"""Exercise constant-time scan batching and file boundaries without changing repository inputs."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


guard = Path(__file__).with_name("check_ct_eq.sh").resolve()
with tempfile.TemporaryDirectory(prefix="gateway-ct-batch-") as temporary:
    root = Path(temporary)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    bins = root / "bin"
    bins.mkdir()
    calls = root / "calls"
    for command in ("awk", "grep"):
        executable = shutil.which(command)
        assert executable, command
        wrapper = bins / command
        wrapper.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' {shlex.quote(command)} >> {shlex.quote(str(calls))}\n"
            f"exec {shlex.quote(executable)} \"$@\"\n"
        )
        wrapper.chmod(0o755)
    environment = dict(os.environ, GATEWAY_CHECK_ROOT=str(root))
    environment["PATH"] = str(bins) + os.pathsep + environment["PATH"]

    def write(name, text):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def run():
        calls.write_text("")
        result = subprocess.run(
            ["bash", str(guard)], env=environment, text=True, capture_output=True, check=False
        )
        return result, calls.read_text().splitlines()

    # An attribute at one file's EOF cannot authorize or taint the next file.
    write("a.rs", "#[derive(Debug)]\n")
    write("b.rs", "pub struct SecretClean;\n")
    write("c.rs", "// prologue\n#[derive(Debug)]\npub struct SecretBad;\n"
          "impl core::fmt::Display for SecretBad {}\n")
    write("d.rs", "#[derive(Debug)]\npub struct SecretAllowed;\n"
          "impl core::fmt::Display for SecretAllowed {}\n")
    write("scripts/allowances/ct-eq-allowances.txt", "d.rs:SecretAllowed # no material\n")
    write("crates/sig/src/ordinary.rs", "pub struct Ordinary;\n")
    for number in range(24):
        write(f"ordinary/{number:02}.rs", "pub struct Ordinary;\n")
    for number in range(8):
        write(f"crates/sig/tests/empty_{number}.rs", "// empty fixture\n")
    # Keep the historical grep expression, including its platform-specific escape semantics.
    labels = "/// Negative\n" * 185 + "\t/// Negative\nt/// Negative\nt/// Negative\n"
    expected_labels = subprocess.run(
        [shutil.which("grep"), "-cE", r"^[ \t]*/// Negative"],
        input=labels, text=True, capture_output=True, check=True,
    ).stdout.strip()
    write("crates/sig/tests/floors.rs", "// ```compile_fail\n" * 32 + labels)

    result, invocations = run()
    assert result.returncode == 1, result
    diagnostics = [line for line in result.stderr.splitlines() if line.startswith(("a.rs:", "b.rs:", "c.rs:", "d.rs:"))]
    assert diagnostics == [
        "c.rs:2: secret-bearing type 'SecretBad' derives Debug; derive nothing that compares, prints or serializes key material — implement PartialEq via subtle::ConstantTimeEq and a redacting Debug by hand",
        "c.rs:4: Display is implemented for secret-bearing type 'SecretBad'; a value that renders itself for a human is a value that ends up in a log",
    ], result.stderr
    assert "below the" not in result.stderr, result.stderr

    # Both floors must independently reject an input below their recorded baseline.
    write("crates/sig/tests/floors.rs", "// ```compile_fail\n" * 31 + "/// Negative\n" * 185)
    result, _ = run()
    assert "compile_fail doctests in crates/sig fell to 31, below the 32 baseline" in result.stderr
    assert "'/// Negative' cases in crates/sig fell to 185, below the 186 baseline" in result.stderr
    (root / "crates/sig/tests/floors.rs").unlink()
    result, _ = run()
    assert "compile_fail doctests in crates/sig fell to 0, below the 32 baseline" in result.stderr
    assert "'/// Negative' cases in crates/sig fell to 0, below the 186 baseline" in result.stderr

    write("c.rs", "pub struct SecretBad;\n")
    write("crates/sig/tests/floors.rs", "// ```compile_fail\n" * 32 + labels)
    result, _ = run()
    assert result.returncode == 0, result.stderr
    assert f"negative cases {expected_labels} >= 186" in result.stdout, result.stdout
    # Extra ordinary files must not each spawn scanners. Allowance membership uses grep too.
    assert invocations.count("awk") <= 3, invocations
    assert invocations.count("grep") <= 17, invocations
    print("OK: constant-time batches preserve diagnostics, file boundaries, allowances and floors")
