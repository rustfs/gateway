#!/usr/bin/env python3
"""Check SSE scan work, file boundaries, scopes and unchanged diagnostics on small fixtures."""

from collections import Counter
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


guard = Path(__file__).with_name("check_sse_key_never_leaks.sh").resolve()
with tempfile.TemporaryDirectory(prefix="gateway-sse-batch-") as temporary:
    root = Path(temporary)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    bins = root / "bin"
    bins.mkdir()
    calls = root / "calls"
    for command in ("awk", "grep"):
        executable = shutil.which(command)
        assert executable, command
        wrapper = bins / command
        wrapper.write_text("#!/bin/sh\n"
                           f"printf '%s\\n' {shlex.quote(command)} >> {shlex.quote(str(calls))}\n"
                           f"exec {shlex.quote(executable)} \"$@\"\n")
        wrapper.chmod(0o755)
    environment = dict(os.environ, GATEWAY_CHECK_ROOT=str(root))
    environment["PATH"] = str(bins) + os.pathsep + environment["PATH"]

    def write(name, text):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def run():
        calls.write_text("")
        result = subprocess.run(["bash", str(guard)], env=environment, text=True, capture_output=True)
        return result, calls.read_text().splitlines()

    header = 'wire_name = "x-amz-server-side-encryption-customer-key"\n'
    headers = "const NEVER_IN_A_RESPONSE: &[&str] = &[SSEC_KEY, COPY_SSEC_KEY];\n"
    key = "key_text.expose(); key_text.expose();\nbool::from(a); bool::from(b);\n"
    write("crates/core/src/sse/headers.rs", headers)
    write("crates/core/src/sse/key.rs", key)
    write("crates/gateway/src/invariants.rs", "use NEVER_IN_A_RESPONSE;\n")
    write("spec/operations/a.toml", "[[output]]\n")
    write("spec/operations/b.toml", header)
    write("crates/other/src/customer_key.rs", 'format!("ordinary");\nbool::from(x); x.expose();\n')
    write("crates/other/tests/example.rs", 'format!("{customer_key}");\n')
    write("crates/other/src/tests.rs", 'format!("{customer_key}");\n')
    write("crates/other/src/comments.rs", '// format!("{customer_key}");\n')
    result, small_calls = run()
    assert result.returncode == 0, result.stderr

    # An output section at another file's EOF cannot classify the first line of this file.
    write("spec/operations/b.toml", "# prologue\n[[output]]\n" + header)
    extra = write("spec/operations/c.toml", "[[output]]\n" + header)
    result, _ = run()
    diagnostics = [line.split(":", 2)[:2] for line in result.stderr.splitlines() if line.startswith("spec/operations/")]
    assert result.returncode == 1 and diagnostics == [["spec/operations/b.toml", "3"], ["spec/operations/c.toml", "2"]], result.stderr
    extra.unlink()
    write("spec/operations/b.toml", header)

    # Test exemption only applies to logging: SSE-module counters still include test files.
    path = write("crates/core/src/sse/tests/probe.rs", 'key_text.expose();\nbool::from(a);\nformat!("{customer_key}");\n')
    result, _ = run()
    assert result.returncode == 1, result.stderr
    assert "probe.rs: bool::from( outside" in result.stderr, result.stderr
    assert "KeyText::expose has 2 call sites" in result.stderr, result.stderr
    assert "bool::from( appears 2 times" in result.stderr, result.stderr
    assert "formatting or logging macro" not in result.stderr, result.stderr
    path.unlink()
    path = write("crates/core/src/sse/escape.rs", "bool::from(a);\n")
    result, _ = run()
    assert result.returncode == 1 and "escape.rs: bool::from( outside" in result.stderr, result.stderr
    path.unlink()

    # Production diagnostics keep their original file and line, while comment-only lines vanish.
    path = write("crates/other/src/logging.rs", '// format!("{ssec_key}");\nformat!("{ssec_key}");\n')
    result, _ = run()
    assert result.returncode == 1 and "logging.rs:2: a formatting or logging macro" in result.stderr, result.stderr
    assert "logging.rs:1:" not in result.stderr, result.stderr
    path.unlink()
    write("crates/core/src/sse/key.rs", "// key_text.expose();\n// bool::from(a);\n")
    result, _ = run()
    assert "KeyText::expose has 0 call sites" in result.stderr, result.stderr
    assert "bool::from( appears 0 times" in result.stderr, result.stderr
    write("crates/core/src/sse/key.rs", "fn ordinary() {}\n")
    result, _ = run()
    assert "KeyText::expose has 0 call sites" in result.stderr, result.stderr
    assert "bool::from( appears 0 times" in result.stderr, result.stderr
    write("crates/core/src/sse/key.rs", key)
    (root / "crates/core/src/sse/headers.rs").unlink()
    result, _ = run()
    assert result.returncode == 1 and "does not exist" in result.stderr, result.stderr
    write("crates/core/src/sse/headers.rs", headers)
    for path in (root / "spec/operations").glob("*.toml"):
        path.unlink()
    result, _ = run()
    assert result.returncode == 1 and "no operation specifications" in result.stderr, result.stderr
    write("spec/operations/a.toml", "[[output]]\n")
    write("spec/operations/b.toml", header)

    # Extra irrelevant sources/specs must add no scanner processes; matching sources still scan.
    for number in range(24):
        write(f"ordinary/{number:02}.rs", "fn ordinary() {}\n")
        write(f"spec/operations/extra_{number:02}.toml", "[[input]]\n" + header)
    result, large_calls = run()
    assert result.returncode == 0, result.stderr
    assert Counter(large_calls) == Counter(small_calls), (small_calls, large_calls)
    # A tracked input disappearing after enumeration must not turn a scan into an empty success.
    subprocess.run(["git", "-C", str(root), "add", "ordinary/00.rs", "spec/operations/a.toml"], check=True)
    (root / "ordinary/00.rs").unlink()
    result, _ = run()
    assert result.returncode == 1 and "cannot inspect Rust sources" in result.stderr, result.stderr
    write("ordinary/00.rs", "fn ordinary() {}\n")
    (root / "spec/operations/a.toml").unlink()
    result, _ = run()
    assert result.returncode == 1 and "cannot read operation specifications" in result.stderr, result.stderr
print("OK: SSE batches preserve file boundaries, line counts, scopes and missing-input failures")
