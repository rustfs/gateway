#!/usr/bin/env python3
"""Exercise actual bootstrap source with isolated child tools, never a workspace build."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

SOURCE = Path(__file__).resolve().parents[1] / "src/bootstrap.rs"
STAGES = ["toolchain check", "dependency fetch", "pinned model verification",
          "generated artifact verification", "workspace test compilation"]

with tempfile.TemporaryDirectory(prefix="gateway-bootstrap-diagnostics-") as directory:
    root = Path(directory)
    bins = root / "bin"
    bins.mkdir()
    tool = '''#!/bin/sh
sleep 0.02
case "$(basename "$0"):$*" in
  cargo:--version|rustc:--version) exit 0 ;;
  'cargo:fetch --locked')
    printf 'fetch\\n' >>"$FIXTURE_LOG"
    exit "${FETCH_EXIT:-0}" ;;
  'cargo:test --workspace --no-run')
    sleep "${COMPILE_DELAY:-0}"
    printf 'compile\\n' >>"$FIXTURE_LOG"
    printf 'fixture compiler stdout must not enter JSON\\n'
    printf 'fixture compiler diagnostic\\n' >&2
    exit "${COMPILE_EXIT:-0}" ;;
  python3:*) printf 'model\\n' >>"$FIXTURE_LOG"; exit "${MODEL_EXIT:-0}" ;;
  *) printf 'unexpected fixture command: %s %s\\n' "$0" "$*" >&2; exit 97 ;;
esac
'''
    for name in ("cargo", "rustc", "python3"):
        path = bins / name
        path.write_text(tool)
        path.chmod(0o755)
    # Compile the real implementation without substituting any of its Rust statements.
    # Only its external codegen dependency is a fixture; these tests concern process diagnostics.
    wrapper = root / "driver.rs"
    wrapper.write_text('''mod codegen {
    pub fn repo_root() -> std::path::PathBuf {
        std::env::var_os("FIXTURE_ROOT").unwrap().into()
    }
    pub fn verify_generated() -> Result<usize, String> {
        std::thread::sleep(std::time::Duration::from_millis(20));
        if std::env::var_os("GENERATED_FAIL").is_some() {
            Err("fixture generated drift".to_owned())
        } else {
            Ok(7)
        }
    }
}
#[path = ''' + json.dumps(str(SOURCE)) + ''']
mod bootstrap;
fn main() -> std::process::ExitCode {
    bootstrap::bootstrap(&std::env::args().skip(1).collect::<Vec<_>>())
}
''')
    executable = root / "bootstrap-fixture"
    compiler = shutil.which("rustc")
    assert compiler is not None, "the pinned Rust compiler is required"
    build = subprocess.run([compiler, "--edition=2024", str(wrapper), "-o", str(executable)],
                           env=dict(os.environ, CARGO=str(bins / "cargo")), capture_output=True, text=True)
    assert build.returncode == 0, build.stderr
    failures = []
    scenarios = [
        ("success-json", {}, ["--json"], 0, 5),
        ("success-plain", {}, [], 0, 5),
        ("compiler-failure", {"COMPILE_EXIT": "23", "COMPILE_DELAY": "0.15"}, ["--json"], 1, 5),
        ("fetch-failure", {"FETCH_EXIT": "24"}, ["--json"], 3, 2),
        ("model-failure", {"MODEL_EXIT": "25"}, ["--json"], 1, 3),
        ("generated-failure", {"GENERATED_FAIL": "1"}, ["--json"], 1, 4),
    ]
    for name, overrides, arguments, code, stage_count in scenarios:
        log = root / (name + ".log")
        environment = dict(os.environ, PATH=str(bins) + os.pathsep + os.environ["PATH"],
                           FIXTURE_ROOT=str(root), FIXTURE_LOG=str(log))
        for key in ("COMPILE_EXIT", "COMPILE_DELAY", "FETCH_EXIT", "MODEL_EXIT", "GENERATED_FAIL"):
            environment.pop(key, None)
        environment.update(overrides)
        started = time.monotonic()
        result = subprocess.run([str(executable), *arguments], env=environment,
                                capture_output=True, text=True, timeout=10)
        observed_runtime = time.monotonic() - started
        try:
            assert result.returncode == code, (result.returncode, result.stderr)
            if stage_count == 5:
                assert "fixture compiler diagnostic" in result.stderr, result.stderr
            reported_total = 0.0
            for stage in STAGES[:stage_count]:
                assert f"bootstrap: {stage} started" in result.stderr, (stage, result.stderr)
                pattern = rf"bootstrap: {re.escape(stage)} finished in ([0-9]+\.[0-9]+)s"
                observed = re.search(pattern, result.stderr)
                assert observed is not None, (stage, result.stderr)
                duration = float(observed.group(1))
                floor = 0.14 if name == "compiler-failure" and stage == "workspace test compilation" else 0.01
                assert duration >= floor, (stage, duration, floor)
                reported_total += duration
            # Each stage rounds to hundredths. The child's sequential stages cannot consume
            # more time than the independent parent's whole-process measurement plus rounding.
            assert reported_total <= observed_runtime + stage_count * 0.005, (reported_total, observed_runtime)
            for stage in STAGES[stage_count:]:
                assert f"bootstrap: {stage} started" not in result.stderr, (stage, result.stderr)
            if stage_count == 5:
                assert log.read_text().splitlines() == ["fetch", "model", "compile"]
            else:
                assert "fixture compiler diagnostic" not in result.stderr, result.stderr
                assert "compile" not in log.read_text().splitlines()
            assert "fixture compiler stdout" not in result.stdout, result.stdout
            if name == "success-json":
                report = json.loads(result.stdout)
                assert report["command"] == "bootstrap" and report["ok"] is True, report
            elif code != 0:
                assert result.stdout == "", result.stdout
                assert "bootstrap: ready" not in result.stderr, result.stderr
        except AssertionError as error:
            failures.append(f"{name}: {error}")
    assert not failures, "\n".join(failures)
print("OK: bootstrap stage timing, compiler diagnostics, exact compile scope and early failures")
