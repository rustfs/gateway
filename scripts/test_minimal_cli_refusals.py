#!/usr/bin/env python3
"""Exercise the smoke script's CLI and startup observers with isolated executable controls.

This does not build or run the listener; real-binary wire and shutdown checks remain in the smoke.
"""
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("run_minimal_listener_smoke.sh")
CASES = [
    ["--port"], ["--listen-everywhere"], ["127.0.0.1"], ["127.0.0.1:65536"],
    ["127.0.0.1:0", "127.0.0.1:0"], ["--host", "127.0.0.1", "--port", "0"],
]


class CliRefusalObserver(unittest.TestCase):
    def run_observer(self, mode="correct", selected=0):
        source = SCRIPT.read_text()
        blocks = re.findall(r"python3 - [^\n]+ <<'PYTEST'\n(.*?)\nPYTEST", source, re.S)
        self.assertEqual(len(blocks), 1, "the real CLI observer must remain identifiable")
        with tempfile.TemporaryDirectory(prefix="gateway-cli-control-") as directory:
            root = pathlib.Path(directory)
            calls = root / "calls.jsonl"
            executable = root / "fake-minimal"
            executable.write_text("#!" + sys.executable + "\n" + f'''
import json, os, signal, sys
arguments = sys.argv[1:]
with open({str(calls)!r}, "a") as output:
    output.write(json.dumps(arguments) + "\\n")
cases = {CASES!r}
index = cases.index(arguments)
expected = 'Error: "expected at most one listen address"' if index == 4 else 'Error: AddrParseError(Socket)'
mode = {mode!r} if index == {selected} else "correct"
if mode == "signal":
    print(expected, file=sys.stderr, flush=True)
    os.kill(os.getpid(), signal.SIGTERM)
if mode == "startup":
    print("Error: address already in use", file=sys.stderr)
    sys.exit(1)
if mode == "panic":
    print("thread main panicked", file=sys.stderr)
    sys.exit(101)
if mode == "silent":
    sys.exit(1)
if mode == "wrong-class":
    print('Error: AddrParseError(Socket)' if index == 4 else 'Error: "expected at most one listen address"', file=sys.stderr)
    sys.exit(1)
if mode == "stdout-error":
    print(expected)
    sys.exit(1)
if mode == "listener-stdout":
    print("listening on http://127.0.0.1:9000")
if mode == "listener-stderr":
    print("listening on http://127.0.0.1:9000", file=sys.stderr)
print(expected, file=sys.stderr)
sys.exit(0 if mode == "success" else 42 if mode == "wrong-exit" else 1)
''')
            executable.chmod(0o700)
            result = subprocess.run(
                [sys.executable, "-c", blocks[0], str(executable)],
                capture_output=True, text=True, timeout=10,
            )
            observed = [json.loads(line) for line in calls.read_text().splitlines()]
            return result, observed

    def test_correct_argument_errors_accept_all_six_original_cases(self):
        result, observed = self.run_observer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(observed, CASES)
        self.assertEqual(result.stdout.count("OK: cli_refuses_"), 6)

    def test_each_case_rejects_unrelated_startup_failure_and_signal(self):
        for selected in range(6):
            for mode in ["startup", "signal", "wrong-class"]:
                with self.subTest(case=selected, mode=mode):
                    result, observed = self.run_observer(mode, selected)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(observed, CASES[:selected + 1])

    def test_wrong_exit_or_output_cannot_certify_argument_rejection(self):
        for mode in ["panic", "silent", "stdout-error", "success", "wrong-exit", "listener-stdout", "listener-stderr"]:
            with self.subTest(mode=mode):
                result, _ = self.run_observer(mode)
                self.assertNotEqual(result.returncode, 0, result.stdout)


class ListenerStartupObserver(unittest.TestCase):
    def run_startup(self, mode):
        source = SCRIPT.read_text()
        cleanup = source[source.index("cleanup() {"):source.index('\ncd "$ROOT"')]
        startup = source.split("\nPYTEST\n", 1)[1].split('\npython3 - "$ADDRESS"', 1)[0]
        with tempfile.TemporaryDirectory(prefix="gateway-startup-control-") as directory:
            root = pathlib.Path(directory)
            (root / "smoke").mkdir()
            (root / "debug/examples").mkdir(parents=True)
            (root / "bin").mkdir()
            ready, release, polls = (root / name for name in ("ready", "release", "polls.jsonl"))
            executable = root / "debug/examples/minimal"
            executable.write_text("#!" + sys.executable + "\n" + f'''
import signal, sys
mode = {mode!r}
if mode == "silent-exit":
    sys.exit(0)
if mode == "startup-error":
    print("unrelated startup failure", file=sys.stderr, flush=True)
    sys.exit(31)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
print("listening on http://127.0.0.1:9000", flush=True)
while True:
    signal.pause()
''')
            executable.chmod(0o700)
            sed = root / "bin/sed"
            sed.write_text("#!" + sys.executable + "\n" + f'''
import json, pathlib, subprocess, sys, time
ready, release, polls = map(pathlib.Path, {list(map(str, (ready, release, polls)))!r})
while not ready.exists():
    time.sleep(0.001)
exists = pathlib.Path(sys.argv[-1]).is_file()
result = subprocess.run([{shutil.which("sed")!r}, *sys.argv[1:]], capture_output=True)
with polls.open("a") as output:
    output.write(json.dumps({{"log_exists": exists, "status": result.returncode}}) + "\\n")
release.write_text("release")
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
sys.exit(result.returncode)
''')
            sed.chmod(0o700)
            # Delay the actual command before its redirection; release it only after the real sed.
            # extdebug skips the original launch once; errexit resumes before the original poll.
            schedule = '''
shopt -s extdebug
schedule_launch() {
    local command="$1"
    if [[ "$command" == *debug/examples/minimal* && "$command" == *127.0.0.1:0* ]]; then
        set +e
        (
            trap - DEBUG EXIT
            printf ready >"$READY"
            while [[ ! -f "$RELEASE" ]]; do sleep 0.001; done
            eval "exec $command"
        ) &
        return 1
    fi
    if [[ "$command" == PROCESS_ID=* ]]; then
        set -e
        trap - DEBUG
    fi
    return 0
}
trap 'schedule_launch "$BASH_COMMAND"' DEBUG
'''
            harness = '\n'.join([
                'set -euo pipefail', 'TARGET_DIR="$1"', 'SMOKE_DIR="$1/smoke"',
                'LOG="$SMOKE_DIR/minimal.log"', 'PROCESS_ID=""',
                'READY="$1/ready"', 'RELEASE="$1/release"', cleanup, schedule, startup,
                'printf "observed address: %s\\n" "$ADDRESS"',
            ])
            process = subprocess.Popen(
                ["bash", "-c", harness, "startup-control", str(root)],
                env={**os.environ, "PATH": str(root / "bin") + os.pathsep + os.environ["PATH"]},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=10)
                result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
                observed = [json.loads(line) for line in polls.read_text().splitlines()]
                return result, observed
            finally:
                release.write_text("rescue")
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                if process.poll() is None:
                    process.communicate(timeout=2)

    def test_delayed_child_redirection_cannot_abort_the_first_poll(self):
        result, observed = self.run_startup("announces")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(observed[0], {"log_exists": True, "status": 0})
        self.assertIn("observed address: 127.0.0.1:9000", result.stdout)

    def test_silent_child_exit_reaches_the_original_startup_refusal(self):
        result, observed = self.run_startup("silent-exit")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(observed[0], {"log_exists": True, "status": 0})
        self.assertIn("example exited before announcing its listener", result.stderr)

    def test_unrelated_startup_failure_remains_visible_and_refused(self):
        result, observed = self.run_startup("startup-error")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(observed[0], {"log_exists": True, "status": 0})
        self.assertIn("example exited before announcing its listener", result.stderr)
        self.assertIn("unrelated startup failure", result.stderr)


if __name__ == "__main__":
    unittest.main()
