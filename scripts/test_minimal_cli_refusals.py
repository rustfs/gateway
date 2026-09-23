#!/usr/bin/env python3
"""Exercise the smoke script's actual CLI observer with isolated executable controls.

This does not build or run the listener; real-binary wire and shutdown checks remain in the smoke.
"""
import json
import pathlib
import re
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


if __name__ == "__main__":
    unittest.main()
