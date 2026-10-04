#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Exercise the Mint guard's complete probe census and execution boundary."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check_mint_report.sh"


def exercise(guard=GUARD, report=None, child_change="", extra_probes=""):
    source = guard.read_text().split("<<'PYEOF'\n", 1)[1].rsplit("\nPYEOF", 1)[0]
    source = source.replace("if failures:\n    for failure in failures:", extra_probes + "\nif failures:\n    for failure in failures:")
    with tempfile.TemporaryDirectory() as directory:
        receipt = Path(directory) / "commands.json"
        wrapper = '''import json, subprocess, sys
calls = []
original = subprocess.run
def traced(command, *args, **kwargs):
    calls.append(command)
    result = original(command, *args, **kwargs)
    if len(command) > 2 and command[2] == "judge":
        exec(CHILD_CHANGE)
    return result
subprocess.run = traced
try:
    exec(compile(SOURCE, "mint-guard-inline", "exec"))
finally:
    RECEIPT.write_text(json.dumps(calls))
'''
        wrapper = "CHILD_CHANGE=" + repr(child_change) + "\nfrom pathlib import Path\nSOURCE=" + repr(source) + "\nRECEIPT=Path(" + repr(str(receipt)) + ")\n" + wrapper
        result = subprocess.run([sys.executable, "-c", wrapper, str(report or ROOT / "ci/mint/report.py")], capture_output=True, text=True, check=False)
        return result, json.loads(receipt.read_text())


class MintExecutionTests(unittest.TestCase):
    def runner(self):
        source = GUARD.read_text().split("<<'PYEOF'\n", 1)[1].rsplit("\nPYEOF", 1)[0]
        prefix = source.split("def rec(", 1)[0]
        namespace = {}
        saved = sys.argv
        try:
            sys.argv = ["guard", str(ROOT / "ci/mint/report.py")]
            exec(compile(prefix, str(GUARD), "exec"), namespace)
        finally:
            sys.argv = saved
        return namespace["run_report"]

    def test_fresh_namespace_and_process_state_restored(self):
        run = self.runner()
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "report.py"
            script.write_text("import os, sys\nassert __name__ == '__main__'\nassert 'visited' not in globals()\nvisited=True\nprint(sys.argv[1])\nprint('diagnostic', file=sys.stderr)\nos.environ['MINT_ISOLATION_SENTINEL']='changed'\nsys.path.append('changed')\nos.chdir('/')\nraise SystemExit(3)\n")
            before = (sys.argv[:], sys.path[:], dict(os.environ), os.getcwd(), sys.modules.get("__main__"))
            for argument in ("first", "second"):
                result = run([sys.executable, str(script), argument])
                self.assertEqual((result.returncode, result.stdout, result.stderr), (3, argument + "\n", "diagnostic\n"))
                self.assertEqual((sys.argv, sys.path, dict(os.environ), os.getcwd(), sys.modules.get("__main__")), before)

    def test_exception_is_not_an_exit_verdict_and_restores_state(self):
        run = self.runner()
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "report.py"
            script.write_text("import os\nos.environ['MINT_ISOLATION_SENTINEL']='changed'\nraise RuntimeError('deliberate reporter crash')\n")
            before = dict(os.environ)
            with self.assertRaisesRegex(RuntimeError, 'deliberate reporter crash'):
                run([sys.executable, str(script)])
            self.assertEqual(dict(os.environ), before)

    def test_missing_report_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                self.runner()([sys.executable, str(Path(directory) / "missing.py")])

    def test_each_invocation_reads_current_report_bytes(self):
        run = self.runner()
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "report.py"
            for code in (0, 1, 2, 3):
                script.write_text(f"raise SystemExit({code})\n")
                self.assertEqual(run([sys.executable, str(script)]).returncode, code)

    def test_missing_json_helper_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "report.py"
            shutil.copyfile(ROOT / "ci/mint/report.py", script)
            evidence = Path(directory) / "log.json"
            evidence.write_text('{}')
            with self.assertRaises(FileNotFoundError):
                self.runner()([sys.executable, str(script), "redact", str(evidence)])

    def test_each_invocation_reads_current_json_helper_bytes(self):
        run = self.runner()
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "report.py"
            shutil.copyfile(ROOT / "ci/mint/report.py", script)
            helper, evidence = Path(directory) / "_redaction.py", Path(directory) / "log.json"
            for label in ("first", "second"):
                helper.write_text(f'def redact_json(text, secrets, redact_text):\n    return {label!r}\n')
                evidence.write_text('{}')
                result = run([sys.executable, str(script), "redact", str(evidence)])
                self.assertEqual(result.returncode, 0)
                self.assertEqual(evidence.read_text(), label)

    def test_late_delimiter_cannot_consume_complete_suffix_records(self):
        result, _ = exercise(extra_probes='''
def late_delimiter_preserved(work, proposal):
    if proposal.exists():
        return "an incomplete run left a proposal behind"
    text = (work / "log/minio-go/log.json").read_text(encoding="utf-8")
    if "synthetic-late-delimiter-material-1266" in text:
        return "a signing value retained material"
    ending = "\\n" + delimiter + "\\n"
    preserved = text.endswith(ending)
    text = text[:-len(ending)] if preserved else text
    try:
        boundary = text.rfind("\\n", 0, text.index('"valid-suffix"')) + 1
        records = [json.loads(text.splitlines()[0]), *json_documents(text[boundary:])]
    except (json.JSONDecodeError, ValueError):
        return "redaction corrupted or lost complete suffix records"
    expected = [json.loads(rec("minio-go", name, status)) for name, status in (
        ("valid-prefix", "PASS"), ("valid-suffix", "NA"), ("valid-after-suffix", "PASS"))]
    if records != expected or '"tail"' not in text:
        return "redaction changed suffix record fields, order or census"
    if not preserved:
        return "redaction discarded the original late delimiter"

for key, value, delimiter in (
    ("credential", '{"nested":"synthetic-late-delimiter-material-1266"', "}"),
    ("StringToSignBytes", '["synthetic-late-delimiter-material-1266"', "]"),
):
    logs = healthy_logs()
    fragment = '{"name":"minio-go","function":"tail","status":"FAIL","' + key + '":' + value
    logs["minio-go"] = (rec("minio-go", "valid-prefix", "PASS") + "\\n" + fragment + "\\n"
        + rec("minio-go", "valid-suffix", "NA") + "\\n" + rec("minio-go", "valid-after-suffix", "PASS") + "\\n" + delimiter)
    probe("late delimiter " + key + " preserves complete suffix records", 3,
        ["record 2 in minio-go/log.json is not valid JSON", '"complete": false'], logs=logs, redact=True,
        record=True, stale_proposal=True, after=late_delimiter_preserved)
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OK: 112 mint report probes;", result.stdout)

    def test_noninteger_system_exit_matches_python(self):
        run = self.runner()
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "report.py"
            script.write_text("raise SystemExit('refused')\n")
            result = run([sys.executable, str(script)])
            self.assertEqual((result.returncode, result.stderr), (1, "refused\n"))

    def test_malformed_diagnostic_keeps_signing_context_and_suffix_records(self):
        result, _ = exercise(extra_probes='''
def malformed_diagnostic_preserved(work, proposal):
    if proposal.exists():
        return "an incomplete run left a proposal behind"
    text = (work / "log/minio-go/log.json").read_text(encoding="utf-8")
    if context_secret and context_secret in text:
        return "malformed diagnostic retained its configured secret prefix"
    if "synthetic-tail-signing-material-1266" in text:
        return "malformed diagnostic retained signing material across JSON tokens"
    if "!INVALID_JSON!" not in text or '"malformed-tail"' not in text:
        return "redaction lost the original malformed record marker or identity"
    try:
        boundary = text.rfind("\\n", 0, text.index('"valid-suffix"')) + 1
        records = [json.loads(text.splitlines()[0]), *json_documents(text[boundary:])]
    except (json.JSONDecodeError, ValueError):
        return "redaction corrupted or lost complete suffix records"
    if records != [prefix, suffix, {**after_suffix, "error": 'Authorization: "[REDACTED]"'}]:
        return "redaction changed complete record fields, order or census"

prefix = json.loads(rec("minio-go", "valid-prefix", "PASS"))
suffix = json.loads(rec("minio-go", "valid-suffix", "NA", error='ordinary "quoted" diagnostic with \\\\ slash and\\nnext line \\u2603'))
after_suffix = json.loads(rec("minio-go", "valid-after-suffix", "PASS", error='Authorization: "synthetic-suffix-signing-material-1266"'))
previous_context_secret = os.environ.get("MINT_JSON_REDACTION_PROBE")
try:
    for label, diagnostic, context_secret in (
        ("Authorization", 'Authorization: "synthetic-tail-signing-material-1266"', ""),
        ("expected signature", 'expected signature: "synthetic-tail-signing-material-1266"', ""),
        ("configured prefix", 'synthetic-known-label-1266 Authorization: "synthetic-tail-signing-material-1266"', "synthetic-known-label-1266"),
    ):
        os.environ["MINT_JSON_REDACTION_PROBE"] = context_secret
        logs = healthy_logs()
        fragment = '{"name":"minio-go","function":"malformed-tail","status":"FAIL","error":"' + diagnostic + '"}'
        logs["minio-go"] = "\\n".join((json.dumps(prefix), fragment, json.dumps(suffix), json.dumps(after_suffix)))
        probe("malformed diagnostic retains signing context " + label, 3,
            ["record 2 in minio-go/log.json is not valid JSON", '"complete": false'], logs=logs, redact=True,
            record=True, stale_proposal=True, after=malformed_diagnostic_preserved)
finally:
    if previous_context_secret is None:
        os.environ.pop("MINT_JSON_REDACTION_PROBE", None)
    else:
        os.environ["MINT_JSON_REDACTION_PROBE"] = previous_context_secret
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_real_cli_disagreement_is_rejected(self):
        for change in ("result.returncode = 99", "result.stdout += 'unexpected stdout'",
                       "result.stderr += 'unexpected stderr'",
                       "Path(command[command.index('--json') + 1]).write_text('changed')"):
            with self.subTest(change=change):
                result, _ = exercise(child_change=change)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("real CLI differs from isolated __main__ execution", result.stderr)

    def test_complete_census_uses_bounded_judge_subprocesses(self):
        result, commands = exercise()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OK: 110 mint report probes;", result.stdout)
        judges = [cmd for cmd in commands if len(cmd) > 2 and cmd[2] == "judge"]
        self.assertEqual(len(judges), 4, "all four CLI exit classes need one boundary control; remaining judges must reuse the interpreter")
        self.assertEqual(sum(len(cmd) > 2 and cmd[2] == "redact" for cmd in commands), 1)
        self.assertEqual(sum(cmd[0] == "bash" for cmd in commands), 7)


if __name__ == "__main__":
    unittest.main()
