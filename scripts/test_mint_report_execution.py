#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Exercise the Mint guard's complete probe census and execution boundary."""
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/check_mint_report.sh"

# What mint's aws-sdk-java-v2 suite writes into a FAIL record's `error`: `ex.toString()`, then
# ` >>> ` and the stack frames. The SDK's AwsServiceException.getMessage() appends
# `(Service: S3, Status Code: NNN, Request ID: ..., Extended Request ID: ...)`.
JAVA_REFUSED = (
    "software.amazon.awssdk.services.s3.model.S3Exception: The request is not valid. "
    "(Service: S3, Status Code: 400, Request ID: 7F2A1C9E4B3D5A60, Extended Request ID: "
    "c2lnbmF0dXJlLWxvb2tpbmctYmFzZTY0LXRleHQ=) >>> [software.amazon.awssdk.core.internal.http."
    "CombinedResponseHandler.handleErrorResponse(CombinedResponseHandler.java:125), software.amazon."
    "awssdk.awscore.exception.AwsServiceException.builder(AwsServiceException.java:40)]"
)
JAVA_CLIENT = (
    "software.amazon.awssdk.core.exception.SdkClientException: Unable to execute HTTP request: "
    "Acquire operation took longer than the configured maximum time. >>> [software.amazon.awssdk."
    "core.internal.http.pipeline.stages.utils.RetryableStageHelper.retryPolicyDisallowedRetryException("
    "RetryableStageHelper.java:143)]"
)
# The whole output alphabet of the classifier: three slots, each `-` when the text names none.
CLASS_SHAPE = re.compile(r"(?:[A-Z][A-Za-z0-9]{0,54}(?:Exception|Error)|-)/(?:[0-9]{3}|-)/(?:[A-Z][A-Za-z0-9.]{0,63}|-)")


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
        self.assertIn("OK: 119 mint report probes;", result.stdout)

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
        self.assertIn("OK: 117 mint report probes;", result.stdout)
        judges = [cmd for cmd in commands if len(cmd) > 2 and cmd[2] == "judge"]
        self.assertEqual(len(judges), 4, "all four CLI exit classes need one boundary control; remaining judges must reuse the interpreter")
        self.assertEqual(sum(len(cmd) > 2 and cmd[2] == "redact" for cmd in commands), 1)
        self.assertEqual(sum(cmd[0] == "bash" for cmd in commands), 7)


class MintFailureClassTests(unittest.TestCase):
    """A FAIL row carries a class drawn from its record's `error` through a fixed grammar, never
    the text itself, so the aggregate can attribute a failure whose raw log stays on the runner
    (rustfs/gateway#1083)."""

    @classmethod
    def setUpClass(cls):
        cls.report = runpy.run_path(str(ROOT / "ci/mint/report.py"))

    def classified(self, error):
        classify = self.report.get("classify_error")
        self.assertIsNotNone(classify, "ci/mint/report.py defines no classify_error")
        value = classify(error)
        self.assertTrue(CLASS_SHAPE.fullmatch(value), f"{value!r} is outside the class alphabet")
        return value

    def test_java_v2_service_refusal_names_the_thrown_class_and_the_status(self):
        # The frames name AwsServiceException after the thrown S3Exception; the thrown one wins.
        self.assertEqual(self.classified(JAVA_REFUSED), "S3Exception/400/-")

    def test_java_v2_client_failure_names_the_class_without_a_status(self):
        self.assertEqual(self.classified(JAVA_CLIENT), "SdkClientException/-/-")

    def test_go_boto_and_xml_locations_name_the_status_and_the_code(self):
        for error, expected in (
            ("operation error S3: PutObject, https response error StatusCode: 400, RequestID: "
             "7F2A1C9E4B3D5A60, HostID: c2lnbmF0dXJl, api error InvalidRequest: The request is not valid.",
             "-/400/InvalidRequest"),
            ('<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>The specified key does not '
             "exist.</Message><RequestId>7F2A1C9E4B3D5A60</RequestId></Error>", "-/-/NoSuchKey"),
            ("An error occurred (AccessDenied) when calling the PutObject operation: Access Denied",
             "-/-/AccessDenied"),
        ):
            with self.subTest(error=error):
                self.assertEqual(self.classified(error), expected)

    def test_missing_or_non_string_error_is_unclassified(self):
        for error in (None, "", "   ", 400, ["S3Exception"], {"class": "S3Exception", "status": 400}):
            with self.subTest(error=error):
                self.assertEqual(self.classified(error), "-/-/-")

    def test_free_text_is_unclassified(self):
        self.assertEqual(self.classified("UNIQUE-UPSTREAM-ERROR-TEXT-7f3a"), "-/-/-")

    def test_status_is_read_only_from_a_three_digit_status_code(self):
        for error in (
            "software.amazon.awssdk.services.s3.model.S3Exception: refused (Service: S3, Request ID: "
            "404ABC, Extended Request ID: 500)",
            "S3Exception: refused (Service: S3, Status Code: 4000, Request ID: X)",
            "S3Exception: refused after 400 ms",
        ):
            with self.subTest(error=error):
                self.assertEqual(self.classified(error), "S3Exception/-/-")

    def test_signing_material_and_identifiers_never_reach_the_class(self):
        error = ("software.amazon.awssdk.core.exception.SdkClientException: AKIAIOSFODNN7EXAMPLE "
                 "feedfacefeedface0001 Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"
                 "20261008/us-east-1/s3/aws4_request (Service: S3, Status Code: 403, Request ID: 7F2A1C9E4B3D5A60)")
        value = self.classified(error)
        self.assertEqual(value, "SdkClientException/403/-")
        for material in ("AKIA", "feedface", "Credential", "7F2A1C9E4B3D5A60", "aws4_request"):
            self.assertNotIn(material, value)

    def test_a_namespace_or_a_lowercase_word_is_not_a_class(self):
        for error in ("Aws::S3::Errors::NoSuchKey: The specified key does not exist.",
                      "operation error S3: PutObject failed with an error", "errors::not_found Error"):
            with self.subTest(error=error):
                self.assertEqual(self.classified(error), "-/-/-")

    def test_a_code_outside_a_recognised_location_is_not_read(self):
        for error in ("code: NoSuchKey, message: missing", "ErrorResponse(code = NoSuchKey, message = missing)",
                      '<Code attr="x">NoSuchKey</Code>', "api error : missing", "An error occurred () when calling"):
            with self.subTest(error=error):
                self.assertEqual(self.classified(error), "-/-/-")

    def test_a_token_longer_than_an_identifier_is_not_a_class_or_a_code(self):
        # A signature or a key that happens to end in `Error` is not a thrown class, and the longest
        # identifier either slot reads is 64 characters.
        longest_class = "A" + "b" * 54 + "Exception"
        longest_code = "A" + "b" * 63
        self.assertEqual(self.classified(longest_class + ": refused"), longest_class + "/-/-")
        self.assertEqual(self.classified(f"<Code>{longest_code}</Code>"), f"-/-/{longest_code}")
        for error in ("A" + "b" * 55 + "Exception: refused", "K" + "A" * 80 + "Error", "Q" + "z" * 200 + "Error",
                      f"<Code>{longest_code}x</Code>", f"An error occurred ({longest_code}x) when calling"):
            with self.subTest(error=error[:40]):
                self.assertEqual(self.classified(error), "-/-/-")


if __name__ == "__main__":
    unittest.main()
