#!/usr/bin/env python3
# Copyright 2026 RustFS Team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Execute the weekly suite step with the runner's inherited errexit.

Responsible for: status, artifact and diagnostic receipts after suite failure, and
strict failure before the suite starts. Not responsible for: Ceph execution or issue
posting. Upstream: e2e-s3tests.yml. Downstream: the existing guard self-test census.
"""

import os
import pathlib
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SHELLS = (("bash", "-e"), ("bash", "--noprofile", "--norc", "-eo", "pipefail"))
SUMMARY = "Measured fixture summary\n"


def suite_script():
    """Read the actual literal block; resolve only its default mode expression."""
    text = (ROOT / ".github/workflows/e2e-s3tests.yml").read_text()
    step = re.search(r"^      - name: Run the suite\n(.*?)(?=^      - name:|\Z)", text, re.M | re.S)
    if step is None:
        raise RuntimeError("the suite step is missing")
    script = textwrap.dedent(step.group(1).split("        run: |\n", 1)[1])
    script = script.replace("${{ inputs.mode || 'ratchet' }}", "ratchet")
    if "${{" in script:
        raise RuntimeError("the suite script has an unresolved expression")
    return script


class WorkflowReceipts(unittest.TestCase):
    def run_step(self, shell, code, setup_failure=False):
        with tempfile.TemporaryDirectory(prefix="gateway-s3tests-receipts-") as directory:
            base = pathlib.Path(directory)
            (base / "scripts").mkdir()
            stub = base / "scripts/ci_budget.sh"
            stub.write_text(
                '#!/usr/bin/env bash\nset -euo pipefail\n'
                'printf "executed\\n" > "$FIXTURE_CALLED"\n'
                'mkdir -p "$RUNNER_TEMP/s3tests-out"\n'
                'printf "Measured fixture summary\\n" > "$RUNNER_TEMP/s3tests-out/summary.md"\n'
                'exit "$FIXTURE_EXIT"\n'
            )
            stub.chmod(0o755)
            runner = base / "runner"
            if setup_failure:
                runner.write_text("a file cannot contain the suite directories")
            output, summary, called = base / "outputs", base / "summary", base / "called"
            output.touch()
            summary.touch()
            script = base / "step.sh"
            script.write_text(suite_script())
            env = os.environ.copy()
            env.update(
                RUNNER_TEMP=str(runner), GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary),
                FIXTURE_CALLED=str(called), FIXTURE_EXIT=str(code),
            )
            result = subprocess.run([*shell, str(script)], cwd=base, env=env, capture_output=True, text=True)
            return result, output.read_text(), summary.read_text(), called.exists(), str(runner / "s3tests-out")

    def check_completed(self, shell, code):
        result, outputs, summary, called, out = self.run_step(shell, code)
        self.assertEqual(result.returncode, code, "the step must preserve the actual runner verdict")
        self.assertTrue(called, "a reported suite verdict needs an executed command")
        records = dict(line.split("=", 1) for line in outputs.splitlines())
        self.assertEqual(records, {"status": str(code), "out": out}, "downstream steps need both actual receipts")
        self.assertTrue(summary.startswith(SUMMARY), "the measured artifact must reach the job summary")
        if code == 0:
            self.assertEqual(summary, SUMMARY, "a healthy run must retain only its measured summary")
            self.assertIn("no regression against ci/s3tests/xfail.txt", result.stdout)
        elif code == 1:
            self.assertEqual(summary, SUMMARY, "a regression must retain its measured summary")
            self.assertIn("::error title=s3-tests regression::", result.stdout)
        elif code == 3:
            self.assertIn("## Ceph s3-tests did not run", summary)
            self.assertIn("::error title=s3-tests environment failure::", result.stdout)
            self.assertNotIn("::error title=s3-tests regression::", result.stdout)
        else:
            self.assertEqual(summary, SUMMARY, "runner failures must retain any measured summary")
            self.assertIn(f"::error title=s3-tests runner failure::The runner exited {code}.", result.stdout)

    def test_nonzero_verdicts_publish_receipts(self):
        for shell in SHELLS:
            for code in (1, 2, 3, 17, 124, 143):
                with self.subTest(shell=shell, code=code):
                    self.check_completed(shell, code)

    def test_success_keeps_its_receipts(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                self.check_completed(shell, 0)

    def test_setup_failure_stops_before_a_suite_verdict(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                result, outputs, summary, called, _ = self.run_step(shell, 0, setup_failure=True)
                self.assertNotEqual(result.returncode, 0, "failed preparation must fail the step")
                self.assertFalse(called, "failed preparation must not start the suite")
                self.assertEqual(outputs, "", "failed preparation cannot publish a suite verdict")
                self.assertEqual(summary, "", "failed preparation measured no suite summary")


if __name__ == "__main__":
    unittest.main()
