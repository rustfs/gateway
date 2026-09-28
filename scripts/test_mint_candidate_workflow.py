#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Execute the workflow's candidate-build shell with a controlled Docker binary."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/e2e-mint.yml'


def workflow_script(name):
    text = WORKFLOW.read_text()
    step = text.split('      - name: ' + name + '\n', 1)[1]
    body = step.split('        run: |\n', 1)[1].split('\n      - ', 1)[0]
    return '\n'.join(line[10:] for line in body.splitlines())


class CandidateWorkflow(unittest.TestCase):
    def run_build(self, mode, docker_exit=0, image='sha256:' + 'a' * 64):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            budget = root / 'scripts/ci_budget.sh'
            budget.write_text('#!/bin/bash\nset -eu\ntest "$1" = 1800\nshift 2\nexec "$@"\n')
            budget.chmod(0o755)
            docker = root / 'docker'
            docker.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
pathlib.Path(os.environ['CAPTURE']).write_text(json.dumps(sys.argv[1:]))
if os.environ['IMAGE'] != 'missing':
    pathlib.Path(sys.argv[sys.argv.index('--iidfile') + 1]).write_text(os.environ['IMAGE'])
sys.exit(int(os.environ['DOCKER_EXIT']))
''')
            docker.chmod(0o755)
            capture = root / 'args.json'
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       CANDIDATE_MODE=mode, RUNNER_TEMP=str(root), CAPTURE=str(capture),
                       IMAGE=image, DOCKER_EXIT=str(docker_exit))
            result = subprocess.run(['bash', '-c', workflow_script('Build the mint image from the reviewed recipe')], cwd=root,
                                    env=env, capture_output=True, text=True)
            return result, json.loads(capture.read_text()) if capture.exists() else None

    def test_every_mode_builds_exact_platform_and_local_recipe(self):
        for mode in ('ratchet', 'record', ''):
            with self.subTest(mode=mode):
                result, args = self.run_build(mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(args[:5], ['build', '--platform', 'linux/amd64', '--progress', 'plain'])
                self.assertEqual(args[-1], 'ci/mint')

    def test_record_builds_exact_platform_and_local_recipe(self):
        result, args = self.run_build('record')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args[:5], ['build', '--platform', 'linux/amd64', '--progress', 'plain'])
        self.assertEqual(args[-1], 'ci/mint')
        self.assertEqual(args[-3], '--iidfile')
        self.assertTrue(args[-2].endswith('/mint-candidate.id'))

    def test_failed_build_cannot_accept_an_image_file(self):
        result, _ = self.run_build('record', docker_exit=17)
        self.assertEqual(result.returncode, 17)

    def test_missing_or_invalid_identity_fails(self):
        for image in ('missing', '', 'latest', 'sha256:' + 'a' * 63,
                      'sha256:' + 'G' * 64, 'sha256:' + 'a' * 64 + '\nextra'):
            with self.subTest(image=image):
                result, _ = self.run_build('record', image=image)
                self.assertNotEqual(result.returncode, 0)


    def run_suite(self, mode, image=True, suite_exit=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            (root / 'ci/mint').mkdir(parents=True)
            budget = root / 'scripts/ci_budget.sh'
            budget.write_text('#!/bin/bash\nset -eu\ntest "$1" = 5400\nshift 2\nexec "$@"\n')
            budget.chmod(0o755)
            runner = root / 'ci/mint/run.sh'
            runner.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
pathlib.Path(os.environ['CAPTURE']).write_text(json.dumps(sys.argv[1:]))
sys.exit(int(os.environ['SUITE_EXIT']))
''')
            runner.chmod(0o755)
            identity = 'sha256:' + 'b' * 64
            if image:
                (root / 'mint-candidate.id').write_text(identity)
            capture = root / 'args.json'
            env = dict(os.environ, CANDIDATE_MODE=mode,
                       RUNNER_TEMP=str(root), CAPTURE=str(capture), SUITE_EXIT=str(suite_exit),
                       GITHUB_OUTPUT=str(root / 'output'), GITHUB_STEP_SUMMARY=str(root / 'summary'))
            script = workflow_script('Run the suite').replace(
                "${{ inputs.mode || 'ratchet' }}", '$CANDIDATE_MODE')
            result = subprocess.run(['bash', '-e', '-c', script], cwd=root,
                                    env=env, capture_output=True, text=True)
            return result, json.loads(capture.read_text()) if capture.exists() else None

    def test_every_mode_measures_the_exact_recipe_image(self):
        for mode in ('ratchet', 'record'):
            with self.subTest(mode=mode):
                result, args = self.run_suite(mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(args[:2], ['--mode', mode])
                self.assertEqual(args[-2:], ['--local-image', 'sha256:' + 'b' * 64])

    def test_suite_cannot_fall_back_to_the_bare_pin_when_the_image_is_missing(self):
        for mode in ('ratchet', 'record'):
            with self.subTest(mode=mode):
                result, args = self.run_suite(mode, image=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(args)

    def test_suite_failure_remains_failure(self):
        for mode in ('ratchet', 'record'):
            for code in (1, 3, 124):
                with self.subTest(mode=mode, code=code):
                    result, _ = self.run_suite(mode, suite_exit=code)
                    self.assertEqual(result.returncode, code)


if __name__ == '__main__':
    unittest.main()
