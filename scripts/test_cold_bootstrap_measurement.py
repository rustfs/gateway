#!/usr/bin/env python3
"""Exercise the temporary cold-bootstrap experiment with fake tools, never a real build."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts/measure_cold_bootstrap.py"
WORKFLOW = ROOT / ".github/workflows/bootstrap-profile-experiment.yml"
SHA = "a" * 40


class ExperimentTests(unittest.TestCase):
    def run_fixture(self, mode="baseline", **overrides):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "bin"
            tools.mkdir()
            program = """#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
name = Path(sys.argv[0]).name
if name == 'git': print('a' * 40)
elif name == 'rustc': print('rustc 1.97.1 (fixture)\\nhost: x86_64-unknown-linux-gnu')
elif sys.argv[1:] == ['--version']: print('cargo 1.97.1 (fixture)')
else:
    print('bootstrap: toolchain check started', flush=True)
    print('bootstrap: workspace test compilation started', file=sys.stderr, flush=True)
    print(json.dumps({'args': sys.argv[1:], 'target': os.environ['CARGO_TARGET_DIR'], 'empty': not any(Path(os.environ['CARGO_TARGET_DIR']).iterdir()), 'debug': [os.environ.get('CARGO_PROFILE_DEV_DEBUG'), os.environ.get('CARGO_PROFILE_TEST_DEBUG')], 'affinity': os.environ.get('FIXTURE_AFFINITY')}), flush=True)
    time.sleep(float(os.environ.get('FIXTURE_DELAY', '.03')))
    print('compiler stderr sentinel', file=sys.stderr, flush=True)
    sys.exit(int(os.environ.get('FIXTURE_EXIT', '0')))
"""
            for name in ["git", "cargo", "rustc"]:
                path = tools / name
                path.write_text(program)
                path.chmod(0o755)
            env = {key: value for key, value in os.environ.items() if not key.startswith("CARGO_PROFILE_")}
            env.update(PATH=str(tools) + os.pathsep + os.environ["PATH"], RUNNER_TEMP=directory,
                       GITHUB_SHA=SHA, ImageOS="ubuntu24", ImageVersion="fixture-image", CARGO_INCREMENTAL="0")
            if mode == "no-debug":
                env.update(CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")
            env.update(overrides)
            # Simulate Linux affinity on any developer host; production uses the OS APIs directly.
            driver = """import os, runpy, sys, tempfile
from pathlib import Path
cpu_path = Path('/proc/cpuinfo')
read_text = Path.read_text
is_file = Path.is_file
def fixture_cpu_text(path, *args, **kwargs):
    if path == cpu_path:
        if os.environ.get('FIXTURE_CPU_MISSING'):
            raise FileNotFoundError('fixture CPU identity missing')
        return 'model name: ' + os.environ.get('FIXTURE_CPU_MODEL', 'controlled fixture CPU')
    return read_text(path, *args, **kwargs)
Path.read_text = fixture_cpu_text
Path.is_file = lambda path: not os.environ.get('FIXTURE_CPU_MISSING') if path == cpu_path else is_file(path)
state = set(range(int(os.environ.get('FIXTURE_CPUS', '4'))))
def set_affinity(pid, cpus):
    global state
    state = set(cpus)
    os.environ['FIXTURE_AFFINITY'] = ','.join(map(str, sorted(state)))
os.sched_getaffinity = lambda pid: state
os.sched_setaffinity = set_affinity
if os.environ.get('FIXTURE_WARM'):
    warmed = Path(os.environ['RUNNER_TEMP']) / 'warm'
    warmed.mkdir()
    (warmed / 'artifact').write_text('occupied')
    tempfile.mkdtemp = lambda **kwargs: str(warmed)
sys.argv = [sys.argv[1], sys.argv[2]]
runpy.run_path(sys.argv[0], run_name='__main__')
"""
            started = time.monotonic()
            result = subprocess.run([sys.executable, "-c", driver, str(WRAPPER), mode], cwd=root,
                                    env=env, text=True, capture_output=True)
            elapsed = time.monotonic() - started
            records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
            return result, records, elapsed

    def assert_success(self, mode):
        result, records, observed = self.run_fixture(mode)
        self.assertEqual(result.returncode, 0, result.stderr)
        identity = next(row for row in records if row['event'] == 'identity')
        self.assertEqual(identity['source_sha'], SHA)
        self.assertEqual(identity['runner_image'], ['ubuntu24', 'fixture-image'])
        self.assertEqual(identity['affinity'], [0, 1])
        self.assertEqual(identity['cpu_model'], 'controlled fixture CPU')
        self.assertTrue(identity['target_empty'])
        lines = [row['line'] for row in records if row['event'] == 'output']
        self.assertIn('compiler stderr sentinel', lines)
        self.assertIn('bootstrap: workspace test compilation started', lines)
        child = json.loads(next(line for line in lines if line.startswith('{')))
        self.assertEqual(child['args'], ['xtask', 'bootstrap'])
        self.assertTrue(child['empty'])
        self.assertEqual(child['affinity'], '0,1')
        self.assertEqual(child['debug'], ['0', '0'] if mode == 'no-debug' else [None, None])
        final = records[-1]
        self.assertEqual(final['event'], 'finished')
        self.assertEqual(final['exit_code'], 0)
        self.assertGreaterEqual(final['elapsed_seconds'], .025)
        self.assertLessEqual(final['elapsed_seconds'], observed + .01)
        times = [row['elapsed_seconds'] for row in records if row['event'] in ['output', 'finished']]
        self.assertEqual(times, sorted(times))

    def test_baseline(self):
        self.assert_success('baseline')

    def test_no_debug(self):
        self.assert_success('no-debug')

    def test_original_failure_status_and_stderr(self):
        for status in [1, 3, 124]:
            result, records, observed = self.run_fixture(FIXTURE_EXIT=str(status), FIXTURE_DELAY='.12')
            self.assertEqual(result.returncode, status, result.stderr)
            self.assertEqual(records[-1]['exit_code'], status)
            self.assertGreaterEqual(records[-1]['elapsed_seconds'], .1)
            self.assertLessEqual(records[-1]['elapsed_seconds'], observed + .01)
            self.assertIn('compiler stderr sentinel', [row.get('line') for row in records])

    def test_invalid_identities_and_scope_fail_before_compile(self):
        cases = [dict(ImageVersion=''), dict(GITHUB_SHA='b' * 40), dict(FIXTURE_CPUS='1'),
                 dict(FIXTURE_WARM='1'), dict(CARGO_INCREMENTAL='1'), dict(CARGO_PROFILE_DEV_DEBUG='0')]
        for overrides in cases:
            result, records, _ = self.run_fixture(**overrides)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse(any(row.get('event') == 'output' for row in records))

    def test_missing_cpu_identity_is_rejected(self):
        for overrides in [dict(FIXTURE_CPU_MISSING='1'), dict(FIXTURE_CPU_MODEL=''), dict(FIXTURE_CPU_MODEL='   ')]:
            with self.subTest(overrides=overrides):
                result, records, _ = self.run_fixture(**overrides)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(any(row.get('event') == 'output' for row in records))

    def test_inherited_build_overrides_are_rejected(self):
        conflicts = ['CARGO_BUILD_BUILD_DIR', 'CARGO_BUILD_TARGET_DIR', 'CARGO_TARGET_DIR', 'CARGO_BUILD_TARGET',
                     'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER',
                     'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER', 'RUSTC', 'CARGO_BUILD_RUSTC',
                     'SCCACHE_DIR', 'CCACHE_DIR', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_RUSTFLAGS',
                     'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS', 'CARGO_PROFILE_DEV_OPT_LEVEL']
        for name in conflicts:
            with self.subTest(variable=name):
                result, records, _ = self.run_fixture(**{name: 'conflicting-build-setting'})
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(any(row.get('event') == 'output' for row in records))

    def test_two_literal_matched_jobs(self):
        parsed = subprocess.run(['ruby', '-ryaml', '-rjson', '-e', 'puts JSON.generate(YAML.load_file(ARGV[0]))', str(WORKFLOW)], text=True, capture_output=True)
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        workflow = json.loads(parsed.stdout)
        jobs = workflow['jobs']
        self.assertEqual(set(jobs), {'baseline', 'no-debug'})
        for mode, job in jobs.items():
            self.assertEqual(job['runs-on'], 'ubuntu-24.04')
            self.assertEqual(job['timeout-minutes'], 8)
            self.assertFalse(set(job) & {'needs', 'if', 'strategy', 'continue-on-error'})
            self.assertEqual(job['steps'][0], {'uses': 'actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10'})
            self.assertEqual(job['steps'][1]['uses'], 'dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30')
            self.assertEqual(job['steps'][1]['with'], {'toolchain': '1.97.1', 'components': 'rustfmt, clippy, rust-src, rust-analyzer'})
            self.assertEqual(job['steps'][-1]['run'], f'scripts/ci_budget.sh 420 "cold bootstrap {mode}" python3 scripts/measure_cold_bootstrap.py {mode}')
            expected = {'CARGO_INCREMENTAL': '0'}
            if mode == 'no-debug':
                expected.update(CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0')
            self.assertEqual(job['env'], expected)
            self.assertEqual(job['steps'][2]['run'], 'python3 scripts/test_cold_bootstrap_measurement.py')
            self.assertEqual(len(job['steps']), 4)
            self.assertFalse(any(set(step) & {'if', 'continue-on-error', 'shell'} for step in job['steps']))


if __name__ == '__main__':
    unittest.main()
