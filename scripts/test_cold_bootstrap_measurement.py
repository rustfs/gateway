#!/usr/bin/env python3
"""Exercise the temporary cold-bootstrap experiment with fake tools, never a real build."""
import json
import os
import signal
import shutil
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
import json, os, sys, time, signal, subprocess
from pathlib import Path
name = Path(sys.argv[0]).name
if name == 'git': print('a' * 40)
elif name == 'rustup':
    if os.environ.get('FIXTURE_NO_TOOLCHAIN') and sys.argv[1:] == ['show', 'active-toolchain']: sys.exit(1)
    if sys.argv[1:] == ['show', 'active-toolchain']: print('' if os.environ.get('FIXTURE_EMPTY_TOOLCHAIN') else '1.97.1-x86_64-unknown-linux-gnu (default)')
    else: print(Path(sys.argv[0]).parent / sys.argv[-1])
elif name == 'rustc': print('rustc 1.97.1 (fixture)\\nhost: x86_64-unknown-linux-gnu')
elif sys.argv[1:] == ['--version']: print('cargo 1.97.1 (fixture)')
else:
    if os.environ.get('FIXTURE_TREE'):
        directory = Path(os.environ['RUNNER_TEMP'])
        if os.environ.get('FIXTURE_CHILD_BLOCK_INT'):
            signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGINT])
        (directory / 'child-mask.json').write_text(json.dumps(sorted(signal.pthread_sigmask(signal.SIG_BLOCK, []))))
        if os.environ.get('FIXTURE_TERM_ACK'):
            def acknowledge(signum, frame):
                (directory / 'term-delivered').touch()
                sys.exit(0)
            signal.signal(signal.SIGTERM, acknowledge)
        if os.environ.get('FIXTURE_IGNORE_TERM'):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        ready = Path(os.environ['RUNNER_TEMP']) / 'grand-ready'
        grand = subprocess.Popen([sys.executable, '-c', "import signal,time,sys; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path(sys.argv[1]).touch(); time.sleep(30)", str(ready)])
        (ready.parent / 'tree.json').write_text(json.dumps([os.getpid(), grand.pid]))
        time.sleep(30)
    print('bootstrap: toolchain check started', flush=True)
    print('bootstrap: workspace test compilation started', file=sys.stderr, flush=True)
    print(json.dumps({'args': sys.argv[1:], 'target': os.environ['CARGO_TARGET_DIR'], 'empty': not any(Path(os.environ['CARGO_TARGET_DIR']).iterdir()), 'debug': [os.environ.get('CARGO_PROFILE_DEV_DEBUG'), os.environ.get('CARGO_PROFILE_TEST_DEBUG')], 'affinity': os.environ.get('FIXTURE_AFFINITY'), 'cargo_home': os.environ.get('CARGO_HOME'), 'cache_empty': not any(Path(os.environ['CARGO_HOME']).iterdir()) if 'CARGO_HOME' in os.environ else False, 'toolchain': os.environ.get('RUSTUP_TOOLCHAIN')}), flush=True)
    time.sleep(float(os.environ.get('FIXTURE_DELAY', '.03')))
    print('compiler stderr sentinel', file=sys.stderr, flush=True)
    sys.exit(int(os.environ.get('FIXTURE_EXIT', '0')))
"""
            for name in ["git", "cargo", "rustc", "rustup"]:
                path = tools / name
                path.write_text(program)
                path.chmod(0o755)
            env = {key: value for key, value in os.environ.items() if not key.startswith("CARGO_PROFILE_")}
            env.update(PATH=str(tools) + os.pathsep + os.environ["PATH"], RUNNER_TEMP=directory,
                       GITHUB_SHA=SHA, ImageOS="ubuntu24", ImageVersion="fixture-image", CARGO_INCREMENTAL="0", CARGO_HOME=str(root / "old-cache"))
            (root / "old-cache").mkdir()
            (root / "old-cache" / "occupied").write_text("warm")
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
if os.environ.get('FIXTURE_WARM_CACHE'):
    create = tempfile.mkdtemp
    def warm_cache(**kwargs):
        path = create(**kwargs)
        if kwargs.get('prefix') == 'bootstrap-cargo-':
            (Path(path) / 'registry').mkdir()
        return path
    tempfile.mkdtemp = warm_cache
sys.argv = [sys.argv[1], sys.argv[2]]
runpy.run_path(sys.argv[0], run_name='__main__')
"""
            started = time.monotonic()
            command = [sys.executable, "-c", driver, str(WRAPPER), mode]
            if env.get('FIXTURE_BUDGET'):
                command = ['bash', str(ROOT / 'scripts/ci_budget.sh'), '5', 'fixture cleanup', *command]
            if env.get('FIXTURE_TREE'):
                process = subprocess.Popen(command, cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                pids = []
                try:
                    deadline = time.monotonic() + 5
                    while not (root / 'grand-ready').exists() and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertTrue((root / 'grand-ready').exists(), 'descendant never became ready')
                    pids = json.loads((root / 'tree.json').read_text())
                    if env.get('FIXTURE_CHECK_MASK'):
                        blocked = json.loads((root / 'child-mask.json').read_text())
                        self.assertNotIn(signal.SIGTERM, blocked)
                        self.assertNotIn(signal.SIGINT, blocked)
                    probe = "import subprocess,sys,json; print(json.dumps([bool((s:=subprocess.run(['ps','-o','stat=','-p',p],text=True,capture_output=True).stdout.strip())) and not s.startswith('Z') for p in sys.argv[1:]]))"
                    def live_at_next_child_start():
                        return json.loads(subprocess.check_output([sys.executable, '-c', probe, *map(str, pids)], text=True))
                    self.assertEqual(live_at_next_child_start(), [True, True])
                    if not env.get('FIXTURE_BUDGET'):
                        process.send_signal(int(env['FIXTURE_TREE']))
                    process.wait(timeout=8)
                    if env.get('FIXTURE_TERM_ACK'):
                        self.assertTrue((root / 'term-delivered').exists(), 'TERM never reached the child handler')
                    self.assertEqual(live_at_next_child_start(), [False, False], 'prior arm still has live descendants when next child starts')
                    out, err = process.communicate(timeout=2)
                    result = subprocess.CompletedProcess(command, process.returncode, out, err)
                finally:
                    for pid in pids:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if process.poll() is None:
                        process.kill()
                    process.communicate()
            else:
                result = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True)
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
        self.assertTrue(identity.get('cargo_home_empty'), 'fresh Cargo cache observation is missing or false')
        self.assertNotEqual(identity['cargo_home'], identity['target'])
        lines = [row['line'] for row in records if row['event'] == 'output']
        self.assertIn('compiler stderr sentinel', lines)
        self.assertIn('bootstrap: workspace test compilation started', lines)
        child = json.loads(next(line for line in lines if line.startswith('{')))
        self.assertEqual(child['args'], ['xtask', 'bootstrap'])
        self.assertTrue(child['empty'])
        self.assertTrue(child['cache_empty'])
        self.assertEqual(child['cargo_home'], identity['cargo_home'])
        self.assertEqual(child['toolchain'], '1.97.1-x86_64-unknown-linux-gnu')
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
                 dict(FIXTURE_EMPTY_TOOLCHAIN='1'), dict(FIXTURE_WARM='1'), dict(FIXTURE_WARM_CACHE='1'), dict(FIXTURE_NO_TOOLCHAIN='1'), dict(CARGO_INCREMENTAL='1'), dict(CARGO_PROFILE_DEV_DEBUG='0')]
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

    def test_interruption_reaps_child_and_stops_grandchild_before_next_arm(self):
        for signum, ignore in [(signal.SIGTERM, '1'), (signal.SIGTERM, ''), (signal.SIGINT, '1')]:
            with self.subTest(signal=signum, child_ignores_term=ignore):
                result, _, _ = self.run_fixture(FIXTURE_TREE=str(signum), FIXTURE_IGNORE_TERM=ignore)
                self.assertEqual(result.returncode, 128 + signum, result.stderr)

    def test_child_default_signal_mask_and_graceful_term_delivery(self):
        for check_mask, acknowledgment in [('1', ''), ('', '1')]:
            with self.subTest(check_mask=check_mask, acknowledgment=acknowledgment):
                result, _, _ = self.run_fixture(FIXTURE_TREE=str(signal.SIGTERM), FIXTURE_CHECK_MASK=check_mask, FIXTURE_TERM_ACK=acknowledgment)
                self.assertEqual(result.returncode, 128 + signal.SIGTERM, result.stderr)
        with self.assertRaisesRegex(AssertionError, 'unexpectedly found'):
            self.run_fixture(FIXTURE_TREE=str(signal.SIGTERM), FIXTURE_CHECK_MASK='1', FIXTURE_CHILD_BLOCK_INT='1')
        with self.assertRaisesRegex(AssertionError, 'TERM never reached'):
            self.run_fixture(FIXTURE_TREE=str(signal.SIGTERM), FIXTURE_TERM_ACK='1', FIXTURE_IGNORE_TERM='1')

    def test_real_outer_timeout_preserves_124_after_cleanup(self):
        if not (shutil.which('timeout') or shutil.which('gtimeout')):
            if os.environ.get('CI'):
                self.fail('GNU timeout is required for CI budget enforcement')
            self.skipTest('GNU timeout is unavailable on this developer host')
        result, _, _ = self.run_fixture(FIXTURE_TREE=str(signal.SIGTERM), FIXTURE_IGNORE_TERM='1', FIXTURE_BUDGET='1')
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertIn('OUT OF TIME', result.stderr)

    def workflow(self):
        parsed = subprocess.run(['ruby', '-ryaml', '-rjson', '-e', 'puts JSON.generate(YAML.load_file(ARGV[0]))', str(WORKFLOW)], text=True, capture_output=True)
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        return json.loads(parsed.stdout)

    def test_two_literal_matched_jobs(self):
        workflow = self.workflow()
        self.assertEqual(workflow.get('on', workflow.get('true')), {'push': {'branches': ['p0/423-bootstrap-stage-diagnostics']}})
        jobs = workflow['jobs']
        self.assertEqual(set(jobs), {'baseline-first', 'candidate-first'})
        for job in jobs.values():
            self.assertEqual(job['runs-on'], 'ubuntu-24.04')
            self.assertEqual(job['timeout-minutes'], 18)
            self.assertFalse(set(job) & {'needs', 'if', 'strategy', 'continue-on-error'})
            self.assertEqual(job['steps'][0], {'uses': 'actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10'})
            self.assertEqual(job['steps'][1]['uses'], 'dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30')
            self.assertEqual(job['steps'][1]['with'], {'toolchain': '1.97.1', 'components': 'rustfmt, clippy, rust-src, rust-analyzer'})
            self.assertEqual(job['env'], {'CARGO_INCREMENTAL': '0'})
            self.assertEqual(job['steps'][2]['run'], 'python3 scripts/test_cold_bootstrap_measurement.py')
            self.assertEqual(len(job['steps']), 4)
            self.assertFalse(any(set(step) & {'if', 'continue-on-error', 'shell'} for step in job['steps']))

    def test_paired_shell_preserves_both_statuses_and_scope(self):
        jobs = self.workflow()['jobs']
        self.assertEqual(set(jobs), {'baseline-first', 'candidate-first'})
        for name, order in [('baseline-first', ['baseline', 'no-debug']), ('candidate-first', ['no-debug', 'baseline'])]:
            for failures in [(0, 0), (3, 0), (0, 7), (124, 3)]:
                with self.subTest(job=name, failures=failures), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'scripts').mkdir()
                    budget = root / 'scripts/ci_budget.sh'
                    budget.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
mode = sys.argv[-1]
with Path('calls').open('a') as out:
    out.write(json.dumps({'args': sys.argv[1:], 'mode': mode, 'debug': [os.environ.get('CARGO_PROFILE_DEV_DEBUG'), os.environ.get('CARGO_PROFILE_TEST_DEBUG')]}) + chr(10))
sys.exit(int(os.environ['BASELINE_EXIT' if mode == 'baseline' else 'CANDIDATE_EXIT']))
""")
                    budget.chmod(0o755)
                    env = {k: v for k, v in os.environ.items() if not k.startswith('CARGO_PROFILE_')}
                    statuses = dict(zip(order, failures))
                    env.update(BASELINE_EXIT=str(statuses['baseline']), CANDIDATE_EXIT=str(statuses['no-debug']))
                    result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', jobs[name]['steps'][-1]['run']], cwd=root, env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 1 if any(failures) else 0, result.stderr)
                    calls = [json.loads(line) for line in (root / 'calls').read_text().splitlines()]
                    self.assertEqual([c['mode'] for c in calls], order)
                    for call in calls:
                        mode = call['mode']
                        self.assertEqual(call['args'], ['420', 'cold bootstrap ' + mode, 'python3', 'scripts/measure_cold_bootstrap.py', mode])
                        self.assertEqual(call['debug'], ['0', '0'] if mode == 'no-debug' else [None, None])
                        self.assertIn(f'diagnostic arm={mode} exit_code={statuses[mode]}', result.stdout)


if __name__ == '__main__':
    unittest.main()
