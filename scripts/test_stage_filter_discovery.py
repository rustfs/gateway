#!/usr/bin/env python3
"""Exercise StageFilter discovery cost and census boundaries, not Rust parsing.

The shell guard owns semantic checks; these isolated git fixtures drive its real
processes and count discovery invocations without measuring elapsed time.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

GUARD = Path(__file__).resolve().with_name('check_stage_filter_sync.sh')
TRAIT = 'crates/gateway/src/ext/filter.rs'
EXEMPT = 'crates/gateway/tests/compile_fail/c_mw_0019_stage_filter_cannot_await.rs'
HEAD = '''pub trait StageFilter: Send + Sync {
    fn on_wire(&self) {}
    fn on_routed(&self) {}
    fn on_response(&self) {}
}
'''
GOOD = 'impl StageFilter for Filter {\n    fn on_wire(&self) {}\n}\n'
BAD = 'impl StageFilter for Filter {\n    async fn on_wire(&self) {}\n}\n'


class Discovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gateway-stage-discovery-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git = shutil.which('git')
        self.grep = shutil.which('grep')
        self.assertIsNotNone(self.git)
        self.assertIsNotNone(self.grep)
        subprocess.run([self.git, 'init', '-q', str(self.root)], check=True)
        self.write(TRAIT, HEAD, tracked=True)
        self.write('crates/demo/src/filter.rs', GOOD, tracked=True)
        self.bin = self.root / 'observer'
        self.bin.mkdir()
        self.log = self.root / 'processes.jsonl'
        wrapper = '''#!{python}
import json, os, sys, subprocess
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
is_discovery = name == 'grep' and any(a.startswith('^[ ') and 'StageFilter' in a for a in args)
if is_discovery:
    with open(os.environ['PROCESS_LOG'], 'a') as log:
        log.write(json.dumps(args) + '\\n')
    if os.environ.get('FAIL_DISCOVERY'):
        if os.environ['FAIL_DISCOVERY'] == 'partial':
            subprocess.run([os.environ['REAL_GREP']] + args)
        sys.exit(2)
if name == 'git' and 'ls-files' in args and os.environ.get('FAIL_CENSUS'):
    if os.environ['FAIL_CENSUS'] == 'partial':
        subprocess.run([os.environ['REAL_GIT']] + args)
    sys.exit(2)
os.execv(os.environ['REAL_' + name.upper()], [name] + args)
'''
        import sys
        for tool in ['git', 'grep']:
            path = self.bin / tool
            path.write_text(wrapper.format(python=sys.executable))
            path.chmod(0o755)

    def write(self, name, text, tracked=False):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        if tracked:
            subprocess.run([self.git, '-C', str(self.root), 'add', '--', name], check=True)
        return path

    def run_guard(self, **extra):
        self.log.write_text('')
        env = dict(os.environ, GATEWAY_CHECK_ROOT=str(self.root),
                   PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                   PROCESS_LOG=str(self.log), REAL_GIT=self.git, REAL_GREP=self.grep, **extra)
        result = subprocess.run(['bash', str(GUARD)], env=env, capture_output=True, text=True)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        return result, calls

    def reject(self, fragment, **env):
        result, _ = self.run_guard(**env)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(fragment, result.stderr)

    def test_discovery_processes_do_not_grow_per_source(self):
        small, first = self.run_guard()
        self.assertEqual(small.returncode, 0, small.stderr)
        for i in range(40):
            self.write(f'crates/noise/src/file_{i}.rs', 'fn unrelated() {}\n', tracked=i % 2 == 0)
        large, second = self.run_guard()
        self.assertEqual(large.returncode, 0, large.stderr)
        print(f'discovery processes: small={len(first)}, plus40={len(second)}', flush=True)
        self.assertGreater(len(first), 0, 'a missing process observer is not zero-cost discovery')
        self.assertEqual(len(second), len(first), 'unrelated files must share discovery processes')
        self.assertEqual(large.stdout, small.stdout)

    def test_bounded_batches_continue_after_no_matches(self):
        (self.root / 'crates/demo/src/filter.rs').write_text('fn unrelated() {}\n')
        for i in range(70):
            self.write(f'crates/noise/src/file_{i}.rs', 'fn unrelated() {}\n')
        self.write('zzz/filter.rs', BAD)
        result, calls = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('zzz/filter.rs:2: a StageFilter seam may not be async', result.stderr)
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertLessEqual(len(call[call.index('--') + 2:]), 64)

    def test_excluded_paths_comments_and_strings_stay_outside(self):
        for name in [EXEMPT, 'generated/forbidden.rs', 'crates/demo/generated/forbidden.rs', 'target/forbidden.rs']:
            self.write(name, BAD, tracked=True)
        self.write('ignored.rs', BAD)
        self.write('.gitignore', 'ignored.rs\n')
        self.write('crates/demo/src/prose.rs', '// impl StageFilter for Comment { async fn on_wire() {} }\nconst TEXT: &str = "impl StageFilter for String {}";\n')
        result, _ = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('2 guarded file(s), 1 implementation(s)', result.stdout)

    def test_tracked_and_untracked_bad_implementations(self):
        for tracked in [False, True]:
            with self.subTest(tracked=tracked):
                path = self.write('crates/demo/src/extra.rs', BAD, tracked=tracked)
                self.reject('extra.rs:2: a StageFilter seam may not be async')
                path.write_text(GOOD)

    def test_path_boundaries(self):
        for name in ['crates/demo/src/space name.rs', 'crates/demo/src/line\nbreak.rs', 'crates/demo/src/café.rs']:
            with self.subTest(name=name):
                path = self.write(name, BAD)
                try:
                    self.reject(name + ':2: a StageFilter seam may not be async')
                finally:
                    path.unlink()

    def test_exemption_is_exact(self):
        self.write(EXEMPT.replace('cannot_await', 'async_copy'), BAD)
        self.reject('async_copy.rs:2: a StageFilter seam may not be async')

    def test_missing_trait(self):
        (self.root / TRAIT).unlink()
        self.reject('does not exist')

    def test_no_external_implementation(self):
        (self.root / 'crates/demo/src/filter.rs').write_text('fn unrelated() {}\n')
        self.reject('no file outside')

    def test_missing_tracked_source(self):
        self.write('crates/demo/src/missing.rs', GOOD, tracked=True).unlink()
        self.reject('discovery failed')

    def test_discovery_error(self):
        self.reject('discovery failed', FAIL_DISCOVERY='1')

    def test_partial_discovery_output_is_not_success(self):
        self.reject('discovery failed', FAIL_DISCOVERY='partial')

    def test_partial_census_is_not_success(self):
        self.reject('cannot enumerate Rust sources', FAIL_CENSUS='partial')

    def test_census_error(self):
        self.reject('Rust sources', FAIL_CENSUS='1')


if __name__ == '__main__':
    unittest.main()
