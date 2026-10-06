#!/usr/bin/env python3
"""Exercise host-tool selection with shell probes; never run a package manager."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
installed=''
command() {
    if [[ "$1" != -v ]]; then builtin command "$@"; return; fi
    case " $MISSING " in
        *" $2 "*)
            case " $installed " in *" $2 "*) return 0 ;; esac
            return 1 ;;
        *) return 0 ;;
    esac
}
id() { printf '0\n'; }
apt-get() {
    printf '%s\n' "$*" >>"$APT_LOG"
    if [[ "$1" == update ]]; then return "${UPDATE_STATUS:-0}"; fi
    if [[ "${INSTALL_STATUS:-0}" != 0 ]]; then return "$INSTALL_STATUS"; fi
    if [[ "${STILL_MISSING:-0}" == 0 ]]; then installed="$MISSING"; fi
}
'''


class HostTools(unittest.TestCase):
    def run_installer(self, *args, missing='', **settings):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prelude = root / 'probes.sh'
            prelude.write_text(PRELUDE)
            log = root / 'apt.log'
            env = dict(os.environ, BASH_ENV=str(prelude), APT_LOG=str(log), MISSING=missing, **settings)
            result = subprocess.run(['bash', str(ROOT / 'scripts/ci_install_host_tools.sh'), *args],
                                    env=env, capture_output=True, text=True)
            return result, log.read_text().splitlines() if log.exists() else []

    def test_target_guards_use_existing_tools_without_apt(self):
        result, calls = self.run_installer('--target-guards')
        self.assertEqual((result.returncode, calls), (0, []))

    def test_target_guards_ignore_absent_unrelated_tools(self):
        result, calls = self.run_installer('--target-guards', missing='cc c++ pkg-config ruby curl ps ss gh')
        self.assertEqual((result.returncode, calls), (0, []))

    def test_target_guards_install_only_missing_requirements(self):
        for missing, packages in (('python3', 'python3'), ('timeout', 'coreutils'),
                                  ('python3 timeout', 'python3 coreutils')):
            with self.subTest(missing=missing):
                result, calls = self.run_installer('--target-guards', missing=missing)
                self.assertEqual((result.returncode, calls),
                                 (0, ['update', 'install -y --no-install-recommends ' + packages]))

    def test_failed_update_stops_before_install(self):
        result, calls = self.run_installer('--target-guards', missing='python3', UPDATE_STATUS='23')
        self.assertEqual((result.returncode, calls), (23, ['update']))

    def test_failed_install_is_not_success(self):
        result, calls = self.run_installer('--target-guards', missing='timeout', INSTALL_STATUS='24')
        self.assertEqual((result.returncode, calls),
                         (24, ['update', 'install -y --no-install-recommends coreutils']))

    def test_install_success_without_required_tool_is_refused(self):
        for missing in ('python3', 'timeout'):
            with self.subTest(missing=missing):
                result, calls = self.run_installer('--target-guards', missing=missing, STILL_MISSING='1')
                self.assertEqual(result.returncode, 1)
                self.assertEqual(len(calls), 2)
                self.assertIn(missing, result.stderr)

    def test_target_guards_refuse_unrelated_opt_ins(self):
        for option in ('--with-gh', '--with-cxx'):
            for args in (('--target-guards', option), (option, '--target-guards')):
                with self.subTest(args=args):
                    result, calls = self.run_installer(*args)
                    self.assertEqual((result.returncode, calls), (2, []))

    def test_unknown_option_stops_before_install(self):
        result, calls = self.run_installer('--unknown', missing='python3')
        self.assertEqual((result.returncode, calls), (2, []))

    def test_ci_requires_the_correct_installation_scope(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        narrow = 'bash scripts/ci_install_host_tools.sh --target-guards'
        normal = 'bash scripts/ci_install_host_tools.sh'
        for name, text, expected in (
            ('correct', workflow, 0),
            ('target reinstalls unrelated tools', workflow.replace(narrow, normal), 1),
            ('static omits build tools', workflow.replace(normal + '\n', narrow + '\n', 1), 1),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / '.github/workflows'
                target.mkdir(parents=True)
                (target / 'ci.yml').write_text(text)
                result = subprocess.run(['bash', str(ROOT / 'scripts/check_ci_time_gate.sh')],
                    env=dict(os.environ, GATEWAY_CHECK_ROOT=directory), capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_default_mode_keeps_its_existing_tools(self):
        result, calls = self.run_installer(missing='cc pkg-config python3 ruby timeout curl ps ss')
        self.assertEqual((result.returncode, calls), (0, ['update',
            'install -y --no-install-recommends build-essential pkg-config python3 ruby coreutils curl ca-certificates procps iproute2']))

    def test_existing_optional_tools_are_still_installed(self):
        for option, missing, packages in (('--with-cxx', 'c++', 'g++'), ('--with-gh', 'gh', 'gh')):
            with self.subTest(option=option):
                result, calls = self.run_installer(option, missing=missing)
                self.assertEqual((result.returncode, calls),
                                 (0, ['update', 'install -y --no-install-recommends ' + packages]))


if __name__ == '__main__':
    unittest.main()
