#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Exercise allowance normalization and its process count, not scan performance.

Uses isolated Git fixtures and the real guard; the central guard suite owns registration.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

GUARD = Path(os.environ.get("GATEWAY_ALLOWANCE_GUARD", Path(__file__).with_name("check_no_minio_source.sh"))).resolve()
LICENSE = "A" + "GPL-3.0"


class Allowances(unittest.TestCase):
    def run_guard(self, allowance, files=None, fail_tr=False):
        with tempfile.TemporaryDirectory(prefix="gateway-allowance-") as directory:
            root = Path(directory)
            repo, shim = root / "repo", root / "shim"
            repo.mkdir()
            shim.mkdir()
            (repo / "scripts/allowances").mkdir(parents=True)
            if allowance is not None:
                (repo / "scripts/allowances/clean-room-allowances.txt").write_text(allowance)
            for name, content in (files or {"plain.txt": "ordinary text\n"}).items():
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            count = root / "count"
            real_tr = shutil.which("tr")
            self.assertIsNotNone(real_tr)
            command = 'cat; exit 7' if fail_tr else f'exec {shlex.quote(real_tr)} "$@"'
            (shim / "tr").write_text(f'#!/bin/sh\nprintf "x\\n" >> {shlex.quote(str(count))}\n{command}\n')
            (shim / "tr").chmod(0o755)
            result = subprocess.run(["bash", str(GUARD)], env={**os.environ, "GATEWAY_CHECK_ROOT": str(repo), "PATH": f'{shim}:{os.environ["PATH"]}'}, capture_output=True, text=True, timeout=15)
            calls = len(count.read_text().splitlines()) if count.exists() else 0
            return result, calls

    def assert_rejected(self, allowance, files, diagnostic):
        result, _ = self.run_guard(allowance, files)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn(diagnostic, result.stderr)

    def test_normalization_process_count_does_not_grow_with_comments(self):
        counts = []
        for lines in (1, 100):
            result, calls = self.run_guard("\t # comment\n\n" * lines)
            self.assertEqual(result.returncode, 0, result.stderr)
            counts.append(calls)
        print(f"allowance normalization subprocess counts: {counts}", flush=True)
        self.assertEqual(counts, [1, 1], "one actual normalization process per allowance file")

    def test_exact_paths_preserve_whitespace_and_comment_semantics(self):
        result, _ = self.run_guard("\t policy.txt \t # explanation\n  docs/a\t  b.txt\t\n", {"policy.txt": LICENSE, "docs/a b.txt": LICENSE})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_glob_is_not_a_path_allowance(self):
        self.assert_rejected("*\n", {"policy.txt": LICENSE}, "policy.txt: names")

    def test_allowance_cannot_cover_another_path(self):
        self.assert_rejected("policy.txt\n", {"policy.txt": LICENSE, "other.txt": LICENSE}, "other.txt: names")

    def test_comment_does_not_become_an_allowance(self):
        self.assert_rejected("# policy.txt\n", {"policy.txt": LICENSE}, "policy.txt: names")

    def test_unterminated_last_line_keeps_existing_read_semantics(self):
        self.assert_rejected("policy.txt", {"policy.txt": LICENSE}, "policy.txt: names")

    def test_missing_allowance_file_fails(self):
        self.assert_rejected(None, {"plain.txt": "ordinary"}, "is missing; the allowlist cannot be skipped")

    def test_allowance_does_not_exempt_origin_claim(self):
        claim = "co" + "pied from MinIO server source"
        self.assert_rejected("policy.txt\n", {"policy.txt": LICENSE + "\n" + claim}, "claims its contents came")

    def test_partial_normalizer_output_and_failure_cannot_pass(self):
        result, calls = self.run_guard("plain.txt\n", fail_tr=True)
        self.assertEqual(calls, 1)
        self.assertNotEqual(result.returncode, 0, "normalizer failure was ignored")
        self.assertIn("cannot normalize the allowance file", result.stderr)


if __name__ == "__main__":
    unittest.main()
