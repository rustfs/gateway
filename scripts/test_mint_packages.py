#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Exercise verified, closed NuGet downloads before any package can be used."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'ci/mint/fetch_packages.py'
spec = importlib.util.spec_from_file_location('mint_packages', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = self.root / 'packages.json'
        self.output = self.root / 'feed'
        self.content = b'reviewed package archive'
        self.name = 'example/1.2.3/example.1.2.3.nupkg'
        self.digest = hashlib.sha256(self.content).hexdigest()
        self.manifest.write_text(json.dumps({self.name: self.digest}))

    def fetch(self, body=None):
        with patch.object(module.urllib.request, 'urlopen', return_value=io.BytesIO(
                self.content if body is None else body)) as request:
            module.fetch(self.manifest, self.output)
        return request

    def test_verified_package_is_saved_under_its_flat_feed_name(self):
        request = self.fetch()
        self.assertEqual([p.name for p in self.output.iterdir()], ['example.1.2.3.nupkg'])
        self.assertEqual((self.output / 'example.1.2.3.nupkg').read_bytes(), self.content)
        self.assertEqual(request.call_args.args[0],
                         'https://api.nuget.org/v3-flatcontainer/' + self.name)
        self.assertGreater(request.call_args.kwargs['timeout'], 0)

    def test_wrong_bytes_never_become_a_package(self):
        with self.assertRaises(ValueError):
            self.fetch(b'changed upstream archive')
        self.assertFalse(list(self.output.glob('*.nupkg')))

    def test_existing_directory_is_rejected(self):
        self.output.mkdir()
        (self.output / 'injected.nupkg').write_bytes(b'foreign')
        with self.assertRaises(FileExistsError):
            self.fetch()

    def test_empty_manifest_is_rejected(self):
        self.manifest.write_text('{}')
        with self.assertRaises(ValueError):
            self.fetch()

    def test_duplicate_package_key_is_rejected(self):
        self.manifest.write_text('{"' + self.name + '":"' + self.digest + '","' +
                                 self.name + '":"' + self.digest + '"}')
        with self.assertRaises(ValueError):
            self.fetch()

    def test_invalid_paths_are_rejected_before_network(self):
        for name in ('../example.nupkg', '/tmp/example.nupkg',
                     'example/1.2.3/other.1.2.3.nupkg',
                     'example/1.2.3/example.9.9.9.nupkg',
                     'example/../example....nupkg',
                     'EXAMPLE/1.2.3/EXAMPLE.1.2.3.nupkg',
                     'example/1.2.3/example.1.2.3.nupkg?redirect=1'):
            with self.subTest(name=name):
                self.manifest.write_text(json.dumps({name: self.digest}))
                with patch.object(module.urllib.request, 'urlopen') as request:
                    with self.assertRaises(ValueError):
                        module.fetch(self.manifest, self.output)
                    request.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_invalid_hashes_are_rejected_before_network(self):
        for value in ('', 'a' * 63, 'g' * 64, 42, None):
            with self.subTest(value=value):
                self.manifest.write_text(json.dumps({self.name: value}))
                with patch.object(module.urllib.request, 'urlopen') as request:
                    with self.assertRaises(ValueError):
                        module.fetch(self.manifest, self.output)
                    request.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_interrupted_download_never_becomes_a_package(self):
        with patch.object(module.urllib.request, 'urlopen', side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):
                module.fetch(self.manifest, self.output)
        self.assertFalse(list(self.output.glob('*.nupkg')))

    def test_non_object_manifest_is_rejected(self):
        self.manifest.write_text('[]')
        with self.assertRaises(ValueError):
            self.fetch()


if __name__ == '__main__':
    unittest.main()
