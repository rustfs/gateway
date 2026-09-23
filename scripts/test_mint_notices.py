#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed controls for notices accompanying the published Mint .NET closure."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / 'ci/mint/collect_notices.py'
spec = importlib.util.spec_from_file_location('mint_notices', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NoticeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.published = self.root / 'published'
        self.feed = self.root / 'feed'
        self.licenses = self.root / 'licenses'
        for path in (self.published, self.feed, self.licenses):
            path.mkdir()
        self.output = self.root / 'notices'
        self.digests = self.root / 'packages.json'
        self.commit = '1' * 40
        self.package = 'example/1.2.3'
        self.archive_name = 'example.1.2.3.nupkg'
        self.archive_key = 'example/1.2.3/' + self.archive_name
        self.nuspec = ('<package><metadata><id>Example</id><version>1.2.3</version>'
                       '<repository type="git" url="https://github.com/example/project" '
                       f'commit="{self.commit}"/></metadata></package>')
        self.archive({'LICENSE.txt': b'Copyright example\nPermission notice\n'})
        self.manifest = {'version': 1, 'projects': ['app/1.0.0'], 'references': {},
                         'packages': {self.package: {'archive_files': ['LICENSE.txt'], 'sources': []}}}
        self.deps = {'runtimeTarget': {'name': 'test/linux-x64'}, 'targets': {'test/linux-x64': {
            'App/1.0.0': {'runtime': {'App.dll': {}}},
            'Example/1.2.3': {'runtime': {'lib/net8.0/Example.dll': {}}}}},
            'libraries': {'App/1.0.0': {'type': 'project'}, 'Example/1.2.3': {'type': 'package'}}}
        (self.published / 'App.dll').write_bytes(b'app')
        (self.published / 'Example.dll').write_bytes(b'assembly')

    def archive(self, notices, extra=None):
        with zipfile.ZipFile(self.feed / self.archive_name, 'w') as archive:
            archive.writestr('example.nuspec', self.nuspec)
            archive.writestr('lib/net8.0/Example.dll', b'assembly')
            for name, content in notices.items():
                archive.writestr(name, content)
            for name, content in (extra or []):
                archive.writestr(name, content)
        self.digests.write_text(json.dumps({self.archive_key: hashlib.sha256(
            (self.feed / self.archive_name).read_bytes()).hexdigest()}))

    def collect(self):
        (self.licenses / 'manifest.json').write_text(json.dumps(self.manifest))
        (self.published / 'Minio.Functional.Tests.deps.json').write_text(json.dumps(self.deps))
        module.collect(self.published, self.feed, self.digests, self.licenses, self.output)

    def reject(self):
        with self.assertRaises((ValueError, OSError, KeyError)):
            self.collect()
        self.assertFalse(self.output.exists())

    def supplemental(self):
        self.archive({})
        content = b'Copyright upstream\nPermission notice\n'
        (self.licenses / 'example-LICENSE.txt').write_bytes(content)
        self.manifest['packages'][self.package] = {'archive_files': [], 'sources': [{
            'file': 'example-LICENSE.txt', 'sha256': hashlib.sha256(content).hexdigest(),
            'repository': 'https://github.com/example/project', 'commit': self.commit,
            'source_path': 'LICENSE',
            'url': f'https://github.com/example/project/blob/{self.commit}/LICENSE'}]}

    def test_archive_notices_and_source_receipts_are_preserved(self):
        self.collect()
        self.assertEqual((self.output / 'example-1.2.3/LICENSE.txt').read_bytes(),
                         b'Copyright example\nPermission notice\n')
        index = json.loads((self.output / 'sources.json').read_text())
        record = index['packages'][self.package]
        self.assertEqual(record['archive_sha256'], json.loads(self.digests.read_text())[self.archive_key])
        self.assertEqual(record['notices'][0]['sha256'], hashlib.sha256(
            (self.output / 'example-1.2.3/LICENSE.txt').read_bytes()).hexdigest())

    def test_pinned_upstream_license_fills_missing_archive_notice(self):
        self.supplemental()
        self.collect()
        self.assertEqual((self.output / 'example-1.2.3/example-LICENSE.txt').read_bytes(),
                         (self.licenses / 'example-LICENSE.txt').read_bytes())
        index = json.loads((self.output / 'sources.json').read_text())
        self.assertEqual(index['packages'][self.package]['notices'][0]['commit'], self.commit)

    def test_runtime_pack_is_part_of_the_shipped_closure(self):
        value = self.deps['targets']['test/linux-x64'].pop('Example/1.2.3')
        self.deps['targets']['test/linux-x64']['runtimepack.Example/1.2.3'] = value
        self.deps['libraries']['runtimepack.Example/1.2.3'] = {'type': 'runtimepack'}
        self.collect()
        self.assertTrue((self.output / 'example-1.2.3/LICENSE.txt').is_file())

    def test_build_only_package_does_not_require_added_notices(self):
        self.deps['targets']['test/linux-x64']['Analyzer/9.0.0'] = {'dependencies': {}}
        self.deps['libraries']['Analyzer/9.0.0'] = {'type': 'package'}
        self.collect()
        self.assertEqual(set(json.loads((self.output / 'sources.json').read_text())['packages']), {self.package})

    def test_missing_runtime_notice_manifest_entry_is_rejected(self):
        self.manifest['packages'].clear()
        self.reject()

    def test_unused_notice_manifest_entry_is_rejected(self):
        self.manifest['packages']['unused/1.0.0'] = {'archive_files': ['LICENSE'], 'sources': []}
        self.reject()

    def test_missing_package_archive_is_rejected(self):
        (self.feed / self.archive_name).unlink()
        self.reject()

    def test_package_digest_mismatch_is_rejected(self):
        self.digests.write_text(json.dumps({self.archive_key: '0' * 64}))
        self.reject()

    def test_missing_archive_notice_is_rejected(self):
        self.archive({})
        self.reject()

    def test_empty_archive_notice_is_rejected(self):
        self.archive({'LICENSE.txt': b'  \n'})
        self.reject()

    def test_duplicate_archive_notice_is_rejected(self):
        self.archive({'LICENSE.txt': b'first'}, [('LICENSE.txt', b'second')])
        self.reject()

    def test_unsafe_archive_notice_path_is_rejected(self):
        self.manifest['packages'][self.package]['archive_files'] = ['../LICENSE']
        self.archive({'../LICENSE': b'notice'})
        self.reject()

    def test_wrong_package_identity_is_rejected(self):
        self.nuspec = self.nuspec.replace('<version>1.2.3</version>', '<version>9.9.9</version>')
        self.archive({'LICENSE.txt': b'notice'})
        self.reject()

    def test_missing_supplemental_license_is_rejected(self):
        self.supplemental()
        (self.licenses / 'example-LICENSE.txt').unlink()
        self.reject()

    def test_supplemental_digest_mismatch_is_rejected(self):
        self.supplemental()
        (self.licenses / 'example-LICENSE.txt').write_text('changed')
        self.reject()

    def test_supplemental_source_commit_must_match_package_receipt(self):
        self.supplemental()
        source = self.manifest['packages'][self.package]['sources'][0]
        source['commit'] = '2' * 40
        source['url'] = source['url'].replace(self.commit, '2' * 40)
        self.reject()

    def test_supplemental_repository_must_match_package_receipt(self):
        self.supplemental()
        source = self.manifest['packages'][self.package]['sources'][0]
        source['repository'] = 'https://github.com/different/project'
        source['url'] = source['url'].replace('example/project', 'different/project')
        self.reject()

    def test_supplemental_url_must_name_exact_commit_and_path(self):
        self.supplemental()
        self.manifest['packages'][self.package]['sources'][0]['url'] = 'https://github.com/example/project/blob/main/LICENSE'
        self.reject()

    def test_unsafe_supplemental_path_is_rejected(self):
        self.supplemental()
        self.manifest['packages'][self.package]['sources'][0]['file'] = '../LICENSE'
        self.reject()

    def test_existing_output_is_refused_without_overwrite(self):
        self.output.mkdir()
        with self.assertRaises(FileExistsError):
            self.collect()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_missing_published_dependency_is_rejected(self):
        (self.published / 'Example.dll').unlink()
        self.reject()

    def test_unaccounted_project_is_rejected(self):
        self.manifest['projects'] = []
        self.reject()

    def test_unaccounted_reference_is_rejected(self):
        self.deps['libraries']['Example/1.2.3']['type'] = 'reference'
        self.reject()

    def test_no_notices_for_a_shipped_package_is_rejected(self):
        self.manifest['packages'][self.package] = {'archive_files': [], 'sources': []}
        self.reject()

    def test_archive_third_party_notice_is_retained_byte_for_byte(self):
        self.archive({'LICENSE.txt': b'license', 'THIRD-PARTY-NOTICES.txt': b'Other copyright and terms'})
        self.manifest['packages'][self.package]['archive_files'].append('THIRD-PARTY-NOTICES.txt')
        self.collect()
        self.assertEqual((self.output / 'example-1.2.3/THIRD-PARTY-NOTICES.txt').read_bytes(),
                         b'Other copyright and terms')

    def reference(self, content=b'reference'):
        self.archive({'LICENSE.txt': b'license'}, [('lib/net8.0/Extension.dll', b'reference')])
        (self.published / 'Extension.dll').write_bytes(content)
        self.deps['targets']['test/linux-x64']['Extension/1.0.0'] = {'runtime': {'Extension.dll': {}}}
        self.deps['libraries']['Extension/1.0.0'] = {'type': 'reference'}
        self.manifest['references']['extension/1.0.0'] = self.package

    def test_reference_is_covered_by_its_byte_verified_runtime_package(self):
        self.reference()
        self.collect()
        self.assertEqual(json.loads((self.output / 'sources.json').read_text())['references'],
                         {'extension/1.0.0': self.package})

    def test_reference_bytes_cannot_be_attributed_to_the_wrong_package(self):
        self.reference(b'different bytes')
        self.reject()

    def test_reference_owner_must_be_a_distributed_package(self):
        self.reference()
        self.manifest['references']['extension/1.0.0'] = 'unused/1.0.0'
        self.reject()

    def test_wrong_package_name_is_rejected(self):
        self.nuspec = self.nuspec.replace('<id>Example</id>', '<id>Different</id>')
        self.archive({'LICENSE.txt': b'notice'})
        self.reject()

    def test_duplicate_digest_identity_is_rejected(self):
        digest = json.loads(self.digests.read_text())[self.archive_key]
        pair = json.dumps(self.archive_key) + ':' + json.dumps(digest)
        self.digests.write_text('{' + pair + ',' + pair + '}')
        self.reject()

    def test_a_notice_alone_does_not_replace_a_license(self):
        self.archive({'THIRD-PARTY-NOTICES.txt': b'other terms'})
        self.manifest['packages'][self.package]['archive_files'] = ['THIRD-PARTY-NOTICES.txt']
        self.reject()

    def test_malformed_commit_is_refused_even_if_metadata_agrees(self):
        self.nuspec = self.nuspec.replace(self.commit, 'z' * 40)
        self.commit = 'z' * 40
        self.supplemental()
        self.reject()


if __name__ == '__main__':
    unittest.main()
