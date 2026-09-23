#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Collect byte-identified notices for the published Mint .NET dependency closure.

Uses the actual publish dependency report, verified package archives, and reviewed
upstream license receipts. Does not fetch packages or decide licenses from SPDX
expressions. The caller separately retains the MinIO source LICENSE for projects.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import xml.etree.ElementTree as ET
import zipfile


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON identity')
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def safe_path(name):
    if (not isinstance(name, str) or not name or '\\' in name
            or PurePosixPath(name).is_absolute()
            or any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError('unsafe notice or asset path')
    return name


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def identity(name):
    if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]*/[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?', name):
        raise ValueError('invalid package identity')
    return name.split('/')


def shipped_packages(published, manifest):
    deps = read_json(published / 'Minio.Functional.Tests.deps.json')
    target = deps['targets'][deps['runtimeTarget']['name']]
    packages = set()
    projects = set()
    references = {}
    for name, entry in target.items():
        assets = {path: metadata for kind in ('runtime', 'native', 'runtimeTargets', 'resources')
                  for path, metadata in entry.get(kind, {}).items()}
        if not assets:
            continue
        for path, metadata in assets.items():
            safe_path(path)
            deployed = Path(PurePosixPath(path).name)
            if 'locale' in metadata:
                deployed = Path(safe_path(metadata['locale'])) / deployed
            if not (published / deployed).is_file():
                raise ValueError('published dependency asset is missing')
        key = name.lower()
        kind = deps['libraries'][name]['type']
        if kind == 'project':
            projects.add(key)
        elif kind == 'reference':
            owner = manifest['references'].get(key)
            if owner is None:
                raise ValueError('published reference has no reviewed package owner')
            references[key] = (owner, list(assets))
        elif kind == 'runtimepack' and key.startswith('runtimepack.'):
            packages.add(key.removeprefix('runtimepack.'))
        elif kind == 'package':
            packages.add(key)
        else:
            raise ValueError('unrecognized published library type')
    if projects != set(manifest['projects']) or set(references) != set(manifest['references']):
        raise ValueError('published project or reference census changed')
    if not packages or packages != set(manifest['packages']):
        raise ValueError('published runtime package census differs from notice manifest')
    if any(owner not in packages for owner, _ in references.values()):
        raise ValueError('published reference owner is not a shipped package')
    return packages, references


def package_metadata(archive, package):
    names = [name for name in archive.namelist() if name.endswith('.nuspec')]
    if len(names) != 1:
        raise ValueError('expected one package metadata record')
    root = ET.fromstring(archive.read(names[0]))
    values = {node.tag.split('}')[-1]: node for node in root.iter()}
    name, version = identity(package)
    if values['id'].text.lower() != name or values['version'].text != version:
        raise ValueError('package metadata identity mismatch')
    repository = values.get('repository')
    return {} if repository is None else dict(repository.attrib)


def collect(published: Path, feed: Path, digests: Path, licenses: Path, destination: Path):
    if destination.exists():
        raise FileExistsError(destination)
    manifest = read_json(licenses / 'manifest.json')
    if manifest['version'] != 1:
        raise ValueError('unsupported notice manifest version')
    package_digests = read_json(digests)
    packages, references = shipped_packages(published, manifest)
    output = {}
    records = {}
    for package in sorted(packages):
        name, version = identity(package)
        archive_name = f'{name}.{version}.nupkg'
        archive_key = f'{package}/{archive_name}'
        archive_path = feed / archive_name
        archive_digest = sha256(archive_path.read_bytes())
        if archive_digest != package_digests.get(archive_key):
            raise ValueError('package archive digest mismatch')
        notices = []
        prefix = f'{name}-{version}'

        def add_notice(filename, content, receipt):
            safe_path(filename)
            key = f'{prefix}/{filename}'
            if not content.strip() or key in output:
                raise ValueError('empty or duplicate distribution notice')
            output[key] = content
            notices.append(dict(receipt, file=key, sha256=sha256(content)))

        with zipfile.ZipFile(archive_path) as archive:
            repository = package_metadata(archive, package)
            policy = manifest['packages'][package]
            for member in policy['archive_files']:
                safe_path(member)
                if archive.namelist().count(member) != 1:
                    raise ValueError('missing or duplicate package notice')
                info = archive.getinfo(member)
                if info.is_dir() or stat.S_ISLNK(info.external_attr >> 16):
                    raise ValueError('package notice must be a regular file')
                add_notice(PurePosixPath(member).name, archive.read(member), {'archive_member': member})
            for source in policy['sources']:
                filename = safe_path(source['file'])
                path = safe_path(source['source_path'])
                commit = source['commit']
                if (not re.fullmatch('[0-9a-f]{40}', commit)
                        or source['repository'] != repository.get('url')
                        or commit != repository.get('commit')
                        or source['url'] != f"{source['repository']}/blob/{commit}/{path}"):
                    raise ValueError('upstream license identity does not match package source')
                content = (licenses / filename).read_bytes()
                if sha256(content) != source['sha256']:
                    raise ValueError('upstream license digest mismatch')
                add_notice(filename, content, source)
            for owner, assets in references.values():
                if owner != package:
                    continue
                for asset in assets:
                    content = (published / PurePosixPath(asset).name).read_bytes()
                    if not any(archive.read(member) == content for member in archive.namelist()
                               if PurePosixPath(member).name == PurePosixPath(asset).name):
                        raise ValueError('published reference bytes do not match their package owner')
        if not notices or not any('license' in record['file'].lower() for record in notices):
            raise ValueError('shipped package has no retained license text')
        records[package] = {'archive': archive_key, 'archive_sha256': archive_digest,
                            'repository': repository, 'notices': notices}
    index = {'version': 1, 'packages': records,
             'projects_with_minio_license_retained_by_caller': manifest['projects'],
             'references': manifest['references']}
    output['sources.json'] = (json.dumps(index, indent=2, sort_keys=True) + '\n').encode()
    destination.mkdir()
    for name, content in output.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('published', 'feed', 'digests', 'licenses', 'destination'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    try:
        collect(args.published, args.feed, args.digests, args.licenses, args.destination)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, ET.ParseError) as error:
        parser.exit(1, f'collect_notices: {error}\n')


if __name__ == '__main__':
    main()
