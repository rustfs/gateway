#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Fetch the reviewed NuGet archive closure into a fresh offline feed.

Owns archive identity before restore executes package targets. Does not resolve
versions, build the SDK suite, or trust NuGet cache metadata as a byte digest.
The image build consumes the resulting feed without network access.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate package entry')
        result[key] = value
    return result


def fetch(manifest: Path, destination: Path) -> None:
    packages = json.loads(manifest.read_text(), object_pairs_hook=unique_object)
    if not isinstance(packages, dict) or not packages:
        raise ValueError('expected a nonempty package digest object')
    for name, digest in packages.items():
        match = re.fullmatch(r'([a-z0-9][a-z0-9.-]*)/([0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?)/([^/]+)', name)
        if match is None or match[3] != f'{match[1]}.{match[2]}.nupkg':
            raise ValueError('invalid canonical package path')
        if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None:
            raise ValueError('invalid package SHA-256')
    destination.mkdir()
    for name, digest in packages.items():
        temporary = destination / '.download'
        try:
            checksum = hashlib.sha256()
            with urllib.request.urlopen('https://api.nuget.org/v3-flatcontainer/' + name,
                                        timeout=60) as response, temporary.open('xb') as output:
                while chunk := response.read(1024 * 1024):
                    checksum.update(chunk)
                    output.write(chunk)
            if checksum.hexdigest() != digest:
                raise ValueError(f'package SHA-256 mismatch: {name}')
            temporary.rename(destination / Path(name).name)
        finally:
            temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    fetch(args.manifest, args.destination)


if __name__ == '__main__':
    main()
