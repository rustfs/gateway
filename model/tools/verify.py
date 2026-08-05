#!/usr/bin/env python3
# Copyright 2026 Beijing Henghesha Technology Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Assert that the vendored Smithy models match what model/PROVENANCE.md claims.

Responsible for: proving the protocol input is exactly the bytes recorded at the
pinned upstream commit, and that PROVENANCE.md still describes them.

NOT responsible for: contacting the network (it never does), or deciding whether
a newer model exists - that is .github/workflows/model-drift.yml.

PROVENANCE.md is parsed, not just read by humans: every number in its tables is
an assertion input, so a bump that forgets to update a count fails here rather
than rotting quietly. Runs in well under a second; safe for the PR gate.

Exit codes: 0 all checks pass, 1 a check failed, 2 usage or I/O error.

Usage: python3 model/tools/verify.py [--root <repo root>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UPSTREAM = "https://github.com/aws/api-models-aws"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MODELS = ("s3", "sts")


def parse_provenance(path):
    """Collect `| field | value |` rows into a dict keyed by lowercased field."""
    fields = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line.startswith("|") or not line.endswith("|"):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) != 2:
                continue
            key, value = cells[0].strip("` "), cells[1].strip()
            if key.lower() in ("field", "---") or set(key) <= {"-"}:
                continue
            fields[key.lower()] = value.strip("`")
    return fields


class Checker:
    def __init__(self):
        self.failures = []

    def check(self, ok, label, expected=None, actual=None):
        if ok:
            print(f"  ok    {label}")
            return True
        detail = f"{label}"
        if expected is not None or actual is not None:
            detail += f"\n          expected: {expected}\n          actual:   {actual}"
        print(f"  FAIL  {detail}")
        self.failures.append(label)
        return False

    def require(self, fields, key):
        value = fields.get(key)
        if value is None:
            self.check(False, f"PROVENANCE.md has field '{key}'")
        return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=REPO_ROOT)
    args = parser.parse_args(argv)

    started = time.time()
    model_dir = os.path.join(args.root, "model")
    provenance_path = os.path.join(model_dir, "PROVENANCE.md")
    if not os.path.isfile(provenance_path):
        print(f"error: {provenance_path} not found", file=sys.stderr)
        return 2

    fields = parse_provenance(provenance_path)
    c = Checker()

    print("provenance")
    upstream = c.require(fields, "upstream repository")
    c.check(
        upstream == UPSTREAM,
        "upstream is the official aws/api-models-aws repository "
        "(the awslabs/aws-sdk-rust mirror is not an acceptable source)",
        UPSTREAM,
        upstream,
    )
    pinned = c.require(fields, "pinned commit") or ""
    c.check(bool(SHA_RE.match(pinned)), "pinned commit is a 40-character hex SHA", "40 hex chars", pinned)
    c.check(
        (c.require(fields, "license") or "") == "Apache-2.0",
        "license recorded as Apache-2.0",
        "Apache-2.0",
        fields.get("license"),
    )

    for name in MODELS:
        print(f"\n{name}")
        path = os.path.join(model_dir, f"{name}.json")
        if not os.path.isfile(path):
            c.check(False, f"model/{name}.json exists")
            continue

        blob = open(path, "rb").read()
        digest = hashlib.sha256(blob).hexdigest()

        sidecar_path = f"{path}.sha256"
        if os.path.isfile(sidecar_path):
            sidecar = open(sidecar_path, "r", encoding="utf-8").read().split()
            sidecar_digest = sidecar[0] if sidecar else ""
            c.check(sidecar_digest == digest, f"model/{name}.json.sha256 sidecar matches file", digest, sidecar_digest)
        else:
            c.check(False, f"model/{name}.json.sha256 exists")

        recorded_digest = c.require(fields, f"{name} model sha256")
        c.check(recorded_digest == digest, f"sha256 matches PROVENANCE.md", recorded_digest, digest)

        recorded_bytes = c.require(fields, f"{name} model bytes") or ""
        c.check(
            recorded_bytes.replace(",", "") == str(len(blob)),
            "byte count matches PROVENANCE.md",
            recorded_bytes,
            len(blob),
        )

        try:
            model = json.loads(blob)
        except json.JSONDecodeError as err:
            c.check(False, f"model/{name}.json is valid JSON", "valid JSON", str(err))
            continue

        c.check(model.get("smithy") == "2.0", "Smithy 2.0 JSON AST", "2.0", model.get("smithy"))

        shapes = model.get("shapes") or {}
        service = c.require(fields, f"{name} service shape")
        entry = shapes.get(service)
        c.check(
            entry is not None and entry.get("type") == "service",
            f"service shape {service} is present",
            "a shape of type 'service'",
            (entry or {}).get("type"),
        )

        recorded_shapes = c.require(fields, f"{name} shape count") or ""
        c.check(
            recorded_shapes.replace(",", "") == str(len(shapes)),
            "shape count matches PROVENANCE.md",
            recorded_shapes,
            len(shapes),
        )

        operations = sum(1 for s in shapes.values() if s.get("type") == "operation")
        recorded_ops = c.require(fields, f"{name} operation count") or ""
        c.check(
            recorded_ops.replace(",", "") == str(operations),
            "operation count matches PROVENANCE.md",
            recorded_ops,
            operations,
        )

        print(f"  info  {len(blob)} bytes, sha256 {digest}")
        print(f"  info  {len(shapes)} shapes, {operations} operations")

    elapsed = time.time() - started
    if c.failures:
        print(f"\nFAILED: {len(c.failures)} check(s) in {elapsed:.2f}s", file=sys.stderr)
        print("If you intended to bump the models, follow model/PROVENANCE.md 'Bumping'.", file=sys.stderr)
        return 1
    print(f"\nok in {elapsed:.2f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
