#!/usr/bin/env python3
# Copyright 2026 RustFS Team
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
"""Extracts the s3s DTO shape facts the migration seam generator needs.

Reads `src/dto/generated.rs` of one s3s release and prints, one fact per line, every struct
member with its type resolved through the type aliases, every string enumeration, and every
union. Only names and type spellings are extracted — no s3s code or documentation — so the output
is a fact table, not a copy of s3s (AGENTS.md Provenance).

Usage: scripts/extract_s3s_shapes.py <path to s3s-X.Y.Z crate> > crates/codegen/src/emit/seam/s3s_X_Y_Z.facts
"""
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
version = root.name.removeprefix("s3s-")
source = (root / "src/dto/generated.rs").read_text()

aliases = {"List": None, "Map": None}
for name, target in re.findall(r"^pub type (\w+) = (.+);$", source, re.M):
    aliases[name] = target
aliases.update({"ContentType": "String", "Body": "Bytes", "Unit": "()"})

enums = set(re.findall(r"^pub struct (\w+)\(Cow<'static, str>\);$", source, re.M))
structs = {}
for name, body in re.findall(r"^pub struct (\w+) \{\n(.*?)^\}", source, re.M | re.S):
    fields = re.findall(r"^    pub (\w+): (.+),$", body, re.M)
    structs[name] = fields
for name in re.findall(r"^pub struct (\w+) \{\}$", source, re.M):
    structs[name] = []
unions = {}
for name, body in re.findall(r"^pub enum (\w+) \{\n(.*?)^\}", source, re.M | re.S):
    unions[name] = re.findall(r"^    (\w+)\((\w+)\),$", body, re.M)

KNOWN = {"String", "i32", "i64", "bool", "Timestamp", "ETag", "ETagCondition", "Range", "CopySource",
         "StreamingBlob", "Bytes", "()", "Event", "SelectObjectContentEventStream"}


def resolve(ty: str) -> str:
    ty = ty.strip()
    # s3s-only runtime members (CompleteMultipartUploadOutput.future, the policy-tag cache, the parsed POST policy) are
    # opaque to the seam: they carry no wire value and take their Default.
    if ty.startswith("BoxFuture<") or ty in ("CachedTags", "PostPolicy"):
        return "opaque"
    for wrapper in ("Option", "List", "Vec", "Box"):
        m = re.fullmatch(rf"{wrapper}<(.+)>", ty)
        if m:
            inner = resolve(m.group(1))
            return {"List": "Vec"}.get(wrapper, wrapper) + f"<{inner}>"
    m = re.fullmatch(r"Map<(\w+), (\w+)>", ty)
    if m:
        return f"Map<{resolve(m.group(1))}, {resolve(m.group(2))}>"
    if ty in enums:
        return f"enum {ty}"
    if ty in structs:
        return f"struct {ty}"
    if ty in unions:
        return f"union {ty}"
    if ty in KNOWN:
        return ty
    if ty in aliases and aliases[ty] is not None:
        return resolve(aliases[ty])
    raise SystemExit(f"unresolved s3s type {ty!r}")


print(f"# s3s {version} DTO facts, extracted by scripts/extract_s3s_shapes.py. Do not edit.")
for name in sorted(enums):
    print(f"enum {name}")
for name in sorted(unions):
    variants = ", ".join(f"{v}: {resolve(t)}" for v, t in unions[name])
    print(f"union {name} {{ {variants} }}")
for name in sorted(structs):
    print(f"struct {name}")
    for field, ty in structs[name]:
        print(f"  {field}: {resolve(ty)}")
