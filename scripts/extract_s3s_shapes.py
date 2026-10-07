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
union; and reads `src/error/generated.rs` for every `S3ErrorCode` variant but `Custom` with the
HTTP status its `status_code` names (`-` when it names none). Only names, type spellings and
status numbers are extracted — no s3s code or documentation — so the output is a fact table, not
a copy of s3s (AGENTS.md Provenance).

Usage: scripts/extract_s3s_shapes.py <path to s3s-X.Y.Z crate> > crates/codegen/src/emit/seam/s3s_X_Y_Z.facts
"""
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
version = root.name.removeprefix("s3s-")
source = (root / "src/dto/generated.rs").read_text()
errors_source = (root / "src/error/generated.rs").read_text()

# The `http::StatusCode` constants the s3s error table names, by number.
STATUS = {
    "MULTIPLE_CHOICES": 300, "MOVED_PERMANENTLY": 301, "FOUND": 302, "SEE_OTHER": 303, "NOT_MODIFIED": 304,
    "USE_PROXY": 305, "TEMPORARY_REDIRECT": 307, "PERMANENT_REDIRECT": 308,
    "BAD_REQUEST": 400, "UNAUTHORIZED": 401, "PAYMENT_REQUIRED": 402, "FORBIDDEN": 403, "NOT_FOUND": 404,
    "METHOD_NOT_ALLOWED": 405, "NOT_ACCEPTABLE": 406, "PROXY_AUTHENTICATION_REQUIRED": 407, "REQUEST_TIMEOUT": 408,
    "CONFLICT": 409, "GONE": 410, "LENGTH_REQUIRED": 411, "PRECONDITION_FAILED": 412, "PAYLOAD_TOO_LARGE": 413,
    "URI_TOO_LONG": 414, "UNSUPPORTED_MEDIA_TYPE": 415, "RANGE_NOT_SATISFIABLE": 416, "EXPECTATION_FAILED": 417,
    "IM_A_TEAPOT": 418, "MISDIRECTED_REQUEST": 421, "UNPROCESSABLE_ENTITY": 422, "LOCKED": 423,
    "FAILED_DEPENDENCY": 424, "TOO_EARLY": 425, "UPGRADE_REQUIRED": 426, "PRECONDITION_REQUIRED": 428,
    "TOO_MANY_REQUESTS": 429, "REQUEST_HEADER_FIELDS_TOO_LARGE": 431, "UNAVAILABLE_FOR_LEGAL_REASONS": 451,
    "INTERNAL_SERVER_ERROR": 500, "NOT_IMPLEMENTED": 501, "BAD_GATEWAY": 502, "SERVICE_UNAVAILABLE": 503,
    "GATEWAY_TIMEOUT": 504, "HTTP_VERSION_NOT_SUPPORTED": 505, "VARIANT_ALSO_NEGOTIATES": 506,
    "INSUFFICIENT_STORAGE": 507, "LOOP_DETECTED": 508, "NOT_EXTENDED": 510, "NETWORK_AUTHENTICATION_REQUIRED": 511,
}

enum_body = re.search(r"^pub enum S3ErrorCode \{\n(.*?)^\}", errors_source, re.M | re.S).group(1)
error_codes = re.findall(r"^    (\w+),$", enum_body, re.M)
status_body = re.search(r"pub fn status_code\(&self\) -> Option<StatusCode> \{\n(.*?)^    \}", errors_source, re.M | re.S).group(1)
error_status = {}
for name, status in re.findall(r"Self::(\w+) => Some\(StatusCode::(\w+)\)", status_body):
    if status not in STATUS:
        raise SystemExit(f"unknown status constant {status!r} for {name}")
    error_status[name] = STATUS[status]
for name in re.findall(r"Self::(\w+) => None", status_body):
    error_status[name] = None
missing = [name for name in error_codes if name not in error_status]
if missing:
    raise SystemExit(f"error codes without a status arm: {missing}")

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


print(f"# s3s {version} DTO and error-code facts, extracted by scripts/extract_s3s_shapes.py. Do not edit.")
for name in error_codes:
    status = error_status[name]
    print(f"error {name} {'-' if status is None else status}")
for name in sorted(enums):
    print(f"enum {name}")
for name in sorted(unions):
    variants = ", ".join(f"{v}: {resolve(t)}" for v, t in unions[name])
    print(f"union {name} {{ {variants} }}")
for name in sorted(structs):
    print(f"struct {name}")
    for field, ty in structs[name]:
        print(f"  {field}: {resolve(ty)}")
