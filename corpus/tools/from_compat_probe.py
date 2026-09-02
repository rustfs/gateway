#!/usr/bin/env python3
"""Convert P8-06 client-matrix probe records into corpus JSONL.

WHAT THIS IS
    A bridge, not the recorder. The P8-04 `CorpusRecorderLayer` — which dumps the whole
    `(method, uri, headers, body)` of every request — lands in the RustFS main repository
    and does not exist yet. The client-matrix runner (rustfs/backlog#1765) already writes
    a *probe* record per request: a named subset of the request head, plus the response
    status. This converts those records so the corpus can hold real four-client traffic
    before the recorder exists.

WHY EVERY ENTRY IT WRITES IS `capture = "head_partial"`
    The probe observes eight named fields. It does not observe `authorization`, `date`,
    `content-length`, `x-amz-copy-source`, or any header nobody asked it for, and it does
    not observe request bodies. An entry produced here therefore carries the headers that
    were measured and nothing else, and `head_partial` is what stops a downstream consumer
    from reading the absence of a header as evidence that it was absent on the wire. The
    `corpus to-case` conversion refuses these entries for exactly that reason.

    `__UNRECORDED__` is the second half of the same rule: the probe records that
    `x-amz-content-sha256` held a hex digest without recording which digest, so the header
    is written with a sentinel rather than with a value nobody measured.

USAGE
    corpus/tools/from_compat_probe.py <run-dir>/results --pins <path/to/compat/versions.toml>
        > /tmp/client-matrix.jsonl
    cargo run -p rustfs-gateway-corpus --bin corpus -- \
        ingest /tmp/client-matrix.jsonl --into corpus --sanitize

    The pins file is the client-matrix runner's `compat/versions.toml`; it is the only
    place a client version is written down, and the source id of every entry is built from
    it. Without it this script refuses to run rather than invent a revision, because an
    unpinned corpus entry cannot be attributed when a differential result changes.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any
from urllib.parse import parse_qsl

# The header names the probe actually observes, and the corpus header each maps onto.
UNRECORDED = "__UNRECORDED__"


def parse_pins(path: pathlib.Path) -> dict[str, str]:
    """Read `[clients.<name>] version = "..."` pairs. A minimal reader, on purpose: this
    file has one shape and a general TOML parser would accept shapes it never has."""
    pins: dict[str, str] = {}
    client: str | None = None
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        section = re.fullmatch(r"\[clients\.([A-Za-z0-9_-]+)\]", stripped)
        if section:
            client = section.group(1)
            continue
        value = re.fullmatch(r'version\s*=\s*"([^"]+)"', stripped)
        if value and client:
            pins[client] = value.group(1)
    for name, version in pins.items():
        if version.lower() in {"latest", "main", "head", "devel", "*", ""}:
            raise SystemExit(f"client `{name}` is not pinned to a concrete version: {version!r}")
    return pins


def operation(method: str, path: str, query: str) -> str:
    """Classify one request into an AWS operation name.

    Only the recorded fields participate: a `CopyObject` is indistinguishable from a
    `PutObject` here because `x-amz-copy-source` is a header the probe does not capture,
    and this function does not guess. That gap is why `corpus/README.md` lists CopyObject
    among the operations with no entries.
    """
    segments = [segment for segment in path.split("/") if segment]
    keys = {name.lower() for name, _ in parse_qsl(query, keep_blank_values=True)}
    if not segments:
        return "ListBuckets"
    if len(segments) == 1:
        if method == "HEAD":
            return "HeadBucket"
        if method == "PUT":
            if "versioning" in keys:
                return "PutBucketVersioning"
            if "lifecycle" in keys:
                return "PutBucketLifecycleConfiguration"
            return "CreateBucket"
        if method == "DELETE":
            return "DeleteBucketLifecycle" if "lifecycle" in keys else "DeleteBucket"
        if method == "POST":
            return "DeleteObjects" if "delete" in keys else "PostObject"
        if "location" in keys:
            return "GetBucketLocation"
        if "versioning" in keys:
            return "GetBucketVersioning"
        if "lifecycle" in keys:
            return "GetBucketLifecycleConfiguration"
        if "versions" in keys:
            return "ListObjectVersions"
        if "uploads" in keys:
            return "ListMultipartUploads"
        if "list-type" in keys:
            return "ListObjectsV2"
        return "ListObjects"
    if method == "HEAD":
        return "HeadObject"
    if method == "PUT":
        if "partnumber" in keys and "uploadid" in keys:
            return "UploadPart"
        if "tagging" in keys:
            return "PutObjectTagging"
        if "acl" in keys:
            return "PutObjectAcl"
        return "PutObject"
    if method == "POST":
        if "uploads" in keys:
            return "CreateMultipartUpload"
        if "uploadid" in keys:
            return "CompleteMultipartUpload"
        return "PostObject"
    if method == "DELETE":
        if "uploadid" in keys:
            return "AbortMultipartUpload"
        if "tagging" in keys:
            return "DeleteObjectTagging"
        return "DeleteObject"
    if "uploadid" in keys:
        return "ListParts"
    if "tagging" in keys:
        return "GetObjectTagging"
    if "acl" in keys:
        return "GetObjectAcl"
    return "GetObject"


def headers_of(record: dict[str, Any]) -> list[list[str]]:
    """The headers the probe measured, in a stable order."""
    headers: list[list[str]] = []
    user_agent = record.get("user_agent") or ""
    if user_agent:
        headers.append(["user-agent", user_agent])
    payload_mode = record.get("payload_mode") or ""
    if payload_mode == "sha256-hex":
        # Present, value not captured. Never a fabricated digest.
        headers.append(["x-amz-content-sha256", UNRECORDED])
    elif payload_mode:
        headers.append(["x-amz-content-sha256", payload_mode])
    if record.get("content_encoding"):
        headers.append(["content-encoding", record["content_encoding"]])
    if record.get("decoded_content_length"):
        headers.append(["x-amz-decoded-content-length", str(record["decoded_content_length"])])
    if record.get("declared_trailer"):
        headers.append(["x-amz-trailer", record["declared_trailer"]])
    return headers


def entry_of(record: dict[str, Any], src: str, recorded: str) -> dict[str, Any]:
    path = record.get("path") or "/"
    query = record.get("query") or ""
    target = f"{path}?{query}" if query else path
    return {
        "v": 1,
        "op": operation(record.get("method", "GET"), path, query),
        "src": src,
        "recorded": recorded,
        "capture": "head_partial",
        # The matrix points its clients at `compat-sut`: the rustfs-gateway-fs reference
        # backend behind a real listener. Real sockets, real SigV4, real wire bytes — and
        # not the production RustFS server, which rustfs/gateway#624 records does not
        # exist as a runnable binary in this repository at all.
        "sut": "gateway-fs-reference",
        "method": record.get("method", "GET"),
        "target": target,
        "headers": headers_of(record),
        "resp": {"status": int(record.get("status", 0))},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=pathlib.Path, help="the runner's results/ directory")
    parser.add_argument("--pins", type=pathlib.Path, required=True, help="compat/versions.toml")
    parser.add_argument("--recorded", required=True, help="recording date, YYYY-MM-DD")
    arguments = parser.parse_args()

    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", arguments.recorded):
        raise SystemExit("--recorded must be YYYY-MM-DD")
    pins = parse_pins(arguments.pins)

    written = 0
    for path in sorted(arguments.results.rglob("*.json")):
        document = json.loads(path.read_text())
        client = document.get("client")
        if not client:
            raise SystemExit(f"{path}: no `client` field; the probe cannot be attributed")
        if client not in pins:
            raise SystemExit(f"{path}: client `{client}` has no pinned version in {arguments.pins}")
        src = f"client-matrix:{client}@{pins[client]}"
        for record in document.get("probe") or []:
            json.dump(entry_of(record, src, arguments.recorded), sys.stdout, separators=(",", ":"))
            sys.stdout.write("\n")
            written += 1
    print(f"converted {written} probe record(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
