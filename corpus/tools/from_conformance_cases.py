#!/usr/bin/env python3
"""Turn the conformance cases that cite an s3s issue into `handwritten:s3s-issues#<n>` entries.

WHAT THIS IS
    rustfs/backlog#1763 wants the corpus to carry the hand-written, issue-derived requests that
    no ordinary client produces. This repository already holds them: every conformance case
    whose `[[case.evidence]]` has `kind = "s3s-issue"` is a request written here from a fact
    recorded in an s3s issue, with the issue URL and a one-sentence summary written by whoever
    authored the case. This script lifts the request bytes of those cases into corpus entries,
    one per request, so the differential and fuzz consumers get them as inputs.

    It copies no s3s text and no s3s code: the request bytes are this repository's, and the
    evidence stays where it was reviewed, in the case. An entry's `src` names the issue
    (`handwritten:s3s-issues#<n>`), and `scripts/check_corpus_provenance.sh` refuses any such
    entry whose issue no conformance case cites as `s3s-issue` evidence.

WHY EVERY ENTRY IT WRITES IS `capture = "head_partial"` AND `sut = "none"`
    A case names the request as authored, not as the runner put it on the wire: the runner adds
    the signing headers, the date and the payload digest at run time. So the headers an entry
    carries are the authored ones, and their absence proves nothing; `head_partial` says
    exactly that, and `corpus to-case` refuses to turn the entry back into a case. No server
    answered anything, so `sut` is `none` and no response is recorded.

WHAT IT SKIPS, AND SAYS SO
    A request whose operation the case does not name, a raw head that is not a parseable
    request line, a body sourced from a file outside `conformance/`, and a generated payload
    over 64 KiB. Each skip is reported on stderr with its case and reason.

USAGE
    corpus/tools/from_conformance_cases.py conformance --recorded 2026-09-28 > /tmp/s3s.jsonl
    cargo run -p rustfs-gateway-corpus --bin corpus -- ingest /tmp/s3s.jsonl --into corpus
"""

from __future__ import annotations

import argparse
import base64
import json
import pathlib
import re
import sys
import tomllib

ISSUE_URL = re.compile(r"^https://github\.com/s3s-project/s3s/(?:issues|pull)/(\d+)$")
MAX_GENERATED = 64 * 1024


class Skip(Exception):
    """A request this converter will not turn into an entry, with the reason."""


def issue_numbers(case: dict) -> list[str]:
    numbers = []
    for item in case.get("case", {}).get("evidence", []) or []:
        if item.get("kind") != "s3s-issue":
            continue
        match = ISSUE_URL.match(item.get("url", ""))
        if match and match.group(1) not in numbers:
            numbers.append(match.group(1))
    return numbers


def payload_bytes(payload: dict, root: pathlib.Path) -> bytes:
    if "utf8" in payload:
        return payload["utf8"].encode()
    if "raw_utf8" in payload:
        return payload["raw_utf8"].encode()
    if "hex" in payload:
        return bytes.fromhex(payload["hex"])
    if "raw_hex" in payload:
        return bytes.fromhex(payload["raw_hex"])
    if "file" in payload:
        path = (root / payload["file"]).resolve()
        if root.resolve() not in path.parents:
            raise Skip(f"body file {payload['file']} is outside the conformance root")
        return path.read_bytes()
    if "size" in payload:
        size = int(payload["size"])
        if size > MAX_GENERATED:
            raise Skip(f"generated payload of {size} bytes is over {MAX_GENERATED}")
        if "fill" not in payload:
            raise Skip("generated payload has no explicit fill, so its bytes are the runner's to choose")
        fill = payload["fill"].encode()
        return (fill * (size // max(len(fill), 1) + 1))[:size]
    raise Skip(f"unrecognised payload source {sorted(payload)}")


def chunk_of(chunk: dict, root: pathlib.Path) -> dict:
    if "action" in chunk:
        out = {"action": chunk["action"]}
        for key in ("delay_ms", "duration_ms"):
            if key in chunk:
                out[key] = chunk[key]
        return out
    data = payload_bytes(chunk, root) * int(chunk.get("repeat", 1))
    if len(data) > MAX_GENERATED:
        raise Skip(f"a repeated chunk of {len(data)} bytes is over {MAX_GENERATED}")
    out = {"bytes_b64": base64.b64encode(data).decode()}
    if "delay_ms" in chunk:
        out["delay_ms"] = chunk["delay_ms"]
    return out


def raw_head(text: str) -> tuple[str, str, list[list[str]]]:
    lines = text.replace("\r\n", "\n").split("\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        raise Skip("raw head does not start with a parseable request line")
    headers = []
    for line in lines[1:]:
        if not line:
            break
        name, separator, value = line.partition(":")
        if not separator:
            raise Skip("raw head carries a header line without a colon")
        headers.append([name.strip().lower(), value.strip()])
    return parts[0], parts[1], headers


def entry_of(request: dict, op: str, issue: str, recorded: str, root: pathlib.Path) -> dict:
    headers: list[list[str]] = []
    if "raw_head_utf8" in request or "raw_head_hex" in request:
        text = request.get("raw_head_utf8")
        if text is None:
            text = bytes.fromhex(request["raw_head_hex"]).decode("utf-8", "replace")
        method, target, headers = raw_head(text)
    else:
        method, target = request.get("method"), request.get("target")
        if not isinstance(method, str) or not isinstance(target, str):
            raise Skip("request names no method or target")
        if "host" in request:
            headers.append(["host", request["host"]])
        for name, value in (request.get("headers") or {}).items():
            headers.append([name.lower(), str(value)])
        for name, value in request.get("raw_headers") or []:
            headers.append([name.lower(), value])
    entry = {
        "v": 1,
        "op": op,
        "src": f"handwritten:s3s-issues#{issue}",
        "recorded": recorded,
        "capture": "head_partial",
        "sut": "none",
        "method": method,
        "target": target,
    }
    if headers:
        entry["headers"] = headers
    if "chunks" in request:
        entry["chunks"] = [chunk_of(chunk, root) for chunk in request["chunks"]]
    elif "body" in request:
        body = payload_bytes(request["body"], root)
        if body:
            entry["chunks"] = [{"bytes_b64": base64.b64encode(body).decode()}]
    return entry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("root", type=pathlib.Path, help="the conformance root (holds cases/)")
    parser.add_argument("--recorded", required=True, help="the date to record, YYYY-MM-DD")
    args = parser.parse_args()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.recorded):
        parser.error("--recorded must be YYYY-MM-DD")

    written = skipped = 0
    for path in sorted((args.root / "cases").rglob("*.toml")):
        case = tomllib.loads(path.read_text())
        issues = issue_numbers(case)
        if not issues:
            continue
        op = case.get("case", {}).get("operation")
        requests = [case["request"]] if "request" in case else [item["request"] for item in case.get("exchanges", [])]
        for index, request in enumerate(requests):
            label = f"{path.relative_to(args.root)} request {index + 1}"
            try:
                if not isinstance(op, str) or not op:
                    raise Skip("the case names no operation")
                print(json.dumps(entry_of(request, op, issues[0], args.recorded, args.root), separators=(",", ":")))
                written += 1
            except Skip as reason:
                print(f"from_conformance_cases: skipped {label}: {reason}", file=sys.stderr)
                skipped += 1
    print(f"from_conformance_cases: wrote {written} entries, skipped {skipped}", file=sys.stderr)
    return 0 if written else 1


if __name__ == "__main__":
    raise SystemExit(main())
