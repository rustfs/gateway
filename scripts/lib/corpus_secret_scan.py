#!/usr/bin/env python3
"""Independent credential scanner over `corpus/**`, used by check_corpus_no_secrets.sh.

It shares no code with `crates/corpus/src/redact.rs`, on purpose. Two implementations of
the same rules disagree when one of them is wrong, and a guard that cannot disagree with
the thing it guards is a guard that reports the same blind spot twice.

Base64 payloads are scanned decoded rather than raw: a secret hidden inside `bytes_b64`
is still a secret, and a raw scan of base64 both misses it and produces long-run false
positives on ordinary object bytes.
"""

from __future__ import annotations

import base64
import binascii
import json
import pathlib
import re
import sys

PLACEHOLDER = "__REDACTED__"

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-amz-copy-source-server-side-encryption-customer-key",
    "x-amz-security-token",
    "x-amz-server-side-encryption-customer-key",
}
SENSITIVE_QUERY_PARAMS = {"x-amz-credential", "x-amz-security-token", "x-amz-signature"}

PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}")
SIGV4 = re.compile(r"(?i)signature=[0-9a-f]{64}")
BASE64_RUN = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")
ASSIGNMENT = re.compile(
    r"(?i)(aws_secret_access_key|secret_access_key|secretaccesskey|secretkey|session_token"
    r"|sessiontoken|private_key|password|passwd)[\"'\s<>/]*[:=][\"'\s]*([^\"'\s,&<]+)"
)


def text_hits(text: str) -> list[str]:
    """Every rule that matches `text`, named."""
    hits: list[str] = []
    if PEM.search(text):
        hits.append("a PEM private key")
    if JWT.search(text):
        hits.append("a JSON Web Token")
    if SIGV4.search(text):
        hits.append("a SigV4 signature")
    for run in BASE64_RUN.findall(text):
        lower = any(character.islower() for character in run)
        upper = any(character.isupper() for character in run)
        digit = any(character.isdigit() for character in run)
        if lower and upper and digit:
            hits.append("an AWS secret access key")
            break
    for _, value in ASSIGNMENT.findall(text):
        if value and value != PLACEHOLDER:
            hits.append("a credential assignment")
            break
    return hits


def decoded(payload: str) -> str:
    try:
        return base64.b64decode(payload, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        # An undecodable payload is scanned as it was written. Skipping it would make a
        # malformed field the one way past this guard.
        return payload


def scan_entry(entry: dict) -> list[str]:
    hits: list[str] = []
    for pair in entry.get("headers") or []:
        if not isinstance(pair, list) or len(pair) != 2:
            hits.append("a header that is not a [name, value] pair")
            continue
        name, value = pair
        if name.lower() in SENSITIVE_HEADERS and value != PLACEHOLDER:
            hits.append(f"a live `{name.lower()}` header")
        hits.extend(text_hits(value))
    target = entry.get("target") or ""
    _, _, query = target.partition("?")
    for part in query.split("&"):
        if not part:
            continue
        name, _, value = part.partition("=")
        if name.lower() in SENSITIVE_QUERY_PARAMS and value != PLACEHOLDER:
            hits.append(f"a live `{name.lower()}` query parameter")
    hits.extend(text_hits(target))
    for chunk in entry.get("chunks") or []:
        if isinstance(chunk, dict) and "bytes_b64" in chunk:
            hits.extend(text_hits(decoded(chunk["bytes_b64"])))
    response = entry.get("resp") or {}
    for pair in response.get("headers") or []:
        if isinstance(pair, list) and len(pair) == 2:
            name, value = pair
            if name.lower() in SENSITIVE_HEADERS and value != PLACEHOLDER:
                hits.append(f"a live `{name.lower()}` response header")
            hits.extend(text_hits(value))
    if response.get("body_b64"):
        hits.extend(text_hits(decoded(response["body_b64"])))
    return hits


def main() -> int:
    root = pathlib.Path(sys.argv[1])
    corpus = root / "corpus"
    violations: list[str] = []
    files = 0
    entries = 0

    for path in sorted(corpus.rglob("*")):
        if not path.is_file():
            continue
        files += 1
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            violations.append(f"{relative}: cannot read: {error}")
            continue
        if path.suffix == ".jsonl":
            for index, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as error:
                    violations.append(f"{relative}:{index}: not valid JSON: {error}")
                    continue
                entries += 1
                for hit in scan_entry(entry):
                    violations.append(f"{relative}:{index}: {hit}")
        else:
            # Everything else in the tree — the manifest, the README, the converter — is
            # scanned as plain text. A secret pasted into a comment is still a secret.
            for index, line in enumerate(text.splitlines(), start=1):
                for hit in text_hits(line):
                    violations.append(f"{relative}:{index}: {hit}")

    if not files:
        print("check_corpus_no_secrets: corpus/ holds no files at all", file=sys.stderr)
        return 1
    for violation in violations:
        print(f"check_corpus_no_secrets: {violation}", file=sys.stderr)
    if violations:
        print(f"check_corpus_no_secrets: {len(violations)} finding(s)", file=sys.stderr)
        return 1
    print(f"OK: no secrets found in corpus/ ({files} file(s), {entries} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
