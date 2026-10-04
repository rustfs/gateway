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
"""Redact decoded Mint JSON documents and preserve observed malformed input.

This private helper owns JSON encoding and malformed signing-value bounds. It does not
judge records, count outcomes or edit a baseline. Upstream: report.py's text redactor.
Downstream: report.py's evidence-file writer and unchanged record reader.
"""
from __future__ import annotations

import json
import re
from typing import Callable

REDACTED = "[REDACTED]"
SENSITIVE_FIELD = re.compile(
    r"(?i)(?:authorization|(?:x-amz-)?(?:signature|credential|security[ _-]?token)|token|"
    r"expected[ _-]?signature|access[ _-]?key(?:[ _-]?id)?|secret[ _-]?(?:access[ _-]?)?key|"
    r"stringtosign(?:bytes)?|canonicalrequest(?:bytes)?|signatureprovided)"
)
JSON_STRING = re.compile(r'"(?:[^"\\\r\n]|\\[^\r\n])*"')


def malformed_value_end(text: str, start: int) -> int:
    """Bound a rejected signing value before independently readable later records."""
    end = len(text)
    # This recognizes framing only and does not judge a record's status. A later
    # closing delimiter cannot absorb records that precede it.
    for boundary in re.finditer(r"(?m)^[ \t]*\{", text[start:]):
        try:
            document, _ = json.JSONDecoder().raw_decode(text, start + boundary.end() - 1)
        except json.JSONDecodeError:
            continue
        if isinstance(document, dict) and {"name", "function", "status"} <= document.keys():
            end = start + boundary.start()
            while end > start and text[end - 1] in "\r\n":
                end -= 1
            break
    quoted, escaped, depth = False, False, 0
    for position in range(start, end):
        character = text[position]
        if quoted:
            if character in "\r\n":
                break
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
                if depth == 0:
                    return position + 1
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
        elif character in "]}":
            if depth == 0:
                return position
            depth -= 1
            if depth == 0:
                return position + 1
        elif depth == 0 and character in ",\r\n":
            return position
    return end


def redact_json_value(value: object, secrets: list[str], redact_text: Callable[[str, list[str]], str]) -> object:
    """Redact decoded strings and complete signing fields without touching record structure."""
    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, list):
        return [redact_json_value(item, secrets, redact_text) for item in value]
    if isinstance(value, dict):
        return {
            redact_text(key, secrets): REDACTED if SENSITIVE_FIELD.fullmatch(key) else redact_json_value(item, secrets, redact_text)
            for key, item in value.items()
        }
    return value


def redact_json_tail(text: str, secrets: list[str], redact_text: Callable[[str, list[str]], str]) -> str:
    """Redact readable strings and signing fields inside an already malformed tail."""
    decoder, chunks, position = json.JSONDecoder(), [], 0
    for match in JSON_STRING.finditer(text):
        if match.start() < position:
            continue
        chunks.append(redact_text(text[position:match.start()], secrets))
        try:
            key = json.loads(match.group())
        except json.JSONDecodeError:
            chunks.append(redact_text(match.group(), secrets))
            position = match.end()
            continue
        chunks.append(json.dumps(redact_text(key, secrets), ensure_ascii=not any("\udc80" <= c <= "\udcff" for c in match.group())))
        position = match.end()
        colon = re.match(r"\s*:\s*", text[position:])
        if not colon or not SENSITIVE_FIELD.fullmatch(key):
            continue
        start = position + colon.end()
        try:
            _, end = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            end = malformed_value_end(text, start)
        chunks.append(text[position:start] + json.dumps(REDACTED))
        position = end
    chunks.append(redact_text(text[position:], secrets))
    return "".join(chunks)


def redact_json(text: str, secrets: list[str], redact_text: Callable[[str, list[str]], str]) -> str:
    """Keep every JSON document in order; an observed malformed tail remains unparseable."""
    if any("\udc80" <= character <= "\udcff" for character in text):
        # Unicode escapes would turn unreadable UTF-8 bytes into a valid measurement.
        return "!INVALID_JSON! " + redact_json_tail(text, secrets, redact_text)
    decoder = json.JSONDecoder()
    chunks: list[str] = []
    position = 0
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position == len(text):
            break
        try:
            document, end = decoder.raw_decode(text, position)
        except json.JSONDecodeError:
            # Keep the observed malformed ordinal even if redaction erases the bad escape.
            chunks.append("!INVALID_JSON! " + redact_json_tail(text[position:], secrets, redact_text))
            break
        chunks.append(json.dumps(redact_json_value(document, secrets, redact_text)) + "\n")
        position = end
    return "".join(chunks)
