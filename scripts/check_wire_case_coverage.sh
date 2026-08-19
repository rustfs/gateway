#!/usr/bin/env bash
set -euo pipefail

# WHAT: Maps every one of the 39 P3-01 wire acceptance ids to a named, enabled, asserting test
# function, or to an explicitly declared block with the issue that owns it.
# WHY: rustfs/backlog#1689 §7 lists 39 ids. A green `crates/http` suite proves that the tests in it
# pass, not that every listed id still has one; and four prior audits of this issue disagreed about
# which ids were covered because each one grepped a different spelling.
# HOW TO EXEMPT: There is no exemption. A case moves out of `blocked` only by naming real
# executable evidence, and moves into it only by editing the blocked set below, which is reviewed.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# id|polarity|status|evidence
#
# `bound`   — evidence is one or more `<path>::<function>` entries separated by `;`.
# `blocked` — evidence is `<owner issue>::<why it is not evidence yet>`; naming a test is refused.
#
# The eight positive ids are `0001`..`0008`; every other id in §7 is negative.
cases=(
    'c-wire-0001|positive|bound|crates/http/tests/host_ambiguity.rs::c_wire_0001_origin_form_with_host_header_is_accepted'
    'c-wire-0002|positive|bound|crates/http/tests/host_ambiguity.rs::c_wire_0002_http2_authority_without_host_header_is_accepted'
    'c-wire-0003|positive|bound|crates/http/tests/host_ambiguity.rs::c_wire_0003_http2_host_header_without_authority_is_accepted'
    'c-wire-0004|positive|bound|crates/http/tests/host_ambiguity.rs::c_wire_0004_authority_and_host_agreeing_byte_for_byte_is_accepted'
    'c-wire-0005|positive|bound|crates/http/tests/header_and_query.rs::c_wire_0005_an_unrelated_non_utf8_header_is_ignored_not_fatal'
    'c-wire-0006|positive|bound|crates/http/tests/header_and_query.rs::c_wire_0006_an_empty_header_value_is_accepted'
    'c-wire-0007|positive|bound|crates/http/tests/host_ambiguity.rs::c_wire_0007_routing_and_signing_read_the_same_stored_host'
    'c-wire-0008|positive|bound|crates/http/tests/framing_smuggling.rs::c_wire_0008_transfer_encoding_chunked_without_content_length_is_accepted'
    'c-wire-0020|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0020_content_length_with_transfer_encoding_is_rejected_without_reading_the_body'
    'c-wire-0021|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0021_repeated_transfer_encoding_is_rejected'
    'c-wire-0022|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0022_chunked_not_last_is_rejected'
    'c-wire-0023|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0023_transfer_encoding_identity_is_rejected'
    'c-wire-0024|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0024_transfer_encoding_on_http2_is_rejected'
    'c-wire-0025|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0025_two_different_content_lengths_are_rejected'
    'c-wire-0026|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0026_two_identical_content_lengths_are_rejected'
    'c-wire-0027|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0027_to_0030_malformed_content_lengths_are_rejected'
    'c-wire-0028|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0028_a_negative_content_length_never_becomes_a_huge_positive_one'
    'c-wire-0029|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0027_to_0030_malformed_content_lengths_are_rejected'
    'c-wire-0030|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0027_to_0030_malformed_content_lengths_are_rejected'
    'c-wire-0031|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0031_a_bare_line_feed_does_not_terminate_a_chunk_size_line'
    'c-wire-0032|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0032_an_over_long_chunk_size_line_is_refused_by_the_limit'
    'c-wire-0033|negative|bound|crates/http/tests/host_ambiguity.rs::c_wire_0033_missing_host_is_rejected'
    'c-wire-0034|negative|bound|crates/http/tests/host_ambiguity.rs::c_wire_0034_empty_host_is_rejected'
    'c-wire-0035|negative|bound|crates/http/tests/host_ambiguity.rs::c_wire_0035_two_conflicting_host_headers_are_rejected'
    'c-wire-0036|negative|bound|crates/http/tests/host_ambiguity.rs::c_wire_0036_two_identical_host_headers_are_also_rejected'
    'c-wire-0037|negative|bound|crates/http/tests/host_ambiguity.rs::c_wire_0037_absolute_form_disagreeing_with_host_header_is_rejected'
    'c-wire-0038|negative|bound|crates/http/tests/host_ambiguity.rs::c_wire_0038_http2_authority_disagreeing_with_host_header_is_rejected'
    'c-wire-0039|negative|bound|crates/http/tests/host_ambiguity.rs::c_wire_0039_non_ascii_host_is_rejected_as_invalid_not_forbidden'
    'c-wire-0040|negative|bound|crates/http/tests/header_and_query.rs::c_wire_0040_a_repeated_authorization_header_is_rejected'
    'c-wire-0041|negative|bound|crates/http/tests/header_and_query.rs::c_wire_0041_a_repeated_content_sha256_header_is_rejected'
    'c-wire-0042|negative|bound|crates/http/tests/header_and_query.rs::c_wire_0042_a_repeated_single_valued_query_parameter_is_rejected'
    'c-wire-0043|negative|bound|crates/http/tests/header_and_query.rs::c_wire_0043_a_signed_or_significant_header_with_non_utf8_bytes_is_rejected'
    'c-wire-0044|negative|bound|crates/http/tests/header_and_query.rs::c_wire_0044_a_metadata_value_that_decodes_to_crlf_is_rejected'
    'c-wire-0045|negative|bound|crates/http/tests/header_and_query.rs::c_wire_0045_a_metadata_key_that_is_not_a_token_is_rejected'
    'c-wire-0060|negative|blocked|rustfs/backlog#1689::a client reset must cancel the handler, and HandlerCancellation has one variant (Deadline); the new cross-crate cancellation contract needs a merged ADR first'
    'c-wire-0061|negative|blocked|rustfs/backlog#1699::the header deadline closing a half-open connection is observed, but no harness measures resident memory or a healthy peer p99 while slow *headers* are parked; the slow-reader harness measures the write side'
    'c-wire-0062|negative|blocked|rustfs/backlog#1699::no head-to-first-body-byte deadline exists; ProgressIo::check_idle resets the idle deadline while a request is in flight, so a peer that never sends a declared body is retired by nothing'
    'c-wire-0063|negative|bound|crates/http/tests/framing_smuggling.rs::c_wire_0063_an_over_large_declared_body_is_400_entity_too_large_and_never_drained;crates/gateway/tests/connection_teardown.rs::c_wire_0063_an_over_large_body_is_refused_on_the_socket_before_it_is_sent'
    'c-wire-0064|negative|blocked|rustfs/backlog#1699::the per-IP half-open ceiling, accept backpressure and the thousand-connection memory budget are each observed by a different test; none of them observes the three together at the scale the case names'
)

# The ids whose evidence must be plural: an intention read inside one crate and an observation made
# on a socket are two claims, and one of them passing has never implied the other.
plural_evidence=('c-wire-0063')

# Editing this set is the only way a case becomes blocked, so a case cannot quietly stop being
# evidence-backed. Each id here must also carry an owning issue in the table above.
blocked_ids=('c-wire-0060' 'c-wire-0061' 'c-wire-0062' 'c-wire-0064')

command -v python3 >/dev/null 2>&1 || {
    printf 'check_wire_case_coverage: required command is missing: python3\n' >&2
    exit 1
}

python3 - "$ROOT" "${#cases[@]}" "$(printf '%s\n' "${plural_evidence[@]}")" "$(printf '%s\n' "${blocked_ids[@]}")" "${cases[@]}" <<'PYEOF'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
declared_total = int(sys.argv[2])
plural_evidence = set(sys.argv[3].split())
blocked_declared = set(sys.argv[4].split())
rows = sys.argv[5:]

# §7 of rustfs/backlog#1689, transcribed once: eight positive ids and thirty-one negative ones.
EXPECTED_IDS = (
    [f"c-wire-{index:04d}" for index in range(1, 9)]
    + [f"c-wire-{index:04d}" for index in range(20, 46)]
    + [f"c-wire-{index:04d}" for index in range(60, 65)]
)
EXPECTED_POSITIVE = 8
EXPECTED_NEGATIVE = 31

# An assertion that only holds a refusal, and one that only holds an acceptance. The two lists are
# what makes a swapped polarity a red build rather than a relabelling: a case declared negative
# whose test never names a refusal is not testing a refusal.
REFUSAL_TOKENS = (
    "expect_err",
    "unwrap_err",
    "is_err",
    ".err()",
    "Err(",
    "WireReject",
    "HostError",
    "ChunkReject",
    "LimitKind",
    "reject_of",
    "host_error",
    "ENTITY_TOO_LARGE",
)
ACCEPTANCE_TOKENS = (".expect(", "is_ok(", ".unwrap()")
ASSERTION_TOKENS = ("assert!", "assert_eq!", "assert_ne!", "assert_matches!")
TEST_ATTRIBUTES = ("#[test]", "#[tokio::test")

failures = []


def fail(message):
    failures.append(message)


def strip_comments_and_literals(source):
    """Blank out comments, string and char literals, keeping every byte offset intact.

    Evidence found in a comment or a string is data. The seventh check in this repository that
    could not fail was a contract asserted only in prose, so the ledger reads code alone.
    """
    out = []
    index = 0
    depth = 0
    length = len(source)
    while index < length:
        if depth:
            if source.startswith("/*", index):
                depth += 1
                out.append("  ")
                index += 2
            elif source.startswith("*/", index):
                depth -= 1
                out.append("  ")
                index += 2
            else:
                out.append("\n" if source[index] == "\n" else " ")
                index += 1
        elif source.startswith("//", index):
            while index < length and source[index] != "\n":
                out.append(" ")
                index += 1
        elif source.startswith("/*", index):
            depth = 1
            out.append("  ")
            index += 2
        elif raw := re.match(r'(?:br|r|b|c)?(#{0,16})"', source[index:]):
            if raw.group(0).endswith('"'):
                hashes = raw.group(1)
                closing = '"' + hashes
                cursor = index + raw.end()
                if hashes:
                    end = source.find(closing, cursor)
                    end = length if end == -1 else end + len(closing)
                else:
                    end = cursor
                    while end < length:
                        if source[end] == "\\":
                            end += 2
                        elif source[end] == '"':
                            end += 1
                            break
                        else:
                            end += 1
                out.extend("\n" if char == "\n" else " " for char in source[index:end])
                index = end
                continue
            out.append(source[index])
            index += 1
        elif char := re.match(r"(?:b)?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^\\'\n])'", source[index:]):
            end = index + char.end()
            out.extend(" " for _ in source[index:end])
            index = end
        else:
            out.append(source[index])
            index += 1
    return "".join(out)


def at_top_level(code, offset):
    """True when `offset` is inside no block, so a `#[cfg(test)] mod` cannot hide the evidence."""
    openers = {"{": 1, "(": 1, "[": 1}
    closers = {"}": 1, ")": 1, "]": 1}
    depth = 0
    for char in code[:offset]:
        depth += openers.get(char, 0)
        depth -= closers.get(char, 0)
    return depth == 0


def function_span(code, name):
    """Returns (attributes, body) for a top-level `fn name()`, or None."""
    pattern = re.compile(rf"(?m)^[ \t]*(?:async\s+)?fn\s+{re.escape(name)}\s*\(\s*\)[^;{{]*\{{")
    match = next((found for found in pattern.finditer(code) if at_top_level(code, found.start())), None)
    if match is None:
        return None
    opening = match.end() - 1
    depth = 1
    cursor = opening + 1
    while cursor < len(code) and depth:
        if code[cursor] == "{":
            depth += 1
        elif code[cursor] == "}":
            depth -= 1
        cursor += 1
    if depth:
        return None
    # Everything from the previous blank-line-separated item start up to the signature carries the
    # attributes, which is where `#[ignore]` and `#[cfg(...)]` hide.
    head = code[:match.start()]
    attribute_start = head.rfind("\n\n")
    attributes = head[attribute_start + 1 :] if attribute_start != -1 else head
    return attributes, code[opening + 1 : cursor - 1]


def name_covers(function, identifier):
    """A `c-wire-0029` row may only point at `c_wire_0029_*` or a `c_wire_0027_to_0030_*` range."""
    number = int(identifier.rsplit("-", 1)[1])
    if function.startswith(f"c_wire_{number:04d}_"):
        return True
    span = re.match(r"^c_wire_(\d{4})_to_(\d{4})_", function)
    return span is not None and int(span.group(1)) <= number <= int(span.group(2))


seen = []
polarity_count = {"positive": 0, "negative": 0}
blocked_seen = set()

if declared_total != len(EXPECTED_IDS):
    fail(f"the table declares {declared_total} rows against the {len(EXPECTED_IDS)} ids of §7")

for position, row in enumerate(rows):
    parts = row.split("|", 3)
    if len(parts) != 4:
        fail(f"row {position + 1} is not `id|polarity|status|evidence`: {row}")
        continue
    identifier, polarity, status, evidence = parts
    if identifier in seen:
        fail(f"{identifier} appears more than once")
        continue
    seen.append(identifier)
    if position >= len(EXPECTED_IDS):
        fail(f"{identifier} is past the end of the §7 id list")
        continue
    if identifier != EXPECTED_IDS[position]:
        fail(f"expected {EXPECTED_IDS[position]} at row {position + 1}, found {identifier}")
        continue
    if polarity not in polarity_count:
        fail(f"{identifier} declares an unknown polarity: {polarity}")
        continue
    polarity_count[polarity] += 1
    expected_polarity = "positive" if int(identifier.rsplit("-", 1)[1]) <= 8 else "negative"
    if polarity != expected_polarity:
        fail(f"{identifier} is {expected_polarity} in §7 but the table calls it {polarity}")
        continue

    if status == "blocked":
        blocked_seen.add(identifier)
        if identifier not in blocked_declared:
            fail(f"{identifier} is blocked but is not in the reviewed blocked set")
            continue
        owner, _, reason = evidence.partition("::")
        if not re.fullmatch(r"rustfs/[a-z]+#\d+", owner):
            fail(f"{identifier} is blocked without an owning issue: {owner!r}")
        if len(reason.strip()) < 40:
            fail(f"{identifier} is blocked without a reason long enough to review: {reason!r}")
        # A blocked case with a test named after it is a case somebody finished and nobody
        # registered, which reads from the ledger exactly like one nobody started.
        number = int(identifier.rsplit("-", 1)[1])
        for candidate in sorted(root.glob("crates/*/tests/*.rs")) + sorted(root.glob("crates/*/src/**/*.rs")):
            if re.search(rf"\bfn\s+c_wire_{number:04d}_", candidate.read_text()):
                fail(f"{identifier} is blocked, but {candidate.relative_to(root)} already names a test for it")
        continue

    if status != "bound":
        fail(f"{identifier} declares an unknown status: {status}")
        continue
    if identifier in blocked_declared:
        fail(f"{identifier} is in the blocked set but the table binds it")
        continue

    entries = [entry for entry in evidence.split(";") if entry]
    if identifier in plural_evidence and len(entries) < 2:
        fail(f"{identifier} needs evidence in more than one crate and names {len(entries)}")
    for entry in entries:
        relative, separator, function = entry.partition("::")
        if not separator or not function:
            fail(f"{identifier} evidence is not `<path>::<function>`: {entry}")
            continue
        path = root / relative
        if not path.is_file():
            fail(f"{identifier} names a file that does not exist: {relative}")
            continue
        if not name_covers(function, identifier):
            fail(f"{identifier} is mapped to `{function}`, whose name does not cover it")
            continue
        source = path.read_text()
        code = strip_comments_and_literals(source)
        span = function_span(code, function)
        if span is None:
            fail(f"{identifier} names no top-level `fn {function}` in {relative}")
            continue
        attributes, body = span
        if not any(attribute in attributes for attribute in TEST_ATTRIBUTES):
            fail(f"{identifier} maps to `{function}` in {relative}, which is not a test")
        if "#[ignore" in attributes:
            fail(f"{identifier} maps to `{function}` in {relative}, which is ignored")
        if "#[cfg" in attributes:
            fail(f"{identifier} maps to `{function}` in {relative}, which is compiled conditionally")
        # An assertion that may or may not be compiled is not evidence that it holds, and a
        # `#[cfg(any())]` statement reads from a diff exactly like the assertion it replaced.
        if "#[cfg" in body:
            fail(f"{identifier} maps to `{function}` in {relative}, whose body is conditionally compiled")
        if not any(token in body for token in ASSERTION_TOKENS):
            fail(f"{identifier} maps to `{function}` in {relative}, whose body asserts nothing")
            continue
        if polarity == "negative" and not any(token in body for token in REFUSAL_TOKENS):
            fail(f"{identifier} is negative but `{function}` in {relative} never names a refusal")
        if polarity == "positive":
            if not any(token in body for token in ACCEPTANCE_TOKENS):
                fail(f"{identifier} is positive but `{function}` in {relative} never accepts anything")
            named = [token for token in REFUSAL_TOKENS if token in body]
            if named:
                fail(f"{identifier} is positive but `{function}` in {relative} asserts a refusal: {named}")

missing = [identifier for identifier in EXPECTED_IDS if identifier not in seen]
if missing:
    fail(f"§7 ids with no row at all: {' '.join(missing)}")
unregistered = blocked_declared - blocked_seen
if unregistered:
    fail(f"the blocked set names ids the table does not block: {' '.join(sorted(unregistered))}")
if polarity_count["positive"] != EXPECTED_POSITIVE or polarity_count["negative"] != EXPECTED_NEGATIVE:
    fail(
        f"§7 is {EXPECTED_POSITIVE} positive and {EXPECTED_NEGATIVE} negative; the table is "
        f"{polarity_count['positive']} and {polarity_count['negative']}"
    )
if polarity_count["negative"] <= polarity_count["positive"]:
    fail("the negative cases must outnumber the positive ones")

if failures:
    for message in failures:
        print(f"check_wire_case_coverage: {message}", file=sys.stderr)
    raise SystemExit(1)

bound = len(EXPECTED_IDS) - len(blocked_declared)
print(f"OK: {bound} of {len(EXPECTED_IDS)} wire acceptance ids map to executable evidence, {len(blocked_declared)} blocked")
PYEOF
