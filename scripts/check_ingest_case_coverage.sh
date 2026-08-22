#!/usr/bin/env bash
set -euo pipefail

# WHAT: Maps every one of the 40 P3-03 ingest ids to a named, enabled, asserting test function, to
# such a function plus the part of the case it does not yet reach, or to an explicitly declared
# block with the issue that owns it.
# WHY: rustfs/backlog#1691 §7 lists 40 ids. `crates/http` has 91 green ingest tests, which proves
# that those tests pass — not that every listed id still has one. Two prior audits of this issue
# reached different answers about which ids were covered because each one counted tests rather
# than ids, and a family counted by test names cannot notice a case nobody wrote.
# HOW TO EXEMPT: There is no exemption. A case moves out of `blocked` only by naming real
# executable evidence, and into it only by editing the blocked set below, which is reviewed. A
# `partial` row must name both: the evidence it has and the half it does not.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# id|polarity|status|evidence
#
# `bound`   — evidence is one or more `<path>::<function>` entries separated by `;`.
# `partial` — evidence is `<bound evidence>@@<owner issue>::<what is still unproved>`. The bound
#             half is checked exactly as a `bound` row is; the rest keeps the gap addressed to
#             somebody. A row that proves half a case and says so is worth more than one that
#             claims the whole of it, and worth far more than one that claims none of it.
# `blocked` — evidence is `<owner issue>::<why it is not evidence yet>`; naming a test is refused.
#
# The ten positive ids are `0001`..`0010`; every other id in §7 is negative.
cases=(
    'c-ing-0001|positive|bound|crates/http/tests/ingest_verify.rs::c_ing_0001_a_signed_body_verifies_and_arrives_byte_for_byte'
    'c-ing-0002|positive|bound|crates/http/tests/ingest_framing.rs::c_ing_0002_unsigned_streaming_with_a_trailer_is_framed_but_unsigned;crates/http/tests/ingest_chunk_rules.rs::c_ing_0002_three_chunks_round_trip_byte_for_byte'
    'c-ing-0003|positive|bound|crates/http/tests/ingest_perf_gates.rs::c_ing_0003_one_scope_is_derived_once_however_many_requests_use_it;crates/http/tests/ingest_perf_gates.rs::c_ing_0003_a_signed_upload_costs_one_hmac_per_chunk_plus_four;crates/gateway/tests/ingest_assembly.rs::c_ing_0003_the_assembly_holds_one_derived_key_per_request_however_many_chunks_it_has'
    'c-ing-0004|positive|bound|crates/http/tests/ingest_perf_gates.rs::c_ing_0004_stripping_chunk_headers_moves_no_bytes_at_all'
    'c-ing-0005|positive|bound|crates/http/tests/ingest_perf_gates.rs::c_ing_0005_four_observers_and_the_signer_each_see_the_body_exactly_once;crates/http/tests/ingest_perf_gates.rs::c_ing_0005_the_single_pass_instrument_reports_two_when_the_body_is_walked_twice'
    'c-ing-0006|positive|bound|crates/http/tests/ingest_framing.rs::c_ing_0006_a_decoded_length_that_fits_inside_the_wire_length_is_accepted'
    'c-ing-0007|positive|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0007_a_chunk_of_exactly_the_ceiling_is_accepted'
    'c-ing-0008|positive|partial|crates/http/tests/ingest_perf_gates.rs::c_ing_0008_observers_are_called_at_chunk_granularity@@rustfs/backlog#1692::the call granularity is proved, but the case also demands that CRC32C be asserted hardware-accelerated and fail on a software fallback; no digest algorithm is implemented in this crate and the checksum authority that owns algorithm selection performs no hardware dispatch assertion'
    'c-ing-0009|positive|bound|crates/http/tests/ingest_verify.rs::c_ing_0009_an_empty_signed_body_still_verifies_its_terminal_chunk'
    'c-ing-0010|positive|bound|crates/gateway/src/chunked.rs::c_ing_0010_a_content_encoding_of_aws_chunked_alongside_a_streaming_signature_still_parses'
    'c-ing-0020|negative|bound|crates/http/tests/ingest_framing.rs::c_ing_0020_a_pipeline_cannot_be_built_for_a_body_the_signature_did_not_frame;crates/gateway/src/chunked.rs::c_ing_0020_an_unframed_mode_never_builds_a_pipeline'
    'c-ing-0021|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0021_a_four_gigabyte_chunk_is_refused_at_the_header_without_reading_a_data_byte'
    'c-ing-0022|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0022_an_over_large_chunk_fed_one_byte_at_a_time_is_still_refused_immediately'
    'c-ing-0023|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0023_a_chunk_size_with_leading_zeros_is_refused'
    'c-ing-0024|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0024_a_chunk_size_with_a_hex_prefix_is_refused'
    'c-ing-0025|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0025_a_signed_chunk_size_is_refused'
    'c-ing-0026|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0026_an_over_long_chunk_size_line_is_refused'
    'c-ing-0027|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0027_a_bare_line_feed_is_refused'
    'c-ing-0028|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0028_whitespace_around_the_chunk_size_is_refused'
    'c-ing-0029|negative|bound|crates/http/tests/ingest_verify.rs::c_ing_0029_to_0031_every_other_spelling_of_the_signature_extension_is_refused'
    'c-ing-0030|negative|bound|crates/http/tests/ingest_verify.rs::c_ing_0029_to_0031_every_other_spelling_of_the_signature_extension_is_refused'
    'c-ing-0031|negative|bound|crates/http/tests/ingest_verify.rs::c_ing_0029_to_0031_every_other_spelling_of_the_signature_extension_is_refused'
    'c-ing-0032|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0032_an_extension_on_unsigned_framing_is_refused'
    'c-ing-0033|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0033_bytes_after_the_terminal_chunk_are_refused'
    'c-ing-0034|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0034_a_micro_chunk_flood_is_refused_by_the_chunk_count_ceiling;crates/http/tests/ingest_chunk_rules.rs::c_ing_0034_framing_overhead_out_of_proportion_to_the_payload_is_refused'
    'c-ing-0035|negative|bound|crates/http/tests/ingest_verify.rs::c_ing_0035_a_bad_first_chunk_signature_delivers_zero_bytes;crates/http/tests/ingest_verify.rs::c_ing_0035_a_bad_later_chunk_delivers_none_of_its_own_bytes'
    'c-ing-0036|negative|bound|crates/http/tests/ingest_verify.rs::c_ing_0036_a_signature_replayed_from_another_position_breaks_the_chain'
    'c-ing-0037|negative|bound|crates/http/tests/ingest_verify.rs::c_ing_0037_chunk_signatures_from_another_request_do_not_verify'
    'c-ing-0038|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0038_more_body_than_declared_is_refused_and_the_counter_never_exceeds_the_declaration'
    'c-ing-0039|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0039_less_body_than_declared_is_refused_and_may_not_be_committed'
    'c-ing-0040|negative|bound|crates/http/tests/ingest_framing.rs::c_ing_0040_a_decoded_length_on_a_non_framed_body_is_refused'
    'c-ing-0041|negative|bound|crates/http/tests/ingest_framing.rs::c_ing_0041_a_framed_body_without_a_decoded_length_is_refused'
    'c-ing-0042|negative|bound|crates/http/tests/ingest_framing.rs::c_ing_0042_a_decoded_length_larger_than_the_wire_length_is_refused'
    'c-ing-0043|negative|bound|crates/http/tests/ingest_chunk_rules.rs::c_ing_0043_a_truncated_stream_fails_and_never_reports_end_of_stream;crates/http/tests/ingest_verify.rs::c_ing_0043_a_truncated_signed_body_reports_what_had_verified'
    'c-ing-0044|negative|bound|crates/gateway/src/chunked.rs::c_ing_0044_a_gzip_content_encoding_is_delivered_without_being_inflated;crates/gateway/src/gate_tests.rs::c_ing_0044_c_lim_0027_gzip_wire_bytes_set_the_body_ceiling'
    'c-ing-0060|negative|bound|crates/gateway/tests/connection_teardown.rs::c_wire_0060_c_ing_0060_c_lim_0060_a_client_reset_cancels_the_handler_rolls_back_and_releases_its_permit'
    'c-ing-0061|negative|blocked|rustfs/gateway#331::the wire reader has a between-frame idle deadline, but SealedBody collects the complete request before dispatch, so a handler cannot stop consuming a stream and exercise end-to-end back-pressure'
    'c-ing-0062|negative|blocked|rustfs/gateway#332::no minimum-throughput floor exists, so a peer feeding one byte per second is refused by no rule; the resident-bytes and healthy-peer-p99 halves also need a harness with a measurable control'
    'c-ing-0063|negative|partial|crates/http/tests/ingest_perf_gates.rs::c_ing_0063_the_window_stays_bounded_by_the_chunk_ceiling;crates/http/tests/ingest_perf_gates.rs::c_ing_0063_the_window_is_not_allocated_up_front;crates/gateway/tests/chunked_allocations.rs::c_ing_0063_an_aws_chunked_upload_holds_one_copy_of_its_body@@rustfs/gateway#331::rustfs/gateway#229 removed the second whole-body copy and the pipeline window itself is bounded, but ChunkIngest still collects the decoded body before dispatch; no test observes bounded ownership across concurrent large logical uploads'
    'c-ing-0064|negative|blocked|rustfs/gateway#333::a Governor refusal that arrives mid-body must propagate as cancellation and close the socket without draining; Governor runs before the body is read, so no mid-upload refusal path exists until the verified streaming-body contract lands'
)

# The ids whose evidence must be plural. Each names two claims that have never implied one
# another: a rule read inside the wire crate and the same rule read where the assembly could
# break it, or an acceptance and the control that proves the instrument could have seen it fail.
plural_evidence=('c-ing-0002' 'c-ing-0003' 'c-ing-0005' 'c-ing-0020')

# Editing this set is the only way a case becomes blocked, so a case cannot quietly stop being
# evidence-backed. Each id here must also carry an owning issue in the table above.
blocked_ids=('c-ing-0061' 'c-ing-0062' 'c-ing-0064')

# The same, for rows that prove part of a case. A partial row is checked as strictly as a bound
# one on the half it claims.
partial_ids=('c-ing-0008' 'c-ing-0063')

command -v python3 >/dev/null 2>&1 || {
    printf 'check_ingest_case_coverage: required command is missing: python3\n' >&2
    exit 1
}

python3 - "$ROOT" "${#cases[@]}" "$(printf '%s\n' "${plural_evidence[@]}")" "$(printf '%s\n' "${blocked_ids[@]}")" "$(printf '%s\n' "${partial_ids[@]}")" "${cases[@]}" <<'PYEOF'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
declared_total = int(sys.argv[2])
plural_evidence = set(sys.argv[3].split())
blocked_declared = set(sys.argv[4].split())
partial_declared = set(sys.argv[5].split())
rows = sys.argv[6:]

# §7 of rustfs/backlog#1691, transcribed once: ten positive ids, twenty-five negative ones, and
# the five concurrency ids the same section lists under its own heading.
EXPECTED_IDS = (
    [f"c-ing-{index:04d}" for index in range(1, 11)]
    + [f"c-ing-{index:04d}" for index in range(20, 45)]
    + [f"c-ing-{index:04d}" for index in range(60, 65)]
)
EXPECTED_POSITIVE = 10
EXPECTED_NEGATIVE = 30

# What a negative case in this family looks like in code. Two shapes, because §7 lists two: a
# refusal with a named reason, and a resource ceiling that holds while the body is accepted (the
# window rows say nothing about a refusal — they say a bound was not exceeded). Both are checked
# for; a body that neither refuses anything nor asserts a bound is not a negative case, and a
# positive row whose body names a refusal is a negative case that was relabelled. That pair is
# what makes a swapped polarity a red build rather than a rename.
REFUSAL_TOKENS = (
    "expect_err",
    "unwrap_err",
    "is_err",
    ".err()",
    "Err(",
    "ChunkReject",
    "ModeConfusion",
    "WireReject",
    "LimitKind",
    "HandlerCancellation::RequestAborted",
    "reject_of",
    "refuse(",
    "is_none()",
)
CEILING_PATTERN = re.compile(r"assert!\((?:[^;]){0,400}?(?:<=|<[^-=])", re.DOTALL)
ASSERTION_TOKENS = ("assert!", "assert_eq!", "assert_ne!", "assert_matches!")
TEST_ATTRIBUTES = ("#[test]", "#[tokio::test")

failures = []


def fail(message):
    failures.append(message)


# Compiled once, then matched with an offset. Cutting a fresh `source[index:]` slice copies the
# whole remainder of the file on every character, which makes an otherwise linear blanking pass
# quadratic in file length; `pattern.match(source, index)` matches at the same place without the
# copy. No pattern here carries `^`, `\A`, `\b` or a lookbehind, so anchoring at the offset is
# exactly what slicing to it already meant. Both `.end()` values are now absolute offsets into
# `source`.
RAW_STRING_RE = re.compile(r'(?:br|r|b|c)?(#{0,16})"')
CHAR_LITERAL_RE = re.compile(r"(?:b)?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^\\'\n])'")


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
        elif raw := RAW_STRING_RE.match(source, index):
            if raw.group(0).endswith('"'):
                hashes = raw.group(1)
                closing = '"' + hashes
                cursor = raw.end()
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
        elif char := CHAR_LITERAL_RE.match(source, index):
            end = char.end()
            out.extend(" " for _ in source[index:end])
            index = end
        else:
            out.append(source[index])
            index += 1
    return "".join(out)


def module_spans(code):
    """Every `mod <name> { .. }` in `code`, as (name, attributes, open, close)."""
    spans = []
    for match in re.finditer(r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", code):
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
            continue
        head = code[: match.start()]
        start = head.rfind("\n\n")
        attributes = head[start + 1 :] if start != -1 else head
        spans.append((match.group(1), attributes, opening, cursor))
    return spans


def enclosing_modules(code, offset):
    """The `mod` blocks containing `offset`, outermost first."""
    return [span for span in module_spans(code) if span[2] < offset < span[3]]


def function_span(code, name):
    """Returns (attributes, body, enclosing modules) for `fn name()`, or None.

    A function nested inside a module is accepted only when every module around it is a plain
    `#[cfg(test)] mod`. That is the one nesting a test may legitimately live in; any other
    `#[cfg(...)]` above it means the assertion may not be compiled at all, and an assertion that
    might not be compiled reads from a diff exactly like the one it replaced.
    """
    pattern = re.compile(rf"(?m)^[ \t]*(?:async\s+)?fn\s+{re.escape(name)}\s*\(\s*\)[^;{{]*\{{")
    match = next(iter(pattern.finditer(code)), None)
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
    head = code[: match.start()]
    attribute_start = head.rfind("\n\n")
    attributes = head[attribute_start + 1 :] if attribute_start != -1 else head
    return attributes, code[opening + 1 : cursor - 1], enclosing_modules(code, match.start())


def name_covers(function, identifier):
    """A row may point at its exact `c_ing_0030_` segment or a leading range."""
    number = int(identifier.rsplit("-", 1)[1])
    if re.search(rf"(?:^|_)c_ing_{number:04d}_", function):
        return True
    span = re.match(r"^c_ing_(\d{4})_to_(\d{4})_", function)
    return span is not None and int(span.group(1)) <= number <= int(span.group(2))


def check_owner(identifier, owner, reason, kind):
    if not re.fullmatch(r"rustfs/[a-z]+#\d+", owner):
        fail(f"{identifier} is {kind} without an owning issue: {owner!r}")
    if len(reason.strip()) < 40:
        fail(f"{identifier} is {kind} without a reason long enough to review: {reason!r}")


def check_evidence(identifier, polarity, evidence):
    entries = [entry for entry in evidence.split(";") if entry]
    if not entries:
        fail(f"{identifier} names no evidence at all")
        return
    if identifier in plural_evidence and len(entries) < 2:
        fail(f"{identifier} needs two independent claims and names {len(entries)}")
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
        code = strip_comments_and_literals(path.read_text())
        span = function_span(code, function)
        if span is None:
            fail(f"{identifier} names no `fn {function}` in {relative}")
            continue
        attributes, body, modules = span
        for name, module_attributes, _, _ in modules:
            cfgs = re.findall(r"#\[cfg\([^\]]*\)\]", module_attributes)
            if cfgs != ["#[cfg(test)]"]:
                fail(
                    f"{identifier} maps to `{function}` inside `mod {name}` in {relative}, "
                    f"whose attributes are {cfgs or 'absent'} rather than exactly `#[cfg(test)]`"
                )
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
        if polarity == "negative":
            refuses = any(token in body for token in REFUSAL_TOKENS)
            bounds = CEILING_PATTERN.search(body) is not None
            if not refuses and not bounds:
                fail(
                    f"{identifier} is negative but `{function}` in {relative} neither names a "
                    f"refusal nor asserts a ceiling"
                )
        if polarity == "positive":
            named = [token for token in REFUSAL_TOKENS if token in body]
            if named:
                fail(f"{identifier} is positive but `{function}` in {relative} asserts a refusal: {named}")


seen = []
polarity_count = {"positive": 0, "negative": 0}
blocked_seen = set()
partial_seen = set()

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
    expected_polarity = "positive" if int(identifier.rsplit("-", 1)[1]) <= 10 else "negative"
    if polarity != expected_polarity:
        fail(f"{identifier} is {expected_polarity} in §7 but the table calls it {polarity}")
        continue

    if status == "blocked":
        blocked_seen.add(identifier)
        if identifier not in blocked_declared:
            fail(f"{identifier} is blocked but is not in the reviewed blocked set")
            continue
        owner, _, reason = evidence.partition("::")
        check_owner(identifier, owner, reason, "blocked")
        # A blocked case with a test named after it is a case somebody finished and nobody
        # registered, which reads from the ledger exactly like one nobody started.
        number = int(identifier.rsplit("-", 1)[1])
        for candidate in sorted(root.glob("crates/*/tests/*.rs")) + sorted(root.glob("crates/*/src/**/*.rs")):
            if re.search(rf"\bfn\s+c_ing_{number:04d}_", candidate.read_text()):
                fail(f"{identifier} is blocked, but {candidate.relative_to(root)} already names a test for it")
        continue

    if status == "partial":
        partial_seen.add(identifier)
        if identifier not in partial_declared:
            fail(f"{identifier} is partial but is not in the reviewed partial set")
            continue
        bound, separator, deferred = evidence.partition("@@")
        if not separator:
            fail(f"{identifier} is partial without naming what is still unproved")
            continue
        owner, _, reason = deferred.partition("::")
        check_owner(identifier, owner, reason, "partial")
        check_evidence(identifier, polarity, bound)
        continue

    if status != "bound":
        fail(f"{identifier} declares an unknown status: {status}")
        continue
    if identifier in blocked_declared or identifier in partial_declared:
        fail(f"{identifier} is in the blocked or partial set but the table binds it outright")
        continue
    check_evidence(identifier, polarity, evidence)

missing = [identifier for identifier in EXPECTED_IDS if identifier not in seen]
if missing:
    fail(f"§7 ids with no row at all: {' '.join(missing)}")
unregistered = blocked_declared - blocked_seen
if unregistered:
    fail(f"the blocked set names ids the table does not block: {' '.join(sorted(unregistered))}")
unregistered = partial_declared - partial_seen
if unregistered:
    fail(f"the partial set names ids the table does not mark partial: {' '.join(sorted(unregistered))}")
if polarity_count["positive"] != EXPECTED_POSITIVE or polarity_count["negative"] != EXPECTED_NEGATIVE:
    fail(
        f"§7 is {EXPECTED_POSITIVE} positive and {EXPECTED_NEGATIVE} negative; the table is "
        f"{polarity_count['positive']} and {polarity_count['negative']}"
    )
if polarity_count["negative"] <= polarity_count["positive"]:
    fail("the negative cases must outnumber the positive ones")

if failures:
    for message in failures:
        print(f"check_ingest_case_coverage: {message}", file=sys.stderr)
    raise SystemExit(1)

bound = len(EXPECTED_IDS) - len(blocked_declared) - len(partial_declared)
print(
    f"OK: {bound} of {len(EXPECTED_IDS)} ingest ids map to executable evidence, "
    f"{len(partial_declared)} partial, {len(blocked_declared)} blocked"
)
PYEOF
