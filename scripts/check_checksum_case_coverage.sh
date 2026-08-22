#!/usr/bin/env bash
set -euo pipefail

# WHAT: Binds all 38 P3-04 c-ck ids to enabled assertions, a mutation-tested guard, a trybuild
# contract, or the live range conformance case.
# WHY: Counting tests cannot detect a case nobody wrote, and a path or comment is not executable
# evidence. This ledger verifies the exact function and rejects ignored, cfg-gated, or assertionless
# bindings.
# HOW TO EXEMPT: There is no exemption. A row changes only by naming replacement evidence that the
# checker can execute or inspect as an active assertion.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# id|polarity|evidence; evidence entries are separated by semicolons.
# test:<path>::<function>
# case:<case path>::<runner path>::<runner function>
# guard:<guard path>::<mutation case label>
# trybuild:<runner path>::<runner function>::<fixture path>
cases=(
    'c-ck-0001|positive|test:crates/http/tests/checksum_arbitration.rs::c_ck_0001_a_matching_checksum_header_verifies_and_reports_what_it_verified'
    'c-ck-0002|positive|test:crates/http/tests/checksum_arbitration.rs::c_ck_0002_a_matching_unsigned_trailer_checksum_verifies_only_at_eof;test:crates/gateway/src/request_body_tests.rs::c_ck_0002_the_streaming_production_path_accepts_a_matching_unsigned_trailer_checksum'
    'c-ck-0003|positive|test:crates/gateway/src/chunked_trailer_tests.rs::c_ck_0003_a_signed_trailer_unlocks_commit_only_after_its_final_hmac;test:crates/gateway/src/request_body_tests.rs::c_ck_0003_the_streaming_production_path_accepts_a_signed_trailer_hmac'
    'c-ck-0004|positive|test:crates/http/tests/checksum_arbitration.rs::c_ck_0004_a_crc64nvme_header_is_verified_and_reported;test:crates/types/src/scalar/tests/checksum_tests.rs::c_cks_0003_crc64nvme_matches_the_published_check_value'
    'c-ck-0005|positive|test:crates/types/src/scalar/tests/checksum_tests.rs::c_cks_0004_part_crcs_combine_into_the_whole;test:crates/types/src/scalar/tests/checksum_tests.rs::a_composite_checksum_carries_its_part_count'
    'c-ck-0006|positive|test:crates/http/tests/checksum_arbitration.rs::c_ck_0006_a_matching_content_md5_verifies_on_its_own'
    'c-ck-0007|positive|test:crates/http/tests/checksum_arbitration.rs::c_ck_0007_a_request_carrying_both_claims_has_both_of_them_checked'
    'c-ck-0008|positive|test:crates/gateway/tests/object_lock_intent.rs::the_capitalised_bypass_spelling_reaches_the_handler_as_true'
    'c-ck-0009|positive|case:conformance/cases/range/c-range-0016.toml::crates/conformance/tests/range_cond_family.rs::the_range_family_runs_green_with_the_blocked_case_recovered'
    'c-ck-0010|positive|test:crates/http/tests/checksum_arbitration.rs::a_split_feed_digests_what_one_feed_digests_and_is_counted_once;test:crates/http/tests/ingest_perf_gates.rs::c_ing_0005_four_observers_and_the_signer_each_see_the_body_exactly_once;test:crates/http/tests/ingest_perf_gates.rs::c_ing_0008_observers_are_called_at_chunk_granularity'
    'c-ck-0020|negative|trybuild:crates/gateway/tests/compile_fail.rs::gateway_compile_fail_contracts_are_enforced::crates/gateway/tests/compile_fail/c_ck_0020_read_trailer_before_eof.rs'
    'c-ck-0021|negative|guard:scripts/check_no_trailer_mutex.sh::the P3-04 trailer mutex alias rejecting a shared slot'
    'c-ck-0022|negative|test:crates/http/tests/ingest_verify.rs::c_ck_0022_to_0025_control_fields_are_not_allowed_trailers'
    'c-ck-0023|negative|test:crates/http/tests/ingest_verify.rs::c_ck_0022_to_0025_control_fields_are_not_allowed_trailers'
    'c-ck-0024|negative|test:crates/http/tests/ingest_verify.rs::c_ck_0022_to_0025_control_fields_are_not_allowed_trailers'
    'c-ck-0025|negative|test:crates/http/tests/ingest_verify.rs::c_ck_0022_to_0025_control_fields_are_not_allowed_trailers'
    'c-ck-0026|negative|test:crates/http/tests/ingest_verify.rs::c_ck_0026_three_actual_trailers_are_refused'
    'c-ck-0027|negative|test:crates/http/tests/ingest_verify.rs::c_ck_0027_a_trailer_section_over_one_kibibyte_is_refused'
    'c-ck-0028|negative|test:crates/http/tests/ingest_verify.rs::c_ck_0028_the_actual_trailer_name_must_equal_the_declaration'
    'c-ck-0029|negative|test:crates/http/tests/ingest_verify.rs::c_ck_0029_every_declared_trailer_must_arrive'
    'c-ck-0030|negative|test:crates/http/tests/ingest_chunk_rules.rs::c_ing_0033_bytes_after_the_terminal_chunk_are_refused'
    'c-ck-0031|negative|test:crates/gateway/src/chunked_trailer_tests.rs::c_ck_0031_a_missing_signed_trailer_hmac_is_forbidden'
    'c-ck-0032|negative|test:crates/gateway/src/chunked_trailer_tests.rs::c_ck_0032_the_trailer_hmac_is_seeded_by_the_zero_chunk_signature'
    'c-ck-0033|negative|test:crates/http/tests/ingest_framing.rs::signatures_or_trailers_without_framing_are_refused'
    'c-ck-0034|negative|test:crates/http/tests/checksum_arbitration.rs::c_ck_0034_two_different_checksum_headers_are_refused_before_any_body_byte'
    'c-ck-0035|negative|test:crates/http/tests/checksum_arbitration.rs::c_ck_0035_a_header_checksum_and_a_trailer_checksum_are_refused_together'
    'c-ck-0036|negative|test:crates/http/tests/checksum_arbitration.rs::c_ck_0036_a_declared_algorithm_that_no_value_header_carries_is_refused'
    'c-ck-0037|negative|test:crates/http/tests/checksum_arbitration.rs::c_ck_0037_a_checksum_value_that_is_not_strict_base64_is_refused_and_not_skipped'
    'c-ck-0038|negative|test:crates/http/tests/checksum_arbitration.rs::c_ck_0038_a_content_md5_that_disagrees_with_the_body_is_a_bad_digest'
    'c-ck-0039|negative|test:crates/http/tests/checksum_arbitration.rs::c_ck_0039_a_checksum_that_disagrees_with_the_body_is_a_checksum_mismatch;test:crates/gateway/src/request_body_tests.rs::c_ck_0039_the_streaming_production_path_refuses_a_mismatched_unsigned_trailer_checksum'
    'c-ck-0040|negative|test:crates/http/tests/checksum_arbitration.rs::c_ck_0040_a_correct_content_md5_does_not_excuse_a_wrong_checksum'
    'c-ck-0041|negative|test:crates/gateway/src/request_body_tests.rs::c_ck_0041_a_matching_checksum_never_substitutes_for_the_payload_hash'
    'c-ck-0042|negative|case:conformance/cases/range/c-range-0016.toml::crates/conformance/tests/range_cond_family.rs::the_range_family_runs_green_with_the_blocked_case_recovered'
    'c-ck-0043|negative|test:crates/http/tests/ingest_verify.rs::c_ck_0043_truncation_before_the_trailer_terminator_is_an_error'
    'c-ck-0060|negative|test:crates/gateway/tests/connection_teardown.rs::c_wire_0060_c_ing_0060_c_lim_0060_a_client_reset_cancels_the_handler_rolls_back_and_releases_its_permit;test:crates/http/tests/ingest_verify.rs::c_ck_0043_truncation_before_the_trailer_terminator_is_an_error'
    'c-ck-0061|negative|test:crates/gateway/tests/streaming_request.rs::c_ing_0061_body_idle_cancels_a_live_handler_and_closes_the_socket;test:crates/gateway/tests/throughput_request.rs::c_ing_0062_concurrent_slow_uploads_bound_rss_and_healthy_p99'
    'c-ck-0062|negative|test:crates/gateway/src/request_body_tests.rs::c_ck_0062_dropping_an_unread_streaming_body_refuses_commit'
    'c-ck-0063|negative|guard:scripts/check_no_trailer_mutex.sh::the P3-04 trailer mutex alias rejecting a shared slot;test:crates/gateway/tests/streaming_request.rs::c_ing_0063_concurrent_large_live_uploads_keep_bounded_resident_ownership;test:crates/gateway/tests/throughput_request.rs::c_ing_0062_concurrent_slow_uploads_bound_rss_and_healthy_p99'
)

plural_ids=(c-ck-0002 c-ck-0003 c-ck-0004 c-ck-0005 c-ck-0010 c-ck-0039 c-ck-0060 c-ck-0061 c-ck-0063)

command -v python3 >/dev/null 2>&1 || {
    printf 'check_checksum_case_coverage: required command is missing: python3\n' >&2
    exit 1
}

python3 - "$ROOT" "${#cases[@]}" "$(printf '%s\n' "${plural_ids[@]}")" "${cases[@]}" <<'PYEOF'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
declared_total = int(sys.argv[2])
plural_ids = set(sys.argv[3].split())
rows = sys.argv[4:]

EXPECTED_IDS = (
    [f"c-ck-{number:04d}" for number in range(1, 11)]
    + [f"c-ck-{number:04d}" for number in range(20, 44)]
    + [f"c-ck-{number:04d}" for number in range(60, 64)]
)
ASSERTIONS = ("assert!", "assert_eq!", "assert_ne!", "assert_matches!")
TEST_ATTRIBUTES = ("#[test]", "#[tokio::test")
failures = []


def fail(message):
    failures.append(message)


RAW_STRING_RE = re.compile(r'(?:br|r|b|c)?(#{0,16})"')
CHAR_LITERAL_RE = re.compile(r"(?:b)?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^\\'\n])'")


def strip_comments_and_literals(source):
    out = []
    index = 0
    depth = 0
    while index < len(source):
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
            while index < len(source) and source[index] != "\n":
                out.append(" ")
                index += 1
        elif source.startswith("/*", index):
            depth = 1
            out.append("  ")
            index += 2
        elif raw := RAW_STRING_RE.match(source, index):
            hashes = raw.group(1)
            closing = '"' + hashes
            cursor = raw.end()
            if hashes:
                end = source.find(closing, cursor)
                end = len(source) if end == -1 else end + len(closing)
            else:
                end = cursor
                while end < len(source):
                    if source[end] == "\\":
                        end += 2
                    elif source[end] == '"':
                        end += 1
                        break
                    else:
                        end += 1
            out.extend("\n" if character == "\n" else " " for character in source[index:end])
            index = end
        elif char := CHAR_LITERAL_RE.match(source, index):
            out.extend(" " for _ in source[index:char.end()])
            index = char.end()
        else:
            out.append(source[index])
            index += 1
    return "".join(out)


def function_span(source, name):
    code = strip_comments_and_literals(source)
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
    head = code[:match.start()]
    start = head.rfind("\n\n")
    attributes = head[start + 2:] if start != -1 else head
    return attributes, code[opening + 1:cursor - 1], source[opening + 1:cursor - 1]


def live_test(identifier, relative, function, require_assertion=True):
    path = root / relative
    if not path.is_file():
        fail(f"{identifier} names a missing test file: {relative}")
        return None
    span = function_span(path.read_text(), function)
    if span is None:
        fail(f"{identifier} names no live fn {function} in {relative}")
        return None
    attributes, body, raw_body = span
    if not any(attribute in attributes for attribute in TEST_ATTRIBUTES):
        fail(f"{identifier} maps to {function}, which is not a test")
    if "#[ignore" in attributes or "#[cfg" in attributes or "#[cfg" in body:
        fail(f"{identifier} maps to {function}, which is ignored or conditionally compiled")
    if require_assertion and not any(token in body for token in ASSERTIONS):
        fail(f"{identifier} maps to {function}, whose live body asserts nothing")
    return raw_body


def check_test(identifier, fields):
    if len(fields) != 2:
        fail(f"{identifier} has malformed test evidence: {'::'.join(fields)}")
        return
    live_test(identifier, fields[0], fields[1])


def check_case(identifier, fields):
    if len(fields) != 3:
        fail(f"{identifier} has malformed conformance evidence: {'::'.join(fields)}")
        return
    case_path, runner_path, runner = fields
    path = root / case_path
    if not path.is_file():
        fail(f"{identifier} names a missing conformance case: {case_path}")
        return
    text = path.read_text()
    required = ('id = "c-range-0016"', "headers_absent", '"x-amz-checksum-crc32" = "*"')
    for token in required:
        if token not in text:
            fail(f"{identifier} conformance backlink lost {token!r}")
    live_test(identifier, runner_path, runner)


def check_guard(identifier, fields):
    if len(fields) != 2:
        fail(f"{identifier} has malformed guard evidence: {'::'.join(fields)}")
        return
    guard_path, label = fields
    path = root / guard_path
    if not path.is_file():
        fail(f"{identifier} names a missing guard: {guard_path}")
        return
    suite_path = root / "scripts/test_guard_scripts.sh"
    if not suite_path.is_file():
        fail(f"{identifier} cannot read the guard mutation suite")
        return
    suite = "\n".join(line for line in suite_path.read_text().splitlines() if not line.lstrip().startswith("#"))
    pattern = re.compile(rf"expect_fail\s+{re.escape(path.name)}\s+\\\s*\n\s*'{re.escape(label)}'")
    if not pattern.search(suite):
        fail(f"{identifier} names guard mutation {label!r}, but it is not a live expect_fail case")


def check_trybuild(identifier, fields):
    if len(fields) != 3:
        fail(f"{identifier} has malformed trybuild evidence: {'::'.join(fields)}")
        return
    runner_path, runner, fixture_path = fields
    raw_body = live_test(identifier, runner_path, runner, require_assertion=False)
    fixture = root / fixture_path
    stderr = fixture.with_suffix(".stderr")
    if not fixture.is_file() or not stderr.is_file():
        fail(f"{identifier} trybuild fixture or stderr is missing: {fixture_path}")
        return
    if raw_body is None or 'compile_fail("tests/compile_fail/c_ck_0020_*.rs")' not in raw_body:
        fail(f"{identifier} trybuild runner no longer compiles the c-ck-0020 fixture")
    source = strip_comments_and_literals(fixture.read_text())
    if "progress.trailers()" not in source:
        fail(f"{identifier} fixture no longer attempts the forbidden early trailer read")
    if "no method named `trailers`" not in stderr.read_text():
        fail(f"{identifier} stderr no longer proves the early read is unavailable")


checkers = {"test": check_test, "case": check_case, "guard": check_guard, "trybuild": check_trybuild}
seen = []
positive = 0
negative = 0

if declared_total != len(EXPECTED_IDS):
    fail(f"the table declares {declared_total} rows against 38 ids")

for position, row in enumerate(rows):
    parts = row.split("|", 2)
    if len(parts) != 3:
        fail(f"row {position + 1} is not id|polarity|evidence")
        continue
    identifier, polarity, evidence = parts
    if position >= len(EXPECTED_IDS) or identifier != EXPECTED_IDS[position]:
        expected = EXPECTED_IDS[position] if position < len(EXPECTED_IDS) else "end of ledger"
        fail(f"row {position + 1} expected {expected}, found {identifier}")
        continue
    if identifier in seen:
        fail(f"{identifier} appears more than once")
    seen.append(identifier)
    expected_polarity = "positive" if position < 10 else "negative"
    if polarity != expected_polarity:
        fail(f"{identifier} must be {expected_polarity}, not {polarity}")
    positive += polarity == "positive"
    negative += polarity == "negative"
    entries = [entry for entry in evidence.split(";") if entry]
    if not entries:
        fail(f"{identifier} names no evidence")
        continue
    if identifier in plural_ids and len(entries) < 2:
        fail(f"{identifier} requires plural evidence and names only {len(entries)} binding(s)")
    for entry in entries:
        kind, separator, rest = entry.partition(":")
        if not separator or kind not in checkers:
            fail(f"{identifier} has unknown evidence kind: {entry}")
            continue
        checkers[kind](identifier, rest.split("::"))

missing = [identifier for identifier in EXPECTED_IDS if identifier not in seen]
if missing:
    fail(f"ids with no row: {' '.join(missing)}")
if positive != 10 or negative != 28:
    fail(f"the ledger must be 10 positive and 28 negative, found {positive} and {negative}")
if negative <= positive:
    fail("negative cases must outnumber positive cases")

if failures:
    for message in failures:
        print(f"check_checksum_case_coverage: {message}", file=sys.stderr)
    raise SystemExit(1)

print("OK: all 38 P3-04 checksum/trailer ids map to active evidence (10 positive, 28 negative)")
PYEOF
