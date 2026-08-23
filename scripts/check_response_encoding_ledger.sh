#!/usr/bin/env bash
set -euo pipefail

# WHAT: Maps all 39 response-encoding acceptance ids in rustfs/backlog#1701 section 7 to
# executable evidence or to an explicit owning block.
# WHY: The requirements were implemented across later payload, committed-response, codec, and
# server slices. Counting files cannot prove that every original row still has a live assertion.
# HOW TO EXEMPT: There is no exemption. A row may be blocked only with an owning issue and reason.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# id|polarity|status|evidence
#
# Bound evidence entries are separated by semicolons:
#   path.rs::test fn name       enabled Rust test
#   path.rs::case fn name       executable payload-ledger case
#   path.toml::/pointer=value   parsed conformance assertion
#   path.sh::guard              deterministic guard, executed against ROOT
#   fixture.rs::trybuild harness.rs
#   rule::no_raw_response_writer
#
# The comments beside corrected rows are part of the reviewed decision in rustfs/backlog#1701:
# they stop this ledger from reviving requirements superseded by the later response design.
requirements=(
    'c-enc-0001|positive|bound|crates/gateway/tests/pipeline.rs::test fn a_not_modified_refusal_carries_neither_content_nor_a_framing_header'
    'c-enc-0002|positive|bound|crates/core/src/codec/tests.rs::test fn n_writes_no_body_on_the_delete_object_no_content_response'
    'c-enc-0003|positive|bound|crates/gateway/tests/pipeline.rs::test fn a_head_keeps_the_headers_a_get_would_have_carried'
    'c-enc-0004|positive|bound|crates/gateway/tests/middleware.rs::test fn a_response_filter_cannot_leave_a_content_length_that_overstates_the_body'
    'c-enc-0005|positive|bound|crates/gateway/tests/payload_transport.rs::test fn c_pay_0009_an_unknown_length_response_is_chunked_without_content_length'
    'c-enc-0006|positive|bound|conformance/cases/mpu/c-mpu-0015.toml::/expect/status=200;conformance/cases/mpu/c-mpu-0015.toml::/expect/body/xml/root=CompleteMultipartUploadResult;crates/gateway/tests/committed_head_runtime.rs::test fn a_frozen_operation_header_is_visible_before_committed_work_finishes;crates/gateway/tests/committed_progress.rs::test fn a_stalled_commit_writes_one_keepalive_byte_after_five_seconds'
    'c-enc-0007|positive|bound|conformance/cases/mpu/c-mpu-0001.toml::/expect/status=200;conformance/cases/mpu/c-mpu-0001.toml::/expect/error/code=InvalidPart;crates/gateway/tests/pipeline.rs::test fn a_committed_response_announces_neither_a_length_nor_a_trailer_section'
    'c-enc-0008|positive|bound|conformance/cases/copy/c-copy-0038.toml::/expect/status=200;conformance/cases/copy/c-copy-0038.toml::/expect/error/code=NoSuchKey;conformance/cases/copy/c-copy-0038.toml::/expect/headers_absent/3=trailer'
    'c-enc-0009|positive|bound|crates/gateway/src/render.rs::test fn a_precondition_failure_renders_its_condition_element;crates/core/src/codec/tests.rs::test fn writes_every_delete_objects_key_into_the_result'
    'c-enc-0010|positive|bound|crates/core/tests/response_override_safety.rs::test fn every_legal_override_still_reaches_its_header'
    'c-enc-0011|positive|bound|crates/stream/src/tests/pay_scale.rs::case fn c_pay_0008'

    # BodylessResponse was superseded by the single final invariant seam. The executable contract
    # is the runtime correction on every method/status path, not a second response type.
    'c-enc-0020|negative|bound|crates/gateway/src/invariants.rs::test fn a_bodyless_status_loses_its_framing_headers_too;crates/gateway/tests/patch_layer_landings.rs::test fn bodyless_status_fix_is_the_response_invariant'
    'c-enc-0021|negative|blocked|rustfs/backlog#1701::the final invariant removes a forbidden 204 body, but no response-correction metric records that backend defect yet'
    'c-enc-0022|negative|bound|crates/gateway/tests/pipeline.rs::test fn a_refusal_answered_to_a_head_carries_no_content_and_still_reports_the_length_it_would_have_sent'
    'c-enc-0023|negative|bound|crates/gateway/tests/pipeline.rs::test fn a_success_answered_to_a_head_carries_no_content_and_still_reports_a_length'
    'c-enc-0024|negative|blocked|rustfs/backlog#1701::a response filter can still construct a Content-Length plus Transfer-Encoding conflict without a typed EncodeError'
    # A blanket ETag-on-304 guard was rejected by the issue decision. This binds the conditional
    # rule: a representation whose 200 carries an ETag keeps that validator on its 304.
    'c-enc-0025|negative|bound|crates/gateway/tests/pipeline.rs::test fn a_not_modified_refusal_carries_neither_content_nor_a_framing_header'
    # Deferred responses never announce trailers, so an unsent declaration is unconstructible.
    'c-enc-0026|negative|bound|crates/gateway/tests/pipeline.rs::test fn a_committed_response_announces_neither_a_length_nor_a_trailer_section'
    'c-enc-0027|negative|bound|crates/core/tests/response_override_safety.rs::test fn n_response_content_disposition_refuses_a_value_a_header_cannot_hold'
    'c-enc-0028|negative|bound|crates/core/tests/response_override_safety.rs::test fn n_response_content_type_refuses_a_value_a_header_cannot_hold'
    'c-enc-0029|negative|bound|crates/core/tests/response_override_safety.rs::test fn n_response_cache_control_refuses_a_value_a_header_cannot_hold;crates/core/tests/response_override_safety.rs::test fn n_response_content_disposition_refuses_a_value_a_header_cannot_hold;crates/core/tests/response_override_safety.rs::test fn n_response_content_encoding_refuses_a_value_a_header_cannot_hold;crates/core/tests/response_override_safety.rs::test fn n_response_content_language_refuses_a_value_a_header_cannot_hold;crates/core/tests/response_override_safety.rs::test fn n_response_content_type_refuses_a_value_a_header_cannot_hold;crates/core/tests/response_override_safety.rs::test fn n_response_expires_refuses_a_value_a_header_cannot_hold'
    'c-enc-0030|negative|bound|scripts/check_no_response_header_unwrap.sh::guard'
    'c-enc-0031|negative|bound|rule::no_raw_response_writer'
    'c-enc-0032|negative|blocked|rustfs/backlog#1701::TemporaryRedirect accepts a validated public RedirectTarget, but no authority proves that its value came only from server configuration'
    'c-enc-0033|negative|bound|crates/core/src/codec/tests/metadata_and_url.rs::test fn metadata_encoded_words_are_decoded_for_storage_and_encoded_again_on_return;crates/core/src/codec/tests/metadata_and_url.rs::test fn nested_metadata_encoded_word_is_reencoded_before_it_reaches_a_client'
    'c-enc-0034|negative|bound|conformance/cases/list/c-list-0035.toml::/expect/body/contains_utf8/0~%01;conformance/cases/list/c-list-0035.toml::/expect/body/not_contains_utf8/0;crates/core/src/codec/tests/metadata_and_url.rs::test fn n_encodes_a_key_xml_cannot_carry_even_though_nothing_asked'
    'c-enc-0035|negative|bound|crates/core/tests/compile_fail/committed_unmarked_operation.rs::trybuild crates/core/tests/compile_fail.rs'
    # A committed panic now ends with an in-body InternalError under the spent status. Closing the
    # socket was the pre-commit design and would discard the only verdict channel left.
    'c-enc-0036|negative|bound|crates/gateway/tests/monomorphic.rs::test fn static_and_dynamic_committed_panics_keep_the_committed_status;crates/server/tests/server_runtime.rs::test fn a_srv_0020_panicking_handler_returns_500_and_server_survives'
    'c-enc-0037|negative|bound|crates/stream/src/tests/pay_cases.rs::case fn c_pay_0031;conformance/cases/mpu/c-mpu-0043.toml::/exchanges/0/expect/error/code=IncompleteBody;conformance/cases/mpu/c-mpu-0043.toml::/exchanges/1/expect/body/not_contains_utf8/0~PartNumber'
    # The fixed machine-specific count was replaced by a counting allocator comparing the same
    # real request path at two body sizes, with zero body-sized copies allowed.
    'c-enc-0038|negative|bound|crates/gateway/tests/request_allocations.rs::test fn a_requests_heap_does_not_grow_with_its_body'
    # The obsolete 96-byte ceiling was rejected. P1-06 boxed cold DTO state; the live GetObject
    # wrapper now has its own compile-time ceiling and 64-bit snapshot.
    'c-enc-0039|negative|bound|crates/core/tests/dto_cold_split.rs::test fn c_enc_0039_req_get_object_has_the_boxed_snapshot_and_stays_within_the_ceiling'
    'c-enc-0040|negative|bound|crates/stream/src/tests/pay_scale.rs::case fn c_pay_0008'
    'c-enc-0041|negative|bound|scripts/check_ci_time_gate.sh::guard'

    'c-enc-0060|negative|blocked|rustfs/backlog#1701::detached work survives body drop and RST, but no CompleteMultipartUpload zero-window test observes backend completion while the client never reads'
    'c-enc-0061|negative|bound|crates/gateway/tests/committed_progress.rs::test fn a_client_reset_after_the_committed_head_does_not_cancel_backend_work'
    'c-enc-0062|negative|bound|crates/gateway/src/commit.rs::test fn the_first_keepalive_waits_a_full_interval_and_ticks_once_per_interval'
    'c-enc-0063|negative|bound|crates/gateway/src/commit.rs::test fn the_first_keepalive_waits_a_full_interval_and_ticks_once_per_interval;crates/gateway/tests/committed_progress.rs::test fn the_default_bound_is_a_whole_number_of_keepalive_intervals'
    # The issue decision permits a smaller real transfer in the PR gate when a GiB cannot finish
    # inside the 30-second feedback contract. These are real zero-window and 1,000-reader probes.
    'c-enc-0064|negative|bound|crates/gateway/tests/payload_transport.rs::test fn c_pay_0063_a_zero_window_timeout_drops_the_response_producer_and_connection;crates/server/tests/server_load.rs::test fn c_lim_0061_a_srv_0026_one_thousand_slow_readers_close_without_starving_healthy_traffic'
    'c-enc-0065|negative|blocked|rustfs/backlog#1701::the five-second cadence is deterministic, but no 512-way committed-response probe bounds timer growth and CPU scaling yet'
)

command -v python3 >/dev/null 2>&1 || {
    printf 'check_response_encoding_ledger: required command is missing: python3\n' >&2
    exit 1
}

python3 - "$ROOT" "${requirements[@]}" <<'PYEOF'
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
rows = sys.argv[2:]
expected_ids = (
    [f"c-enc-{number:04d}" for number in range(1, 12)]
    + [f"c-enc-{number:04d}" for number in range(20, 42)]
    + [f"c-enc-{number:04d}" for number in range(60, 66)]
)
failures = []


def fail(message):
    failures.append(message)


def mask_rust(source):
    """Blank comments and literals while preserving newlines and token offsets."""
    out = list(source)
    index = 0

    def blank(start, end):
        for pos in range(start, min(end, len(out))):
            if out[pos] != "\n":
                out[pos] = " "

    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = len(source) if end < 0 else end
            blank(index, end)
            index = end
        elif source.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < len(source) and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            blank(index, end)
            index = end
        elif source[index] == '"':
            quote = source[index]
            end = index + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                elif source[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
            blank(index, end)
            index = end
        elif source[index] == "'" and (char := re.match(r"'(?:\\.|[^'\\\n])'", source[index:])):
            end = index + len(char.group(0))
            blank(index, end)
            index = end
        elif source[index] == "r" and (match := re.match(r'r(#{0,16})"', source[index:])):
            hashes = match.group(1)
            end_token = '"' + hashes
            end = source.find(end_token, index + len(match.group(0)))
            end = len(source) if end < 0 else end + len(end_token)
            blank(index, end)
            index = end
        else:
            index += 1
    return "".join(out)


def active_function(relative, selector, require_test):
    path = root / relative
    if not path.is_file():
        fail(f"{relative}: evidence file is missing")
        return
    name = selector.removeprefix("test fn ").removeprefix("case fn ")
    masked = mask_rust(path.read_text())
    if re.search(r"#!?\s*\[\s*cfg\s*\(\s*any\s*\(\s*\)\s*\)\s*\]", masked):
        fail(f"{relative}::{name}: mapped evidence is inside a cfg(any()) file, module, or item")
    pattern = re.compile(rf"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{re.escape(name)}\s*\(")
    matches = list(pattern.finditer(masked))
    if len(matches) != 1:
        fail(f"{relative}: expected one real fn {name}, found {len(matches)}")
        return
    prefix = masked[: matches[0].start()]
    attributes = re.search(r"((?:[ \t]*#\s*\[[^\]]*\]\s*)+)$", prefix, flags=re.S)
    attrs = attributes.group(1) if attributes else ""
    if re.search(r"#\s*\[\s*cfg\b", attrs):
        fail(f"{relative}::{name}: mapped evidence is cfg-gated")
    if require_test and not re.search(r"#\s*\[\s*(?:test|tokio::test\b)", attrs):
        fail(f"{relative}::{name}: mapped function is not an enabled test")
    if not require_test:
        ledger = root / "crates/stream/src/tests/pay_ledger.rs"
        if not ledger.is_file():
            fail(f"{relative}::{name}: payload ledger is missing")
        else:
            ledger_code = mask_rust(ledger.read_text())
            if len(re.findall(rf"\brun\s*:\s*pay_(?:scale|cases)::{re.escape(name)}\b", ledger_code)) != 1:
                fail(f"{relative}::{name}: payload ledger does not run this case exactly once")
            active_function(
                "crates/stream/src/tests/pay_ledger.rs",
                "test fn every_bound_row_runs_and_observes_what_it_declared",
                True,
            )


documents = {}


def load_toml(relative):
    if relative not in documents:
        path = root / relative
        try:
            documents[relative] = tomllib.loads(path.read_text())
        except (OSError, tomllib.TOMLDecodeError) as error:
            fail(f"{relative}: {error}")
            documents[relative] = None
    return documents[relative]


def resolve(document, pointer):
    current = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            return None
    return current


def check_toml(identifier, relative, selector):
    document = load_toml(relative)
    if document is None:
        return
    for separator in ("~", "="):
        pointer, found, literal = selector.partition(separator)
        if found:
            break
    else:
        pointer, separator, literal = selector, "", ""
    if not pointer.startswith("/"):
        fail(f"{identifier}: invalid TOML pointer {selector!r}")
        return
    value = resolve(document, pointer)
    if value is None:
        fail(f"{identifier}: {relative}{pointer} does not resolve")
    elif separator == "=" and str(value) != literal:
        fail(f"{identifier}: {relative}{pointer} is {value!r}, expected {literal!r}")
    elif separator == "~" and literal not in str(value):
        fail(f"{identifier}: {relative}{pointer} does not contain {literal!r}")
    elif separator == "" and value in ("", [], {}):
        fail(f"{identifier}: {relative}{pointer} resolves to empty evidence")


def check_trybuild(identifier, fixture, selector):
    harness = selector.removeprefix("trybuild ")
    if not (root / fixture).is_file():
        fail(f"{identifier}: trybuild fixture is missing: {fixture}")
        return
    active_function(harness, "test fn compile_time_contracts_are_not_openable", True)
    source = (root / harness).read_text()
    lines = [line for line in source.splitlines() if not line.lstrip().startswith("//")]
    call = '    cases.compile_fail("tests/compile_fail/committed_*.rs");'
    if lines.count(call) != 1:
        fail(f"{identifier}: {harness} does not execute committed_*.rs exactly once")


def check_guard(identifier, relative):
    path = root / relative
    if not path.is_file() or not os.access(path, os.X_OK):
        fail(f"{identifier}: guard is missing or not executable: {relative}")
        return
    environment = os.environ.copy()
    environment["GATEWAY_CHECK_ROOT"] = str(root)
    result = subprocess.run(["bash", str(path)], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        fail(f"{identifier}: {relative} failed: {result.stderr.strip()}")


def check_no_raw_response_writer(identifier):
    forbidden = re.compile(r"\bpub\s+(?:struct\s+ResponseWriter\b|(?:async\s+)?fn\s+(?:write_raw|write_bytes)\s*\()")
    for base in (root / "crates/core/src", root / "crates/gateway/src"):
        if not base.is_dir():
            fail(f"{identifier}: required source root is missing: {base.relative_to(root)}")
            continue
        for path in base.rglob("*.rs"):
            relative = path.relative_to(root)
            if "generated" in relative.parts:
                continue
            try:
                masked = mask_rust(path.read_text())
            except OSError as error:
                fail(f"{identifier}: cannot read {relative}: {error}")
                continue
            if forbidden.search(masked):
                fail(f"{identifier}: raw response-writer API is public in {relative}")


parsed = {}
for row in rows:
    parts = row.split("|", 3)
    if len(parts) != 4:
        fail(f"row is not id|polarity|status|evidence: {row}")
        continue
    identifier, polarity, status, evidence = parts
    if identifier in parsed:
        fail(f"duplicate acceptance id: {identifier}")
        continue
    if polarity not in ("positive", "negative"):
        fail(f"{identifier}: invalid polarity {polarity!r}")
    if status not in ("bound", "blocked"):
        fail(f"{identifier}: invalid status {status!r}")
    parsed[identifier] = (polarity, status, evidence)

for identifier in expected_ids:
    if identifier not in parsed:
        fail(f"section 7 acceptance id has no ledger row: {identifier}")
for identifier in parsed:
    if identifier not in expected_ids:
        fail(f"ledger row names an unknown acceptance id: {identifier}")

positive = sum(polarity == "positive" for polarity, _, _ in parsed.values())
negative = sum(polarity == "negative" for polarity, _, _ in parsed.values())
if (positive, negative) != (11, 28):
    fail(f"section 7 is 11 positive and 28 negative; ledger reads {positive}/{negative}")

owner = re.compile(r"^rustfs/(?:backlog|gateway)#[0-9]+$")
for identifier in expected_ids:
    if identifier not in parsed:
        continue
    _, status, evidence = parsed[identifier]
    if status == "blocked":
        issue, separator, reason = evidence.partition("::")
        if not separator or not owner.fullmatch(issue) or len(reason) < 40:
            fail(f"{identifier}: blocked evidence must be <owner issue>::<specific reason>")
        continue
    entries = [entry for entry in evidence.split(";") if entry]
    if not entries:
        fail(f"{identifier}: bound row has no evidence")
        continue
    for entry in entries:
        relative, separator, selector = entry.partition("::")
        if not separator:
            fail(f"{identifier}: invalid evidence entry {entry!r}")
        elif relative == "rule" and selector == "no_raw_response_writer":
            check_no_raw_response_writer(identifier)
        elif relative.endswith(".toml"):
            check_toml(identifier, relative, selector)
        elif relative.endswith(".sh") and selector == "guard":
            check_guard(identifier, relative)
        elif relative.endswith(".rs") and selector.startswith("test fn "):
            active_function(relative, selector, True)
        elif relative.endswith(".rs") and selector.startswith("case fn "):
            active_function(relative, selector, False)
        elif relative.endswith(".rs") and selector.startswith("trybuild "):
            check_trybuild(identifier, relative, selector)
        else:
            fail(f"{identifier}: unsupported evidence entry {entry!r}")

if failures:
    for message in failures:
        print(f"check_response_encoding_ledger: {message}", file=sys.stderr)
    raise SystemExit(1)

bound = sum(status == "bound" for _, status, _ in parsed.values())
blocked = len(parsed) - bound
print(f"OK: {len(parsed)} response-encoding ids — {bound} bound, {blocked} blocked with owners")
PYEOF
