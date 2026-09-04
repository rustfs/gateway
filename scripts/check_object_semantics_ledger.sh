#!/usr/bin/env bash
set -euo pipefail

# WHAT: Maps every one of the 62 object data-plane acceptance ids in rustfs/backlog#1680 §7 to a
# named assertion inside a real conformance case or Rust test, or to an explicitly declared block
# with the issue that owns it.
# WHY: §7 is a list of protocol rules, and a green `object/` run proves that the cases in the corpus
# pass — not that each of those 62 rules still has one. Two prior audits of that issue disagreed
# about which rules were covered because each counted case *files* rather than assertions, and the
# corpus deliberately folds several rules into one case.
# HOW TO EXEMPT: There is no exemption. A row moves out of `blocked` only by naming an assertion
# that resolves, and moves into it only by editing the ledger below, which is reviewed.
#
# Three mutations this ledger is built to die on, each named in the pull request that added it:
#   1. delete a mapping   — the id roll call below stops seeing 62 ids exactly once.
#   2. delete an assertion — the pointer into the case no longer resolves, or resolves to something
#                            other than the literal recorded here.
#   3. flip a polarity     — either the §7 polarity recorded on a row (the 24/38 split stops
#                            adding up) or the `polarity` a case declares (the case polarity table
#                            below stops matching the files).

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# id|polarity|status|evidence
#
# `bound`   — evidence is one or more `<path>::<selector>` entries separated by `;`.
#             A `.toml` selector is `<json pointer>`, `<pointer>=<literal>` or `<pointer>~<substring>`,
#             resolved against the parsed case document. A `.rs` selector is `fn <name>`.
# `blocked` — evidence is `<owner issue>::<why it is not an assertion yet>`; naming a path is refused.
#
# The polarity column is §7's own, per rule. It is not the polarity of the case that carries the
# assertion: one case answers several rules and the corpus labels a case by its input, not by each
# rule it happens to settle. The case labels are pinned separately, below.
requirements=(
    'c-obj-0001|positive|bound|conformance/cases/object/c-object-0018.toml::/exchanges/1/expect/headers_present/content-encoding=gzip'
    'c-obj-0002|positive|bound|conformance/cases/object/c-object-0018.toml::/exchanges/1/expect/headers_present/content-disposition~filename="report.txt";conformance/cases/object/c-object-0006.toml::/exchanges/1/expect/headers_present/cache-control=max-age=60;conformance/cases/object/c-object-0006.toml::/exchanges/1/expect/headers_present/content-language=en-GB'
    'c-obj-0003|positive|bound|conformance/cases/object/c-object-0006.toml::/exchanges/1/expect/headers_present/expires=not-a-date-at-all'
    'c-obj-0004|positive|bound|conformance/cases/object/c-object-0005.toml::/expect/headers_present/content-disposition~filename="report.txt"'
    'c-obj-0005|positive|bound|conformance/cases/object/c-object-0019.toml::/expect/headers_present/content-language=fr-CA;conformance/cases/object/c-object-0019.toml::/expect/headers_present/content-encoding=identity;conformance/cases/object/c-object-0019.toml::/expect/headers_present/expires=Thu, 01 Jan 1970 00:00:00 GMT'
    'c-obj-0006|positive|bound|conformance/cases/object/c-object-0017.toml::/exchanges/1/expect/headers_present/content-type=binary/octet-stream'
    'c-obj-0007|negative|bound|conformance/cases/object/c-object-0012.toml::/exchanges/0/expect/headers_absent/0=x-amz-storage-class'
    'c-obj-0008|positive|bound|conformance/cases/mpu/c-mpu-0007.toml::/exchanges/3/expect/headers_present/x-amz-storage-class=GLACIER'
    'c-obj-0009|positive|bound|conformance/cases/object/c-object-0041.toml::/exchanges/0/expect/headers_present/etag="5eb63bbbe01eeed093cb22bb8f5acdc3";conformance/cases/object/c-object-0041.toml::/exchanges/0/expect/headers_present/x-amz-checksum-crc32c=yZRlqg==;conformance/cases/object/c-object-0041.toml::/exchanges/1/expect/headers_present/etag="5eb63bbbe01eeed093cb22bb8f5acdc3";conformance/cases/object/c-object-0041.toml::/exchanges/1/expect/headers_present/x-amz-checksum-crc32c=yZRlqg=='
    'c-obj-0010|positive|bound|conformance/cases/object/c-object-0002.toml::/exchanges/0/expect/headers_present/content-length=11;conformance/cases/object/c-object-0002.toml::/exchanges/1/expect/headers_present/content-length=11'
    'c-obj-0011|positive|bound|conformance/cases/object/c-object-0040.toml::/exchanges/1/expect/headers_present/x-amz-meta-caption==?UTF-8?B?5Lit5paH?='
    'c-obj-0012|positive|bound|conformance/cases/object/c-object-0040.toml::/exchanges/0/request/headers/x-amz-meta-caption==?UTF-8?B?5Lit?=   =?UTF-8?B?5paH?=;conformance/cases/object/c-object-0040.toml::/exchanges/1/expect/headers_present/x-amz-meta-caption==?UTF-8?B?5Lit5paH?='
    'c-obj-0013|positive|bound|conformance/cases/object/c-object-0028.toml::/exchanges/1/expect/header_name_bytes_exact=True;conformance/cases/object/c-object-0028.toml::/exchanges/1/expect/headers_present/x-amz-meta-mixedcase=kept'
    'c-obj-0014|positive|bound|conformance/cases/object/c-object-0001.toml::/expect/headers_present/content-length=11'
    'c-obj-0015|positive|bound|crates/gateway/tests/payload_transport.rs::fn c_pay_0009_an_unknown_length_response_is_chunked_without_content_length'
    'c-obj-0016|positive|bound|conformance/cases/object/c-object-0036.toml::/exchanges/0/expect/status=204;conformance/cases/object/c-object-0036.toml::/exchanges/0/expect/headers_present/x-amz-delete-marker=true'
    'c-obj-0017|positive|bound|conformance/cases/object/c-object-0045.toml::/request/target=/conf-object-null-version/versioned/read.txt?versionId=null;conformance/cases/object/c-object-0045.toml::/expect/status=404;conformance/cases/object/c-object-0045.toml::/expect/error/code=NoSuchVersion'
    'c-obj-0018|positive|bound|conformance/cases/tagging/c-tagging-0019.toml::/exchanges/1/expect/headers_present/x-amz-tagging-count=2'
    'c-obj-0019|positive|bound|conformance/cases/object/c-object-0004.toml::/expect/body/exact_utf8~<Deleted><Key>batch/two</Key></Deleted>'
    'c-obj-0020|positive|bound|conformance/cases/object/c-object-0024.toml::/expect/body/exact_utf8~<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></DeleteResult>'
    'c-obj-0021|positive|bound|conformance/cases/object/c-object-0041.toml::/exchanges/0/expect/headers_present/x-amz-checksum-crc32c=yZRlqg==;conformance/cases/object/c-object-0041.toml::/exchanges/1/expect/headers_present/x-amz-checksum-crc32c=yZRlqg==;conformance/cases/object/c-object-0041.toml::/exchanges/2/expect/headers_present/x-amz-checksum-crc32c=yZRlqg=='
    'c-obj-0022|positive|bound|conformance/cases/object/c-object-0042.toml::/exchanges/0/expect/headers_present/x-amz-checksum-crc64nvme=jSnVw/bqjr4=;conformance/cases/object/c-object-0042.toml::/exchanges/1/expect/headers_present/x-amz-checksum-crc64nvme=jSnVw/bqjr4='
    'c-obj-0023|positive|bound|conformance/cases/naming/c-naming-0001.toml::/expect/body/exact_utf8=the empty segment survived'
    'c-obj-0024|positive|bound|conformance/cases/naming/c-naming-0025.toml::/exchanges/1/expect/body/exact_utf8=stored in the folded slot'
    'c-obj-0025|negative|bound|crates/http/tests/header_and_query.rs::fn c_wire_0006_an_empty_header_value_is_accepted'
    'c-obj-0026|negative|bound|crates/http/tests/header_and_query.rs::fn c_wire_0005_an_unrelated_non_utf8_header_is_ignored_not_fatal'
    'c-obj-0027|negative|bound|conformance/cases/object/c-object-0027.toml::/exchanges/0/expect/headers_present/etag="5eb63bbbe01eeed093cb22bb8f5acdc3"'
    'c-obj-0028|negative|bound|conformance/cases/object/c-object-0027.toml::/exchanges/1/expect/headers_present/etag="5eb63bbbe01eeed093cb22bb8f5acdc3"'
    'c-obj-0029|negative|bound|conformance/cases/object/c-object-0007.toml::/expect/error/code=NoSuchKey'
    'c-obj-0030|negative|bound|conformance/cases/object/c-object-0025.toml::/exchanges/0/expect/error/code=NoSuchBucket'
    'c-obj-0031|negative|bound|conformance/cases/object/c-object-0003.toml::/expect/status=204'
    'c-obj-0032|negative|bound|conformance/cases/object/c-object-0025.toml::/exchanges/1/expect/error/code=NoSuchBucket'
    'c-obj-0033|negative|bound|conformance/cases/object/c-object-0004.toml::/expect/body/exact_utf8~<Deleted><Key>batch/absent</Key></Deleted>'
    'c-obj-0034|negative|bound|conformance/cases/object/c-object-0011.toml::/expect/body/exact_utf8~<Error><Key>batch/retained</Key>'
    'c-obj-0035|negative|bound|conformance/cases/object/c-object-0010.toml::/expect/body/contains_utf8/1=Content-MD5'
    'c-obj-0036|negative|bound|conformance/cases/object/c-object-0026.toml::/exchanges/0/expect/error/code=InvalidDigest'
    'c-obj-0037|negative|bound|conformance/cases/object/c-object-0026.toml::/exchanges/1/expect/error/code=BadDigest'
    'c-obj-0038|negative|bound|conformance/cases/object/c-object-0013.toml::/expect/error/code=InvalidRequest'
    'c-obj-0039|negative|bound|conformance/cases/object/c-object-0044.toml::/request/headers/x-amz-sdk-checksum-algorithm=CRC32;conformance/cases/object/c-object-0044.toml::/expect/error/code=InvalidRequest;conformance/cases/object/c-object-0044.toml::/expect/request_progress/body_fully_sent=False'
    'c-obj-0040|negative|bound|conformance/cases/object/c-object-0043.toml::/exchanges/0/expect/error/code=XAmzContentChecksumMismatch'
    'c-obj-0041|negative|bound|conformance/cases/object/c-object-0043.toml::/exchanges/0/expect/error/code=XAmzContentChecksumMismatch;conformance/cases/object/c-object-0043.toml::/exchanges/1/expect/error/code=BadDigest'
    'c-obj-0042|negative|bound|conformance/cases/object/c-object-0030.toml::/expect/status=411;conformance/cases/object/c-object-0030.toml::/expect/error/code=MissingContentLength;conformance/cases/object/c-object-0030.toml::/expect/connection_after=closed'
    'c-obj-0043|negative|bound|conformance/cases/object/c-object-0054.toml::/exchanges/0/request/headers/content-length=1048576;conformance/cases/object/c-object-0054.toml::/exchanges/0/request/chunks/0/raw_utf8~only a few bytes;conformance/cases/object/c-object-0054.toml::/exchanges/0/request/chunks/1/action=half_close;conformance/cases/object/c-object-0054.toml::/exchanges/0/expect/status=400;conformance/cases/object/c-object-0054.toml::/exchanges/0/expect/headers_absent/0=etag;conformance/cases/object/c-object-0054.toml::/exchanges/0/expect/error/code=IncompleteBody;conformance/cases/object/c-object-0054.toml::/exchanges/1/expect/status=404;conformance/cases/object/c-object-0054.toml::/exchanges/1/expect/error/code=NoSuchKey'
    'c-obj-0044|negative|bound|conformance/cases/object/c-object-0056.toml::/exchanges/0/request/headers/content-length=57;conformance/cases/object/c-object-0056.toml::/exchanges/0/request/chunks/1/action=stall;conformance/cases/object/c-object-0056.toml::/exchanges/0/request/chunks/1/duration_ms=1500;conformance/cases/object/c-object-0056.toml::/exchanges/0/expect/status=400;conformance/cases/object/c-object-0056.toml::/exchanges/0/expect/connection_after=closed;conformance/cases/object/c-object-0056.toml::/exchanges/0/expect/headers_absent/0=etag;conformance/cases/object/c-object-0056.toml::/exchanges/0/expect/error/code=RequestTimeout;conformance/cases/object/c-object-0056.toml::/exchanges/0/expect/request_progress/body_bytes_sent_at_response=26;conformance/cases/object/c-object-0056.toml::/exchanges/0/expect/request_progress/body_fully_sent=False;conformance/cases/object/c-object-0056.toml::/exchanges/0/expect/timing/terminate_within_ms=5000;conformance/cases/object/c-object-0056.toml::/exchanges/0/expect/body/contains_utf8/0~the request body stopped making progress;conformance/cases/object/c-object-0056.toml::/exchanges/1/expect/status=404;conformance/cases/object/c-object-0056.toml::/exchanges/1/expect/error/code=NoSuchKey;conformance/cases/object/c-object-0056.toml::/exchanges/2/expect/status=200;conformance/cases/object/c-object-0056.toml::/exchanges/2/expect/headers_present/etag=*;conformance/cases/object/c-object-0056.toml::/exchanges/3/expect/status=200;conformance/cases/object/c-object-0056.toml::/exchanges/3/expect/body/exact_utf8=complete paced object'
    'c-obj-0045|negative|bound|crates/http/tests/framing_smuggling.rs::fn c_wire_0063_an_over_large_declared_body_is_400_entity_too_large_and_never_drained'
    'c-obj-0046|negative|bound|conformance/cases/object/c-object-0008.toml::/expect/body/size=0'
    'c-obj-0047|negative|bound|conformance/cases/object/c-object-0053.toml::/exchanges/0/expect/status=403;conformance/cases/object/c-object-0053.toml::/exchanges/0/expect/body/size=0;conformance/cases/object/c-object-0053.toml::/exchanges/1/expect/status=403;conformance/cases/object/c-object-0053.toml::/exchanges/2/expect/status=403;conformance/cases/object/c-object-0053.toml::/exchanges/3/expect/status=200;conformance/cases/object/c-object-0053.toml::/exchanges/4/expect/status=200'
    'c-obj-0048|negative|bound|conformance/cases/object/c-object-0052.toml::/exchanges/0/expect/status=403;conformance/cases/object/c-object-0052.toml::/exchanges/0/expect/body/not_contains_utf8/0=hidden/missing.txt;conformance/cases/object/c-object-0052.toml::/exchanges/3/expect/status=404;conformance/cases/object/c-object-0052.toml::/exchanges/3/expect/error/code=NoSuchKey;conformance/cases/object/c-object-0052.toml::/exchanges/4/expect/status=200'
    'c-obj-0049|negative|bound|conformance/cases/object/c-object-0036.toml::/exchanges/1/expect/error/code=MethodNotAllowed;conformance/cases/object/c-object-0038.toml::/exchanges/1/expect/status=405'
    'c-obj-0050|negative|bound|conformance/cases/object/c-object-0037.toml::/exchanges/1/expect/error/code=NoSuchKey;conformance/cases/object/c-object-0037.toml::/exchanges/1/expect/headers_present/x-amz-delete-marker=true'
    'c-obj-0051|negative|bound|conformance/cases/object/c-object-0046.toml::/expect/error/code=AccessDenied;conformance/cases/object/c-object-0051.toml::/expect/request_progress/body_fully_sent=False'
    'c-obj-0052|negative|bound|conformance/cases/object/c-object-0015.toml::/expect/request_progress/body_fully_sent=False'
    'c-obj-0053|negative|bound|conformance/cases/object/c-object-0021.toml::/expect/error/code=MalformedXML'
    'c-obj-0054|negative|bound|conformance/cases/object/c-object-0022.toml::/expect/body/exact_utf8~<Deleted><Key>batch/one</Key></Deleted>'
    'c-obj-0055|negative|bound|conformance/cases/object/c-object-0022.toml::/request/body/utf8~<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">;conformance/cases/object/c-object-0022.toml::/expect/status=200'
    'c-obj-0056|negative|bound|conformance/cases/object/c-object-0023.toml::/expect/body/not_contains_utf8/0=<Deleted>'
    'c-obj-0057|negative|bound|conformance/cases/object/c-object-0055.toml::/exchanges/0/request/headers/content-length=1048576;conformance/cases/object/c-object-0055.toml::/exchanges/0/request/chunks/0/raw_utf8~received but never committed;conformance/cases/object/c-object-0055.toml::/exchanges/0/request/chunks/1/action=close;conformance/cases/object/c-object-0055.toml::/exchanges/0/expect/kind=connection_reset;conformance/cases/object/c-object-0055.toml::/exchanges/1/expect/status=404;conformance/cases/object/c-object-0055.toml::/exchanges/1/expect/error/code=NoSuchKey;conformance/cases/object/c-object-0055.toml::/exchanges/2/expect/status=200;conformance/cases/object/c-object-0055.toml::/exchanges/3/expect/status=200;conformance/cases/object/c-object-0055.toml::/exchanges/3/expect/body/exact_utf8=complete object'
    # Repointed by the rustfs/backlog#1701 §4.4 slice. The rule is unchanged; the assertion it
    # named was not one. `headers_absent/0=x-injected` could not fail for any reachable
    # defect — a response header named by the caller is unconstructible under
    # `#![forbid(unsafe_code)]` with every insertion going through `HeaderName::from_bytes`
    # on a compile-time constant — so the ledger was holding this rule against a check that
    # read green with the whole guard deleted. The body needle carries the same literal and
    # does fail (it catches the value being echoed into the refusal), and the refusal's own
    # code is now what the rule is really bound to.
    'c-obj-0058|negative|bound|conformance/cases/object/c-object-0020.toml::/expect/body/not_contains_utf8/0=x-injected;conformance/cases/object/c-object-0020.toml::/expect/error/code=InvalidArgument'
    'c-obj-0059|negative|bound|conformance/cases/naming/c-naming-0017.toml::/expect/body/exact_utf8=decoded once;conformance/cases/naming/c-naming-0010.toml::/expect/error/code=InvalidArgument'
    'c-obj-0060|negative|bound|conformance/cases/object/c-object-0003.toml::/expect/headers_absent/0=content-length'
    'c-obj-0061|positive|bound|conformance/cases/object/c-object-0029.toml::/exchanges/2/expect/headers_present/x-amz-request-id=*;conformance/cases/object/c-object-0029.toml::/exchanges/0/expect/headers_present/accept-ranges=bytes'
    'c-obj-0062|negative|bound|conformance/cases/cond/c-cond-0023.toml::/exchanges/0/expect/body/not_contains_utf8/0=xmlns'
)

# §7 counts itself: 24 positive and 38 negative. Transcribed once, so that flipping a row's
# polarity to make a rule look like the other kind of evidence stops the build.
EXPECTED_POSITIVE=24
EXPECTED_NEGATIVE=38

# The polarity each named case declares, transcribed from the case files. This is the second half of
# the polarity guard and the independent one: the row column above is the *rule's* polarity, this is
# the *corpus's*, and the corpus's is what `negative >= positive` in the suite is counted from. A
# case relabelled to move that ratio stops this ledger.
case_polarity=(
    'conformance/cases/cond/c-cond-0023.toml|negative'
    'conformance/cases/mpu/c-mpu-0007.toml|positive'
    'conformance/cases/naming/c-naming-0001.toml|positive'
    'conformance/cases/naming/c-naming-0010.toml|negative'
    'conformance/cases/naming/c-naming-0017.toml|positive'
    'conformance/cases/naming/c-naming-0025.toml|positive'
    'conformance/cases/object/c-object-0001.toml|positive'
    'conformance/cases/object/c-object-0002.toml|positive'
    'conformance/cases/object/c-object-0003.toml|positive'
    'conformance/cases/object/c-object-0004.toml|positive'
    'conformance/cases/object/c-object-0005.toml|positive'
    'conformance/cases/object/c-object-0006.toml|positive'
    'conformance/cases/object/c-object-0007.toml|negative'
    'conformance/cases/object/c-object-0008.toml|negative'
    'conformance/cases/object/c-object-0010.toml|negative'
    'conformance/cases/object/c-object-0011.toml|negative'
    'conformance/cases/object/c-object-0012.toml|negative'
    'conformance/cases/object/c-object-0013.toml|negative'
    'conformance/cases/object/c-object-0015.toml|negative'
    'conformance/cases/object/c-object-0017.toml|positive'
    'conformance/cases/object/c-object-0018.toml|positive'
    'conformance/cases/object/c-object-0019.toml|positive'
    'conformance/cases/object/c-object-0020.toml|negative'
    'conformance/cases/object/c-object-0021.toml|negative'
    'conformance/cases/object/c-object-0022.toml|negative'
    'conformance/cases/object/c-object-0023.toml|negative'
    'conformance/cases/object/c-object-0024.toml|positive'
    'conformance/cases/object/c-object-0025.toml|negative'
    'conformance/cases/object/c-object-0026.toml|negative'
    'conformance/cases/object/c-object-0027.toml|negative'
    'conformance/cases/object/c-object-0028.toml|positive'
    'conformance/cases/object/c-object-0029.toml|positive'
    'conformance/cases/object/c-object-0030.toml|negative'
    'conformance/cases/object/c-object-0036.toml|negative'
    'conformance/cases/object/c-object-0037.toml|negative'
    'conformance/cases/object/c-object-0038.toml|negative'
    'conformance/cases/object/c-object-0040.toml|positive'
    'conformance/cases/object/c-object-0041.toml|positive'
    'conformance/cases/object/c-object-0042.toml|positive'
    'conformance/cases/object/c-object-0043.toml|negative'
    'conformance/cases/object/c-object-0044.toml|negative'
    'conformance/cases/object/c-object-0045.toml|positive'
    'conformance/cases/object/c-object-0046.toml|negative'
    'conformance/cases/object/c-object-0051.toml|negative'
    'conformance/cases/object/c-object-0052.toml|negative'
    'conformance/cases/object/c-object-0053.toml|negative'
    'conformance/cases/object/c-object-0054.toml|negative'
    'conformance/cases/object/c-object-0055.toml|negative'
    'conformance/cases/object/c-object-0056.toml|negative'
    'conformance/cases/tagging/c-tagging-0019.toml|positive'
)

command -v python3 >/dev/null 2>&1 || {
    printf 'check_object_semantics_ledger: required command is missing: python3\n' >&2
    exit 1
}

python3 - "$ROOT" "$EXPECTED_POSITIVE" "$EXPECTED_NEGATIVE" "$(printf '%s\n' "${case_polarity[@]}")" "${requirements[@]}" <<'PYEOF'
import re
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
expected_positive = int(sys.argv[2])
expected_negative = int(sys.argv[3])
declared_case_polarity = [line for line in sys.argv[4].splitlines() if line.strip()]
rows = sys.argv[5:]

# §7 of rustfs/backlog#1680, transcribed once.
EXPECTED_IDS = [f"c-obj-{index:04d}" for index in range(1, 63)]

failures = []


def fail(message):
    failures.append(message)


# -- The roll call ---------------------------------------------------------------------------
# Mutation 1 dies here: a deleted row leaves an id with no mapping, and a duplicated one leaves an
# id claimed twice. Neither is a difference a reader would notice in a diff of sixty-two lines.
parsed = {}
order = []
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
        fail(f"{identifier}: polarity must be positive or negative, not {polarity!r}")
        continue
    if status not in ("bound", "blocked"):
        fail(f"{identifier}: status must be bound or blocked, not {status!r}")
        continue
    parsed[identifier] = (polarity, status, evidence)
    order.append(identifier)

missing = [identifier for identifier in EXPECTED_IDS if identifier not in parsed]
unexpected = [identifier for identifier in order if identifier not in EXPECTED_IDS]
for identifier in missing:
    fail(f"§7 acceptance id has no ledger row: {identifier}")
for identifier in unexpected:
    fail(f"ledger row names an id §7 does not list: {identifier}")

# -- The polarity arithmetic -----------------------------------------------------------------
# Mutation 3, first half: §7 counts twenty-four positive rules and thirty-eight negative ones, and
# a suite that keeps negatives in the majority is the reason the count is worth pinning.
positive = sum(1 for polarity, _, _ in parsed.values() if polarity == "positive")
negative = sum(1 for polarity, _, _ in parsed.values() if polarity == "negative")
if (positive, negative) != (expected_positive, expected_negative):
    fail(
        f"§7 is {expected_positive} positive and {expected_negative} negative; "
        f"the ledger reads {positive} positive and {negative} negative"
    )

# -- The case labels -------------------------------------------------------------------------
# Mutation 3, second half, and the independent one: the polarity the corpus itself declares.
documents = {}


def load(relative):
    if relative not in documents:
        path = root / relative
        if not path.is_file():
            documents[relative] = None
        else:
            try:
                documents[relative] = tomllib.loads(path.read_text())
            except (OSError, tomllib.TOMLDecodeError) as error:
                fail(f"{relative}: {error}")
                documents[relative] = None
    return documents[relative]


labelled = set()
for line in declared_case_polarity:
    relative, _, polarity = line.partition("|")
    labelled.add(relative)
    document = load(relative)
    if document is None:
        fail(f"case named by the polarity table is missing or unreadable: {relative}")
        continue
    observed = document.get("case", {}).get("polarity")
    if observed != polarity:
        fail(f"{relative}: the ledger records polarity {polarity!r}, the case declares {observed!r}")


# -- The assertions --------------------------------------------------------------------------
# Mutation 2 dies here: a pointer that no longer resolves, or that resolves to something other than
# the literal recorded, is an assertion the ledger claimed and the corpus no longer makes.
def resolve(document, pointer):
    """Walk a JSON pointer through a parsed TOML document. `None` for anything unreachable."""
    current = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                return None
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or int(token) >= len(current):
                return None
            current = current[int(token)]
        else:
            return None
    return current


def check_toml_evidence(identifier, relative, selector):
    document = load(relative)
    if document is None:
        fail(f"{identifier}: evidence file is missing: {relative}")
        return
    if relative not in labelled:
        fail(f"{identifier}: {relative} carries an assertion but no row in the case polarity table")
        return
    for separator in ("~", "="):
        pointer, found, literal = selector.partition(separator)
        if found:
            break
    else:
        pointer, separator, literal = selector, "", ""
    if not pointer.startswith("/"):
        fail(f"{identifier}: selector is not a JSON pointer: {selector}")
        return
    value = resolve(document, pointer)
    if value is None:
        fail(f"{identifier}: {relative} no longer carries an assertion at {pointer}")
        return
    if separator == "" and (value == "" or value == [] or value == {}):
        fail(f"{identifier}: {relative}{pointer} resolves to an empty value")
        return
    if separator == "=" and str(value) != literal:
        fail(f"{identifier}: {relative}{pointer} is {value!r}, the ledger records {literal!r}")
        return
    if separator == "~" and literal not in str(value):
        fail(f"{identifier}: {relative}{pointer} does not contain {literal!r}")


def check_rust_evidence(identifier, relative, selector):
    path = root / relative
    if not path.is_file():
        fail(f"{identifier}: evidence file is missing: {relative}")
        return
    if not selector.startswith("fn "):
        fail(f"{identifier}: Rust evidence must name a test function, not {selector!r}")
        return
    name = selector.removeprefix("fn ")
    source = path.read_text()
    # Comments are blanked before the search: a test named only in prose is not a test.
    source = re.sub(r"(?m)//.*$", "", source)
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    pattern = re.compile(rf"(?m)^[ \t]*(?:async\s+)?fn\s+{re.escape(name)}\s*\(")
    if len(pattern.findall(source)) != 1:
        fail(f"{identifier}: {relative} has no single top-level fn {name}")
        return
    attributed = re.compile(
        rf"#\s*\[\s*(?:test|tokio::test[^\]]*)\s*\]\s*(?:async\s+)?fn\s+{re.escape(name)}\s*\("
    )
    if not attributed.search(source):
        fail(f"{identifier}: {relative}::{name} is not an enabled test")


OWNER = re.compile(r"^rustfs/(backlog|gateway)#[0-9]+$")

for identifier in EXPECTED_IDS:
    if identifier not in parsed:
        continue
    _, status, evidence = parsed[identifier]
    if status == "blocked":
        owner, _, reason = evidence.partition("::")
        if not OWNER.match(owner):
            fail(f"{identifier}: a blocked row must open with an owning issue, not {owner!r}")
            continue
        if len(reason) < 40:
            fail(f"{identifier}: a blocked row must say why in a sentence, not {reason!r}")
        if ".toml" in reason.split(" — ")[0] and "::" in evidence[len(owner) + 2 :]:
            fail(f"{identifier}: a blocked row must not name evidence")
        continue
    entries = [entry for entry in evidence.split(";") if entry]
    if not entries:
        fail(f"{identifier}: a bound row names no evidence")
        continue
    for entry in entries:
        relative, separator, selector = entry.partition("::")
        if not separator:
            fail(f"{identifier}: evidence is not <path>::<selector>: {entry}")
            continue
        if relative.endswith(".toml"):
            check_toml_evidence(identifier, relative, selector)
        elif relative.endswith(".rs"):
            check_rust_evidence(identifier, relative, selector)
        else:
            fail(f"{identifier}: evidence is neither a case nor a Rust test: {relative}")

# Every case the polarity table pins must actually be used, or the table becomes a place where a
# deleted mapping can hide.
used = set()
for _, status, evidence in parsed.values():
    if status != "bound":
        continue
    for entry in evidence.split(";"):
        relative, separator, _ = entry.partition("::")
        if separator and relative.endswith(".toml"):
            used.add(relative)
for relative in sorted(labelled - used):
    fail(f"the case polarity table pins {relative}, which no bound row names")

if failures:
    for message in failures:
        print(f"check_object_semantics_ledger: {message}", file=sys.stderr)
    raise SystemExit(1)

bound = sum(1 for _, status, _ in parsed.values() if status == "bound")
blocked = len(parsed) - bound
print(
    f"OK: {len(parsed)} object acceptance ids — {bound} bound to a resolved assertion, "
    f"{blocked} blocked with an owning issue"
)
PYEOF
