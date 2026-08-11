#!/usr/bin/env bash
set -euo pipefail

# The vendored timestamp corpus is compatibility evidence only while its exact
# upstream bytes, license, and attribution remain reproducible.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if ! command -v python3 >/dev/null 2>&1; then
    printf 'check_smithy_timestamp_corpus: required command is missing: python3\n' >&2
    exit 1
fi

python3 - "$ROOT_DIR" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
corpus_path = root / "crates/types/tests/data/date_time_format_test_suite.json"
mapping_path = root / "crates/types/tests/data/README.md"
notice_path = root / "NOTICE"
third_party_path = root / "THIRD-PARTY-NOTICES.md"

required_files = (corpus_path, mapping_path, notice_path, third_party_path)
for path in required_files:
    if not path.is_file():
        print(f"check_smithy_timestamp_corpus: required input is missing: {path.relative_to(root)}", file=sys.stderr)
        raise SystemExit(1)

corpus = corpus_path.read_bytes()
expected_bytes = 152_448
expected_sha256 = "95adad86782f37c5eff4601cccaeb76b5ef827121ad7b2f7030224d231a746bd"
if len(corpus) != expected_bytes:
    print(f"check_smithy_timestamp_corpus: byte count changed: {len(corpus)} != {expected_bytes}", file=sys.stderr)
    raise SystemExit(1)
actual_sha256 = hashlib.sha256(corpus).hexdigest()
if actual_sha256 != expected_sha256:
    print(f"check_smithy_timestamp_corpus: SHA-256 changed: {actual_sha256}", file=sys.stderr)
    raise SystemExit(1)

try:
    suite = json.loads(corpus)
except json.JSONDecodeError as error:
    print(f"check_smithy_timestamp_corpus: corpus is not valid JSON: {error}", file=sys.stderr)
    raise SystemExit(1)

sections = {
    "format_date_time": 122,
    "format_epoch_seconds": 122,
    "format_http_date": 122,
    "parse_date_time": 86,
    "parse_epoch_seconds": 122,
    "parse_http_date": 86,
}
for name, expected_count in sections.items():
    cases = suite.get(name)
    if not isinstance(cases, list) or len(cases) != expected_count:
        print(f"check_smithy_timestamp_corpus: {name} must contain {expected_count} cases", file=sys.stderr)
        raise SystemExit(1)

commit = "2744eb413935073aa43800e58e36268cd90b3a83"
upstream_path = "rust-runtime/aws-smithy-types/test_data/date_time_format_test_suite.json"
copyright_notice = "Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved."
required_provenance = (
    "https://github.com/smithy-lang/smithy-rs",
    commit,
    upstream_path,
    expected_sha256,
    "Apache-2.0",
    copyright_notice,
)
for path in (notice_path, mapping_path):
    text = path.read_text()
    missing = [value for value in required_provenance if value not in text]
    if missing:
        print(f"check_smithy_timestamp_corpus: {path.relative_to(root)} lacks provenance: {missing[0]}", file=sys.stderr)
        raise SystemExit(1)

mapping = mapping_path.read_text()
for row in (
    "| `date-time` | `TimestampFormat::Iso8601` |",
    "| `epoch-seconds` | `TimestampFormat::EpochSeconds` |",
    "| `http-date` | `TimestampFormat::HttpDate` |",
    "| no upstream section | `TimestampFormat::Iso8601Basic` |",
):
    if row not in mapping:
        print(f"check_smithy_timestamp_corpus: format mapping row is missing: {row}", file=sys.stderr)
        raise SystemExit(1)

third_party = third_party_path.read_text()
required_third_party = (
    "Smithy timestamp format test suite",
    "https://github.com/smithy-lang/smithy-rs",
    "Apache License 2.0",
    "crates/types/tests/data/README.md",
    "NOTICE",
    copyright_notice,
)
missing = [value for value in required_third_party if value not in third_party]
if missing:
    print(f"check_smithy_timestamp_corpus: third-party notice lacks attribution: {missing[0]}", file=sys.stderr)
    raise SystemExit(1)
PY
