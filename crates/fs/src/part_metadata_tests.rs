// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Stored part identities and checksums through the complete version-record grammar.
//!
//! Responsible for: sparse identities, checksum consistency, bounded rows and legacy absence.
//! NOT responsible for: HTTP part-list pagination or byte-window arithmetic.
//! Upstream: completion records. Downstream: record validation and the filesystem gate.

use super::{decode_version_record, encode_version_record};
use rustfs_gateway::ChecksumSpec;

fn record(checksum: &str, lengths: &str, details: &str) -> String {
    format!("1\n6b\n76\nobject\n0\n00000000000000000000000000000000-2\n3\n5354414e44415244\n{checksum}{lengths}{details}")
}

const LENGTHS: &str = "parts/1 2\n1\n2\n";
const DETAILS: &str = "part-meta/1 2\n2 - -\n5 - -\n";

fn parsed(encoded: &str) -> Result<super::VersionRecord, rustfs_gateway::HandlerError> {
    decode_version_record(std::path::PathBuf::new(), encoded)
}

fn object_checksum() -> String {
    let first = ChecksumSpec::parse_header("x-amz-checksum-crc32", "AAAAAA==").expect("CRC32");
    let second = ChecksumSpec::parse_header("x-amz-checksum-crc32", "AAAAAQ==").expect("CRC32");
    let value = ChecksumSpec::composite_of(&[first, second]).expect("matching algorithms");
    format!("checksum/2 1\nCRC32 COMPOSITE {}\n", value.render_base64())
}

#[test]
fn sparse_part_metadata_roundtrips_with_its_length_table() {
    let encoded = record("", LENGTHS, DETAILS);
    let decoded = parsed(&encoded).expect("sparse metadata");
    assert!(encode_version_record(&decoded).ends_with(&format!("{LENGTHS}{DETAILS}")));
}

#[test]
fn individual_checksums_roundtrip_beside_the_object_checksum() {
    for (algorithm, first, second) in [
        ("CRC32", "AAAAAA==", "AAAAAQ=="),
        ("SHA1", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAAAAAAAAAAAAAAAAAAAAAAAAAE="),
    ] {
        let header = format!("x-amz-checksum-{}", algorithm.to_ascii_lowercase());
        let parts = [
            ChecksumSpec::parse_header(&header, first).expect("first checksum"),
            ChecksumSpec::parse_header(&header, second).expect("second checksum"),
        ];
        let value = ChecksumSpec::composite_of(&parts).expect("same algorithm");
        let checksum = format!("checksum/2 1\n{algorithm} COMPOSITE {}\n", value.render_base64());
        let details = format!("part-meta/1 2\n2 {algorithm} {first}\n5 {algorithm} {second}\n");
        let decoded = parsed(&record(&checksum, LENGTHS, &details)).expect("part checksums");
        assert!(encode_version_record(&decoded).ends_with(&format!("{checksum}{LENGTHS}{details}")));
    }
}

#[test]
fn n_old_length_tables_do_not_invent_part_details() {
    let decoded = parsed(&record("", LENGTHS, "")).expect("old lengths");
    assert!(!encode_version_record(&decoded).contains("part-meta/"));
}

#[test]
fn n_metadata_counts_are_bounded_before_rows_are_consumed() {
    for count in ["0", "10001", "bad", "18446744073709551616"] {
        let details = format!("part-meta/1 {count}\n{}", "2 - -\n".repeat(10001));
        assert!(parsed(&record("", LENGTHS, &details)).is_err(), "{count}");
        let rows = "2 - -\n".repeat(10001);
        let mut lines = rows.lines();
        assert!(crate::part_metadata::decode(&mut lines, count).is_err());
        assert_eq!(lines.count(), 10001, "a rejected count must not consume rows");
    }
}

#[test]
fn n_malformed_or_mismatched_metadata_rows_are_refused() {
    for details in [
        "part-meta/1 1\n2 - -\n",
        "part-meta/1 2\n2 - -\n",
        "part-meta/1 2\n2 - -\n5 - -\n9 - -\n",
        "part-meta/1 2\n2 -\n5 - -\n",
        "part-meta/1 2\n2 - - extra\n5 - -\n",
        "part-meta/1 2\n2  - -\n5 - -\n",
    ] {
        assert!(parsed(&record("", LENGTHS, details)).is_err(), "{details}");
    }
}

#[test]
fn n_original_numbers_must_increase_inside_the_upload_bounds() {
    for pair in [
        ("0", "5"),
        ("2", "10001"),
        ("2", "2"),
        ("5", "2"),
        ("-1", "5"),
        ("+2", "5"),
        ("02", "5"),
        ("bad", "5"),
    ] {
        let details = format!("part-meta/1 2\n{} - -\n{} - -\n", pair.0, pair.1);
        assert!(parsed(&record("", LENGTHS, &details)).is_err(), "{pair:?}");
    }
}

#[test]
fn n_metadata_requires_a_completed_object_and_length_table() {
    assert!(parsed(&record("", "", DETAILS)).is_err());
    assert!(parsed(&record("", LENGTHS, DETAILS).replace("\nobject\n", "\ndelete\n")).is_err());
}

#[test]
fn n_individual_checksum_presence_and_algorithm_must_match_the_object() {
    let checksum = object_checksum();
    for details in [
        DETAILS,
        "part-meta/1 2\n2 CRC32 AAAAAA==\n5 - -\n",
        "part-meta/1 2\n2 CRC32 AAAAAA==\n5 CRC32C AAAAAQ==\n",
        "part-meta/1 2\n2 CRC32 bad\n5 CRC32 AAAAAQ==\n",
        "part-meta/1 2\n2 Unknown AAAAAA==\n5 CRC32 AAAAAQ==\n",
        "part-meta/1 2\n2 - AAAAAA==\n5 CRC32 AAAAAQ==\n",
        "part-meta/1 2\n2 CRC32 -\n5 CRC32 AAAAAQ==\n",
    ] {
        assert!(parsed(&record(&checksum, LENGTHS, details)).is_err(), "{details}");
    }
    assert!(parsed(&record("", LENGTHS, "part-meta/1 2\n2 CRC32 AAAAAA==\n5 CRC32 AAAAAQ==\n")).is_err());
    for row in ["2 - AAAAAA==", "2 CRC32 -"] {
        let details = format!("part-meta/1 2\n{row}\n5 - -\n");
        assert!(parsed(&record("", LENGTHS, &details)).is_err());
    }
}

#[test]
fn n_composite_checksums_are_not_individual_part_values() {
    let details = "part-meta/1 2\n2 CRC32 AAAAAA==-2\n5 CRC32 AAAAAQ==\n";
    assert!(parsed(&record(&object_checksum(), LENGTHS, details)).is_err());
}

#[test]
fn n_part_metadata_cannot_hide_a_later_or_reordered_section() {
    for details in [
        format!("{DETAILS}meta/1 0\n"),
        DETAILS.replace("part-meta/1", "part-meta/2"),
        format!("{DETAILS}{LENGTHS}"),
    ] {
        assert!(parsed(&record("", LENGTHS, &details)).is_err());
    }
    assert!(parsed(&record("", "", &format!("{DETAILS}{LENGTHS}"))).is_err());
}
