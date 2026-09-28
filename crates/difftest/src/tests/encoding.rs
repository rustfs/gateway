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

//! Judges the output matrix: exact registered differences per sample, no stale encode entry, and
//! every s3s output member set by some sample.
//!
//! Responsible for: holding each output sample to its expected set of known-diff ids in both
//! directions, every encode register entry to at least one sample, and every member of every
//! diffed operation's s3s output to a sample that sets it (so a conversion that dropped a member
//! would leave a difference some sample shows).
//! NOT responsible for: the samples (`samples/outputs.rs`, `samples/outputs_more.rs`) or the injected encoder
//! defects (`encode_controls.rs`).
//! Upstream: the samples, the checked-in register. Downstream: none.

use std::collections::{BTreeMap, BTreeSet};

use crate::known::Kind;
use crate::samples::OutputRow;
use crate::{Differ, KnownDiffs};

/// Every output sample.
pub(crate) fn all_rows() -> Vec<OutputRow> {
    crate::samples::outputs()
}

/// Positive — every sample produces exactly its registered differences: a new difference fails as
/// unregistered, one that went away fails as an expectation no longer met.
#[test]
fn every_output_sample_produces_exactly_its_registered_differences() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    let differ = Differ::new().expect("both stacks build");
    let mut problems = Vec::new();
    let mut names = BTreeSet::new();
    for row in all_rows() {
        assert!(names.insert(row.sample.name.clone()), "sample {} is listed twice", row.sample.name);
        let diff = differ
            .encode(&row.sample)
            .unwrap_or_else(|error| panic!("{}: {error}", row.sample.name));
        let verdict = register.verdict(diff.findings());
        for failure in &verdict.failures {
            problems.push(format!("{}: unregistered {failure}", row.sample.name));
        }
        let matched: BTreeSet<&str> = verdict.known.iter().map(|(_, id)| id.as_str()).collect();
        let expected: BTreeSet<&str> = row.expect.iter().copied().collect();
        if matched != expected {
            problems.push(format!("{}: matched {matched:?}, expected {expected:?}", row.sample.name));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Negative — an encode register entry no sample produces is stale and fails.
#[test]
fn every_encode_register_entry_is_produced_by_some_sample() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    let produced: BTreeSet<&str> = all_rows().iter().flat_map(|row| row.expect.iter().copied()).collect();
    let stale: Vec<&str> = register
        .entries()
        .iter()
        .filter(|entry| entry.kind == Kind::Encode && !produced.contains(entry.id.as_str()))
        .map(|entry| entry.id.as_str())
        .collect();
    assert!(stale.is_empty(), "register entries no sample produces: {stale:?}");
}

/// The top-level member names a pinned s3s output's `Debug` prints: it prints exactly the members
/// that are set.
fn set_members(debug: &str) -> BTreeSet<String> {
    let Some(open) = debug.find('{') else {
        return BTreeSet::new();
    };
    let mut members = BTreeSet::new();
    let (mut depth, mut quoted, mut escaped, mut start) = (0_i32, false, false, open + 1);
    for (index, character) in debug.char_indices().skip(open + 1) {
        if quoted {
            match (escaped, character) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => quoted = false,
                _ => {}
            }
            continue;
        }
        match character {
            '"' => quoted = true,
            '{' | '[' | '(' => depth += 1,
            '}' | ']' | ')' if depth > 0 => depth -= 1,
            ':' if depth == 0 => {
                let name = debug[start..index].trim().trim_start_matches(',').trim();
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
                    members.insert(name.to_owned());
                }
            }
            ',' if depth == 0 => start = index,
            _ => {}
        }
    }
    members
}

/// Every member of every diffed operation's pinned s3s output.
const OUTPUT_MEMBERS: &[(&str, &[&str])] = &[
    (
        "GetObject",
        &[
            "accept_ranges",
            "body",
            "bucket_key_enabled",
            "cache_control",
            "checksum_crc32",
            "checksum_crc32c",
            "checksum_crc64nvme",
            "checksum_md5",
            "checksum_sha1",
            "checksum_sha256",
            "checksum_sha512",
            "checksum_type",
            "checksum_xxhash128",
            "checksum_xxhash3",
            "checksum_xxhash64",
            "content_disposition",
            "content_encoding",
            "content_language",
            "content_length",
            "content_range",
            "content_type",
            "delete_marker",
            "e_tag",
            "expiration",
            "expires",
            "last_modified",
            "metadata",
            "missing_meta",
            "object_lock_legal_hold_status",
            "object_lock_mode",
            "object_lock_retain_until_date",
            "parts_count",
            "replication_status",
            "request_charged",
            "restore",
            "sse_customer_algorithm",
            "sse_customer_key_md5",
            "ssekms_key_id",
            "server_side_encryption",
            "storage_class",
            "tag_count",
            "version_id",
            "website_redirect_location",
        ],
    ),
    (
        "HeadObject",
        &[
            "accept_ranges",
            "archive_status",
            "bucket_key_enabled",
            "cache_control",
            "checksum_crc32",
            "checksum_crc32c",
            "checksum_crc64nvme",
            "checksum_md5",
            "checksum_sha1",
            "checksum_sha256",
            "checksum_sha512",
            "checksum_type",
            "checksum_xxhash128",
            "checksum_xxhash3",
            "checksum_xxhash64",
            "content_disposition",
            "content_encoding",
            "content_language",
            "content_length",
            "content_range",
            "content_type",
            "delete_marker",
            "e_tag",
            "expiration",
            "expires",
            "last_modified",
            "metadata",
            "missing_meta",
            "object_lock_legal_hold_status",
            "object_lock_mode",
            "object_lock_retain_until_date",
            "parts_count",
            "replication_status",
            "request_charged",
            "restore",
            "sse_customer_algorithm",
            "sse_customer_key_md5",
            "ssekms_key_id",
            "server_side_encryption",
            "storage_class",
            "tag_count",
            "version_id",
            "website_redirect_location",
        ],
    ),
    (
        "PutObject",
        &[
            "bucket_key_enabled",
            "checksum_crc32",
            "checksum_crc32c",
            "checksum_crc64nvme",
            "checksum_md5",
            "checksum_sha1",
            "checksum_sha256",
            "checksum_sha512",
            "checksum_type",
            "checksum_xxhash128",
            "checksum_xxhash3",
            "checksum_xxhash64",
            "e_tag",
            "expiration",
            "request_charged",
            "sse_customer_algorithm",
            "sse_customer_key_md5",
            "ssekms_encryption_context",
            "ssekms_key_id",
            "server_side_encryption",
            "size",
            "version_id",
        ],
    ),
    ("DeleteObject", &["delete_marker", "request_charged", "version_id"]),
    ("DeleteObjects", &["deleted", "errors", "request_charged"]),
    (
        "CopyObject",
        &[
            "bucket_key_enabled",
            "copy_object_result",
            "copy_source_version_id",
            "expiration",
            "request_charged",
            "sse_customer_algorithm",
            "sse_customer_key_md5",
            "ssekms_encryption_context",
            "ssekms_key_id",
            "server_side_encryption",
            "version_id",
        ],
    ),
    (
        "ListObjects",
        &[
            "name",
            "prefix",
            "marker",
            "max_keys",
            "is_truncated",
            "contents",
            "common_prefixes",
            "delimiter",
            "next_marker",
            "encoding_type",
            "request_charged",
        ],
    ),
    (
        "ListObjectsV2",
        &[
            "name",
            "prefix",
            "max_keys",
            "key_count",
            "continuation_token",
            "is_truncated",
            "next_continuation_token",
            "contents",
            "common_prefixes",
            "delimiter",
            "encoding_type",
            "start_after",
            "request_charged",
        ],
    ),
    (
        "ListObjectVersions",
        &[
            "common_prefixes",
            "delete_markers",
            "delimiter",
            "encoding_type",
            "is_truncated",
            "key_marker",
            "max_keys",
            "name",
            "next_key_marker",
            "next_version_id_marker",
            "prefix",
            "request_charged",
            "version_id_marker",
            "versions",
        ],
    ),
    (
        "ListMultipartUploads",
        &[
            "bucket",
            "common_prefixes",
            "delimiter",
            "encoding_type",
            "is_truncated",
            "key_marker",
            "max_uploads",
            "next_key_marker",
            "next_upload_id_marker",
            "prefix",
            "request_charged",
            "upload_id_marker",
            "uploads",
        ],
    ),
    (
        "CreateMultipartUpload",
        &[
            "abort_date",
            "abort_rule_id",
            "bucket",
            "bucket_key_enabled",
            "checksum_algorithm",
            "checksum_type",
            "key",
            "request_charged",
            "sse_customer_algorithm",
            "sse_customer_key_md5",
            "ssekms_encryption_context",
            "ssekms_key_id",
            "server_side_encryption",
            "upload_id",
        ],
    ),
    (
        "UploadPart",
        &[
            "bucket_key_enabled",
            "checksum_crc32",
            "checksum_crc32c",
            "checksum_crc64nvme",
            "checksum_md5",
            "checksum_sha1",
            "checksum_sha256",
            "checksum_sha512",
            "checksum_xxhash128",
            "checksum_xxhash3",
            "checksum_xxhash64",
            "e_tag",
            "request_charged",
            "sse_customer_algorithm",
            "sse_customer_key_md5",
            "ssekms_key_id",
            "server_side_encryption",
        ],
    ),
    (
        "CompleteMultipartUpload",
        &[
            "bucket",
            "bucket_key_enabled",
            "checksum_crc32",
            "checksum_crc32c",
            "checksum_crc64nvme",
            "checksum_md5",
            "checksum_sha1",
            "checksum_sha256",
            "checksum_sha512",
            "checksum_type",
            "checksum_xxhash128",
            "checksum_xxhash3",
            "checksum_xxhash64",
            "e_tag",
            "expiration",
            "key",
            "location",
            "request_charged",
            "ssekms_key_id",
            "server_side_encryption",
            "version_id",
            "future",
        ],
    ),
    ("AbortMultipartUpload", &["request_charged"]),
    (
        "ListParts",
        &[
            "abort_date",
            "abort_rule_id",
            "bucket",
            "checksum_algorithm",
            "checksum_type",
            "initiator",
            "is_truncated",
            "key",
            "max_parts",
            "next_part_number_marker",
            "owner",
            "part_number_marker",
            "parts",
            "request_charged",
            "storage_class",
            "upload_id",
        ],
    ),
    ("CreateBucket", &["bucket_arn", "location"]),
    ("DeleteBucket", &[]),
    (
        "HeadBucket",
        &[
            "access_point_alias",
            "bucket_arn",
            "bucket_location_name",
            "bucket_location_type",
            "bucket_region",
        ],
    ),
    ("ListBuckets", &["buckets", "continuation_token", "owner", "prefix"]),
    ("GetBucketLocation", &["location_constraint"]),
    ("GetBucketVersioning", &["mfa_delete", "status"]),
    ("PutBucketVersioning", &[]),
];

/// Negative — a member no sample sets is a member whose conversion nobody exercised: a conversion
/// that dropped it would leave every sample green. Every member of every diffed operation's s3s
/// output must be set by a sample that both stacks encoded, or be the one member a refused sample
/// was refused for; and the table must name every diffed operation.
#[test]
fn every_s3s_output_member_is_set_by_some_sample() {
    let mut seen: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    for row in all_rows() {
        let output = (row.sample.output)();
        let operation = output.operation();
        let members = set_members(&format!("{output:?}"));
        match (row.sample.output)().into_gateway() {
            // Encoded on both stacks: every member it sets was compared.
            Ok(_) => seen.entry(operation).or_default().extend(members),
            // Refused: only the member the refusal names was exercised, and only when the sample
            // sets it — a sample refused for one member proves nothing about the others it sets.
            Err(refused) if members.contains(refused.member) => {
                seen.entry(operation).or_default().insert(refused.member.to_owned());
            }
            Err(_) => {}
        }
    }
    let listed: BTreeSet<&str> = OUTPUT_MEMBERS.iter().map(|(operation, _)| *operation).collect();
    let diffed: BTreeSet<&str> = crate::DIFFED_OPERATIONS.iter().copied().collect();
    assert_eq!(listed, diffed);
    let mut problems = Vec::new();
    for (operation, members) in OUTPUT_MEMBERS {
        let set = seen.get(operation).cloned().unwrap_or_default();
        let unset: Vec<&&str> = members.iter().filter(|member| !set.contains(**member)).collect();
        let unknown: Vec<&String> = set.iter().filter(|member| !members.contains(&member.as_str())).collect();
        if !unset.is_empty() || !unknown.is_empty() {
            problems.push(format!("{operation}: never set {unset:?}; set but not listed {unknown:?}"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Positive — the member reader returns the top-level names only, whatever the values hold.
#[test]
fn the_member_reader_reads_top_level_names_only() {
    let debug = r#"Output { e_tag: Some(Strong("a,b: c")), owner: Owner { id: "x" }, size: 5 }"#;
    let names: Vec<String> = set_members(debug).into_iter().collect();
    assert_eq!(names, ["e_tag", "owner", "size"]);
}
