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

//! The pinned proof of each rollback constraint, and the refusals of a malformed register.
//!
//! Responsible for: re-proving `rb-mpu-0001` against the real algorithm set and the pinned s3s
//! model, and refusing by name every way an entry can be malformed or unbound.
//! NOT responsible for: running a previous release (it is not in the tree); what it admitted is
//! pinned as `PREVIOUS_RELEASE`, and the test fails the moment the current set moves past it
//! without a matching entry.
//! Upstream: [`super`]. Downstream: nothing.
//!
//! 2 positive / 4 negative.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use rustfs_gateway_types::compat::s3s_0_17_0::s3s::dto::ChecksumAlgorithm as CandidateChecksumAlgorithm;
use rustfs_gateway_types::compat::s3s_9c4690d8::s3s::dto::ChecksumAlgorithm as BaselineChecksumAlgorithm;
use rustfs_gateway_types::{ChecksumAlgorithm, ChecksumSpec};

use super::{
    ROLLBACK_AUTHORITY, ROLLBACK_CONSTRAINTS, RollbackConstraint, RollbackConstraintError, build_rollback_constraints, validate,
};

/// The checksum algorithms the previous release (rustfs-gateway-types 0.21.1) admitted, by wire
/// name. Anything the current release admits beyond these is state that release cannot read.
const PREVIOUS_RELEASE: [&str; 5] = ["CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256"];

/// The five algorithms `rb-mpu-0001` names, in `ChecksumAlgorithm::ALL` order.
const ADDED_2026_04: [&str; 5] = ["SHA512", "MD5", "XXHASH64", "XXHASH3", "XXHASH128"];

fn entry(id: &str) -> RollbackConstraint {
    *ROLLBACK_CONSTRAINTS
        .iter()
        .find(|entry| entry.id == id)
        .unwrap_or_else(|| panic!("{id} is registered"))
}

/// Positive — the multipart checksum state this release can create and the previous one cannot
/// read is exactly what the entry records, rolling back to the s3s stack is unaffected, and the
/// entry says what an operator must do first.
///
/// Constraint: `rb-mpu-0001`
#[test]
fn rollback_past_the_2026_04_checksums_requires_draining_their_multipart_uploads() {
    let recorded = entry("rb-mpu-0001");

    // What this release admits beyond the previous one is exactly the five the entry names. An
    // eleventh algorithm fails here until it has a constraint of its own.
    let added: Vec<&str> = ChecksumAlgorithm::ALL
        .iter()
        .map(|algo| algo.wire_name())
        .filter(|name| !PREVIOUS_RELEASE.contains(name))
        .collect();
    assert_eq!(added, ADDED_2026_04);
    for name in PREVIOUS_RELEASE {
        assert!(
            ChecksumAlgorithm::from_wire_name(name).is_some(),
            "{name}: state the previous release wrote still reads"
        );
    }

    // Each of the five is one a part can carry and an upload record can name.
    for algo in ChecksumAlgorithm::ALL
        .iter()
        .filter(|algo| ADDED_2026_04.contains(&algo.wire_name()))
    {
        let part = ChecksumSpec::from_digest(*algo, &vec![0u8; algo.digest_len()]).expect("the algorithm's own width");
        assert_eq!(ChecksumSpec::parse_header(algo.header_name(), part.render_base64()), Ok(part));
        assert!(recorded.state.contains(algo.wire_name()), "{} is named by the entry", algo.wire_name());
    }

    // Rolling back to the s3s stack is unaffected: the baseline revision and the one RustFS main
    // links both name all five. The rollback revision (s3s bdcb6259) is not re-exported by the seam;
    // its generated dto defines the same five constants, checked by reading that source.
    let baseline = [
        BaselineChecksumAlgorithm::SHA512,
        BaselineChecksumAlgorithm::MD5,
        BaselineChecksumAlgorithm::XXHASH64,
        BaselineChecksumAlgorithm::XXHASH3,
        BaselineChecksumAlgorithm::XXHASH128,
    ];
    let candidate = [
        CandidateChecksumAlgorithm::SHA512,
        CandidateChecksumAlgorithm::MD5,
        CandidateChecksumAlgorithm::XXHASH64,
        CandidateChecksumAlgorithm::XXHASH3,
        CandidateChecksumAlgorithm::XXHASH128,
    ];
    assert_eq!(baseline, ADDED_2026_04);
    assert_eq!(candidate, ADDED_2026_04);
    assert!(recorded.s3s_rollback.starts_with("unaffected"), "{}", recorded.s3s_rollback);

    // The entry states the operator action and answers to the writer admission / rollback issue.
    assert!(
        recorded.operator_action.contains("drain in-flight multipart uploads"),
        "{}",
        recorded.operator_action
    );
    assert!(recorded.decisions.contains(&ROLLBACK_AUTHORITY));
    assert!(recorded.decisions.contains(&"https://github.com/rustfs/gateway/issues/751"));
}

/// Positive — the real register validates and renders every entry.
#[test]
fn the_register_is_valid_and_renders_every_constraint() {
    let report = build_rollback_constraints().expect("the register is well formed");
    let rendered = report.render();
    assert!(
        rendered.starts_with("rollback constraints: entries=1 authority=https://github.com/rustfs/backlog/issues/1768\n"),
        "{rendered}"
    );
    for entry in &ROLLBACK_CONSTRAINTS {
        assert!(rendered.contains(&format!("constraint {} ", entry.id)), "{rendered}");
    }
}

/// Negative — an entry whose pinned test does not exist, or does not carry its id, is refused.
#[test]
fn n_an_entry_bound_to_no_pinned_test_is_refused() {
    let unbound = RollbackConstraint {
        test: "no_such_pinned_test",
        ..entry("rb-mpu-0001")
    };
    assert_eq!(
        validate(&[unbound], super::PINNED_TESTS),
        Err(RollbackConstraintError::UnboundTest("rb-mpu-0001"))
    );
    let renamed = RollbackConstraint {
        id: "rb-mpu-0002",
        ..entry("rb-mpu-0001")
    };
    assert_eq!(
        validate(&[renamed], super::PINNED_TESTS),
        Err(RollbackConstraintError::UnboundTest("rb-mpu-0002")),
        "the test exists but carries another id"
    );
}

/// Negative — an entry that does not answer to rustfs/backlog#1768 is refused.
#[test]
fn n_an_entry_without_the_rollback_authority_is_refused() {
    let orphan = RollbackConstraint {
        decisions: &["https://github.com/rustfs/gateway/issues/751"],
        ..entry("rb-mpu-0001")
    };
    assert_eq!(
        validate(&[orphan], super::PINNED_TESTS),
        Err(RollbackConstraintError::MissingAuthority("rb-mpu-0001"))
    );
}

/// Negative — a malformed id, a duplicate id, and an empty field are each refused by name.
#[test]
fn n_a_malformed_duplicate_or_empty_entry_is_refused() {
    let malformed = RollbackConstraint {
        id: "rb-0001",
        ..entry("rb-mpu-0001")
    };
    assert_eq!(
        validate(&[malformed], super::PINNED_TESTS),
        Err(RollbackConstraintError::MalformedId("rb-0001"))
    );
    let original = entry("rb-mpu-0001");
    assert_eq!(
        validate(&[original, original], super::PINNED_TESTS),
        Err(RollbackConstraintError::DuplicateId("rb-mpu-0001"))
    );
    let empty = RollbackConstraint {
        operator_action: " ",
        ..entry("rb-mpu-0001")
    };
    assert_eq!(
        validate(&[empty], super::PINNED_TESTS),
        Err(RollbackConstraintError::EmptyField {
            id: "rb-mpu-0001",
            field: "operator_action",
        })
    );
}

/// Negative — an empty register is not a valid one: the inventory always carries this entry.
#[test]
fn n_an_empty_register_is_refused() {
    assert_eq!(validate(&[], super::PINNED_TESTS), Err(RollbackConstraintError::Empty));
}
