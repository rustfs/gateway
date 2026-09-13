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

//! Revision-selection tests for the compat oracle facade.
//!
//! Responsible for: proving the manifest pins exactly the revisions `OracleRevision` names, that
//! selecting a revision reaches a different compilation in both directions, and that the selection
//! is always restored. NOT responsible for: D1-D5 assertions, which stay in
//! `rustfs-gateway-goldens`. Upstream: `super`. Downstream: none; test-only.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;
use crate::persistence::{PersistedBlockedEncryptionTypes, PersistedBucketEncryptionRule, PersistedEncryptionByDefault};

/// A Rule member s3s `bdcb6259` and later read and `9c4690d8` refuses as an unknown child.
const BLOCKED_SSE_C: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><BlockedEncryptionTypes><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes></Rule></ServerSideEncryptionConfiguration>";

#[test]
fn every_revision_is_the_one_the_manifest_pins() {
    let manifest = include_str!("../../Cargo.toml");
    for (alias, oracle) in [
        ("s3s_baseline", OracleRevision::Baseline),
        ("s3s_rollback", OracleRevision::Rollback),
        ("s3s_candidate", OracleRevision::Candidate),
    ] {
        let line = manifest
            .lines()
            .find(|line| line.starts_with(&format!("{alias} = ")))
            .unwrap_or_else(|| panic!("{alias} must be declared"));
        assert!(line.contains("package = \"s3s\""), "{line}");
        assert!(line.contains(&format!("git = \"{}\"", oracle.repository())), "{line}");
        assert!(line.contains(&format!("rev = \"{}\"", oracle.revision())), "{line}");
        assert!(line.contains("optional = true"), "{line}");
    }
    let revisions = OracleRevision::ALL.map(OracleRevision::revision);
    for (index, revision) in revisions.iter().enumerate() {
        assert!(!revisions[..index].contains(revision), "{revision} plays two roles");
    }
    assert!(
        !manifest.lines().any(|line| line.starts_with("s3s = ")),
        "a bare `s3s` would let an adapter that forgot `super::` measure the baseline silently"
    );
}

fn blocked_sse_c() -> PersistedBucketEncryptionConfiguration {
    PersistedBucketEncryptionConfiguration {
        rules: vec![PersistedBucketEncryptionRule {
            blocked_encryption_types: Some(PersistedBlockedEncryptionTypes {
                encryption_types: vec!["SSE-C".to_owned()],
            }),
            ..PersistedBucketEncryptionRule::default()
        }],
    }
}

/// rustfs/gateway#740: the rollback and candidate revisions read the member into the persisted
/// structure, and the baseline still refuses it as an unknown `Rule` child.
#[test]
fn only_revisions_with_the_newer_member_read_blocked_encryption_types() {
    assert_eq!(selected_oracle(), OracleRevision::Baseline);
    parse_s3s_bucket_encryption(BLOCKED_SSE_C).expect_err("s3s 9c4690d8 refuses the unknown Rule child");
    for oracle in [OracleRevision::Rollback, OracleRevision::Candidate] {
        let read = with_oracle(oracle, || parse_s3s_bucket_encryption(BLOCKED_SSE_C)).expect("the newer revisions read it");
        assert_eq!(read.structure, blocked_sse_c(), "{oracle}: the member is carried, never dropped");
        assert_eq!(read.behavior, [(None, None, None, Some(vec!["SSE-C".to_owned()]))], "{oracle}");
        let written = with_oracle(oracle, || serialize_s3s_bucket_encryption(&blocked_sse_c())).expect("and write it");
        assert_eq!(written, BLOCKED_SSE_C, "{oracle}");
    }
}

/// The baseline has no field for the member, so its writer refuses rather than dropping the block.
#[test]
fn n_the_baseline_writer_refuses_a_block_it_cannot_carry() {
    let error = serialize_s3s_bucket_encryption(&blocked_sse_c()).expect_err("dropping the block would unblock SSE-C");
    assert!(error.to_string().contains("BlockedEncryptionTypes"), "{error}");
}

#[test]
fn every_revision_writes_and_reads_the_same_bucket_encryption_bytes() {
    let value = PersistedBucketEncryptionConfiguration {
        rules: vec![PersistedBucketEncryptionRule {
            apply_server_side_encryption_by_default: Some(PersistedEncryptionByDefault {
                sse_algorithm: "aws:kms".to_owned(),
                kms_master_key_id: Some("key".to_owned()),
            }),
            bucket_key_enabled: Some(true),
            blocked_encryption_types: None,
        }],
    };
    let written = OracleRevision::ALL
        .map(|oracle| with_oracle(oracle, || serialize_s3s_bucket_encryption(&value)).expect("every revision writes the rule"));
    assert_eq!(written[0], written[1]);
    assert_eq!(written[0], written[2]);
    for oracle in OracleRevision::ALL {
        let read = with_oracle(oracle, || parse_s3s_bucket_encryption(&written[0])).expect("every revision reads its own bytes");
        assert_eq!(read.structure, value, "{oracle}");
    }
}

#[test]
fn selection_is_restored_after_nesting_and_after_a_panic() {
    with_oracle(OracleRevision::Candidate, || {
        assert_eq!(selected_oracle(), OracleRevision::Candidate);
        with_oracle(OracleRevision::Rollback, || assert_eq!(selected_oracle(), OracleRevision::Rollback));
        assert_eq!(selected_oracle(), OracleRevision::Candidate);
    });
    assert_eq!(selected_oracle(), OracleRevision::Baseline);
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        with_oracle(OracleRevision::Candidate, || panic!("a measurement failed mid-run"))
    }));
    assert!(unwound.is_err());
    assert_eq!(selected_oracle(), OracleRevision::Baseline);
}

#[test]
fn display_names_role_and_short_revision() {
    assert_eq!(OracleRevision::Baseline.to_string(), "baseline s3s@9c4690d8");
    assert_eq!(OracleRevision::Rollback.to_string(), "rollback s3s@bdcb6259");
    assert_eq!(OracleRevision::Candidate.to_string(), "candidate s3s@f3e17541");
}

#[test]
fn every_rustfs_build_names_a_pinned_commit_and_a_build() {
    for (oracle, build) in [
        (OracleRevision::Baseline, "1.0.0-rc.5-preview.2"),
        (OracleRevision::Rollback, "1.0.0-rc.6"),
        (OracleRevision::Candidate, "main"),
    ] {
        let named = oracle.rustfs_build();
        let commit = named
            .strip_prefix("rustfs/rustfs@")
            .and_then(|rest| rest.strip_suffix(&format!(" ({build})")))
            .unwrap_or_else(|| panic!("{oracle}: {named}"));
        assert_eq!(commit.len(), 40, "{oracle}: {named}");
        assert!(
            commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{oracle}: {named}"
        );
    }
}
