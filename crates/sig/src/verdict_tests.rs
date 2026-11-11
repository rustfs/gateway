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

//! The verdict's own unit suite, split out at the 800-line limit.
//!
//! Responsible for: what is decidable from a `Verdict`, an `Identity` and an `AuthError` alone —
//! the anonymous evidence rule, the shared credential-rejection message, the audit rendering, the
//! verified scope a verdict carries, and the access key id grammar.
//! NOT responsible for: how a verdict is reached, which is `crates/sig/tests/*.rs`, or the
//! compile-time guarantees, which are the doctests in `super`.
//! Upstream: `super`. Downstream: Cargo's test harness.

use super::*;
use crate::scheme::{SigIdentity, SigService};

fn identity() -> Identity {
    Identity::new("AKIAIOSFODNN7EXAMPLE").expect("valid access key id")
}

#[test]
fn no_credentials_yields_anonymous() {
    let evidence = CredentialPresence::NONE.into_evidence().expect("nothing presented");
    assert!(Verdict::anonymous(evidence).is_anonymous());
}

#[test]
fn presented_credentials_cannot_be_downgraded_to_anonymous() {
    let presented = CredentialPresence::NONE.with_authorization_header();
    assert_eq!(presented.into_evidence().err(), Some(CredentialsWerePresented));
}

#[test]
fn a_security_token_alone_still_counts_as_presented() {
    let presented = CredentialPresence::NONE.with_security_token();
    assert!(presented.any());
    assert!(presented.into_evidence().is_err());
}

#[test]
fn the_two_credential_rejections_share_one_message() {
    assert_eq!(AuthError::InvalidAccessKeyId.message(), AuthError::SignatureDoesNotMatch.message());
    assert_ne!(AuthError::InvalidAccessKeyId.code(), AuthError::SignatureDoesNotMatch.code());
}

#[test]
fn algorithm_mismatch_is_not_reported_to_the_client() {
    assert_eq!(AuthError::from(VerifyRejection::AlgorithmMismatch), AuthError::SignatureDoesNotMatch);
    assert_eq!(AuthError::from(VerifyRejection::Mismatch), AuthError::SignatureDoesNotMatch);
}

#[test]
fn a_rejected_verdict_names_no_principal() {
    let verdict = Verdict::reject(AuthError::InvalidAccessKeyId);
    assert!(verdict.identity().is_none());
    assert!(!verdict.is_authenticated());
}

#[test]
fn debug_of_an_authenticated_verdict_shows_the_key_id_and_no_proof_bytes() {
    let scheme = AuthScheme::sigv4_header(SigIdentity::LongTerm, SigService::S3);
    let proof = crate::Signature::HmacSha256(crate::CtBytes::from_array([3u8; 32]))
        .ct_verify(&crate::Signature::HmacSha256(crate::CtBytes::from_array([3u8; 32])))
        .expect("equal signatures match");
    let rendered = format!("{:?}", Verdict::authenticated(identity(), scheme, proof));
    assert!(rendered.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(rendered.contains("<constant-time match>"));
}

fn proof() -> SignatureMatch {
    crate::Signature::HmacSha256(crate::CtBytes::from_array([3u8; 32]))
        .ct_verify(&crate::Signature::HmacSha256(crate::CtBytes::from_array([3u8; 32])))
        .expect("equal signatures match")
}

fn scope(region: &str) -> VerifiedScope {
    VerifiedScope::from_checked_parts(crate::ScopeDate::parse("20150830").expect("valid"), region, "s3")
}

/// Positive — the scope the signature was verified under travels with the verdict, every
/// field in the spelling that was signed.
#[test]
fn an_authenticated_verdict_carries_the_scope_it_was_verified_under() {
    let scheme = AuthScheme::sigv4_header(SigIdentity::LongTerm, SigService::S3);
    let verdict = Verdict::authenticated_in_scope(identity(), scheme, scope("eu-west-1"), proof());
    let carried = verdict.verified_scope().expect("a SigV4 verdict names its scope");
    assert_eq!(
        (carried.date().as_str(), carried.region(), carried.service()),
        ("20150830", "eu-west-1", "s3")
    );
}

/// Negative — a verdict that was never given a scope reports none, whatever its outcome. A
/// scope is never inferred: SigV2 and a custom scheme have no credential scope at all.
#[test]
fn a_verdict_built_without_a_scope_reports_none() {
    let scheme = AuthScheme::sigv2_header(SigIdentity::LongTerm, SigService::S3);
    assert!(Verdict::authenticated(identity(), scheme, proof()).verified_scope().is_none());
    assert!(Verdict::reject(AuthError::SignatureDoesNotMatch).verified_scope().is_none());
    let evidence = CredentialPresence::NONE.into_evidence().expect("nothing presented");
    assert!(Verdict::anonymous(evidence).verified_scope().is_none());
}

/// Negative — the audit rendering names the scope, which is public, and still no proof bytes.
#[test]
fn debug_of_a_scoped_verdict_names_the_scope() {
    let scheme = AuthScheme::sigv4_header(SigIdentity::LongTerm, SigService::S3);
    let rendered = format!("{:?}", Verdict::authenticated_in_scope(identity(), scheme, scope("eu-west-1"), proof()));
    assert!(rendered.contains("eu-west-1"), "{rendered}");
    assert!(rendered.contains("<constant-time match>"), "{rendered}");
}

#[test]
fn access_key_ids_with_control_characters_are_rejected() {
    for bad in ["", "AKIA\r\nX-Injected: 1", "AKIA KEY", "AKIA\u{0}KEY", "AKIA\u{e9}KEY"] {
        assert_eq!(Identity::new(bad), Err(SigParseError::InvalidAccessKeyId), "must reject {bad:?}");
    }
    assert_eq!(Identity::new(&"A".repeat(129)), Err(SigParseError::InvalidAccessKeyId));
}
