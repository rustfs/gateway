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

//! The legacy RustFS key floor (rustfs/gateway#1107), held to the keys legacy RustFS accepts.
//!
//! Responsible for: [`KeyFloor::RustfsLegacy`] — every key legacy RustFS's protocol front hands its
//! storage reaches the handler as the same bytes, the three representation rules (empty, longer
//! than 1024 bytes, NUL) still refuse, the single decode stays single, the validator still runs,
//! and the default floor does not move.
//! NOT responsible for: the default floor rule by rule (`naming_tests.rs`), or where in the
//! pipeline the key is materialised (`rustfs_gateway_core::codec::view`).
//! Upstream: [`crate::scalar::naming`]. Downstream: nothing.

use std::sync::Arc;

use crate::scalar::{KeyFloor, NamePolicy, NameRejection, NameValidator, ObjectKey, SlashPolicy, Stricter};

/// The RustFS profile's naming: the legacy slash rule and the legacy key floor.
fn legacy() -> NamePolicy {
    NamePolicy::default()
        .with_slash_policy(SlashPolicy::RustfsLegacy)
        .with_legacy_rustfs_key_floor()
}

fn path_key(label: &str) -> Result<String, NameRejection> {
    ObjectKey::materialize(label, &legacy()).map(|key| key.as_str().to_owned())
}

fn body_key(decoded: &str) -> Result<String, NameRejection> {
    ObjectKey::materialize_decoded(decoded, &legacy()).map(|key| key.as_str().to_owned())
}

// ---------------------------------------------------------------------------
// Positive: what legacy RustFS stores reaches the handler as the same bytes.
// ---------------------------------------------------------------------------

#[test]
fn every_key_legacy_rustfs_stores_reaches_the_handler_unchanged() {
    // Each measured on legacy RustFS: `PUT /b/<label>` answered 200 and `GET` read it back.
    for (label, stored) in [
        ("a%01b", "a\u{1}b"),
        ("a%09b", "a\tb"),
        ("a%0Bb", "a\u{b}b"),
        ("a%1Fb", "a\u{1f}b"),
        ("a%7Fb", "a\u{7f}b"),
        ("a%C2%85b", "a\u{85}b"),
        ("a%252Fb", "a%2Fb"),
        ("a%255Cb", "a%5Cb"),
        ("a%252e%252e", "a%2e%2e"),
        ("%5Cx", "\\x"),
        ("%5C%5Cserver%5Cshare", "\\\\server\\share"),
        ("C:%5Cx", "C:\\x"),
        ("c:/x", "c:/x"),
        ("100%25done", "100%done"),
    ] {
        assert_eq!(path_key(label), Ok(stored.to_owned()), "{label:?}");
    }
}

#[test]
fn keys_legacy_rustfs_refuses_in_its_storage_reach_the_handler_to_be_refused_there() {
    // Legacy RustFS's protocol front hands these to RustFS, whose storage layer answers
    // `400 InvalidArgument` after authorization; the gateway hands them over the same way.
    for (label, handed) in [
        ("a/../b", "a/../b"),
        ("../b", "../b"),
        ("a/..", "a/.."),
        ("a/./b", "a/./b"),
        ("..", ".."),
        (".", "."),
        ("a%5C..%5Cb", "a\\..\\b"),
        ("a/%20../b", "a/ ../b"),
        ("a%0Ab", "a\nb"),
        ("a%0Db", "a\rb"),
        ("a//b", "a//b"),
    ] {
        assert_eq!(path_key(label), Ok(handed.to_owned()), "{label:?}");
    }
}

#[test]
fn a_body_key_is_held_to_the_same_rule() {
    // `DeleteObjects` names these in its body; legacy RustFS answers each with a per-key error
    // and deletes the rest, so none of them may refuse the whole request.
    for key in ["a/../b", "//x", "/", "a\u{1}b", "C:\\x"] {
        assert_eq!(body_key(key), Ok(key.to_owned()), "{key:?}");
    }
}

// ---------------------------------------------------------------------------
// Negative: what the legacy floor must still refuse, and what it must not change.
// ---------------------------------------------------------------------------

#[test]
fn n_the_three_representation_rules_still_refuse() {
    assert_eq!(path_key("a%00b"), Err(NameRejection::Nul), "an ObjectKey cannot hold a NUL");
    assert_eq!(body_key("a\u{0}b"), Err(NameRejection::Nul));
    assert_eq!(body_key(""), Err(NameRejection::Empty));
    assert_eq!(path_key(&"k".repeat(1025)), Err(NameRejection::TooLong));
    assert_eq!(body_key(&"k".repeat(1025)), Err(NameRejection::TooLong));
    assert_eq!(path_key(&"k".repeat(1024)).map(|key| key.len()), Ok(1024));
}

#[test]
fn n_the_single_decode_stays_single() {
    // The residue is kept as literal text, never decoded a second time into a separator.
    assert_eq!(path_key("%252e%252e/x"), Ok("%2e%2e/x".to_owned()));
    assert_eq!(path_key("a%252Fb").map(|key| key.contains('/')), Ok(false));
    assert_eq!(path_key("a%FFb"), Err(NameRejection::InvalidUtf8), "still UTF-8 or nothing");
}

#[test]
fn n_the_slash_rule_still_runs_first() {
    // The floor reads the folded key: `//x` is `x`, and a key of slashes only is `/`.
    assert_eq!(path_key("//x"), Ok("x".to_owned()));
    assert_eq!(path_key("//"), Ok("/".to_owned()));
    let folded_at_limit = format!("/{}", "k".repeat(1024));
    assert_eq!(path_key(&folded_at_limit).map(|key| key.len()), Ok(1024));
}

#[derive(Debug)]
struct TenantPrefixOnly;

impl NameValidator for TenantPrefixOnly {
    fn check_bucket(&self, _name: &str) -> Stricter {
        Stricter::NoOpinion
    }

    fn check_key(&self, key: &str) -> Stricter {
        if key.starts_with("tenant/") {
            Stricter::NoOpinion
        } else {
            Stricter::Reject(NameRejection::rejected_by_validator("a key must live under tenant/"))
        }
    }
}

#[test]
fn n_the_validator_still_runs_after_the_legacy_floor() {
    let policy = legacy().with_validator(Arc::new(TenantPrefixOnly));
    assert!(ObjectKey::materialize("tenant/a%01b", &policy).is_ok());
    assert_eq!(
        ObjectKey::materialize("other/a%01b", &policy),
        Err(NameRejection::rejected_by_validator("a key must live under tenant/"))
    );
}

#[test]
fn n_the_default_floor_does_not_move() {
    let default = NamePolicy::default();
    assert_eq!(default.key_floor(), KeyFloor::Unconditional);
    assert_eq!(ObjectKey::materialize("a/../b", &default), Err(NameRejection::TraversalSegment));
    assert_eq!(ObjectKey::materialize("a%01b", &default), Err(NameRejection::ControlCharacter));
    assert_eq!(ObjectKey::materialize("a%252Fb", &default), Err(NameRejection::EncodedSeparator));
    assert_eq!(ObjectKey::materialize("%5Cx", &default), Err(NameRejection::AbsoluteOrUnc));
    assert_eq!(ObjectKey::materialize_decoded("a/../b", &default), Err(NameRejection::TraversalSegment));
    // The slash rule alone does not lower the floor: only the named floor does.
    let slash_only = NamePolicy::default().with_slash_policy(SlashPolicy::RustfsLegacy);
    assert_eq!(slash_only.key_floor(), KeyFloor::Unconditional);
    assert_eq!(ObjectKey::materialize("a%01b", &slash_only), Err(NameRejection::ControlCharacter));
}

#[test]
fn n_the_bucket_floor_is_not_the_key_floor() {
    use crate::scalar::BucketName;
    for name in ["a%2Fb", "a/b", "a\u{1}b", "ab"] {
        assert!(BucketName::materialize(name, &legacy()).is_err(), "{name:?}");
    }
}

#[test]
fn n_the_floor_names_itself_and_says_it_lowers_the_default() {
    assert!(KeyFloor::RustfsLegacy.lowers_the_default());
    assert!(!KeyFloor::Unconditional.lowers_the_default());
    assert_eq!(KeyFloor::RustfsLegacy.as_str(), "rustfs-legacy");
    assert_eq!(KeyFloor::Unconditional.as_str(), "unconditional");
    assert_eq!(legacy().key_floor(), KeyFloor::RustfsLegacy);
}
