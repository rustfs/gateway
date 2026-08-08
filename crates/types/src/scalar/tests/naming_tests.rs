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

//! The safety floor, the slash policy, and the proof that a validator can only narrow.
//!
//! Responsible for: every floor rule as an independent case, the two slash policies against each
//! other, the single-decode rule and the trap it exists to close, and the three properties a
//! [`NameValidator`] is not allowed to break.
//! NOT responsible for: how a rejection is rendered as an HTTP error (`rustfs-gateway-core`), or
//! where in the pipeline materialisation happens (`rustfs_gateway_core::codec::view`).
//! Upstream: [`crate::scalar::naming`], [`crate::scalar::name`]. Downstream: nothing.

use std::sync::Arc;

use crate::scalar::{
    AwsNameValidator, BucketName, NamePolicy, NameRejection, NameValidator, ObjectKey, SlashPolicy, Stricter, floor_check_bucket,
    floor_check_key,
};

/// The default policy: AWS slash semantics and the AWS bucket naming rules.
fn aws() -> NamePolicy {
    NamePolicy::default()
}

/// The MinIO-compatible policy RustFS runs in production today.
fn collapsing() -> NamePolicy {
    NamePolicy::default().with_slash_policy(SlashPolicy::Collapse)
}

/// A validator that says yes to everything — the shape a deployment reaches for when it wants
/// looser bucket names, and the shape the floor has to survive.
#[derive(Debug)]
struct PermitEverything;

impl NameValidator for PermitEverything {
    fn check_bucket(&self, _name: &str) -> Stricter {
        Stricter::NoOpinion
    }

    fn check_key(&self, _key: &str) -> Stricter {
        Stricter::NoOpinion
    }
}

/// A validator strictly narrower than the AWS rules: keys must live under `tenant/`.
#[derive(Debug)]
struct TenantPrefixOnly;

impl NameValidator for TenantPrefixOnly {
    fn check_bucket(&self, name: &str) -> Stricter {
        AwsNameValidator.check_bucket(name)
    }

    fn check_key(&self, key: &str) -> Stricter {
        if key.starts_with("tenant/") {
            Stricter::NoOpinion
        } else {
            Stricter::Reject(NameRejection::rejected_by_validator("a key must live under tenant/"))
        }
    }
}

fn permissive() -> NamePolicy {
    NamePolicy::default().with_validator(Arc::new(PermitEverything))
}

// ---------------------------------------------------------------------------
// Positive: the shapes that must keep working.
// ---------------------------------------------------------------------------

#[test]
fn c_name_0001_a_double_slash_is_preserved_under_the_default_policy() {
    // `PUT /bucket//key` splits into the bucket label `bucket` and the key label `/key`.
    let key = ObjectKey::materialize("/key", &aws()).expect("AWS preserves the empty segment");
    assert_eq!(key.as_str(), "/key");

    let inner = ObjectKey::materialize("a//b", &aws()).expect("an interior empty segment survives too");
    assert_eq!(inner.as_str(), "a//b");
}

#[test]
fn c_name_0002_the_collapse_policy_folds_runs_of_slashes() {
    let key = ObjectKey::materialize("/key", &collapsing()).expect("collapse accepts it");
    assert_eq!(key.as_str(), "key", "the MinIO-compatible spelling drops the leading empty segment");

    let inner = ObjectKey::materialize("a//b", &collapsing()).expect("collapse accepts it");
    assert_eq!(inner.as_str(), "a/b");
}

#[test]
fn c_name_0003_a_key_is_percent_decoded_exactly_once() {
    let space = ObjectKey::materialize("a%20b", &aws()).expect("an encoded space is ordinary");
    assert_eq!(space.as_str(), "a b");
    assert_eq!(space.as_encoded(), "a%20b", "the signature covers the spelling the client sent");

    let plus = ObjectKey::materialize("a%2Bb", &aws()).expect("an encoded plus is ordinary");
    assert_eq!(plus.as_str(), "a+b");

    // A single-encoded slash is a legal key byte and stays one after the single decode.
    let slash = ObjectKey::materialize("a%2Fb", &aws()).expect("one decode yields one slash");
    assert_eq!(slash.as_str(), "a/b");

    // Two three-byte characters: U+20AC EURO SIGN twice. Written as escapes rather than as the
    // glyphs, because the CJK guard reads this file and a literal is the wrong argument to have.
    let utf8 = ObjectKey::materialize("%E2%82%AC%E2%82%AC", &aws()).expect("multi-byte UTF-8 decodes once");
    assert_eq!(utf8.as_str(), "\u{20ac}\u{20ac}");
    assert_eq!(utf8.len_bytes(), 6, "the length is bytes, not characters");
}

#[test]
fn c_name_0004_a_key_at_the_byte_limit_is_accepted_and_one_past_it_is_not() {
    let at_limit = "k".repeat(1024);
    assert!(
        ObjectKey::materialize(&at_limit, &aws()).is_ok(),
        "1024 bytes is the limit, not one under it"
    );

    let over_limit = "k".repeat(1025);
    assert_eq!(
        ObjectKey::materialize(&over_limit, &aws()),
        Err(NameRejection::TooLong),
        "1025 bytes is over"
    );

    // Bytes, not characters: 342 three-byte characters is 1026 bytes and 342 characters.
    let multibyte = "€".repeat(342);
    assert_eq!(multibyte.chars().count(), 342);
    assert_eq!(multibyte.len(), 1026);
    assert_eq!(ObjectKey::materialize(&multibyte, &aws()), Err(NameRejection::TooLong));
}

#[test]
fn c_name_0005_the_bucket_length_boundaries_are_both_inclusive() {
    assert!(BucketName::materialize("abc", &aws()).is_ok());
    assert!(BucketName::materialize(&"a".repeat(63), &aws()).is_ok());
}

#[test]
fn c_name_0006_a_looser_validator_may_widen_what_the_floor_allows() {
    // Uppercase is an AWS rule, not a floor rule, so a deployment may accept it.
    assert!(BucketName::materialize("MyBucket", &aws()).is_err(), "the default rules refuse it");
    let widened = BucketName::materialize("MyBucket", &permissive()).expect("a looser validator may accept it");
    assert_eq!(widened.as_str(), "MyBucket");
}

#[test]
fn c_name_0007_a_single_dot_segment_is_a_key_byte_and_not_a_directory() {
    for key in ["a/./b", "./a", "a/.", "."] {
        let parsed = ObjectKey::materialize(key, &aws()).expect("a single dot has no path meaning to S3");
        assert_eq!(parsed.as_str(), key, "the key must survive byte for byte");
    }
}

#[test]
fn a_space_at_either_end_of_a_key_is_kept() {
    // A leading or trailing space is an ordinary key byte on AWS. Trimming it here would mean a
    // caller could never round-trip what its client sent, and two distinct objects would merge.
    for key in [" leading", "trailing ", " both "] {
        let parsed = ObjectKey::materialize(key, &aws()).expect("a space is not a control character");
        assert_eq!(parsed.as_str(), key);
    }
}

#[test]
fn unicode_is_not_nfc_normalised() {
    // U+00E9 and U+0065 U+0301 render identically and are different keys. Normalising here would
    // merge two objects a client can distinguish; the cost of not normalising is that a client
    // which sends both spellings gets both objects, which is what AWS does.
    let composed = ObjectKey::materialize("caf%C3%A9", &aws()).expect("composed");
    let decomposed = ObjectKey::materialize("cafe%CC%81", &aws()).expect("decomposed");
    assert_eq!(composed.as_str(), "caf\u{e9}");
    assert_eq!(decomposed.as_str(), "cafe\u{301}");
    assert_ne!(composed.as_str(), decomposed.as_str(), "two spellings stay two keys");
}

// ---------------------------------------------------------------------------
// Negative: the floor, one rule at a time.
// ---------------------------------------------------------------------------

#[test]
fn c_name_0009_a_dot_dot_segment_is_refused_in_every_spelling() {
    for key in ["../other/obj", "a/../b", "a/..", "..", "a/b/../../../etc/passwd"] {
        assert_eq!(
            ObjectKey::materialize(key, &aws()),
            Err(NameRejection::TraversalSegment),
            "{key:?} must not reach storage"
        );
    }
}

#[test]
fn c_name_0010_a_single_encoded_dot_dot_decodes_into_the_traversal_the_floor_refuses() {
    assert_eq!(
        ObjectKey::materialize("%2e%2e/other/obj", &aws()),
        Err(NameRejection::TraversalSegment),
        "one decode turns %2e%2e into .., which the floor sees"
    );
    assert_eq!(ObjectKey::materialize("%2E%2E%2Fx", &aws()), Err(NameRejection::TraversalSegment));
}

#[test]
fn c_name_0011_a_double_encoded_traversal_is_refused_rather_than_decoded_twice() {
    // `%252e%252e` decodes *once* to `%2e%2e`. Decoding again would produce `..`, which is the
    // trap; refusing the residue is how "exactly one decode" is made observable.
    assert_eq!(
        ObjectKey::materialize("%252e%252e/x", &aws()),
        Err(NameRejection::EncodedSeparator),
        "the once-decoded value still spells a traversal"
    );
    assert_eq!(
        ObjectKey::materialize("a%252Fb", &aws()),
        Err(NameRejection::EncodedSeparator),
        "an encoded separator surviving one decode is refused"
    );
    assert_eq!(ObjectKey::materialize("a%255Cb", &aws()), Err(NameRejection::EncodedSeparator));
}

#[test]
fn a_percent_that_is_not_an_encoded_separator_survives_one_decode() {
    // The residue rule is about separators, not about the percent sign: a key may contain one.
    let literal = ObjectKey::materialize("100%25done", &aws()).expect("an encoded percent is a key byte");
    assert_eq!(literal.as_str(), "100%done");
    let dot = ObjectKey::materialize("v1%252e0", &aws()).expect("a single encoded dot is not a traversal");
    assert_eq!(dot.as_str(), "v1%2e0");
}

#[test]
fn c_name_0012_a_backslash_delimited_traversal_is_refused() {
    for key in ["..\\x", "a\\..\\b", "a\\..", "..\\..\\etc\\passwd"] {
        assert_eq!(
            ObjectKey::materialize(key, &aws()),
            Err(NameRejection::TraversalSegment),
            "{key:?}: a backslash is a separator on the platform the storage layer may run on"
        );
    }
    // A backslash that is not delimiting a traversal is an ordinary key byte, as it is on AWS.
    let ordinary = ObjectKey::materialize("a%5Cb", &aws()).expect("a lone backslash is a key byte");
    assert_eq!(ordinary.as_str(), "a\\b");
}

#[test]
fn c_name_0013_a_nul_or_control_character_is_refused() {
    assert_eq!(ObjectKey::materialize("a%00b", &aws()), Err(NameRejection::Nul));
    for key in ["a%01b", "a%1Fb", "a%7Fb", "a%09b", "a%0Ab", "a%0Db"] {
        assert_eq!(
            ObjectKey::materialize(key, &aws()),
            Err(NameRejection::ControlCharacter),
            "{key:?} must not be a name a client can choose"
        );
    }
}

#[test]
fn c_name_0014_absolute_and_unc_key_shapes_are_refused() {
    for key in [
        "C:\\x",
        "c:/x",
        "\\\\?\\UNC\\x",
        "\\\\server\\share",
        "//server/share",
        "///x",
    ] {
        assert!(
            ObjectKey::materialize(key, &aws()).is_err(),
            "{key:?} names a location rather than an object"
        );
    }
    // One leading slash is the AWS `PUT /bucket//key` spelling and stays legal; two is the UNC one.
    assert!(ObjectKey::materialize("/key", &aws()).is_ok());
    assert_eq!(ObjectKey::materialize("//key", &aws()), Err(NameRejection::AbsoluteOrUnc));
}

#[test]
fn c_name_0015_a_key_that_is_not_utf8_after_one_decode_is_refused() {
    assert_eq!(ObjectKey::materialize("a%FFb", &aws()), Err(NameRejection::InvalidUtf8));
    assert_eq!(
        ObjectKey::materialize("%ED%A0%80", &aws()),
        Err(NameRejection::InvalidUtf8),
        "a surrogate half is not UTF-8 and is not replaced lossily"
    );
}

#[test]
fn c_name_0016_an_empty_key_is_refused_under_both_policies() {
    assert_eq!(ObjectKey::materialize("", &aws()), Err(NameRejection::Empty));
    // Collapse can turn a non-empty label into an empty key; the floor still runs afterwards.
    assert_eq!(ObjectKey::materialize("/", &collapsing()), Err(NameRejection::Empty));
    assert_eq!(ObjectKey::materialize("//", &collapsing()), Err(NameRejection::Empty));
}

#[test]
fn c_name_0017_a_permissive_validator_cannot_open_a_traversal() {
    // E-1: the floor runs first and the validator's answer is AND-ed with it. `PermitEverything`
    // says yes to every one of these and every one is still refused.
    for key in ["../x", "a/../b", "a%00b", "%2e%2e/x", "\\\\?\\UNC\\x", "//server/share"] {
        assert!(
            ObjectKey::materialize(key, &permissive()).is_err(),
            "{key:?} was let through by a validator that has no power to let it through"
        );
    }
    for name in ["", "ab", &"a".repeat(64), "has/slash", "has\0nul"] {
        assert!(
            BucketName::materialize(name, &permissive()).is_err(),
            "{name:?} is refused by the floor whatever the validator says"
        );
    }
}

#[test]
fn a_stricter_validator_narrows_what_the_floor_allowed() {
    let policy = NamePolicy::default().with_validator(Arc::new(TenantPrefixOnly));
    assert!(ObjectKey::materialize("tenant/a.txt", &policy).is_ok());
    assert_eq!(
        ObjectKey::materialize("other/a.txt", &policy),
        Err(NameRejection::rejected_by_validator("a key must live under tenant/")),
        "a validator may refuse what the floor allowed"
    );
    // And it still cannot re-open the floor.
    assert_eq!(ObjectKey::materialize("tenant/../etc", &policy), Err(NameRejection::TraversalSegment));
}

#[test]
fn c_name_0025_the_bucket_floor_and_the_aws_rules_are_separable() {
    // Floor rules: no deployment can turn these off.
    for name in ["", "ab", &"a".repeat(64), "a/b", "a\\b", "a\u{0}b", "a\u{1}b", "a b", "a%2Fb"] {
        assert!(floor_check_bucket(name).is_err(), "{name:?} must be refused by the floor");
    }
    // AWS rules: the default validator refuses these, and only the default validator does.
    for name in [
        "MyBucket",
        "my_bucket",
        "-bucket",
        "bucket-",
        ".bucket",
        "bucket.",
        "my..bucket",
    ] {
        assert!(floor_check_bucket(name).is_ok(), "{name:?} is not a floor violation");
        assert!(BucketName::materialize(name, &aws()).is_err(), "{name:?} breaks the AWS rules");
    }
    assert!(BucketName::materialize("192.168.1.1", &aws()).is_err(), "an IPv4 shape is reserved");
    assert!(BucketName::materialize("xn--bucket", &aws()).is_err());
    assert!(BucketName::materialize("bucket-s3alias", &aws()).is_err());
    assert!(
        BucketName::materialize("bucket--x-s3", &aws()).is_err(),
        "the S3 Express directory-bucket suffix is not accepted by the general rules"
    );
}

#[test]
fn the_key_floor_is_reachable_on_an_already_decoded_value() {
    // The body-element and query paths hand over a value that was decoded by their own reader, so
    // the floor has to be callable without a second decode.
    assert!(floor_check_key("ordinary/key.txt").is_ok());
    assert_eq!(floor_check_key("a/../b"), Err(NameRejection::TraversalSegment));
    assert_eq!(floor_check_key("a\u{1}b"), Err(NameRejection::ControlCharacter));
    assert_eq!(floor_check_key(""), Err(NameRejection::Empty));
}

#[test]
fn every_floor_rejection_names_an_error_code_and_a_reason() {
    let all = [
        NameRejection::Empty,
        NameRejection::TooShort,
        NameRejection::TooLong,
        NameRejection::Nul,
        NameRejection::ControlCharacter,
        NameRejection::TraversalSegment,
        NameRejection::EncodedSeparator,
        NameRejection::AbsoluteOrUnc,
        NameRejection::PathSeparator,
        NameRejection::InvalidUtf8,
        NameRejection::CharacterSet,
        NameRejection::Reserved,
        NameRejection::rejected_by_validator("because"),
    ];
    for rejection in all {
        assert!(!rejection.reason().is_empty(), "{rejection:?} has no reason");
    }
    assert_eq!(NameRejection::TooLong.key_error_code(), crate::ErrorCode::KEY_TOO_LONG);
    assert_eq!(NameRejection::TraversalSegment.key_error_code(), crate::ErrorCode::INVALID_ARGUMENT);
}

#[test]
fn the_slash_policy_runs_before_the_floor_and_not_after_it() {
    // Collapse folds slashes; it is not a cleaner. A traversal survives it and is then refused.
    assert_eq!(
        ObjectKey::materialize("a//../b", &collapsing()),
        Err(NameRejection::TraversalSegment),
        "collapsing does not resolve a dot-dot segment"
    );
    // And a shape the floor refuses under AwsPreserve becomes legal under Collapse only when
    // collapsing genuinely removed the offending run.
    assert_eq!(ObjectKey::materialize("//key", &aws()), Err(NameRejection::AbsoluteOrUnc));
    assert_eq!(
        ObjectKey::materialize("//key", &collapsing()).map(|k| k.as_str().to_owned()),
        Ok("key".to_owned())
    );
}

#[test]
fn a_collapsed_key_keeps_the_spelling_the_signature_covers() {
    let key = ObjectKey::materialize("a//b", &collapsing()).expect("collapse accepts it");
    assert_eq!(key.as_str(), "a/b", "storage and authorization see the collapsed value");
    assert_eq!(key.as_encoded(), "a//b", "the signature still covers what arrived on the wire");
}

#[test]
fn a_thousand_slashes_are_refused_or_folded_without_quadratic_work() {
    let many = format!("a{}", "/".repeat(10_000));
    // Under AwsPreserve the run is kept, so the key is 10_001 bytes and the limit refuses it.
    assert_eq!(ObjectKey::materialize(&many, &aws()), Err(NameRejection::TooLong));
    // Under Collapse the run folds *before* the floor runs, so the same input is a two-byte key.
    // This is the observable consequence of the documented order and is pinned in both
    // directions: a length check placed before the policy would refuse this one too.
    assert_eq!(
        ObjectKey::materialize(&many, &collapsing()).map(|k| k.as_str().to_owned()),
        Ok("a/".to_owned())
    );

    // A run that fits: collapsing is linear and the result is what it says.
    let short = format!("a{}b", "/".repeat(500));
    assert_eq!(
        ObjectKey::materialize(&short, &collapsing()).map(|k| k.as_str().to_owned()),
        Ok("a/b".to_owned())
    );
}

#[test]
fn the_default_policy_is_the_aws_one() {
    assert_eq!(NamePolicy::default().slash_policy(), SlashPolicy::AwsPreserve);
    // M-9: switching the policy renames every object whose key held an empty segment, so the two
    // values answer this question differently and a start-up posture report can print it.
    assert!(!SlashPolicy::AwsPreserve.rewrites_keys());
    assert!(SlashPolicy::Collapse.rewrites_keys());
}
