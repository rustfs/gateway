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

//! Bucket name and object key cases, including the non-normalisation guarantee.
//!
//! Responsible for: the length and character boundaries, the reserved shapes, the predicates, and
//! the property that decoding a key never rewrites it.
//! NOT responsible for: pluggable naming policy, which arrives with the validator extension point.
//! Upstream: [`crate::scalar::name`]. Downstream: nothing.

use proptest::prelude::*;

use crate::scalar::{BucketName, ObjectKey};

#[test]
fn c_name_0001_an_ordinary_key_is_accepted() {
    let key = ObjectKey::new("a/b/c.txt").expect("an ordinary key is valid");
    assert_eq!(key.as_str(), "a/b/c.txt");
    assert_eq!(key.len_bytes(), 9);
    assert!(!key.needs_url_encoding());
}

#[test]
fn c_name_0002_an_ordinary_bucket_name_is_accepted() {
    let bucket = BucketName::new("my-bucket-1").expect("an ordinary bucket name is valid");
    assert_eq!(bucket.as_str(), "my-bucket-1");
    assert!(bucket.is_vhost_safe());
}

#[test]
fn c_name_n001_a_key_over_the_byte_limit_is_rejected() {
    let at_limit = "k".repeat(1024);
    assert!(ObjectKey::new(at_limit).is_ok());
    let over_limit = "k".repeat(1025);
    assert!(ObjectKey::new(over_limit).is_err());
    assert!(ObjectKey::new("").is_err());

    // The limit is bytes, not characters: 342 three-byte characters plus one is over it.
    let multibyte = "€".repeat(342);
    assert_eq!(multibyte.len(), 1026);
    assert!(ObjectKey::new(multibyte).is_err());
}

#[test]
fn c_name_n002_a_nul_in_a_key_is_rejected() {
    assert!(ObjectKey::new("a\u{0}b").is_err());
}

#[test]
fn c_name_n003_keys_are_never_normalised() {
    // Collapsing `//` or resolving `..` here would make the value the authorizer sees differ from
    // the value the storage layer uses, which is the shape of two published advisories.
    for key in ["a//b", "a/./b", "a/../b", "./a", "a/b/", "//"] {
        let parsed = ObjectKey::new(key).expect("every one of these is a legal key");
        assert_eq!(parsed.as_str(), key, "the key must survive byte for byte");
    }
}

#[test]
fn c_name_n004_control_characters_force_url_encoding() {
    for key in ["a\u{1}b", "a\u{7}b", "a\u{1f}b"] {
        assert!(
            ObjectKey::new(key).expect("legal key").needs_url_encoding(),
            "{key:?} has no XML spelling at all, escaped or otherwise"
        );
    }
    // The three characters XML *can* carry out of the C0 block do not force anything.
    for key in ["a\tb", "a\nb", "a\rb", "a b"] {
        assert!(!ObjectKey::new(key).expect("legal key").needs_url_encoding(), "{key:?}");
    }
    // `&` and `<` used to be asserted here as forcing encoding. They are XML-representable, the
    // writer escapes them, and `conformance/cases/list/c-list-0036` pins that a key carrying `&`,
    // `<`, `>` and `"` comes back escaped rather than percent-encoded. The original assertion
    // therefore contradicted the wire contract: acting on it would rewrite keys every client
    // already reads correctly, and it was only invisible because nothing called the predicate.
    for key in ["a&b", "a<b", "a>b", "a\"b"] {
        assert!(!ObjectKey::new(key).expect("legal key").needs_url_encoding(), "{key:?}");
    }
}

#[test]
fn xml_representability_is_about_the_bytes_not_the_escaping() {
    use crate::scalar::is_xml_representable;

    assert!(is_xml_representable("ordinary/key.txt"));
    assert!(is_xml_representable("a&b<c>d\"e\t\n\r"), "everything here has an XML spelling");
    assert!(!is_xml_representable("ctrl\u{1}key.txt"));
    assert!(!is_xml_representable("\u{b}"), "a vertical tab is excluded like the rest of C0");
    assert!(!is_xml_representable("\u{fffe}"), "XML 1.0 excludes the final two BMP code points");
    assert!(!is_xml_representable("\u{ffff}"), "XML 1.0 excludes the final two BMP code points");
}

#[test]
fn a_percent_encoded_key_keeps_both_spellings() {
    let key = ObjectKey::from_encoded_path("a%2Fb%20c").expect("valid");
    assert_eq!(key.as_str(), "a/b c", "the decoded form is what authorization and storage use");
    assert_eq!(key.as_encoded(), "a%2Fb%20c", "the encoded form is what the signature covers");

    let plain = ObjectKey::from_encoded_path("plain").expect("valid");
    assert_eq!(plain.as_encoded(), "plain");
}

#[test]
fn an_invalid_utf8_percent_sequence_is_rejected() {
    assert!(ObjectKey::from_encoded_path("a%FFb").is_err());
    assert!(ObjectKey::from_encoded_path("a%00b").is_err());
}

#[test]
fn c_name_n005_an_ipv4_shaped_bucket_name_is_rejected() {
    assert!(BucketName::new("192.168.0.1").is_err());
    assert!(BucketName::new("255.255.255.255").is_err());
    // Only a full four-octet shape is reserved; these are ordinary names.
    assert!(BucketName::new("192.168.0").is_ok());
    assert!(BucketName::new("192.168.0.1.2").is_ok());
    assert!(BucketName::new("256.256.256.256").is_ok());
}

#[test]
fn c_name_n006_the_length_bounds_are_enforced() {
    assert!(BucketName::new("ab").is_err());
    assert!(BucketName::new("abc").is_ok());
    assert!(BucketName::new("a".repeat(63)).is_ok());
    assert!(BucketName::new("a".repeat(64)).is_err());
}

#[test]
fn the_bucket_character_set_and_edges_are_enforced() {
    for name in [
        "my_bucket", // underscore
        "-bucket",   // leading hyphen
        "bucket-",   // trailing hyphen
        ".bucket",   // leading dot
        "bucket.",   // trailing dot
        "my bucket", // space
    ] {
        assert!(BucketName::new(name).is_err(), "{name} must be rejected");
    }
}

#[test]
fn c_name_n007_uppercase_bucket_names_are_rejected() {
    assert!(BucketName::new("My-Bucket").is_err());
    assert!(BucketName::new("MY-BUCKET").is_err());
}

#[test]
fn c_name_n008_consecutive_dots_are_rejected() {
    assert!(BucketName::new("a..b").is_err());
    assert!(BucketName::new("my..bucket").is_err());
}

#[test]
fn reserved_prefixes_and_suffixes_are_rejected() {
    assert!(BucketName::new("xn--bucket").is_err());
    assert!(BucketName::new("sthree-bucket").is_err());
    assert!(BucketName::new("bucket-s3alias").is_err());
    assert!(BucketName::new("bucket--ol-s3").is_err());
}

#[test]
fn c_name_n009_a_dotted_bucket_is_legal_but_not_vhost_safe() {
    // Rejecting these would make existing data unreachable; the routing layer needs the predicate
    // to fall back to path style instead.
    let bucket = BucketName::new("my.bucket").expect("dotted names are legal");
    assert!(!bucket.is_vhost_safe());
}

proptest! {
    /// Whatever the key contains, constructing it never changes a byte.
    #[test]
    fn construction_never_rewrites_a_key(key in "[^\u{0}]{1,200}") {
        prop_assume!(key.len() <= 1024);
        let parsed = ObjectKey::new(key.clone()).expect("any non-empty NUL-free key under the limit is valid");
        prop_assert_eq!(parsed.as_str(), key.as_str());
    }
}
