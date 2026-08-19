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

//! P2-06 evidence: SigV2's string-to-sign, sub-resource coverage and constant-time verification.
//!
//! Responsible for: executable evidence for `c-sig-0501`..`c-sig-0554` that this crate can carry
//! without a wired verifier — the sub-resource census, the six-line string-to-sign in both
//! locations, strict `Authorization: AWS` parsing, the 20-byte base64 codec, the SigV2-only
//! `Expires` rules, and the policy switch.
//! NOT responsible for: the floor's admission decisions (`security_floor*.rs`), the SigV4
//! canonical request (`canonical_request.rs`), or the compile-time boundaries
//! (`compile_fail.rs`).
//! Upstream: `rustfs_gateway_sig::sig_v2`. Downstream: `tests/integration.rs`, which is the only
//! Cargo target that compiles this file.

use http::Method;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_sig::sig_v2::{
    INCLUDED_QUERY, SigV2Mode, SigV2Policy, SigV2StringToSignSpec, parse_authorization, parse_presigned_expires, verify_presented,
};
use rustfs_gateway_sig::{AuthError, CtBytes, RawQuery, RequestNow, SecretBytes, Signature};

/// The published AWS example secret. It authenticates nothing anywhere, and is the same constant
/// `crates/sig/src/derive.rs` already uses for the SigV4 vectors.
const EXAMPLE_SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

fn secret() -> SecretBytes {
    SecretBytes::new(EXAMPLE_SECRET)
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("test header name");
        let value = HeaderValue::from_str(value).expect("test header value");
        map.append(name, value);
    }
    map
}

fn header_sts(method: &Method, path: &str, query: &str, pairs: &[(&str, &str)], bucket: Option<&str>) -> String {
    let map = headers(pairs);
    let raw = RawQuery::new(query);
    SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, method, path, &raw, &map, bucket)
        .build()
        .expect("string-to-sign")
        .text()
        .to_owned()
}

// ---------------------------------------------------------------------------------------------
// Positive
// ---------------------------------------------------------------------------------------------

/// Positive — c-sig-0501: the documented virtual-hosted object GET produces the documented
/// six-line string-to-sign.
///
/// Shape per <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTAuthentication.html>: verb,
/// Content-MD5, Content-Type, Date, the `x-amz-*` block, then the canonicalized resource with the
/// virtual-host bucket in front of the path.
#[test]
fn c_sig_0501_a_virtual_hosted_object_get_matches_the_documented_shape() {
    let text = header_sts(
        &Method::GET,
        "/photos/puppy.jpg",
        "",
        &[("Date", "Tue, 27 Mar 2007 19:36:42 +0000")],
        Some("johnsmith"),
    );
    assert_eq!(text, "GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/johnsmith/photos/puppy.jpg");
}

/// Positive — c-sig-0502: an object PUT carries Content-MD5, Content-Type and one `x-amz-` line.
#[test]
fn c_sig_0502_an_object_put_carries_md5_content_type_and_the_amz_block() {
    let text = header_sts(
        &Method::PUT,
        "/db-backup.dat.gz",
        "",
        &[
            ("Content-Md5", "c8fdb181845a4ca6b8fec737b3581d76"),
            ("Content-Type", "text/html"),
            ("Date", "Tue, 27 Mar 2007 21:15:45 +0000"),
            ("x-amz-acl", "public-read"),
        ],
        Some("static.johnsmith.net"),
    );
    assert_eq!(
        text,
        concat!(
            "PUT\nc8fdb181845a4ca6b8fec737b3581d76\ntext/html\nTue, 27 Mar 2007 21:15:45 +0000\n",
            "x-amz-acl:public-read\n",
            "/static.johnsmith.net/db-backup.dat.gz"
        )
    );
}

/// Positive — c-sig-0503: a bucket listing signs the trailing slash it addressed.
#[test]
fn c_sig_0503_a_bucket_listing_signs_its_trailing_slash() {
    let text = header_sts(
        &Method::GET,
        "/",
        "prefix=photos&max-keys=50&marker=puppy",
        &[("Date", "Tue, 27 Mar 2007 19:42:41 +0000")],
        Some("johnsmith"),
    );
    assert_eq!(text, "GET\n\n\nTue, 27 Mar 2007 19:42:41 +0000\n/johnsmith/");
}

/// Positive — c-sig-0504: a path-style request with no bucket prefix verifies end to end.
///
/// The expected base64 was produced by an implementation independent of this crate (CPython's
/// `hmac`/`hashlib` over the same secret and string-to-sign), so this is a cross-implementation
/// known-answer test rather than a restatement of our own output.
#[test]
fn c_sig_0504_a_correct_signature_verifies_against_an_independent_vector() {
    let text = header_sts(
        &Method::GET,
        "/photos/puppy.jpg",
        "",
        &[("Date", "Tue, 27 Mar 2007 19:36:42 +0000")],
        None,
    );
    assert_eq!(text, "GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/photos/puppy.jpg");

    let presented = parse_authorization("AWS AKIAIOSFODNN7EXAMPLE:eYGVLwbQe8+xIYUM4rD/L+kYWV8=").expect("parsed");
    assert_eq!(presented.access_key_id(), "AKIAIOSFODNN7EXAMPLE");

    let query = RawQuery::new("");
    let map = headers(&[("Date", "Tue, 27 Mar 2007 19:36:42 +0000")]);
    let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &Method::GET, "/photos/puppy.jpg", &query, &map, None);
    let expected = spec.build().expect("string-to-sign").sign(&secret());
    let proof = verify_presented(presented.presented(), &expected);
    assert!(proof.is_ok());
}

/// Positive — c-sig-0505: `?cors` reaches the canonicalized resource (the s3s#517 regression).
#[test]
fn c_sig_0505_the_cors_subresource_is_covered() {
    let text = header_sts(
        &Method::PUT,
        "/",
        "cors",
        &[("Date", "Tue, 27 Mar 2007 19:36:42 +0000")],
        Some("johnsmith"),
    );
    assert!(text.ends_with("/johnsmith/?cors"), "{text}");
}

/// Positive — c-sig-0506: an `x-amz-date` header empties the `{Date}` line.
///
/// The single most expensive rule to miss: every client that sends `x-amz-date` fails
/// verification if the `Date` header's value is written here instead.
#[test]
fn c_sig_0506_x_amz_date_empties_the_date_line() {
    let text = header_sts(
        &Method::GET,
        "/photos/puppy.jpg",
        "",
        &[
            ("Date", "Tue, 27 Mar 2007 19:36:42 +0000"),
            ("x-amz-date", "Tue, 27 Mar 2007 19:36:42 +0000"),
        ],
        None,
    );
    assert_eq!(text, "GET\n\n\n\nx-amz-date:Tue, 27 Mar 2007 19:36:42 +0000\n/photos/puppy.jpg");
}

/// Positive — c-sig-0507: without `x-amz-date`, the `Date` header's value is the `{Date}` line.
#[test]
fn c_sig_0507_without_x_amz_date_the_date_header_is_used() {
    let text = header_sts(&Method::GET, "/o", "", &[("Date", "Tue, 27 Mar 2007 19:36:42 +0000")], None);
    assert_eq!(text, "GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/o");
}

/// Positive — c-sig-0508: repeated `x-amz-*` values are trimmed and comma-joined without a space.
#[test]
fn c_sig_0508_repeated_amz_values_are_trimmed_and_comma_joined() {
    let text = header_sts(
        &Method::GET,
        "/o",
        "",
        &[("Date", "d"), ("x-amz-meta-foo", "  bar  "), ("x-amz-meta-foo", "\tbaz ")],
        None,
    );
    assert_eq!(text, "GET\n\n\nd\nx-amz-meta-foo:bar,baz\n/o");
}

/// Positive — c-sig-0509: `x-amz-*` headers are emitted in ascending name order, each with a
/// trailing newline, whatever order they arrived in.
#[test]
fn c_sig_0509_amz_headers_are_sorted_and_each_line_is_terminated() {
    let text = header_sts(
        &Method::GET,
        "/o",
        "",
        &[
            ("Date", "d"),
            ("X-Amz-Meta-Zebra", "z"),
            ("x-amz-acl", "public-read"),
            ("X-AMZ-META-ALPHA", "a"),
        ],
        None,
    );
    assert_eq!(text, "GET\n\n\nd\nx-amz-acl:public-read\nx-amz-meta-alpha:a\nx-amz-meta-zebra:z\n/o");
}

/// Positive — c-sig-0510: a valueless sub-resource is written as the bare key.
#[test]
fn c_sig_0510_a_valueless_subresource_is_written_without_an_equals_sign() {
    let text = header_sts(&Method::GET, "/o", "acl", &[("Date", "d")], None);
    assert!(text.ends_with("/o?acl"), "{text}");
    assert!(!text.contains("acl="), "{text}");
}

/// Positive — c-sig-0511: several sub-resources are emitted in ascending key order, whatever
/// order the query put them in.
#[test]
fn c_sig_0511_multiple_subresources_are_emitted_in_ascending_order() {
    let text = header_sts(&Method::GET, "/o", "uploadId=x&partNumber=1", &[("Date", "d")], None);
    assert!(text.ends_with("/o?partNumber=1&uploadId=x"), "{text}");
}

// ---------------------------------------------------------------------------------------------
// Negative
// ---------------------------------------------------------------------------------------------

/// Negative — c-sig-0530: the sub-resource set is strictly ascending, pair by pair.
///
/// The append loop walks the constant in order and relies on that order for the `?`/`&`
/// separators; one entry in the wrong place silently changes every multi-sub-resource signature.
#[test]
fn c_sig_0530_included_query_is_strictly_ascending() {
    for pair in INCLUDED_QUERY.windows(2) {
        assert!(pair[0] < pair[1], "{} must sort before {}", pair[0], pair[1]);
    }
}

/// Negative — c-sig-0531: the sub-resource set is exactly botocore's `QSAOfInterest`.
///
/// Re-derived from botocore `HmacV1Auth.QSAOfInterest` (`botocore/auth.py`, method
/// `canonical_resource`): 36 literals with `requestPayment` written twice, so 35 unique names.
/// A silently dropped entry is the s3s#517 defect, in which botocore-signed requests to the
/// missing sub-resources stopped verifying.
#[test]
fn c_sig_0531_included_query_is_exactly_the_botocore_set() {
    let botocore = [
        "accelerate",
        "acl",
        "cors",
        "defaultObjectAcl",
        "location",
        "logging",
        "partNumber",
        "policy",
        "requestPayment",
        "torrent",
        "versioning",
        "versionId",
        "versions",
        "website",
        "uploads",
        "uploadId",
        "response-content-type",
        "response-content-language",
        "response-expires",
        "response-cache-control",
        "response-content-disposition",
        "response-content-encoding",
        "delete",
        "lifecycle",
        "tagging",
        "restore",
        "storageClass",
        "notification",
        "replication",
        "requestPayment",
        "analytics",
        "metrics",
        "inventory",
        "select",
        "select-type",
        "object-lock",
    ];
    let mut unique: Vec<&str> = botocore.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(botocore.len(), 36, "botocore writes requestPayment twice");
    assert_eq!(unique.len(), 35);
    assert_eq!(INCLUDED_QUERY.len(), 35);
    assert_eq!(INCLUDED_QUERY.as_slice(), unique.as_slice());
    // `encryption` is deliberately absent: botocore does not sign it, so covering it here would
    // reject correctly-signed botocore requests to `?encryption`.
    assert!(!INCLUDED_QUERY.contains(&"encryption"));
    // The four names the sub-resource gap was reported against are present.
    for name in ["cors", "tagging", "lifecycle", "object-lock"] {
        assert!(INCLUDED_QUERY.contains(&name), "{name} must be covered");
    }
}

/// Negative — c-sig-0532: every signed component changes the string-to-sign.
///
/// Seven mutations — method, Content-MD5, Content-Type, Date, an `x-amz-*` value, a sub-resource
/// value, and the URI path — each of which must produce a different string, because a component
/// that does not reach the string-to-sign is a component an attacker may rewrite freely.
#[test]
fn c_sig_0532_every_signed_component_changes_the_string_to_sign() {
    let base_headers = [
        ("Content-Md5", "c8fdb181845a4ca6b8fec737b3581d76"),
        ("Content-Type", "text/html"),
        ("Date", "Tue, 27 Mar 2007 21:15:45 +0000"),
        ("x-amz-acl", "public-read"),
    ];
    let base = header_sts(&Method::PUT, "/o", "versionId=v1", &base_headers, None);

    let mutations = [
        header_sts(&Method::POST, "/o", "versionId=v1", &base_headers, None),
        header_sts(
            &Method::PUT,
            "/o",
            "versionId=v1",
            &[
                ("Content-Md5", "d8fdb181845a4ca6b8fec737b3581d76"),
                ("Content-Type", "text/html"),
                ("Date", "Tue, 27 Mar 2007 21:15:45 +0000"),
                ("x-amz-acl", "public-read"),
            ],
            None,
        ),
        header_sts(
            &Method::PUT,
            "/o",
            "versionId=v1",
            &[
                ("Content-Md5", "c8fdb181845a4ca6b8fec737b3581d76"),
                ("Content-Type", "text/plain"),
                ("Date", "Tue, 27 Mar 2007 21:15:45 +0000"),
                ("x-amz-acl", "public-read"),
            ],
            None,
        ),
        header_sts(
            &Method::PUT,
            "/o",
            "versionId=v1",
            &[
                ("Content-Md5", "c8fdb181845a4ca6b8fec737b3581d76"),
                ("Content-Type", "text/html"),
                ("Date", "Tue, 27 Mar 2007 21:15:46 +0000"),
                ("x-amz-acl", "public-read"),
            ],
            None,
        ),
        header_sts(
            &Method::PUT,
            "/o",
            "versionId=v1",
            &[
                ("Content-Md5", "c8fdb181845a4ca6b8fec737b3581d76"),
                ("Content-Type", "text/html"),
                ("Date", "Tue, 27 Mar 2007 21:15:45 +0000"),
                ("x-amz-acl", "private"),
            ],
            None,
        ),
        header_sts(&Method::PUT, "/o", "versionId=v2", &base_headers, None),
        header_sts(&Method::PUT, "/other", "versionId=v1", &base_headers, None),
    ];
    assert_eq!(mutations.len(), 7);
    for (index, mutated) in mutations.iter().enumerate() {
        assert_ne!(*mutated, base, "mutation {index} left the string-to-sign unchanged");
    }
}

/// Negative — c-sig-0533: a URL-safe base64 signature is refused (the rustfs#4456 regression).
#[test]
fn c_sig_0533_url_safe_base64_is_refused() {
    // The same 20 bytes in both alphabets, so the length, the padding and the trailing bits are
    // all correct and the alphabet is the only difference. A fixture that also breaks one of the
    // other rules would pass this test with the alphabet check deleted.
    let standard = "AWS key:AAAA+Pv/v/v/v/v/v/v/v/v/vwA=";
    let url_safe = "AWS key:AAAA-Pv_v_v_v_v_v_v_v_v_vwA=";
    assert!(parse_authorization(standard).is_ok());
    assert_eq!(parse_authorization(url_safe).err(), Some(AuthError::AuthorizationHeaderMalformed));
}

/// Negative — c-sig-0534: padding must be exact — neither absent nor doubled.
#[test]
fn c_sig_0534_base64_padding_must_be_exact() {
    let valid = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    assert!(parse_authorization(&format!("AWS key:{valid}")).is_ok());
    assert_eq!(
        parse_authorization("AWS key:AAAAAAAAAAAAAAAAAAAAAAAAAAA").err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
    assert_eq!(
        parse_authorization("AWS key:AAAAAAAAAAAAAAAAAAAAAAAAAA==").err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — c-sig-0535: whitespace and trailing rubbish inside the signature are refused.
#[test]
fn c_sig_0535_base64_whitespace_and_trailing_bytes_are_refused() {
    // A space inside an otherwise correctly-sized field.
    assert_eq!(
        parse_authorization("AWS key:AAAAAAAAAAAAA AAAAAAAAAAAAA=").err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
    // One byte of rubbish after the pad.
    assert_eq!(
        parse_authorization("AWS key:AAAAAAAAAAAAAAAAAAAAAAAAAAA=x").err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — c-sig-0536: a signature that decodes to anything other than 20 bytes is refused
/// rather than truncated or zero-padded.
#[test]
fn c_sig_0536_only_twenty_bytes_are_accepted() {
    // The base64 of a 32-byte SigV4 signature: 44 characters, canonical, and still wrong here.
    let sha256_width = "A".repeat(43) + "=";
    assert_eq!(
        parse_authorization(&format!("AWS key:{sha256_width}")).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
    // The base64 of 16 bytes: canonical, and the wrong width.
    assert_eq!(
        parse_authorization("AWS key:AAAAAAAAAAAAAAAAAAAAAA==").err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — c-sig-0537: non-canonical trailing bits give two spellings of one value.
#[test]
fn c_sig_0537_non_canonical_trailing_bits_are_refused() {
    // The final data character of a 20-byte encoding contributes only 4 of its 6 bits.
    assert!(parse_authorization("AWS key:AAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_ok());
    assert_eq!(
        parse_authorization("AWS key:AAAAAAAAAAAAAAAAAAAAAAAAAAB=").err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — c-sig-0538: six malformed `Authorization: AWS ...` spellings, all refused.
#[test]
fn c_sig_0538_the_authorization_grammar_is_exact() {
    let signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let malformed = [
        format!("AWSkey:{signature}"),
        format!("AWS  key:{signature}"),
        format!("AWS key{signature}"),
        format!("AWS key:extra:{signature}"),
        format!("AWS :{signature}"),
        "AWS key:".to_owned(),
        format!(" AWS key:{signature}"),
        format!("AWS key:{signature} "),
        format!("aws key:{signature}"),
    ];
    for raw in &malformed {
        assert_eq!(
            parse_authorization(raw).err(),
            Some(AuthError::AuthorizationHeaderMalformed),
            "{raw:?} must not parse"
        );
    }
    assert!(parse_authorization(&format!("AWS key:{signature}")).is_ok());
}

/// Negative — c-sig-0580: the SigV2 access key id obeys the same character-set and length rule as
/// SigV4's credential scope, in both directions.
///
/// The access key id is the one authentication value that legitimately reaches a log line and an
/// audit record, which is why its character set is a rule rather than a formality. SigV2 used to
/// check only for control characters and whitespace, so a non-ASCII or multi-kilobyte identifier
/// could reach the credential store and whatever writes it down; `Identity::new` is the single
/// place that rule lives and SigV2 now goes through it too.
#[test]
fn c_sig_0580_the_access_key_id_obeys_the_shared_identity_rule() {
    let signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let accented = format!("AWS AKIDEXAMPL\u{c9}:{signature}");
    assert!(parse_authorization(&accented).is_err());
    let over = format!("AWS {}:{signature}", "A".repeat(129));
    assert!(parse_authorization(&over).is_err());
    // The other direction, so the rule is a boundary and not a blanket refusal.
    let at_limit = format!("AWS {}:{signature}", "A".repeat(128));
    assert!(parse_authorization(&at_limit).is_ok());
}

/// Negative — c-sig-0539: a wrong signature does not verify, first byte or last.
#[test]
fn c_sig_0539_a_wrong_signature_never_verifies() {
    let expected = Signature::HmacSha1(CtBytes::from_array([7u8; 20]));
    let mut first = [7u8; 20];
    first[0] ^= 0x01;
    let mut last = [7u8; 20];
    last[19] ^= 0x01;
    for bytes in [first, last] {
        let presented = Signature::HmacSha1(CtBytes::from_array(bytes));
        assert_eq!(verify_presented(&presented, &expected).err(), Some(AuthError::SignatureDoesNotMatch));
    }
}

/// Negative — c-sig-0540: a 32-byte SigV4 signature is never compared against a 20-byte SigV2 one.
#[test]
fn c_sig_0540_widths_are_never_coerced() {
    let sigv4 = Signature::HmacSha256(CtBytes::from_array([0u8; 32]));
    let sigv2 = Signature::HmacSha1(CtBytes::from_array([0u8; 20]));
    assert_eq!(verify_presented(&sigv4, &sigv2).err(), Some(AuthError::SignatureDoesNotMatch));
}

/// Negative — c-sig-0544: `Expires` must be a strict unsigned decimal, present exactly once.
#[test]
fn c_sig_0544_expires_must_be_a_strict_unsigned_decimal() {
    let now = RequestNow::from_unix_seconds(1_000_000);
    for raw in ["", "not-a-number", "-1", "+1", "1.5", " 1", "1 ", "0x10", "1_000", "\u{ff10}"] {
        assert_eq!(
            parse_presigned_expires(raw, now).err(),
            Some(AuthError::AuthorizationQueryParametersError),
            "{raw:?} must not parse"
        );
    }
    assert!(parse_presigned_expires("1000060", now).is_ok());
}

/// Negative — c-sig-0545: an `Expires` more than seven days out is refused.
///
/// SigV2's `Expires` is an absolute Unix second, not SigV4's relative window, so H2 does not
/// apply verbatim; the equivalent 604800-second ceiling is enforced here instead.
#[test]
fn c_sig_0545_expires_beyond_seven_days_is_refused() {
    let now = RequestNow::from_unix_seconds(1_000_000);
    assert!(parse_presigned_expires("1604800", now).is_ok());
    assert_eq!(
        parse_presigned_expires("1604801", now).err(),
        Some(AuthError::AuthorizationQueryParametersError)
    );
}

/// Negative — c-sig-0546: an `Expires` at or before the present is expired.
#[test]
fn c_sig_0546_an_elapsed_expires_is_refused() {
    let now = RequestNow::from_unix_seconds(1_000_000);
    assert_eq!(parse_presigned_expires("1000000", now).err(), Some(AuthError::RequestExpired));
    assert_eq!(parse_presigned_expires("999999", now).err(), Some(AuthError::RequestExpired));
    assert!(parse_presigned_expires("1000001", now).is_ok());
}

/// Negative — c-sig-0547: an `Expires` at the integer ceiling is checked, never wrapped.
///
/// A wrapping subtraction turns `u64::MAX` into "already expired" or, worse, into a window that
/// passes the seven-day ceiling — a URL that never expires.
#[test]
fn c_sig_0547_an_expires_at_the_ceiling_is_checked_not_wrapped() {
    let now = RequestNow::from_unix_seconds(1_000_000);
    for raw in [u64::MAX.to_string(), i64::MAX.to_string(), "9".repeat(40)] {
        assert_eq!(
            parse_presigned_expires(&raw, now).err(),
            Some(AuthError::AuthorizationQueryParametersError),
            "{raw} must not pass"
        );
    }
}

/// Negative — c-sig-0548: a query parameter outside the sub-resource set is not covered.
///
/// This is a weakness of the SigV2 specification, not a choice made here: appending `&foo=1` to a
/// SigV2 URL leaves the signature valid. The assertion pins the fact so nobody later mistakes it
/// for an implementation bug, and `docs/security-model.md` records it as the second reason SigV2
/// presigned is off by default.
#[test]
fn c_sig_0548_query_outside_the_subresource_set_is_not_covered() {
    let covered = header_sts(&Method::GET, "/o", "acl", &[("Date", "d")], None);
    let tampered = header_sts(&Method::GET, "/o", "acl&foo=1", &[("Date", "d")], None);
    assert_eq!(covered, tampered);
    assert!(!tampered.contains("foo"), "{tampered}");
}

/// Negative — c-sig-0541: the default policy refuses presigned SigV2.
#[test]
fn c_sig_0541_the_default_policy_refuses_presigned() {
    let policy = SigV2Policy::default();
    assert_eq!(policy, SigV2Policy::HeaderOnly);
    assert!(policy.allows(SigV2Mode::HeaderAuth));
    assert!(!policy.allows(SigV2Mode::PresignedUrl));
    assert_eq!(policy.as_str(), "HeaderOnly");
}

/// Negative — c-sig-0542: `Disabled` refuses both locations.
#[test]
fn c_sig_0542_the_disabled_policy_refuses_both_locations() {
    let policy = SigV2Policy::Disabled;
    assert!(!policy.allows(SigV2Mode::HeaderAuth));
    assert!(!policy.allows(SigV2Mode::PresignedUrl));
    assert_eq!(policy.as_str(), "Disabled");
    // Both directions: the opt-in value does allow both, so the switch is not stuck on "no".
    assert!(SigV2Policy::HeaderAndPresigned.allows(SigV2Mode::HeaderAuth));
    assert!(SigV2Policy::HeaderAndPresigned.allows(SigV2Mode::PresignedUrl));
}

/// Negative — c-sig-0543: a presigned string-to-sign puts `Expires` where the date goes, and a
/// missing or malformed `Expires` is refused rather than defaulted.
#[test]
fn c_sig_0543_presigned_signs_the_expires_parameter_in_the_date_slot() {
    let map = headers(&[("Date", "Tue, 27 Mar 2007 19:36:42 +0000"), ("x-amz-date", "irrelevant")]);
    let raw = RawQuery::new("AWSAccessKeyId=key&Expires=1175139620&Signature=abc&acl");
    let text =
        SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, &Method::GET, "/photos/puppy.jpg", &raw, &map, Some("johnsmith"))
            .build()
            .expect("string-to-sign")
            .text()
            .to_owned();
    assert_eq!(text, "GET\n\n\n1175139620\nx-amz-date:irrelevant\n/johnsmith/photos/puppy.jpg?acl");

    let missing = RawQuery::new("AWSAccessKeyId=key&Signature=abc");
    assert_eq!(
        SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, &Method::GET, "/o", &missing, &map, None)
            .build()
            .err(),
        Some(AuthError::AuthorizationQueryParametersError)
    );
    let malformed = RawQuery::new("AWSAccessKeyId=key&Expires=tomorrow&Signature=abc");
    assert_eq!(
        SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, &Method::GET, "/o", &malformed, &map, None)
            .build()
            .err(),
        Some(AuthError::AuthorizationQueryParametersError)
    );
}

/// Negative — c-sig-0549: a repeated sub-resource has no canonical spelling and is refused.
#[test]
fn c_sig_0549_a_repeated_subresource_is_refused() {
    let map = headers(&[("Date", "d")]);
    let raw = RawQuery::new("versionId=v1&versionId=v2");
    assert_eq!(
        SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &Method::GET, "/o", &raw, &map, None)
            .build()
            .err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — c-sig-0553: a lookalike host contributes no bucket prefix.
///
/// The caller supplies the virtual-host bucket; `None` must produce no prefix at all rather than
/// an empty segment, so a host that failed the label boundary check cannot slip a `/` in.
#[test]
fn c_sig_0553_no_virtual_host_bucket_means_no_prefix() {
    let text = header_sts(&Method::GET, "/photos/puppy.jpg", "", &[("Date", "d")], None);
    assert!(text.ends_with("\n/photos/puppy.jpg"), "{text}");
    assert!(!text.contains("//"), "{text}");
}

/// Negative — c-sig-0554: a header value that is not UTF-8, and a duplicated `Date`, are refused
/// rather than guessed at.
#[test]
fn c_sig_0554_ambiguous_header_input_is_refused() {
    let mut map = HeaderMap::new();
    map.append(HeaderName::from_static("date"), HeaderValue::from_static("a"));
    map.append(HeaderName::from_static("date"), HeaderValue::from_static("b"));
    let raw = RawQuery::new("");
    assert_eq!(
        SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &Method::GET, "/o", &raw, &map, None)
            .build()
            .err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );

    let mut binary = HeaderMap::new();
    binary.append(HeaderName::from_static("date"), HeaderValue::from_static("d"));
    binary.append(
        HeaderName::from_static("x-amz-meta-raw"),
        HeaderValue::from_bytes(&[0xff, 0xfe]).expect("opaque bytes"),
    );
    assert_eq!(
        SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &Method::GET, "/o", &raw, &binary, None)
            .build()
            .err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — c-sig-0556: two different query spellings canonicalise to one string-to-sign.
///
/// Not in this task's case table; found by the `security-adversary` pass and pinned here.
/// A covered sub-resource's value is percent-decoded before it is written into
/// `CanonicalizedResource`, and the block's own separator is `&`. So
/// `?acl=x%26versionId%3Dy` — one parameter whose value happens to decode to `x&versionId=y` —
/// produces byte-for-byte the same preimage as `?acl=x&versionId=y`, which is two parameters. A
/// signature minted for one is valid for the other, and the router sees different parameters in
/// each.
///
/// This is the SigV2 algorithm, not this implementation: botocore's `canonical_resource` decodes
/// with `parse_qsl` and joins with `&`, so it computes the identical string. Diverging here would
/// refuse requests AWS's own SDK signs successfully, so the collision is pinned rather than
/// closed, recorded in `docs/security-model.md`, and left as an explicit decision for the slice
/// that wires SigV2 into the verifier. The assertion exists so the fact cannot be lost, and so a
/// later change that *does* close it fails loudly rather than quietly changing every signature.
#[test]
fn c_sig_0556_a_decoded_subresource_value_can_forge_a_second_parameter() {
    let smuggled = header_sts(&Method::GET, "/o", "acl=x%26versionId%3Dy", &[("Date", "d")], None);
    let honest = header_sts(&Method::GET, "/o", "acl=x&versionId=y", &[("Date", "d")], None);
    assert_eq!(smuggled, honest);
    assert!(honest.ends_with("/o?acl=x&versionId=y"), "{honest}");
}
