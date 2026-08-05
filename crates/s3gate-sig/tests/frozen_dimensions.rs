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

//! The frozen-dimension case suite (`c-sig-0001` .. `c-sig-0025`), run against the public API.
//!
//! Responsible for: every case listed in the P2-01 task issue that can be expressed at runtime,
//! plus the source-level guards that keep the two crate invariants true as the crate grows.
//! NOT responsible for: the seven compile-time cases `c-sig-0014` .. `c-sig-0020` — those are
//! `compile_fail` rustdoc examples on `CtBytes`, `Signature`, `SessionToken`, `SigFamily` and
//! `TrailerSet`, and `cargo test` runs them as doctests. They live next to the types they
//! constrain so that a maintainer removing a rule sees the test that forbids it.
//! Upstream: the `s3gate-sig` public API. Downstream: none (test target).

use s3gate_sig::codec::{decode_base64_sha256, decode_hex_lower, encode_base64_sha256, encode_hex_lower};
use s3gate_sig::{
    ALGORITHM_SIGV2_PREFIX, ALGORITHM_SIGV4, ALGORITHM_SIGV4A, AuthScheme, CtBytes, DeclaredTrailers, EMPTY_PAYLOAD_SHA256_HEX,
    PayloadMode, STREAMING_ECDSA, STREAMING_ECDSA_TRAILER, STREAMING_SIGNED, STREAMING_SIGNED_TRAILER,
    STREAMING_UNSIGNED_TRAILER, SessionToken, SigFamily, SigIdentity, SigLocation, SigParseError, SigService, Signature,
    TrailerName, TrailerSet, UNSIGNED_PAYLOAD, Unimplemented, VerifyRejection,
};

const DIGEST: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96,
    0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

fn trailer_name(name: &str) -> TrailerName {
    TrailerName::new(name).expect("test trailer name is valid")
}

fn declared(names: &[&str], signed: bool) -> TrailerSet {
    let set =
        DeclaredTrailers::new(names.iter().map(|name| trailer_name(name)), signed).expect("test trailer declaration is valid");
    TrailerSet::Declared(set)
}

// ---------------------------------------------------------------------------
// Positive cases
// ---------------------------------------------------------------------------

/// c-sig-0001 — a body-less request is `Empty` and is never framed.
#[test]
fn c_sig_0001_empty_is_not_framed() {
    let mode = PayloadMode::Empty;
    assert!(!mode.is_framed());
    assert!(!mode.requires_decoded_length());
    assert_eq!(mode.canonical_payload_token().as_str(), EMPTY_PAYLOAD_SHA256_HEX);
}

/// c-sig-0002 — 64 lowercase hex characters parse to `ExactSha256`, and the canonical token is
/// the client's own string rather than a re-spelling of it.
#[test]
fn c_sig_0002_hex_digest_keeps_its_signed_spelling() {
    let hex = encode_hex_lower(&DIGEST);
    let mode = PayloadMode::parse(&hex, TrailerSet::None).expect("valid hex digest");
    assert_eq!(mode, PayloadMode::ExactSha256(DIGEST));
    assert_eq!(mode.canonical_payload_token().as_str(), hex);
    assert_eq!(mode.digest(), Some(&DIGEST));
    assert!(!mode.is_framed());
}

/// c-sig-0003 — the base64 form (s3s#631) carries the same digest as the hex form but a
/// different canonical token, which is why the two variants cannot be merged.
#[test]
fn c_sig_0003_base64_digest_is_a_distinct_variant() {
    let base64 = encode_base64_sha256(&DIGEST);
    let hex = encode_hex_lower(&DIGEST);
    let mode = PayloadMode::parse(&base64, TrailerSet::None).expect("valid base64 digest");
    assert_eq!(mode, PayloadMode::Base64Sha256(DIGEST));
    assert_eq!(mode.digest(), PayloadMode::ExactSha256(DIGEST).digest());
    assert_eq!(mode.canonical_payload_token().as_str(), base64);
    assert_ne!(mode.canonical_payload_token().as_str(), hex);
    assert_eq!(decode_base64_sha256(&base64), decode_hex_lower::<32>(&hex));
}

/// c-sig-0004 — `UNSIGNED-PAYLOAD` parses and is not framed.
#[test]
fn c_sig_0004_unsigned_payload_is_not_framed() {
    let mode = PayloadMode::parse(UNSIGNED_PAYLOAD, TrailerSet::None).expect("valid keyword");
    assert_eq!(mode, PayloadMode::Unsigned);
    assert!(!mode.is_framed());
    assert_eq!(mode.canonical_payload_token().as_str(), UNSIGNED_PAYLOAD);
}

/// c-sig-0005 — `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` is framed and chunk-signed.
#[test]
fn c_sig_0005_streaming_signed_is_framed() {
    let mode = PayloadMode::parse(STREAMING_SIGNED, TrailerSet::None).expect("valid keyword");
    assert!(mode.is_framed());
    assert!(mode.has_chunk_signatures());
    assert_eq!(mode.trailer(), Some(&TrailerSet::None));
    assert_eq!(mode.canonical_payload_token().as_str(), STREAMING_SIGNED);
}

/// c-sig-0006 — the `-TRAILER` form carries the declared names and the trailer-signature flag.
#[test]
fn c_sig_0006_streaming_signed_trailer_carries_the_declaration() {
    let trailer = declared(&["x-amz-checksum-crc32"], true);
    let mode = PayloadMode::parse(STREAMING_SIGNED_TRAILER, trailer).expect("valid keyword");
    assert!(mode.is_framed());
    let set = mode.trailer().and_then(TrailerSet::declared).expect("declared");
    assert!(set.is_signed());
    assert_eq!(set.names().len(), 1);
    assert_eq!(set.names()[0].as_str(), "x-amz-checksum-crc32");
    assert_eq!(mode.canonical_payload_token().as_str(), STREAMING_SIGNED_TRAILER);
}

/// c-sig-0007 — `STREAMING-UNSIGNED-PAYLOAD-TRAILER` is framed but has no chunk signatures.
#[test]
fn c_sig_0007_streaming_unsigned_trailer_is_framed_without_signatures() {
    let trailer = declared(&["x-amz-checksum-crc32c"], false);
    let mode = PayloadMode::parse(STREAMING_UNSIGNED_TRAILER, trailer).expect("valid keyword");
    assert!(mode.is_framed());
    assert!(!mode.has_chunk_signatures());
    assert_eq!(mode.canonical_payload_token().as_str(), STREAMING_UNSIGNED_TRAILER);
}

/// c-sig-0008 — a 20-byte SigV2 signature is representable, and comparing two equal ones yields
/// the `SignatureMatch` proof.
#[test]
fn c_sig_0008_sigv2_signature_is_twenty_bytes() {
    let presented = Signature::HmacSha1(CtBytes::from_array([0x5a; 20]));
    let expected = Signature::HmacSha1(CtBytes::from_array([0x5a; 20]));
    assert_eq!(presented.width(), 20);
    assert!(presented.ct_verify(&expected).is_ok());
}

/// Positive — every service in the IR's `service` enum parses and round-trips.
#[test]
fn services_round_trip_through_their_wire_spelling() {
    for (text, expected) in [
        ("s3", SigService::S3),
        ("sts", SigService::Sts),
        ("s3express", SigService::S3Express),
        ("s3-object-lambda", SigService::S3ObjectLambda),
        ("s3-outposts", SigService::S3Outposts),
    ] {
        let parsed = SigService::parse(text).expect("known service");
        assert_eq!(parsed, expected);
        assert_eq!(parsed.as_str(), text);
    }
}

/// Positive — the familiar flat scheme names map onto the four axes without losing a dimension.
#[test]
fn flat_scheme_names_map_onto_the_four_axes() {
    let header = AuthScheme::sigv4_header(SigIdentity::LongTerm, SigService::S3);
    assert_eq!(header.family, SigFamily::V4);
    assert_eq!(header.location, SigLocation::Header);
    assert!(!header.location.is_presigned());

    let token = SessionToken::new("session").expect("non-empty");
    let presigned = AuthScheme::sigv4_presigned(SigIdentity::Session { token }, SigService::Sts);
    assert!(presigned.location.is_presigned());
    assert!(presigned.identity.session_token().is_some());

    let anonymous = AuthScheme::anonymous(SigService::S3);
    assert!(anonymous.identity.is_anonymous());

    let post = AuthScheme::post_policy(SigFamily::V4, SigIdentity::Anonymous, SigService::S3);
    assert_eq!(post.location, SigLocation::FormField);
    assert!(post.identity.is_anonymous());

    let v2 = AuthScheme::sigv2_header(SigIdentity::LongTerm, SigService::S3);
    assert_eq!(v2.family, SigFamily::V2);
    assert_eq!(SigFamily::from_algorithm(ALGORITHM_SIGV2_PREFIX), Ok(SigFamily::V2));
    assert_eq!(SigFamily::from_algorithm(ALGORITHM_SIGV4), Ok(SigFamily::V4));
    assert!(
        AuthScheme::sigv2_presigned(SigIdentity::LongTerm, SigService::S3)
            .location
            .is_presigned()
    );
}

// ---------------------------------------------------------------------------
// Negative cases
// ---------------------------------------------------------------------------

/// c-sig-0009 — a request that merely declares `Content-Encoding: aws-chunked` stays unframed.
/// The claim is not even expressible: no constructor or method takes `Content-Encoding`, so the
/// only way to reach a framed mode is a streaming `x-amz-content-sha256` (rustfs#4960 regression).
#[test]
fn c_sig_0009_content_encoding_cannot_enable_framing() {
    for value in [UNSIGNED_PAYLOAD, &encode_hex_lower(&DIGEST)] {
        let mode = PayloadMode::parse(value, TrailerSet::None).expect("valid value");
        assert!(!mode.is_framed(), "{value} must not be framed");
        assert!(!mode.has_chunk_signatures());
    }
}

/// c-sig-0010 — under a non-streaming mode `x-amz-decoded-content-length` is forbidden, so the
/// wire layer must reject the header rather than treat it as extra information.
#[test]
fn c_sig_0010_non_streaming_modes_forbid_decoded_length() {
    let hex = encode_hex_lower(&DIGEST);
    for mode in [
        PayloadMode::Empty,
        PayloadMode::parse(&hex, TrailerSet::None).expect("hex"),
        PayloadMode::parse(&encode_base64_sha256(&DIGEST), TrailerSet::None).expect("base64"),
        PayloadMode::parse(UNSIGNED_PAYLOAD, TrailerSet::None).expect("unsigned"),
    ] {
        assert!(!mode.requires_decoded_length());
    }
}

/// c-sig-0011 — under both streaming modes the decoded length is mandatory.
#[test]
fn c_sig_0011_streaming_modes_require_decoded_length() {
    let signed = PayloadMode::parse(STREAMING_SIGNED, TrailerSet::None).expect("signed streaming");
    let unsigned =
        PayloadMode::parse(STREAMING_UNSIGNED_TRAILER, declared(&["x-amz-checksum-crc32"], false)).expect("unsigned streaming");
    assert!(signed.requires_decoded_length());
    assert!(unsigned.requires_decoded_length());
}

/// c-sig-0012 — the SigV4a streaming values are refused with `NotImplemented`, never decoded as
/// SigV4 chunks.
#[test]
fn c_sig_0012_streaming_sigv4a_is_not_implemented() {
    for value in [STREAMING_ECDSA, STREAMING_ECDSA_TRAILER] {
        let err = PayloadMode::parse(value, TrailerSet::None).expect_err("must not parse");
        assert_eq!(err, SigParseError::NotImplemented(Unimplemented::StreamingSigV4a));
    }
}

/// c-sig-0013 — `AWS4-ECDSA-P256-SHA256` parses to its own family and never degrades to SigV4.
#[test]
fn c_sig_0013_sigv4a_never_degrades_to_sigv4() {
    let family = SigFamily::from_algorithm(ALGORITHM_SIGV4A).expect("recognised");
    assert_eq!(family, SigFamily::V4a);
    assert_ne!(family, SigFamily::V4);
    assert!(!family.is_verification_implemented());
    assert_eq!(family.ensure_implemented(), Err(SigParseError::NotImplemented(Unimplemented::SigV4a)));
    let scheme = AuthScheme::new(family, SigLocation::Header, SigIdentity::LongTerm, SigService::S3);
    assert!(!scheme.is_verification_implemented());
}

/// c-sig-0020 (runtime half) — two different algorithms are never compared by truncating or
/// zero-extending either side; the comparison is refused outright.
#[test]
fn c_sig_0020_mixed_algorithms_are_refused() {
    let sha256 = Signature::HmacSha256(CtBytes::from_array([0u8; 32]));
    let sha1 = Signature::HmacSha1(CtBytes::from_array([0u8; 20]));
    assert!(matches!(sha256.ct_verify(&sha1), Err(VerifyRejection::AlgorithmMismatch)));
    assert!(matches!(sha1.ct_verify(&sha256), Err(VerifyRejection::AlgorithmMismatch)));
}

/// c-sig-0021 — declared and received trailers must agree exactly.
#[test]
fn c_sig_0021_received_trailers_must_match_the_declaration() {
    let set = DeclaredTrailers::new([trailer_name("x-amz-checksum-crc32")], false).expect("valid");
    assert!(!set.matches_received(&[trailer_name("x-amz-checksum-crc32c")]));
    assert!(!set.matches_received(&[]));
    assert!(!set.matches_received(&[trailer_name("x-amz-checksum-crc32"), trailer_name("x-amz-checksum-sha256"),]));
    assert!(set.matches_received(&[trailer_name("x-amz-checksum-crc32")]));
}

/// c-sig-0022 — declaring the trailer mode with no names is rejected, not treated as "no trailer".
#[test]
fn c_sig_0022_empty_trailer_declaration_is_rejected() {
    let err = DeclaredTrailers::new([], false).expect_err("empty declaration must fail");
    assert_eq!(err, SigParseError::EmptyTrailerDeclaration);
}

/// c-sig-0023 — more trailers than the protocol can carry is rejected.
#[test]
fn c_sig_0023_too_many_trailers_are_rejected() {
    let err = DeclaredTrailers::new(
        [
            trailer_name("x-amz-checksum-crc32"),
            trailer_name("x-amz-checksum-sha256"),
            trailer_name("x-amz-checksum-crc64nvme"),
        ],
        true,
    )
    .expect_err("three trailers must fail");
    assert_eq!(err, SigParseError::TooManyTrailers);
}

/// c-sig-0024 — a hex digest of the wrong length is rejected, never truncated or zero-padded.
#[test]
fn c_sig_0024_wrong_length_hex_is_rejected() {
    let hex = encode_hex_lower(&DIGEST);
    for bad in [hex[..63].to_owned(), format!("{hex}a"), format!("{hex}00")] {
        assert_eq!(PayloadMode::parse(&bad, TrailerSet::None), Err(SigParseError::MalformedContentSha256));
    }
    assert_eq!(decode_hex_lower::<32>(&hex[..63]), Err(SigParseError::MalformedHex));
    // Uppercase hex is a different signed string, not a lenient spelling of the same one.
    assert_eq!(
        PayloadMode::parse(&hex.to_uppercase(), TrailerSet::None),
        Err(SigParseError::MalformedContentSha256)
    );
}

/// c-sig-0025 — non-canonical base64 is rejected, so two spellings can never decode to one digest.
#[test]
fn c_sig_0025_non_canonical_base64_is_rejected() {
    let base64 = encode_base64_sha256(&DIGEST);
    let unpadded = base64.trim_end_matches('=').to_owned();
    let url_safe = base64.replace('+', "-").replace('/', "_");
    let mut candidates = vec![
        unpadded,
        format!("{base64}="),
        format!("{}==", &base64[..42]),
        format!(" {base64}"),
    ];
    if url_safe != base64 {
        candidates.push(url_safe);
    }
    for bad in candidates {
        assert_eq!(
            PayloadMode::parse(&bad, TrailerSet::None),
            Err(SigParseError::MalformedContentSha256),
            "must reject {bad}"
        );
    }
}

/// Negative — the `-TRAILER` values require a declaration, and the non-trailer values forbid one.
#[test]
fn trailer_declaration_must_agree_with_the_payload_mode() {
    assert_eq!(
        PayloadMode::parse(STREAMING_SIGNED_TRAILER, TrailerSet::None),
        Err(SigParseError::TrailerRequired)
    );
    assert_eq!(
        PayloadMode::parse(STREAMING_UNSIGNED_TRAILER, TrailerSet::None),
        Err(SigParseError::TrailerRequired)
    );
    assert_eq!(
        PayloadMode::parse(STREAMING_SIGNED, declared(&["x-amz-checksum-crc32"], true)),
        Err(SigParseError::TrailerNotAllowed)
    );
    assert_eq!(
        PayloadMode::parse(UNSIGNED_PAYLOAD, declared(&["x-amz-checksum-crc32"], false)),
        Err(SigParseError::TrailerNotAllowed)
    );
    assert_eq!(
        PayloadMode::parse(&encode_hex_lower(&DIGEST), declared(&["x-amz-checksum-crc32"], false)),
        Err(SigParseError::TrailerNotAllowed)
    );
}

/// Negative — an unsigned streaming payload has no signature chain, so it cannot have a trailer
/// signature either.
#[test]
fn unsigned_streaming_rejects_a_trailer_signature() {
    assert_eq!(
        PayloadMode::parse(STREAMING_UNSIGNED_TRAILER, declared(&["x-amz-checksum-crc32"], true)),
        Err(SigParseError::TrailerSignatureNotAllowed)
    );
}

/// Negative — near-miss spellings of the keywords are rejected rather than normalised.
#[test]
fn keyword_near_misses_are_rejected() {
    for bad in [
        "",
        " ",
        "unsigned-payload",
        "UNSIGNED_PAYLOAD",
        " UNSIGNED-PAYLOAD",
        "UNSIGNED-PAYLOAD ",
        "STREAMING-AWS4-HMAC-SHA256",
        "STREAMING-UNSIGNED-PAYLOAD",
        "streaming-aws4-hmac-sha256-payload",
        "e3b0c44298fc1c14",
    ] {
        assert_eq!(
            PayloadMode::parse(bad, TrailerSet::None),
            Err(SigParseError::MalformedContentSha256),
            "must reject {bad:?}"
        );
    }
}

/// Negative — `STREAMING-UNSIGNED-PAYLOAD` without `-TRAILER` is not a mode AWS defines, and it
/// must not be accepted as a shorthand for the trailer form.
#[test]
fn unsigned_streaming_without_trailer_is_not_a_mode() {
    assert_eq!(
        PayloadMode::parse("STREAMING-UNSIGNED-PAYLOAD", declared(&["x-amz-checksum-crc32"], false)),
        Err(SigParseError::MalformedContentSha256)
    );
}

/// Negative — unknown or differently-cased services are rejected, so a scope cannot be widened by
/// spelling.
#[test]
fn unknown_services_are_rejected() {
    for bad in [
        "",
        "S3",
        "s3 ",
        "iam",
        "s3control",
        "execute-api",
        "s3_express",
        "S3-Object-Lambda",
    ] {
        assert_eq!(SigService::parse(bad), Err(SigParseError::UnknownService), "must reject {bad:?}");
    }
}

/// Negative — unknown or differently-cased algorithms are rejected.
#[test]
fn unknown_algorithms_are_rejected() {
    for bad in [
        "",
        "aws4-hmac-sha256",
        "AWS4-HMAC-SHA1",
        "AWS4-HMAC-SHA256 ",
        "AWS4-ECDSA-P384-SHA384",
        "aws",
    ] {
        assert_eq!(
            SigFamily::from_algorithm(bad),
            Err(SigParseError::UnknownAlgorithm),
            "must reject {bad:?}"
        );
    }
}

/// Negative — a trailer name outside the `x-amz-` namespace, or in the wrong case, is rejected.
#[test]
fn invalid_trailer_names_are_rejected() {
    for bad in [
        "",
        "x-amz-",
        "X-Amz-Checksum-Crc32",
        "checksum-crc32",
        "x-amz-checksum crc32",
        "x-amz-ché",
    ] {
        assert_eq!(TrailerName::new(bad), Err(SigParseError::InvalidTrailerName), "must reject {bad:?}");
    }
}

/// Negative — a present-but-empty session token is a rejection, not "no session".
#[test]
fn empty_session_token_is_rejected() {
    // `assert_eq!` is unavailable: `SessionToken` has neither `Debug` nor `PartialEq`, by design.
    assert!(matches!(SessionToken::new(""), Err(SigParseError::EmptySessionToken)));
}

/// Negative — one flipped byte anywhere in the signature is a mismatch.
#[test]
fn a_single_flipped_byte_is_a_mismatch() {
    let expected = Signature::HmacSha256(CtBytes::from_array([0x11; 32]));
    for index in [0usize, 15, 31] {
        let mut bytes = [0x11u8; 32];
        bytes[index] ^= 0x80;
        let presented = Signature::HmacSha256(CtBytes::from_array(bytes));
        assert!(matches!(presented.ct_verify(&expected), Err(VerifyRejection::Mismatch)));
    }
}

// ---------------------------------------------------------------------------
// Source-level guards: the two crate invariants, asserted against the source itself
// ---------------------------------------------------------------------------

const SOURCES: [(&str, &str); 6] = [
    ("lib.rs", include_str!("../src/lib.rs")),
    ("codec.rs", include_str!("../src/codec.rs")),
    ("error.rs", include_str!("../src/error.rs")),
    ("mode.rs", include_str!("../src/mode.rs")),
    ("scheme.rs", include_str!("../src/scheme.rs")),
    ("secret.rs", include_str!("../src/secret.rs")),
];

const SIGNATURE_RS: &str = include_str!("../src/signature.rs");

/// Guard — no secret-bearing type may derive `PartialEq`, `Eq` or `Debug`.
///
/// `scripts/check_ct_eq.sh` enforces the same rule repository-wide; this test is the in-crate
/// copy so that `cargo test -p s3gate-sig` fails on its own, without waiting for CI.
#[test]
fn secret_bearing_types_derive_nothing_that_compares_or_prints() {
    let sensitive = [
        "Signature",
        "Secret",
        "SecretKey",
        "SigningKey",
        "SessionToken",
        "SigningPayload",
    ];
    let banned = ["PartialEq", "Eq", "Debug"];
    let mut checked = 0usize;

    for (name, source) in SOURCES.iter().chain(core::iter::once(&("signature.rs", SIGNATURE_RS))) {
        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            let Some(rest) = declaration_name(trimmed) else {
                continue;
            };
            if !sensitive.iter().any(|needle| rest.contains(needle)) {
                continue;
            }
            checked += 1;
            // Walk back over the attribute block directly above the declaration.
            for previous in lines[..index].iter().rev() {
                let previous = previous.trim_start();
                if previous.starts_with("///") || previous.starts_with("//") || previous.is_empty() {
                    continue;
                }
                if !previous.starts_with("#[") {
                    break;
                }
                for trait_name in banned {
                    assert!(
                        !derives(previous, trait_name),
                        "{name}: secret-bearing type `{rest}` derives {trait_name}"
                    );
                }
            }
        }
    }
    assert!(checked >= 4, "expected the sensitive declarations to be found, saw {checked}");
}

fn declaration_name(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix("pub struct ")
        .or_else(|| line.strip_prefix("pub enum "))
        .or_else(|| line.strip_prefix("struct "))
        .or_else(|| line.strip_prefix("enum "))?;
    Some(
        rest.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .next()
            .unwrap_or(rest),
    )
}

fn derives(attribute: &str, trait_name: &str) -> bool {
    let Some(start) = attribute.find("derive(") else {
        return false;
    };
    let body = &attribute[start + "derive(".len()..];
    let end = body.find(')').unwrap_or(body.len());
    body[..end].split(',').any(|item| item.trim() == trait_name)
}

/// Guard — `Content-Encoding` is never an input to anything in this crate.
///
/// It may only appear in prose explaining why it is not an input. The moment it appears in code,
/// somebody has re-introduced the rustfs#4960 derivation.
#[test]
fn content_encoding_appears_only_in_prose() {
    for (name, source) in SOURCES.iter().chain(core::iter::once(&("signature.rs", SIGNATURE_RS))) {
        for (number, line) in source.lines().enumerate() {
            let lowered = line.to_ascii_lowercase();
            if !lowered.contains("content-encoding") && !lowered.contains("content_encoding") {
                continue;
            }
            let trimmed = line.trim_start();
            assert!(
                trimmed.starts_with("//"),
                "{name}:{}: Content-Encoding reached executable code; framing is derived from \
                 x-amz-content-sha256 only",
                number + 1
            );
        }
    }
}
