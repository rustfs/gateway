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

//! The verification-proof case suite (`c-sig-0101` .. `c-sig-0128`), run against the public API.
//!
//! Responsible for: every P2-02 case that can be expressed at run time, plus the source-level
//! guards for the ones that cannot — "no `Serialize` anywhere in the crate" is a property of the
//! whole crate rather than of one call, and "the secret is zeroized on drop" cannot be observed
//! without reading freed memory, which needs `unsafe` and is forbidden repository-wide.
//! NOT responsible for: the compile-time cases `c-sig-0117` .. `c-sig-0125`, which are
//! `compile_fail` rustdoc examples on `Verdict`, `SignatureMatch`, `SecretBytes`, `SigningKey` and
//! `SessionToken` and run as doctests; nor the latency cases `c-sig-0107`, `c-sig-0108` and
//! `c-sig-0111`, which live in `tests/timing.rs`; nor `c-sig-0126`/`c-sig-0127`, which are
//! negative controls on `scripts/check_ct_eq.sh`.
//! Upstream: the `s3gate-sig` public API. Downstream: none (test target).

use s3gate_sig::codec::{decode_base64_sha256, decode_hex_lower};
use s3gate_sig::timing::{CredentialLookup, Disposition, FailureFloor, LookupBudget, SIDE_CHANNELS, placeholder_secret};
use s3gate_sig::{
    AuthError, AuthScheme, CredentialPresence, CredentialsWerePresented, CtBytes, Identity, SecretBytes, SessionToken,
    SigIdentity, SigParseError, SigService, Signature, SigningKey, Verdict, VerifyRejection,
};

const KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";

// ---------------------------------------------------------------------------
// A miniature of the P2-04 authentication stage
//
// It is written the only way these types allow, which is the point: there is no reachable line in
// it that says "the access key exists, therefore authenticated".
// ---------------------------------------------------------------------------

/// A deterministic, secret-dependent stand-in for the SigV4 signature.
///
/// It is emphatically not an HMAC — P2-03 owns the real four-step derivation. All this fixture
/// needs is a value that depends on the secret and is the right width, so that the stage below has
/// the same shape as the real one.
fn stub_sign(secret: &SecretBytes) -> Signature {
    let bytes = secret.expose();
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let byte = bytes[index % bytes.len()];
        *slot = byte ^ u8::try_from(index).unwrap_or(0);
    }
    Signature::HmacSha256(CtBytes::from_array(out))
}

fn authenticate(presence: CredentialPresence, lookup: CredentialLookup, presented: &Signature) -> Verdict {
    // Anonymous is established, never assumed: the evidence is refused if anything was presented.
    if !presence.any() {
        return match presence.into_evidence() {
            Ok(ack) => Verdict::anonymous(ack),
            Err(CredentialsWerePresented) => Verdict::reject(AuthError::AuthorizationHeaderMalformed),
        };
    }

    // An unknown access key does not short-circuit. It signs with the placeholder and runs the
    // whole comparison, so the two rejections cost the same (T1).
    let (secret, key_is_known) = match lookup {
        CredentialLookup::Found(secret) => (secret, true),
        CredentialLookup::Unknown => (placeholder_secret(), false),
        // `CredentialLookup` is `#[non_exhaustive]`; the wildcard fails closed, which is the only
        // safe default for a future outcome this fixture has never heard of.
        _ => return Verdict::reject(AuthError::AccessDenied),
    };

    let expected = stub_sign(&secret);
    match presented.ct_verify(&expected) {
        Ok(proof) if key_is_known => {
            let identity = Identity::new(KEY_ID).expect("fixture key id is valid");
            let scheme = AuthScheme::sigv4_header(SigIdentity::LongTerm, SigService::S3);
            Verdict::authenticated(identity, scheme, proof)
        }
        // The placeholder cannot authenticate anybody, whatever it compared to.
        Ok(_) => Verdict::reject(AuthError::InvalidAccessKeyId),
        Err(rejection) if key_is_known => Verdict::reject(AuthError::from(rejection)),
        Err(_) => Verdict::reject(AuthError::InvalidAccessKeyId),
    }
}

fn signed_request() -> CredentialPresence {
    CredentialPresence::NONE.with_authorization_header()
}

fn real_secret() -> SecretBytes {
    SecretBytes::new(b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
}

// ---------------------------------------------------------------------------
// Positive cases
// ---------------------------------------------------------------------------

/// Positive — c-sig-0101: two equal SigV4 signatures produce a `SignatureMatch`.
#[test]
fn c_sig_0101_equal_sigv4_signatures_produce_a_proof() {
    let lhs = Signature::HmacSha256(CtBytes::from_array([0x5a; 32]));
    let rhs = Signature::HmacSha256(CtBytes::from_array([0x5a; 32]));
    // `assert_eq!` is unavailable on purpose: `SignatureMatch` has neither `Debug` nor `PartialEq`.
    assert!(lhs.ct_verify(&rhs).is_ok());
}

/// Positive — c-sig-0102: SigV2's 20-byte HMAC-SHA1 signature verifies through the same entry point.
#[test]
fn c_sig_0102_equal_sigv2_signatures_produce_a_proof() {
    let lhs = Signature::HmacSha1(CtBytes::from_array([0x11; 20]));
    let rhs = Signature::HmacSha1(CtBytes::from_array([0x11; 20]));
    assert!(lhs.ct_verify(&rhs).is_ok());
}

/// Positive — c-sig-0103: a well-formed 64-character lowercase hex digest decodes to 32 bytes.
#[test]
fn c_sig_0103_exact_lowercase_hex_decodes() {
    let decoded = decode_hex_lower::<32>(&"ab".repeat(32)).expect("valid digest");
    assert_eq!(decoded, [0xab; 32]);
}

/// Positive — c-sig-0104: canonical padded standard base64 decodes to the same 32 bytes.
#[test]
fn c_sig_0104_canonical_base64_decodes() {
    // 32 zero bytes, standard alphabet, one padding character.
    let decoded = decode_base64_sha256("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").expect("valid digest");
    assert_eq!(decoded, [0u8; 32]);
}

/// Positive — c-sig-0105: a request that presented nothing is `Anonymous`, and anonymity is a
/// result of checking rather than a branch that was skipped.
#[test]
fn c_sig_0105_no_credentials_is_an_anonymous_verdict() {
    let presented = Signature::HmacSha256(CtBytes::from_array([0u8; 32]));
    let verdict = authenticate(CredentialPresence::NONE, CredentialLookup::Unknown, &presented);
    assert!(verdict.is_anonymous());
    assert!(verdict.identity().is_none());
}

/// Positive — a correct signature under a known key authenticates, and names the principal.
#[test]
fn a_correct_signature_authenticates_and_names_the_principal() {
    let presented = stub_sign(&real_secret());
    let verdict = authenticate(signed_request(), CredentialLookup::Found(real_secret()), &presented);
    assert!(verdict.is_authenticated());
    assert_eq!(verdict.identity().map(Identity::access_key_id), Some(KEY_ID));
}

/// Positive — the side-channel register is complete and every entry still has an owner.
#[test]
fn the_side_channel_register_is_complete() {
    assert_eq!(SIDE_CHANNELS.len(), 10);
    let closed = SIDE_CHANNELS
        .iter()
        .filter(|channel| channel.disposition == Disposition::ClosedHere)
        .count();
    assert!(closed >= 7, "most channels must be closed here, not deferred; saw {closed}");
    assert!(SIDE_CHANNELS.iter().any(|channel| matches!(channel.disposition, Disposition::AcceptedRisk(_))));
    assert!(SIDE_CHANNELS.iter().any(|channel| matches!(channel.disposition, Disposition::DeferredTo(_))));
}

/// Positive — the unauthenticated credential lookup is bounded in both dimensions (T2).
#[test]
fn the_credential_lookup_is_bounded_and_negatively_cached() {
    let budget = LookupBudget::DEFAULT;
    assert!(!budget.timeout().is_zero(), "an unbounded provider call is an unauthenticated hang");
    assert!(!budget.negative_ttl().is_zero(), "without a negative cache every forged key is a round trip");
    assert!(!budget.negative_ttl_jitter().is_zero(), "unjittered expiry is a thundering herd");
    assert!(budget.jittered_negative_ttl(0.5) <= budget.negative_ttl());
}

// ---------------------------------------------------------------------------
// Negative cases
// ---------------------------------------------------------------------------

/// Negative — c-sig-0106: every key-material container is zeroized on drop and allocated once.
///
/// Observing the wiped bytes would mean reading freed memory, which needs `unsafe` and is
/// forbidden repository-wide, so the property is asserted where it is actually decided: the field
/// types. A container that is not wrapped in `Zeroizing` is not wiped, and one built on `Vec<u8>`
/// or `String` leaves the buffers of every reallocation behind on the heap where no `Drop` reaches
/// them.
#[test]
fn c_sig_0106_key_material_is_zeroized_and_never_grows() {
    let source = include_str!("../src/secret.rs");
    let mut checked = 0usize;
    for declaration in ["pub struct SecretBytes(", "pub struct SigningKey("] {
        let line = source
            .lines()
            .find(|line| line.starts_with(declaration))
            .unwrap_or_else(|| panic!("{declaration} must exist"));
        assert!(line.contains("Zeroizing<"), "{declaration} is not wiped on drop: {line}");
        assert!(line.contains("Box<[u8]>"), "{declaration} must be allocated once: {line}");
        assert!(!line.contains("Vec<") && !line.contains("String"), "{declaration} may not grow: {line}");
        checked += 1;
    }
    assert_eq!(checked, 2);
    // `SessionToken` inherits the guarantee by wrapping `SecretBytes`.
    assert!(source.contains("pub struct SessionToken(SecretBytes)"));
}

/// Negative — c-sig-0107: a difference in the first byte is a mismatch and yields no proof.
#[test]
fn c_sig_0107_a_first_byte_difference_is_a_mismatch() {
    let mut bytes = [0x5a; 32];
    bytes[0] ^= 0x80;
    let presented = Signature::HmacSha256(CtBytes::from_array(bytes));
    let expected = Signature::HmacSha256(CtBytes::from_array([0x5a; 32]));
    assert!(matches!(presented.ct_verify(&expected), Err(VerifyRejection::Mismatch)));
}

/// Negative — c-sig-0108: a difference in the last byte is the same mismatch, with no early exit.
#[test]
fn c_sig_0108_a_last_byte_difference_is_the_same_mismatch() {
    let mut bytes = [0x5a; 32];
    bytes[31] ^= 0x01;
    let presented = Signature::HmacSha256(CtBytes::from_array(bytes));
    let expected = Signature::HmacSha256(CtBytes::from_array([0x5a; 32]));
    assert!(matches!(presented.ct_verify(&expected), Err(VerifyRejection::Mismatch)));
}

/// Negative — c-sig-0109: different algorithm families are refused, never truncated or zero-padded.
#[test]
fn c_sig_0109_algorithm_families_are_never_coerced() {
    let sha256 = Signature::HmacSha256(CtBytes::from_array([0u8; 32]));
    let sha1 = Signature::HmacSha1(CtBytes::from_array([0u8; 20]));
    let ecdsa = Signature::EcdsaP256(CtBytes::from_array([0u8; 64]));
    for (lhs, rhs) in [(&sha256, &sha1), (&sha1, &sha256), (&sha256, &ecdsa), (&sha1, &ecdsa)] {
        assert!(matches!(lhs.ct_verify(rhs), Err(VerifyRejection::AlgorithmMismatch)));
    }
    // The client is told neither which family was expected nor that the widths differed.
    assert_eq!(AuthError::from(VerifyRejection::AlgorithmMismatch), AuthError::SignatureDoesNotMatch);
}

/// Negative — c-sig-0110: CVE-2025-31489 regression. A known access key with a signature computed
/// under the wrong secret is rejected; "the key exists" authenticates nobody.
#[test]
fn c_sig_0110_a_known_key_with_a_wrong_signature_is_rejected() {
    let forged = stub_sign(&SecretBytes::new(b"an-attackers-guess-at-the-secret-access-ke"));
    let verdict = authenticate(signed_request(), CredentialLookup::Found(real_secret()), &forged);
    assert!(!verdict.is_authenticated());
    assert_eq!(verdict.rejection(), Some(AuthError::SignatureDoesNotMatch));
    assert!(verdict.identity().is_none(), "a rejected request must not be attributed to the key it claimed");
}

/// Negative — c-sig-0111 (functional half): an unknown access key and a bad signature are rejected
/// with the AWS-compatible distinct codes, but with the same message and the same amount of work.
/// The latency half of this case lives in `tests/timing.rs`.
#[test]
fn c_sig_0111_the_two_credential_rejections_differ_only_in_their_code() {
    let presented = stub_sign(&real_secret());
    let unknown = authenticate(signed_request(), CredentialLookup::Unknown, &presented);
    let forged = authenticate(
        signed_request(),
        CredentialLookup::Found(real_secret()),
        &Signature::HmacSha256(CtBytes::from_array([0u8; 32])),
    );

    assert_eq!(unknown.rejection(), Some(AuthError::InvalidAccessKeyId));
    assert_eq!(forged.rejection(), Some(AuthError::SignatureDoesNotMatch));
    // AWS compatibility: the codes stay distinct (clients branch on them).
    assert_ne!(AuthError::InvalidAccessKeyId.code(), AuthError::SignatureDoesNotMatch.code());
    // Everything else is identical: no detail, no expected value, one message.
    assert_eq!(AuthError::InvalidAccessKeyId.message(), AuthError::SignatureDoesNotMatch.message());
    assert_eq!(AuthError::InvalidAccessKeyId.to_string(), AuthError::SignatureDoesNotMatch.to_string());
    assert!(AuthError::InvalidAccessKeyId.is_credential_rejection());
    assert!(AuthError::SignatureDoesNotMatch.is_credential_rejection());
}

/// Negative — c-sig-0112: hex of the wrong length is rejected, never truncated or zero-padded.
#[test]
fn c_sig_0112_wrong_length_hex_is_rejected() {
    for length in [0usize, 63, 65, 128] {
        assert_eq!(decode_hex_lower::<32>(&"a".repeat(length)), Err(SigParseError::MalformedHex), "length {length}");
    }
}

/// Negative — c-sig-0113: the URL-safe base64 alphabet is a different string for the same bytes.
#[test]
fn c_sig_0113_url_safe_base64_is_rejected() {
    let canonical = "++++++++++++++++++++++++++++++++++++++++///=";
    let url_safe = canonical.replace('+', "-").replace('/', "_");
    assert_eq!(decode_base64_sha256(&url_safe), Err(SigParseError::MalformedBase64));
}

/// Negative — c-sig-0114: missing or extra base64 padding is rejected.
#[test]
fn c_sig_0114_base64_padding_must_be_exact() {
    let canonical = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    assert_eq!(decode_base64_sha256(canonical.trim_end_matches('=')), Err(SigParseError::MalformedBase64));
    assert_eq!(decode_base64_sha256(&format!("{canonical}=")), Err(SigParseError::MalformedBase64));
    assert_eq!(
        decode_base64_sha256(&canonical.replace("AAAA", "AA=A")),
        Err(SigParseError::MalformedBase64)
    );
}

/// Negative — c-sig-0115: whitespace anywhere in a base64 digest is rejected (T10).
#[test]
fn c_sig_0115_base64_whitespace_is_rejected() {
    let canonical = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    for mutated in [
        format!("{}\n", &canonical[..canonical.len() - 1]),
        format!(" {}", &canonical[..canonical.len() - 1]),
        format!("{}\t", &canonical[..canonical.len() - 1]),
    ] {
        assert_eq!(decode_base64_sha256(&mutated), Err(SigParseError::MalformedBase64), "{mutated:?}");
    }
}

/// Negative — c-sig-0116: non-hex bytes, including uppercase and Unicode look-alikes, are rejected.
#[test]
fn c_sig_0116_non_hex_characters_are_rejected() {
    assert_eq!(decode_hex_lower::<32>(&"AB".repeat(32)), Err(SigParseError::MalformedHex));
    assert_eq!(decode_hex_lower::<32>(&"gg".repeat(32)), Err(SigParseError::MalformedHex));
    // A Cyrillic "а" is two UTF-8 bytes, so this string is still 64 bytes long and reaches the
    // alphabet check, which rejects it. Nothing normalises it into an `a` on the way.
    let homoglyph = format!("\u{430}{}", &"ab".repeat(32)[2..]);
    assert_eq!(decode_hex_lower::<32>(&homoglyph), Err(SigParseError::MalformedHex));
}

/// Negative — c-sig-0123: the crate cannot serialize key material, because it has no serializer.
///
/// Stronger than a `compile_fail` on one call: `serde` is absent from the manifest entirely, so
/// there is no `#[derive(Serialize)]` anywhere to be re-introduced by a later edit without also
/// adding a dependency, which is visible in review.
#[test]
fn c_sig_0123_no_serialization_path_exists() {
    let manifest = include_str!("../Cargo.toml");
    assert!(!manifest.contains("serde"), "s3gate-sig must not gain a serializer");
    for (name, source) in sources() {
        // Prose may explain why there is no serializer; executable code may not name one.
        for (number, line) in source.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            assert!(
                !line.contains("Serialize") && !line.contains("Deserialize"),
                "{name}:{}: a serializer reached executable code: {line}",
                number + 1
            );
        }
    }
}

/// Negative — c-sig-0128: no rendering of a verdict, a scheme or an identity contains a credential.
#[test]
fn c_sig_0128_nothing_printable_carries_a_credential() {
    let token = SessionToken::new("FQoGZXIvYXdzEXAMPLESESSIONTOKEN").expect("non-empty");
    let scheme = AuthScheme::sigv4_presigned(SigIdentity::Session { token }, SigService::S3);
    let proof = Signature::HmacSha256(CtBytes::from_array([0x7f; 32]))
        .ct_verify(&Signature::HmacSha256(CtBytes::from_array([0x7f; 32])))
        .expect("equal signatures match");
    let verdict = Verdict::authenticated(Identity::new(KEY_ID).expect("valid"), scheme, proof);

    let rendered = format!("{verdict:?}");
    for forbidden in ["FQoGZXIvYXdzEXAMPLESESSIONTOKEN", "wJalrXUtnFEMI", "7f7f7f", "\u{7f}"] {
        assert!(!rendered.contains(forbidden), "{forbidden:?} leaked into {rendered}");
    }
    assert!(rendered.contains("<redacted>"), "the session token must be named but not printed");
    assert!(rendered.contains(KEY_ID), "the access key id is the one value that belongs in an audit record");

    // The rejection side carries nothing at all.
    for error in [AuthError::InvalidAccessKeyId, AuthError::SignatureDoesNotMatch, AuthError::AccessDenied] {
        let rendered = format!("{:?} {}", Verdict::reject(error), error);
        assert!(!rendered.contains(KEY_ID));
        assert!(!rendered.contains("wJalrXUtnFEMI"));
    }
}

/// Negative — a request that presented credentials can never be downgraded to anonymous.
#[test]
fn presented_credentials_are_never_downgraded_to_anonymous() {
    let surfaces = [
        CredentialPresence::NONE.with_authorization_header(),
        CredentialPresence::NONE.with_query_signature(),
        CredentialPresence::NONE.with_post_policy_signature(),
        CredentialPresence::NONE.with_security_token(),
    ];
    for presence in surfaces {
        assert!(presence.any());
        assert_eq!(presence.into_evidence().err(), Some(CredentialsWerePresented));
        let verdict = authenticate(presence, CredentialLookup::Unknown, &Signature::HmacSha256(CtBytes::from_array([0u8; 32])));
        assert!(!verdict.is_anonymous(), "a presented credential must be verified or rejected");
    }
}

/// Negative — two populated signature surfaces are ambiguous, not "try both".
#[test]
fn two_signature_surfaces_are_ambiguous() {
    let both = CredentialPresence::NONE.with_authorization_header().with_query_signature();
    assert!(both.is_ambiguous());
    assert!(!CredentialPresence::NONE.with_authorization_header().is_ambiguous());
    // A security token alongside one signature is normal, not ambiguous.
    assert!(!CredentialPresence::NONE.with_query_signature().with_security_token().is_ambiguous());
}

/// Negative — a credential provider that cannot answer never produces an authentication failure.
#[test]
fn an_unavailable_provider_is_not_an_authentication_failure() {
    let presented = stub_sign(&real_secret());
    let verdict = authenticate(signed_request(), CredentialLookup::Unavailable, &presented);
    assert_ne!(verdict.rejection(), Some(AuthError::SignatureDoesNotMatch));
    assert_ne!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId));
    assert!(!CredentialLookup::Unavailable.requires_parity_work());
}

/// Negative — an access key id that could corrupt an audit record is rejected at construction.
#[test]
fn access_key_ids_that_could_inject_into_a_log_are_rejected() {
    for bad in ["", "AKIA\r\nLevel: forged", "AKIA KEY", "AKIA\u{0}KEY", "AKIA\u{e9}KEY", "\u{7f}"] {
        assert_eq!(Identity::new(bad), Err(SigParseError::InvalidAccessKeyId), "must reject {bad:?}");
    }
    assert_eq!(Identity::new(&"A".repeat(129)), Err(SigParseError::InvalidAccessKeyId));
    assert!(Identity::new(&"A".repeat(128)).is_ok());
}

/// Negative — the failure latency floor is never zero by default, and never shortens a failure.
#[test]
fn the_failure_floor_cannot_be_skipped_by_default() {
    let floor = FailureFloor::default();
    assert!(!floor.floor().is_zero());
    assert!(floor.remaining(core::time::Duration::ZERO).is_some());
    // A rejection that already took longer than the floor is answered immediately, not truncated.
    assert!(floor.remaining(floor.floor() * 2).is_none());
}

/// Negative — `bool::from` appears exactly once in the crate, inside the one comparison (T8).
///
/// The repository-wide guard is `scripts/check_ct_eq.sh`; this is the in-crate copy, so
/// `cargo test -p s3gate-sig` fails on its own without waiting for CI.
#[test]
fn choice_is_converted_to_bool_exactly_once() {
    let mut total = 0usize;
    for (name, source) in sources() {
        let count = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .filter(|line| line.contains("bool::from("))
            .count();
        if name != "signature.rs" {
            assert_eq!(count, 0, "{name} converts a Choice to bool; only signature.rs may");
        }
        total += count;
    }
    assert_eq!(total, 1, "exactly one Choice-to-bool conversion may exist");
}

/// Negative — `subtle`'s escape hatch is never used.
#[test]
fn the_constant_time_escape_hatch_is_never_used() {
    for (name, source) in sources() {
        for forbidden in ["unwrap_u8(", ".into() &&", ".into() ||"] {
            assert!(
                !source
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("//"))
                    .any(|line| line.contains(forbidden)),
                "{name} uses {forbidden}"
            );
        }
    }
}

/// Negative — no key material is ever held in a growing buffer (T9).
#[test]
fn key_material_never_lives_in_a_growing_buffer() {
    let material = ["secret", "signing_key", "session_token", "derived_key", "private_key"];
    for (name, source) in sources() {
        for (number, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if !line.contains("Vec<u8>") && !line.contains("String") {
                continue;
            }
            let lowered = line.to_ascii_lowercase();
            assert!(
                !material.iter().any(|needle| lowered.contains(needle)),
                "{name}:{}: key material in a reallocating buffer: {line}",
                number + 1
            );
        }
    }
}

/// Negative — the negative cases in this file outnumber the positive ones.
#[test]
fn negative_cases_outnumber_positive_ones() {
    let source = include_str!("verification_proof.rs");
    let negative = source.lines().filter(|line| line.starts_with("/// Negative")).count();
    let positive = source.lines().filter(|line| line.starts_with("/// Positive")).count();
    let total = source.lines().filter(|line| line.trim() == "#[test]").count();
    assert_eq!(negative + positive, total, "every test must be labelled Positive or Negative");
    assert!(negative >= positive, "negative cases must outnumber positive ones: {negative} vs {positive}");
}

fn sources() -> Vec<(&'static str, &'static str)> {
    vec![
        ("lib.rs", include_str!("../src/lib.rs")),
        ("codec.rs", include_str!("../src/codec.rs")),
        ("error.rs", include_str!("../src/error.rs")),
        ("mode.rs", include_str!("../src/mode.rs")),
        ("scheme.rs", include_str!("../src/scheme.rs")),
        ("secret.rs", include_str!("../src/secret.rs")),
        ("signature.rs", include_str!("../src/signature.rs")),
        ("timing.rs", include_str!("../src/timing.rs")),
        ("verdict.rs", include_str!("../src/verdict.rs")),
    ]
}

/// Negative — a `SigningKey` is exactly one HMAC wide and cannot be widened by construction.
#[test]
fn a_signing_key_cannot_be_the_wrong_width() {
    assert_eq!(SigningKey::LEN, 32);
    let key = SigningKey::from_array([0u8; 32]);
    assert_eq!(key.expose().len(), 32);
}
