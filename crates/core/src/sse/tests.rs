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

//! [`super::enforce`] against real request heads: the gate, the order, and the constant sentences.
//!
//! Responsible for: the enforcement's behaviour as a whole — the transport gate in both
//! directions, the fixed order of the checks, the channel exclusivity, and the property that no
//! refusal sentence carries a key, a digest or a key id.
//! NOT responsible for: the pieces, each of which is tested beside itself — the strict base64
//! codec in [`super::base64`], the digest agreement in [`super::key`], the managed channel's
//! value rules in [`super::headers`], the multipart comparison in [`super::consistency`] — or
//! anything about a *response*, which is `crates/gateway`'s `tests/sse_runtime.rs`.
//! Upstream: [`super`]. Downstream: nothing; this is a leaf test module.

use rustfs_gateway_http::{Limits, WireRequest};

use super::*;
use crate::TargetKind;

/// A 32-byte key and its true MD5.
const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const MD5_A: &str = "tP/LI3N87DFaSk0aoqYgzg==";
/// A different key and its true MD5.
const KEY_B: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
const MD5_B: &str = "v2HomVYPq94vbXb0BabrcA==";
/// A plausible KMS key ARN; asserted absent from every sentence.
const KEY_ARN: &str = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

/// The target-side trio, spelled out once.
fn target_trio(key: &'static str, digest: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![(SSEC_ALGORITHM, CUSTOMER_ALGORITHM), (SSEC_KEY, key), (SSEC_KEY_MD5, digest)]
}

/// The copy-source trio.
fn source_trio(key: &'static str, digest: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![
        (COPY_SSEC_ALGORITHM, CUSTOMER_ALGORITHM),
        (COPY_SSEC_KEY, key),
        (COPY_SSEC_KEY_MD5, digest),
    ]
}

/// Runs [`enforce`] over a `PUT /bucket/key` carrying `headers`.
fn enforce_with(
    headers: &[(&'static str, &'static str)],
    transport: TransportSecurity,
    config: &SseConfig,
) -> Result<SseEnforced, SseRejection> {
    let mut request = http::Request::builder()
        .method("PUT")
        .uri("http://host.invalid/conf-sse/object")
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    for (name, value) in headers {
        request.headers_mut().append(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a legal header name"),
            http::HeaderValue::from_str(value).expect("a legal header value"),
        );
    }
    let accepted = WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable");
    let view = MetaView::of(&accepted, TargetKind::Object).expect("the path names an object");
    enforce(&view, transport, config)
}

/// [`SseEnforced`] has no `Debug` and no `PartialEq`, on purpose: it carries values derived from
/// key material, and this repository does not give such types a derived rendering or a
/// short-circuiting comparison. These two helpers are the consequence — `expect` and `assert_eq!`
/// on the `Ok` side are not available, and adding the derives "just for tests" would remove the
/// property the type exists for.
fn served(result: Result<SseEnforced, SseRejection>) -> SseEnforced {
    match result {
        Ok(enforced) => enforced,
        Err(rejection) => panic!("the request was refused: {rejection:?}"),
    }
}

fn refused(result: Result<SseEnforced, SseRejection>) -> SseRejection {
    match result {
        Ok(_) => panic!("the request was served"),
        Err(rejection) => rejection,
    }
}

fn is_ok(result: &Result<SseEnforced, SseRejection>) -> bool {
    result.is_ok()
}

/// The common case: over TLS, with the strict default configuration.
fn over_tls(headers: &[(&'static str, &'static str)]) -> Result<SseEnforced, SseRejection> {
    enforce_with(headers, TransportSecurity::Encrypted, &SseConfig::strict())
}

/// The same request over cleartext.
fn over_plaintext(headers: &[(&'static str, &'static str)]) -> Result<SseEnforced, SseRejection> {
    enforce_with(headers, TransportSecurity::Plaintext, &SseConfig::strict())
}

// ── positive ─────────────────────────────────────────────────────────────────────────────────

/// A complete, agreeing trio over TLS is served, and the fingerprint is the digest the caller
/// sent.
#[test]
fn a_complete_customer_key_over_tls_is_accepted() {
    let enforced = served(over_tls(&target_trio(KEY_A, MD5_A)));
    let expected = base64::decode_exact::<16>(MD5_A).expect("canonical");
    assert_eq!(enforced.customer_key_fingerprint().map(KeyFingerprint::as_array), Some(&expected));
    assert!(enforced.copy_source_key_fingerprint().is_none());
    assert!(enforced.managed_algorithm().is_none());
}

/// A copy carries two independent keys and both are read.
#[test]
fn both_key_positions_are_read_independently_on_one_request() {
    let mut headers = target_trio(KEY_A, MD5_A);
    headers.extend(source_trio(KEY_B, MD5_B));
    let enforced = served(over_tls(&headers));
    let target = base64::decode_exact::<16>(MD5_A).expect("canonical");
    let source = base64::decode_exact::<16>(MD5_B).expect("canonical");
    assert_eq!(enforced.customer_key_fingerprint().map(KeyFingerprint::as_array), Some(&target));
    assert_eq!(enforced.copy_source_key_fingerprint().map(KeyFingerprint::as_array), Some(&source));
}

/// A copy-source key with no target key is legal: reading an encrypted source into a plaintext
/// destination is a request AWS accepts.
#[test]
fn a_copy_source_key_alone_is_accepted() {
    let enforced = served(over_tls(&source_trio(KEY_A, MD5_A)));
    assert!(enforced.customer_key_fingerprint().is_none());
    assert!(enforced.copy_source_key_fingerprint().is_some());
}

/// The managed channel puts no key on the wire, so it is not gated by the transport.
#[test]
fn a_server_managed_algorithm_is_served_over_cleartext() {
    let enforced = served(over_plaintext(&[(SSE_ALGORITHM, "AES256")]));
    assert_eq!(enforced.managed_algorithm().map(SseAlgorithm::as_str), Some("AES256"));
}

/// A request that says nothing about encryption passes and declares nothing. The framework does
/// not invent an object-level declaration; the bucket default is the backend's to apply.
#[test]
fn a_request_with_no_sse_headers_declares_nothing() {
    let enforced = served(over_plaintext(&[]));
    assert!(enforced.customer_key_fingerprint().is_none());
    assert!(enforced.copy_source_key_fingerprint().is_none());
    assert!(enforced.managed_algorithm().is_none());
}

// ── negative: the transport gate ─────────────────────────────────────────────────────────────

/// The headline refusal.
#[test]
fn n_a_customer_key_over_cleartext_is_refused() {
    assert_eq!(refused(over_plaintext(&target_trio(KEY_A, MD5_A))), SseRejection::PlaintextCustomerKey);
    assert_eq!(
        SseRejection::PlaintextCustomerKey.code(),
        rustfs_gateway_types::ErrorCode::INVALID_REQUEST
    );
}

/// Every fragment of either trio trips the gate. One header out of three is still a request that
/// put key material, or an announcement of it, on a cleartext wire.
#[test]
fn n_any_single_customer_key_header_trips_the_gate() {
    for name in [
        SSEC_ALGORITHM,
        SSEC_KEY,
        SSEC_KEY_MD5,
        COPY_SSEC_ALGORITHM,
        COPY_SSEC_KEY,
        COPY_SSEC_KEY_MD5,
    ] {
        let value = if name.ends_with("algorithm") {
            CUSTOMER_ALGORITHM
        } else {
            KEY_A
        };
        assert_eq!(
            refused(over_plaintext(&[(name, value)])),
            SseRejection::PlaintextCustomerKey,
            "{name} did not trip the transport gate"
        );
    }
}

/// `X-Forwarded-Proto` is a request header and is never consulted.
///
/// The whole attack is one line long: a caller that could turn the gate off by claiming its own
/// connection was encrypted would turn it off precisely when it mattered. Both spellings and both
/// casings, because "we only look at the lowercase one" is the same defect with a smaller
/// blast radius.
#[test]
fn n_a_forwarded_protocol_header_does_not_open_the_gate() {
    for claim in [
        ("x-forwarded-proto", "https"),
        ("X-Forwarded-Proto", "https"),
        ("x-forwarded-protocol", "https"),
        ("x-forwarded-ssl", "on"),
        ("front-end-https", "on"),
        ("x-url-scheme", "https"),
    ] {
        let mut headers = target_trio(KEY_A, MD5_A);
        headers.push(claim);
        assert_eq!(
            refused(over_plaintext(&headers)),
            SseRejection::PlaintextCustomerKey,
            "{} opened the transport gate",
            claim.0
        );
    }
}

/// The gate is not "refuse everything": the same request over TLS is served, and a request with
/// no key is served over cleartext. A gate stuck closed satisfies every test that expects a
/// refusal.
#[test]
fn n_the_gate_refuses_only_what_it_is_for() {
    assert!(is_ok(&over_tls(&target_trio(KEY_A, MD5_A))), "TLS must serve the same request");
    assert!(is_ok(&over_plaintext(&[])), "a request with no key must not be gated");
    assert!(
        is_ok(&over_plaintext(&[(SSE_ALGORITHM, "AES256")])),
        "the managed channel must not be gated"
    );
}

/// The acknowledged escape hatch works, and works only when acknowledged.
#[test]
fn n_the_plaintext_allowance_is_off_until_a_deployment_spells_it_out() {
    let headers = target_trio(KEY_A, MD5_A);
    assert_eq!(
        refused(enforce_with(&headers, TransportSecurity::Plaintext, &SseConfig::default())),
        SseRejection::PlaintextCustomerKey,
        "the default configuration must refuse"
    );
    let acknowledged = SseConfig::allowing_customer_keys_over_plaintext(
        PlaintextCustomerKeyAck::i_understand_customer_keys_will_be_sent_in_the_clear(),
    );
    assert!(acknowledged.allows_customer_keys_over_plaintext());
    assert!(
        is_ok(&enforce_with(&headers, TransportSecurity::Plaintext, &acknowledged)),
        "the acknowledged configuration must serve"
    );
    assert!(!SseConfig::default().allows_customer_keys_over_plaintext());
}

/// Legacy RustFS's gate, with TLS required: only the target's key.
fn target_gate() -> SseConfig {
    SseConfig::refusing_only_target_keys_over_plaintext(
        PlaintextCustomerKeyAck::i_understand_customer_keys_will_be_sent_in_the_clear(),
    )
}

/// Under the target-only gate a copy source's key is served over cleartext, and read exactly as
/// over TLS; the configuration says so.
#[test]
fn the_target_only_gate_serves_a_copy_source_key_over_cleartext() {
    let enforced = served(enforce_with(&source_trio(KEY_A, MD5_A), TransportSecurity::Plaintext, &target_gate()));
    let source = base64::decode_exact::<16>(MD5_A).expect("canonical");
    assert_eq!(enforced.copy_source_key_fingerprint().map(KeyFingerprint::as_array), Some(&source));
    assert!(target_gate().allows_copy_source_keys_over_plaintext());
    assert!(!target_gate().allows_customer_keys_over_plaintext());
}

/// Under the target-only gate every fragment of the target's trio still trips the gate over
/// cleartext, alone or beside a copy source's key.
#[test]
fn n_the_target_only_gate_still_refuses_every_target_key_fragment() {
    for name in [SSEC_ALGORITHM, SSEC_KEY, SSEC_KEY_MD5] {
        let value = if name.ends_with("algorithm") {
            CUSTOMER_ALGORITHM
        } else {
            KEY_A
        };
        let mut headers = source_trio(KEY_B, MD5_B);
        headers.push((name, value));
        for request in [vec![(name, value)], headers] {
            assert_eq!(
                refused(enforce_with(&request, TransportSecurity::Plaintext, &target_gate())),
                SseRejection::PlaintextCustomerKey,
                "{name}"
            );
        }
    }
}

/// The strict default and the full allowance are unchanged by the target-only reading: the default
/// gates both positions, the allowance neither.
#[test]
fn n_the_two_other_configurations_treat_both_positions_alike() {
    assert!(!SseConfig::strict().allows_copy_source_keys_over_plaintext());
    let open = SseConfig::allowing_customer_keys_over_plaintext(
        PlaintextCustomerKeyAck::i_understand_customer_keys_will_be_sent_in_the_clear(),
    );
    assert!(open.allows_copy_source_keys_over_plaintext());
    assert!(is_ok(&enforce_with(&target_trio(KEY_A, MD5_A), TransportSecurity::Plaintext, &open)));
    assert_eq!(refused(over_plaintext(&source_trio(KEY_A, MD5_A))), SseRejection::PlaintextCustomerKey);
}

/// The gate runs first, so a request that is also wrong in some other way still gets the gate's
/// answer and nothing about its key material.
#[test]
fn n_the_gate_runs_before_every_value_check() {
    let mut malformed = target_trio("not base64", "also not base64");
    malformed.push((SSE_ALGORITHM, "aws:kms"));
    assert_eq!(refused(over_plaintext(&malformed)), SseRejection::PlaintextCustomerKey);
}

// ── negative: the two channels ───────────────────────────────────────────────────────────────

/// A managed algorithm and a customer key on one request is a contradiction, not a choice.
#[test]
fn n_the_two_channels_at_once_are_refused() {
    let mut headers = target_trio(KEY_A, MD5_A);
    headers.push((SSE_ALGORITHM, "aws:kms"));
    assert_eq!(refused(over_tls(&headers)), SseRejection::ChannelsContradict);
    assert_eq!(SseRejection::ChannelsContradict.code(), rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT);
}

/// A KMS qualifier is enough to contradict; the algorithm header need not be there.
#[test]
fn n_a_kms_qualifier_beside_a_customer_key_is_the_same_contradiction() {
    for qualifier in [
        (SSE_KMS_KEY_ID, KEY_ARN),
        (SSE_CONTEXT, "eyJhIjoiYiJ9"),
        (SSE_BUCKET_KEY_ENABLED, "true"),
    ] {
        let mut headers = target_trio(KEY_A, MD5_A);
        headers.push(qualifier);
        assert_eq!(refused(over_tls(&headers)), SseRejection::ChannelsContradict, "{}", qualifier.0);
    }
}

/// A copy-source key beside a managed algorithm is a copy from an SSE-C source into an SSE-S3 or
/// SSE-KMS target, not a contradiction: the source key decrypts the source, and the target is
/// encrypted as the managed headers say.
///
/// This case asserted `ChannelsContradict` until rustfs/backlog#1677 (R11). AWS documents the copy
/// as allowed: the copy-source customer-key headers are what S3 decrypts the source with, and a
/// CopyObject may encrypt its target with an S3-managed key, a KMS key or a customer key whatever
/// the source used (<https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html>);
/// legacy RustFS checks the managed channel against the target's key headers only
/// (rustfs/rustfs@e870a6d25b `rustfs/src/storage/sse.rs:626-634`). The contradiction on the
/// target's own key is still pinned by the two cases above and the one below.
#[test]
fn a_managed_algorithm_beside_a_copy_source_key_is_a_copy_into_managed_encryption() {
    for managed in [
        vec![(SSE_ALGORITHM, "AES256")],
        vec![(SSE_ALGORITHM, "aws:kms"), (SSE_KMS_KEY_ID, KEY_ARN)],
    ] {
        let mut headers = source_trio(KEY_A, MD5_A);
        headers.extend(managed.iter().copied());
        let enforced = served(over_tls(&headers));
        let source = base64::decode_exact::<16>(MD5_A).expect("canonical");
        assert_eq!(enforced.copy_source_key_fingerprint().map(KeyFingerprint::as_array), Some(&source));
        assert!(enforced.customer_key_fingerprint().is_none());
        assert!(enforced.managed_algorithm().is_some(), "{managed:?}");
    }
}

/// The target's own key beside a managed algorithm is still the contradiction on a copy, whatever
/// key the source carries.
#[test]
fn n_a_managed_algorithm_beside_the_target_key_contradicts_on_a_copy_too() {
    let mut headers = source_trio(KEY_A, MD5_A);
    headers.extend(target_trio(KEY_B, MD5_B));
    headers.push((SSE_ALGORITHM, "AES256"));
    assert_eq!(refused(over_tls(&headers)), SseRejection::ChannelsContradict);
    let mut fragment = source_trio(KEY_A, MD5_A);
    fragment.push((SSEC_KEY_MD5, MD5_B));
    fragment.push((SSE_KMS_KEY_ID, KEY_ARN));
    assert_eq!(refused(over_tls(&fragment)), SseRejection::ChannelsContradict);
}

// ── negative: the customer key trio ──────────────────────────────────────────────────────────

/// Every incomplete spelling of the trio, on both sides.
#[test]
fn n_an_incomplete_trio_is_refused_on_either_side() {
    let target: [Vec<(&'static str, &'static str)>; 6] = [
        vec![(SSEC_ALGORITHM, CUSTOMER_ALGORITHM)],
        vec![(SSEC_KEY, KEY_A)],
        vec![(SSEC_KEY_MD5, MD5_A)],
        vec![(SSEC_ALGORITHM, CUSTOMER_ALGORITHM), (SSEC_KEY, KEY_A)],
        vec![(SSEC_ALGORITHM, CUSTOMER_ALGORITHM), (SSEC_KEY_MD5, MD5_A)],
        vec![(SSEC_KEY, KEY_A), (SSEC_KEY_MD5, MD5_A)],
    ];
    for headers in target {
        assert_eq!(
            refused(over_tls(&headers)),
            SseRejection::CustomerTrioIncomplete(KeySide::Target),
            "{headers:?} was not refused as incomplete"
        );
    }
    let source: [Vec<(&'static str, &'static str)>; 3] = [
        vec![(COPY_SSEC_ALGORITHM, CUSTOMER_ALGORITHM)],
        vec![(COPY_SSEC_KEY, KEY_A)],
        vec![(COPY_SSEC_ALGORITHM, CUSTOMER_ALGORITHM), (COPY_SSEC_KEY_MD5, MD5_A)],
    ];
    for headers in source {
        assert_eq!(
            refused(over_tls(&headers)),
            SseRejection::CustomerTrioIncomplete(KeySide::CopySource),
            "{headers:?} was not refused as incomplete"
        );
    }
}

/// Anything but `AES256`, including the lowercase spelling of it.
#[test]
fn n_a_customer_algorithm_other_than_aes256_is_refused() {
    for spelling in ["AES128", "aes256", "", "AES256 ", "aws:kms"] {
        let headers = vec![(SSEC_ALGORITHM, spelling), (SSEC_KEY, KEY_A), (SSEC_KEY_MD5, MD5_A)];
        assert_eq!(
            refused(over_tls(&headers)),
            SseRejection::CustomerAlgorithmUnknown(KeySide::Target),
            "accepted {spelling:?}"
        );
    }
}

/// A key of the wrong width, a digest of the wrong width, a lenient spelling, and a pair that
/// does not agree — all one refusal.
#[test]
fn n_every_malformed_or_disagreeing_pair_is_one_refusal() {
    let pairs: [(&'static str, &'static str); 6] = [
        // The right key with somebody else's digest.
        (KEY_A, MD5_B),
        // Somebody else's key with the right digest: the same mistake from the other side.
        (KEY_B, MD5_A),
        // Thirty-one bytes.
        ("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==", MD5_A),
        // Thirty-three bytes.
        ("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g", MD5_A),
        // A digest of fifteen bytes.
        (KEY_A, "AAECAwQFBgcICQoLDA0O"),
        // The key without its padding.
        ("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", MD5_A),
    ];
    for (key, digest) in pairs {
        assert_eq!(
            refused(over_tls(&target_trio_owned(key, digest))),
            SseRejection::CustomerKeyMalformed(KeySide::Target),
            "key {key:?} with digest {digest:?} produced a different refusal"
        );
    }
}

/// The same for the copy-source position, which is a separate code path.
#[test]
fn n_a_disagreeing_copy_source_pair_is_refused_on_its_own_side() {
    let headers = vec![
        (COPY_SSEC_ALGORITHM, CUSTOMER_ALGORITHM),
        (COPY_SSEC_KEY, KEY_A),
        (COPY_SSEC_KEY_MD5, MD5_B),
    ];
    assert_eq!(refused(over_tls(&headers)), SseRejection::CustomerKeyMalformed(KeySide::CopySource));
}

/// A repeated key header is two keys, and two keys is not a value this service picks between.
///
/// `MetaView::header` joins repeated field lines with `, `, which no strict base64 decoder
/// accepts — so the request is refused rather than served under whichever line arrived first.
#[test]
fn n_a_repeated_customer_key_header_is_refused() {
    let headers = vec![
        (SSEC_ALGORITHM, CUSTOMER_ALGORITHM),
        (SSEC_KEY, KEY_A),
        (SSEC_KEY, KEY_B),
        (SSEC_KEY_MD5, MD5_A),
    ];
    assert_eq!(refused(over_tls(&headers)), SseRejection::CustomerKeyMalformed(KeySide::Target));
}

// ── negative: the managed channel through a real request head ────────────────────────────────

#[test]
fn n_an_unknown_managed_algorithm_is_refused_through_the_request_head() {
    let refusal = refused(over_tls(&[(SSE_ALGORITHM, "aes256")]));
    assert!(matches!(refusal, SseRejection::ManagedChannelInvalid(_)));
    assert_eq!(refusal.code(), rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT);
}

#[test]
fn n_a_kms_key_id_with_no_algorithm_beside_it_is_refused() {
    assert_eq!(
        refused(over_tls(&[(SSE_KMS_KEY_ID, KEY_ARN)])),
        SseRejection::ManagedChannelInvalid(ManagedRejection::QualifierWithoutAlgorithm)
    );
}

#[test]
fn n_a_bucket_key_switch_that_is_not_a_boolean_is_refused() {
    let headers = vec![(SSE_ALGORITHM, "aws:kms"), (SSE_BUCKET_KEY_ENABLED, "TRUE")];
    assert_eq!(
        refused(over_tls(&headers)),
        SseRejection::ManagedChannelInvalid(ManagedRejection::BucketKeyNotABoolean)
    );
}

// ── negative: what a refusal may say ─────────────────────────────────────────────────────────

/// No sentence this module can produce carries a key, a digest, a key id, or any other request
/// byte.
///
/// The corpus below is every rejection the enforcement can construct. The assertion is over the
/// *rendered sentence*, because that is what reaches an error document and an access log; a
/// variant that carried the value privately and rendered a constant would pass, and so it should.
#[test]
fn n_no_refusal_sentence_carries_a_key_a_digest_or_a_key_id() {
    let every_rejection = [
        SseRejection::PlaintextCustomerKey,
        SseRejection::ChannelsContradict,
        SseRejection::CustomerTrioIncomplete(KeySide::Target),
        SseRejection::CustomerTrioIncomplete(KeySide::CopySource),
        SseRejection::CustomerAlgorithmUnknown(KeySide::Target),
        SseRejection::CustomerAlgorithmUnknown(KeySide::CopySource),
        SseRejection::CustomerKeyMalformed(KeySide::Target),
        SseRejection::CustomerKeyMalformed(KeySide::CopySource),
        SseRejection::ManagedChannelInvalid(ManagedRejection::QualifierWithoutAlgorithm),
        SseRejection::ManagedChannelInvalid(ManagedRejection::KmsQualifierWithoutKmsAlgorithm),
        SseRejection::ManagedChannelInvalid(ManagedRejection::BucketKeyNotABoolean),
        SseRejection::ManagedChannelInvalid(ManagedRejection::ContextNotBase64),
        SseRejection::ManagedChannelInvalid(ManagedRejection::ContextNotJson),
        SseRejection::ManagedChannelInvalid(ManagedRejection::Document(
            crate::ops::shared::encryption::EncryptionRejection::AlgorithmUnknown,
        )),
        SseRejection::ManagedChannelInvalid(ManagedRejection::Document(
            crate::ops::shared::encryption::EncryptionRejection::KmsKeyWithoutKmsAlgorithm,
        )),
    ];
    // The decoded key bytes as well as their base64 text: a sentence that quoted the raw key
    // would not contain the base64 spelling of it.
    let raw_key = base64::decode_exact::<32>(KEY_A).expect("canonical");
    let raw_digest = base64::decode_exact::<16>(MD5_A).expect("canonical");
    for rejection in every_rejection {
        let sentence = rejection.reason();
        assert!(!sentence.contains(KEY_A), "{rejection:?} quotes the key");
        assert!(!sentence.contains(KEY_B), "{rejection:?} quotes the other key");
        assert!(!sentence.contains(MD5_A), "{rejection:?} quotes the digest");
        assert!(!sentence.contains(MD5_B), "{rejection:?} quotes the other digest");
        assert!(!sentence.contains(KEY_ARN), "{rejection:?} quotes the KMS key id");
        assert!(!sentence.contains("arn:"), "{rejection:?} quotes an ARN");
        assert!(
            !sentence.as_bytes().windows(raw_key.len()).any(|window| window == raw_key),
            "{rejection:?} carries the raw key bytes"
        );
        assert!(
            !sentence
                .as_bytes()
                .windows(raw_digest.len())
                .any(|window| window == raw_digest),
            "{rejection:?} carries the raw digest bytes"
        );
        assert!(!sentence.is_empty(), "{rejection:?} has no sentence at all");
    }
}

/// The refusal a caller receives is the same whichever half of the pair it got wrong — not only
/// the same variant, but the same code and the same bytes.
#[test]
fn n_a_wrong_digest_and_a_wrong_key_produce_identical_answers() {
    let wrong_digest = refused(over_tls(&target_trio_owned(KEY_A, MD5_B)));
    let wrong_key = refused(over_tls(&target_trio_owned(KEY_B, MD5_A)));
    assert_eq!(wrong_digest, wrong_key);
    assert_eq!(wrong_digest.code(), wrong_key.code());
    assert_eq!(wrong_digest.reason(), wrong_key.reason());
}

/// The trio is spelled with runtime values, which the `&'static str` fixture helpers cannot take.
fn target_trio_owned(key: &'static str, digest: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![(SSEC_ALGORITHM, CUSTOMER_ALGORITHM), (SSEC_KEY, key), (SSEC_KEY_MD5, digest)]
}

/// The gate does not depend on which operation the path names.
///
/// Stated because the pipeline calls `enforce` before it knows anything an operation could
/// change, and a future edit that made the gate conditional on a per-operation flag would be a
/// gate a new operation can be added without.
#[test]
fn n_the_gate_is_the_same_for_a_bucket_target_as_for_an_object() {
    let request = http::Request::builder()
        .method("POST")
        .uri("http://host.invalid/conf-sse?delete")
        .header("host", "host.invalid")
        .header(SSEC_ALGORITHM, CUSTOMER_ALGORITHM)
        .header(SSEC_KEY, KEY_A)
        .header(SSEC_KEY_MD5, MD5_A)
        .body(())
        .expect("well formed");
    let accepted = WireRequest::accept(request, &Limits::default()).expect("acceptable");
    let view = MetaView::of(&accepted, TargetKind::Bucket).expect("the path names a bucket");
    assert_eq!(
        refused(enforce(&view, TransportSecurity::Plaintext, &SseConfig::strict())),
        SseRejection::PlaintextCustomerKey
    );
}
