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

//! The legacy RustFS SigV4 header guard's unit suite, split out of its module for size.
//!
//! Responsible for: the guard's rules over a request head — which `Authorization` values read,
//! which algorithm tokens are refused, which `x-amz-*` headers must be signed on each form — as
//! the scenarios of RustFS's own guard tests state them (`rustfs/src/auth.rs` `ghsa_xm99_*`,
//! `ghsa_g8w9_*`; `rustfs/src/server/layer.rs` `sigv4_header_guard_layer_*`), and the refusal it
//! renders.
//! NOT responsible for: where the pipeline asks (`compat/sut`'s `sigv4_header_guard_tests` drive the
//! whole assembly).
//! Upstream: `super`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;

use http::HeaderValue;

use rustfs_gateway_core::TargetKind;

const SIGNED_ALL: &str = "host;x-amz-content-sha256;x-amz-date";
const PRESIGNED_HOST_ONLY: &str = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20260827T000000Z&X-Amz-Expires=900&\
     X-Amz-SignedHeaders=host&X-Amz-Credential=test/20260827/us-east-1/s3/aws4_request&X-Amz-Signature=signature";
const PRESIGNED_TAGGING: &str = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20260827T000000Z&X-Amz-Expires=900&\
     X-Amz-SignedHeaders=host%3Bx-amz-tagging%3Bx-amz-meta-owner&X-Amz-Credential=test/20260827/us-east-1/s3/aws4_request&\
     X-Amz-Signature=signature";

fn authorization(algorithm: &str, signed: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{algorithm} Credential=test/20260827/us-east-1/s3/aws4_request, SignedHeaders={signed}, Signature={}",
        "0".repeat(64)
    ))
    .expect("a header value")
}

fn header_signed(signed: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, authorization(SIGV4_ALGORITHM, signed));
    headers.insert("x-amz-date", HeaderValue::from_static("20260827T000000Z"));
    headers.insert("x-amz-content-sha256", HeaderValue::from_static("UNSIGNED-PAYLOAD"));
    headers
}

fn path_style() -> ResolvedHost {
    ResolvedHost::standard(TargetKind::Object)
}

fn guard(headers: &HeaderMap, query: &str) -> Option<S3Error> {
    SigV4HeaderGuard::LegacyRustfs.refusal(headers, query, &Method::PUT, &path_style(), ResponseKind::Other)
}

fn sentence_of(refusal: Option<S3Error>) -> Option<String> {
    refusal.map(|refusal| {
        assert_eq!(refusal.code(), Some(&ErrorCode::ACCESS_DENIED));
        assert_eq!(refusal.status().as_u16(), 403);
        assert!(refusal.must_close_connection(), "a guard refusal must close");
        refusal.message().unwrap_or_default().to_owned()
    })
}

// ── header-signed SigV4 ────────────────────────────────────────────────────────────────────────

/// Negative — every unsigned `x-amz-*` header on a header-signed request is refused, whatever
/// the query says, and `x-amz-date` is not exempt.
#[test]
fn n_an_unsigned_amz_header_on_a_header_signed_request_is_refused() {
    for name in [
        "x-amz-copy-source",
        "x-amz-copy-source-range",
        "x-amz-tagging",
        "x-amz-meta-owner",
        "x-amz-metadata-directive",
        "x-amz-security-token",
        "x-amz-server-side-encryption",
    ] {
        let mut headers = header_signed(SIGNED_ALL);
        headers.insert(http::HeaderName::from_static(name), HeaderValue::from_static("injected"));
        assert_eq!(sentence_of(guard(&headers, "")).as_deref(), Some(UNSIGNED_HEADERS), "{name}");
        assert_eq!(sentence_of(guard(&headers, "tagging")).as_deref(), Some(UNSIGNED_HEADERS), "{name}");
    }
    let headers = header_signed("host;x-amz-content-sha256");
    assert_eq!(sentence_of(guard(&headers, "")).as_deref(), Some(UNSIGNED_HEADERS));
}

/// Positive — the four envelope headers and `x-amz-cf-id` may stay unsigned; a signed header of any
/// casing is covered; a non-`x-amz-*` header is not the guard's.
#[test]
fn the_envelope_headers_and_the_cdn_id_may_stay_unsigned() {
    let mut headers = header_signed("host;x-amz-date");
    headers.insert("x-amz-cf-id", HeaderValue::from_static("cdn-request"));
    headers.insert("x-amz-decoded-content-length", HeaderValue::from_static("1024"));
    headers.insert("x-amz-trailer", HeaderValue::from_static("x-amz-checksum-crc32"));
    headers.insert("x-amz-checksum-algorithm", HeaderValue::from_static("CRC32"));
    headers.insert("content-type", HeaderValue::from_static("text/plain"));
    assert_eq!(sentence_of(guard(&headers, "")), None);

    let mut signed_copy = header_signed("host;x-amz-content-sha256;x-amz-copy-source;x-amz-date");
    signed_copy.insert("x-amz-copy-source", HeaderValue::from_static("/source/secret"));
    assert_eq!(sentence_of(guard(&signed_copy, "")), None);

    let mixed_case = header_signed("Host;X-Amz-Content-Sha256;X-Amz-Date");
    assert_eq!(sentence_of(guard(&mixed_case, "")), None);
}

/// Negative — the exemption is by exact name: a header that merely begins like an envelope header
/// is still refused.
#[test]
fn n_the_envelope_exemption_is_by_exact_name() {
    let mut headers = header_signed("host;x-amz-date");
    headers.insert("x-amz-sdk-checksum-algorithm", HeaderValue::from_static("CRC32"));
    assert_eq!(sentence_of(guard(&headers, "")).as_deref(), Some(UNSIGNED_HEADERS));
}

/// Negative — an algorithm token other than `AWS4-HMAC-SHA256`, in any case, is refused as
/// unsupported, and cannot carry an unsigned header past the guard either.
#[test]
fn n_another_algorithm_token_is_refused_as_unsupported() {
    for algorithm in ["OTHER", "aws4-hmac-sha256", "AWS4-ECDSA-P256-SHA256", "AWS4-HMAC-SHA512"] {
        let mut headers = header_signed(SIGNED_ALL);
        headers.insert(AUTHORIZATION, authorization(algorithm, SIGNED_ALL));
        assert_eq!(sentence_of(guard(&headers, "")).as_deref(), Some(UNSUPPORTED_ALGORITHM), "{algorithm}");
        headers.insert("x-amz-copy-source", HeaderValue::from_static("/source/secret"));
        assert!(guard(&headers, "").is_some(), "{algorithm}");
    }
}

/// Negative — a value that claims `AWS4-HMAC-SHA256` and does not read is refused as invalid; every
/// part of the shape is load-bearing.
#[test]
fn n_an_unreadable_aws4_value_is_refused_as_invalid() {
    let sig = "0".repeat(64);
    for value in [
        "AWS4-HMAC-SHA256".to_owned(),
        "AWS4-HMAC-SHA256 invalid".to_owned(),
        "AWS4-HMAC-SHA256 Credential=test/20260827/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc".to_owned(),
        format!(
            "AWS4-HMAC-SHA256 Credential=test/20260827/us-east-1/s3/aws4_request, SignedHeaders=host, Signature={}",
            "A".repeat(64)
        ),
        format!("AWS4-HMAC-SHA256 Credential=test/20261301/us-east-1/s3/aws4_request, SignedHeaders=host, Signature={sig}"),
        format!("AWS4-HMAC-SHA256 Credential=test/20270229/us-east-1/s3/aws4_request, SignedHeaders=host, Signature={sig}"),
        format!("AWS4-HMAC-SHA256 Credential=test/2026082/us-east-1/s3/aws4_request, SignedHeaders=host, Signature={sig}"),
        format!("AWS4-HMAC-SHA256 Credential=test/20260827/us-east-1//aws4_request, SignedHeaders=host, Signature={sig}"),
        format!("AWS4-HMAC-SHA256 Credential=test/20260827/us-east-1/s3/aws4_request SignedHeaders=host, Signature={sig}"),
        format!("AWS4-HMAC-SHA256 Credential=test/20260827/us-east-1/s3/aws4_request, SignedHeaders=host Signature={sig}"),
        format!(
            "AWS4-HMAC-SHA256 Credential=test/20260827/us-east-1/s3/aws4_request, SignedHeaders=host, Signature={sig} trailing"
        ),
        format!("AWS4-HMAC-SHA256Credential=test/20260827/us-east-1/s3/aws4_request, SignedHeaders=host, Signature={sig}"),
    ] {
        let mut headers = header_signed("host");
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&value).expect("a header value"));
        assert_eq!(sentence_of(guard(&headers, "")).as_deref(), Some(INVALID_HEADER), "{value:?}");
    }
}

/// Positive — the shape's permitted freedoms: an empty key and region, a leap day, a comma inside
/// the key, tabs where whitespace is allowed, no space after the commas, and trailing whitespace.
/// (The shape also admits CR and LF, which no header value can carry.)
#[test]
fn a_readable_value_passes_in_every_permitted_spelling() {
    let sig = "0".repeat(64);
    for value in [
        format!("AWS4-HMAC-SHA256 Credential=/20240229//s3/aws4_request, SignedHeaders={SIGNED_ALL}, Signature={sig}"),
        format!(
            "AWS4-HMAC-SHA256\tCredential=test/20260827/us-east-1/s3/aws4_request,SignedHeaders={SIGNED_ALL},Signature={sig}"
        ),
        format!(
            "AWS4-HMAC-SHA256 \t Credential=test/20260827/us-east-1/s3/aws4_request,\t SignedHeaders={SIGNED_ALL},\t Signature={sig} \t"
        ),
        format!(
            "AWS4-HMAC-SHA256 Credential=k,ey/20000229/us-east-1/s3/aws4_request, SignedHeaders={SIGNED_ALL}, Signature={sig}"
        ),
    ] {
        let mut headers = header_signed(SIGNED_ALL);
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&value).expect("a header value"));
        assert_eq!(sentence_of(guard(&headers, "")), None, "{value:?}");
    }
}

/// Negative — every `Authorization` value is checked; a second one that signs less refuses.
#[test]
fn n_a_second_authorization_value_is_checked_on_its_own() {
    let mut headers = header_signed("host;x-amz-content-sha256;x-amz-copy-source;x-amz-date");
    headers.insert("x-amz-copy-source", HeaderValue::from_static("/source/secret"));
    headers.append(AUTHORIZATION, authorization(SIGV4_ALGORITHM, SIGNED_ALL));
    assert_eq!(sentence_of(guard(&headers, "")).as_deref(), Some(UNSIGNED_HEADERS));
}

/// Positive — anonymous, SigV2 and bearer requests carry no SigV4 list; the guard leaves them to
/// the authenticator.
#[test]
fn a_request_without_a_sigv4_header_is_not_the_guards() {
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-copy-source", HeaderValue::from_static("/source/secret"));
    assert_eq!(sentence_of(guard(&headers, "")), None);
    for value in ["AWS key:signature", "Bearer token", "AWS4-HMAC-SHA25 Credential=x"] {
        headers.insert(AUTHORIZATION, HeaderValue::from_static(value));
        assert_eq!(sentence_of(guard(&headers, "")), None, "{value}");
    }
    headers.insert(AUTHORIZATION, HeaderValue::from_bytes(b"AWS4-HMAC-SHA256 \xff").expect("an opaque value"));
    assert_eq!(sentence_of(guard(&headers, "")), None, "a value that is not text is not read");
}

// ── presigned SigV4 ────────────────────────────────────────────────────────────────────────────

/// Negative — a presigned query signs only what `X-Amz-SignedHeaders` names; every other `x-amz-*`
/// header is refused.
#[test]
fn n_an_unsigned_amz_header_on_a_presigned_request_is_refused() {
    for name in [
        "x-amz-tagging",
        "x-amz-website-redirect-location",
        "x-amz-storage-class",
        "x-amz-acl",
        "x-amz-meta-owner",
        "x-amz-object-lock-mode",
        "x-amz-server-side-encryption",
        "x-amz-content-sha256",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        headers.insert(http::HeaderName::from_static(name), HeaderValue::from_static("attacker-controlled"));
        assert_eq!(
            sentence_of(guard(&headers, PRESIGNED_HOST_ONLY)).as_deref(),
            Some(UNSIGNED_HEADERS),
            "{name}"
        );
    }
    let mut plain = HeaderMap::new();
    plain.insert("content-type", HeaderValue::from_static("text/plain"));
    plain.insert("cache-control", HeaderValue::from_static("no-store"));
    assert_eq!(sentence_of(guard(&plain, PRESIGNED_HOST_ONLY)), None);
}

/// Negative — detection and the signed list follow the verifier's reading: any case of the
/// signature key is presigned, a missing list signs nothing, a differently cased list key does not
/// widen the list, and a repeated exact key signs nothing at all.
#[test]
fn n_the_presigned_list_cannot_be_widened_or_dropped() {
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-tagging", HeaderValue::from_static("a=b"));
    let without_list = PRESIGNED_HOST_ONLY.replace("&X-Amz-SignedHeaders=host", "");
    let lowercase = PRESIGNED_HOST_ONLY.to_ascii_lowercase();
    let widened_by_case = format!("{PRESIGNED_HOST_ONLY}&x-amz-signedheaders=host%3Bx-amz-tagging");
    let duplicated = format!("{PRESIGNED_HOST_ONLY}&X-Amz-SignedHeaders=host%3Bx-amz-tagging");
    let encoded_key = PRESIGNED_HOST_ONLY.replace("X-Amz-Signature=", "X%2DAmz%2DSignature=");
    for query in [without_list, lowercase, widened_by_case, duplicated, encoded_key] {
        assert_eq!(sentence_of(guard(&headers, &query)).as_deref(), Some(UNSIGNED_HEADERS), "{query}");
    }
}

/// Positive — a signed header passes in any casing of the list, `x-amz-cf-id` may stay unsigned,
/// and one further unsigned header on top still refuses.
#[test]
fn a_presigned_request_passes_with_signed_or_exempt_headers() {
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-tagging", HeaderValue::from_static("owner=app"));
    headers.insert("x-amz-meta-owner", HeaderValue::from_static("app"));
    assert_eq!(sentence_of(guard(&headers, PRESIGNED_TAGGING)), None);
    let uppercase = PRESIGNED_TAGGING.replace("x-amz-tagging", "X-Amz-Tagging");
    assert_eq!(sentence_of(guard(&headers, &uppercase)), None);
    let spaced = PRESIGNED_TAGGING.replace("host%3Bx-amz-tagging", "host%3B+x-amz-tagging+");
    assert_eq!(sentence_of(guard(&headers, &spaced)), None, "a list entry is trimmed");
    headers.insert("x-amz-cf-id", HeaderValue::from_static("cloudfront-request-id"));
    assert_eq!(sentence_of(guard(&headers, PRESIGNED_TAGGING)), None);
    headers.insert("x-amz-storage-class", HeaderValue::from_static("REDUCED_REDUNDANCY"));
    assert_eq!(sentence_of(guard(&headers, PRESIGNED_TAGGING)).as_deref(), Some(UNSIGNED_HEADERS));
}

/// Negative — neither signature form widens the other: a header signed in `Authorization` is still
/// unsigned for the presigned list, and the other way round.
#[test]
fn n_header_and_query_signatures_cannot_widen_each_other() {
    let mut headers = header_signed("host;x-amz-content-sha256;x-amz-copy-source;x-amz-date");
    headers.insert("x-amz-copy-source", HeaderValue::from_static("/source/secret"));
    assert_eq!(
        sentence_of(guard(&headers, "X-Amz-Signature=test&X-Amz-SignedHeaders=host")).as_deref(),
        Some(UNSIGNED_HEADERS)
    );
    let mut signing_less = header_signed(SIGNED_ALL);
    signing_less.insert("x-amz-copy-source", HeaderValue::from_static("/source/secret"));
    let presigned_copy = "X-Amz-Signature=test&X-Amz-SignedHeaders=host%3Bx-amz-copy-source%3Bx-amz-content-sha256%3Bx-amz-date";
    assert_eq!(sentence_of(guard(&signing_less, presigned_copy)).as_deref(), Some(UNSIGNED_HEADERS));
}

/// Positive — a query without the SigV4 signature key is not presigned: a SigV2 URL and an ordinary
/// sub-resource query leave the headers to the authenticator.
#[test]
fn a_query_without_the_sigv4_signature_is_not_presigned() {
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-tagging", HeaderValue::from_static("owner=app"));
    for query in [
        "",
        "versioning=",
        "AWSAccessKeyId=test&Expires=1893456000&Signature=abc",
        "X-Amz-Signatures=x",
    ] {
        assert_eq!(sentence_of(guard(&headers, query)), None, "{query}");
    }
}

// ── the switch and its position ────────────────────────────────────────────────────────────────

/// Negative — off by default, the guard answers nothing.
#[test]
fn n_the_default_assembly_does_not_guard() {
    assert_eq!(SigV4HeaderGuard::default(), SigV4HeaderGuard::Off);
    let mut headers = header_signed(SIGNED_ALL);
    headers.insert(AUTHORIZATION, authorization("OTHER", SIGNED_ALL));
    assert!(
        SigV4HeaderGuard::Off
            .refusal(&headers, "", &Method::GET, &path_style(), ResponseKind::Other)
            .is_none()
    );
}

/// Negative — a service-root write the gateway would answer with its virtual-host hint keeps that
/// answer, as RustFS's hint layer answers before its guard; a read of the root does not.
#[test]
fn n_a_hinted_service_root_write_is_left_to_the_hint() {
    let mut headers = header_signed(SIGNED_ALL);
    headers.insert(AUTHORIZATION, authorization("OTHER", SIGNED_ALL));
    let hinted =
        ResolvedHost::standard(TargetKind::Service).with_diagnostic(Some(crate::ext::VhostHint::LooksLikeVhostButNotConfigured));
    for method in [Method::PUT, Method::DELETE] {
        assert!(
            SigV4HeaderGuard::LegacyRustfs
                .refusal(&headers, "", &method, &hinted, ResponseKind::Other)
                .is_none(),
            "{method}"
        );
    }
    assert!(
        SigV4HeaderGuard::LegacyRustfs
            .refusal(&headers, "", &Method::GET, &hinted, ResponseKind::Other)
            .is_some()
    );
}

/// Negative — a `HEAD` is refused like any other method: the same code, sentence and close. That
/// a `HEAD` answer carries no document is the pipeline's response invariant, asserted through the
/// whole assembly in `compat/sut`.
#[test]
fn n_a_head_is_refused_like_any_other_method() {
    let mut headers = header_signed(SIGNED_ALL);
    headers.insert(AUTHORIZATION, authorization("OTHER", SIGNED_ALL));
    let refusal = SigV4HeaderGuard::LegacyRustfs.refusal(&headers, "", &Method::HEAD, &path_style(), ResponseKind::Head);
    assert_eq!(sentence_of(refusal).as_deref(), Some(UNSUPPORTED_ALGORITHM));
}

/// The date rule on its own: real calendar days only.
#[test]
fn only_real_calendar_days_read() {
    for date in ["20240229", "20000229", "00000229", "20261231", "99991231"] {
        assert!(is_calendar_date(date), "{date}");
    }
    for date in [
        "20230229", "19000229", "20261301", "20260001", "20260100", "20260431", "2026082", "2026082a", "+2026082",
    ] {
        assert!(!is_calendar_date(date), "{date}");
    }
}

/// The form decoding on its own.
#[test]
fn a_query_component_is_decoded_as_a_form() {
    assert_eq!(form_decode("a+b%3Bc"), "a b;c");
    assert_eq!(form_decode("%zz%4"), "%zz%4");
    assert_eq!(form_decode("%41%62"), "Ab");
}
