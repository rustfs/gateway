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

//! `c-sig-0401`..`c-sig-0416` — the signer round trip, from outside the crate.
//!
//! Responsible for: proving that a request signed through the **public** API verifies through the
//! **public** verification path — floor, clock, scope cross-check, signed-header rules, canonical
//! request, constant-time comparison — and that each way of breaking it is refused. Being an
//! external crate is the point: it cannot reach a `pub(crate)` shortcut, so a round trip that
//! passes here is one a real client could perform.
//! NOT responsible for: the AWS signing test suite and anything needing `VerifiedScope`, which live
//! in `src/signer_tests.rs` because the suite's placeholder service name is unspellable here.
//! Upstream: `rustfs-gateway-sig`'s public API. Downstream: none (test-only).

use http::Method;
use http::header::{HeaderMap, HeaderName};
use rustfs_gateway_sig::{
    AmzDate, AuthError, CanonicalRequestSpec, ExpectedScope, MAX_PRESIGNED_EXPIRY_SECONDS, PayloadMode, PresignedParams, RawHost,
    RawQuery, RegionSet, RequestNow, ScopeDate, SecretBytes, SessionToken, SigLocation, SigService, SigV4Authorization,
    SigV4Signer, SignedHeaderSet, SignedRequest, SignerError, SigningCredentials, SigningRequest, SigningScope, SkewWindow,
    Tamper, TamperComponent, TrailerSet, UriPathCandidates, WireView, X_AMZ_CONTENT_SHA256_HEADER_NAME, calculate_signature,
    enforce_clock_skew, enforce_no_duplicate_sig_params, enforce_presign_expiry, enforce_scope, signing_key,
};

const EXAMPLE_KEY: &[u8] = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const EXAMPLE_ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
const EXAMPLE_TIMESTAMP: &str = "20150830T123600Z";
const EXAMPLE_DAY: &str = "20150830";
const EXAMPLE_NOW: i64 = 1_440_938_160;

fn host() -> RawHost {
    RawHost::from_host_header(b"example.amazonaws.com").expect("a valid host")
}

fn timestamp() -> AmzDate {
    AmzDate::parse(EXAMPLE_TIMESTAMP).expect("a valid timestamp")
}

fn signer() -> SigV4Signer {
    let credentials = SigningCredentials::new(EXAMPLE_ACCESS_KEY_ID, EXAMPLE_KEY).expect("valid credentials");
    let scope = SigningScope::new(ScopeDate::parse(EXAMPLE_DAY).expect("a valid day"), "us-east-1", SigService::S3)
        .expect("a serviceable scope");
    SigV4Signer::new(credentials, scope)
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("a test header name");
        map.append(name, value.parse().expect("a test header value"));
    }
    map
}

/// The verification path, assembled from the crate's public exports only.
///
/// The floor runs first, exactly as `SecurityFloor::admit` orders it: duplicates, then the clock,
/// then — for a presigned URL — expiry, and only then the scope cross-check and the comparison.
fn verify(signed: &SignedRequest, now: RequestNow) -> Result<(), AuthError> {
    let raw_query = RawQuery::new(signed.query());
    let view = WireView::new(signed.headers(), raw_query);
    enforce_no_duplicate_sig_params(&view)?;

    let presigned = signed.location() == SigLocation::Query;
    let (scope, list, presented, date) = if presigned {
        let params = PresignedParams::parse(&raw_query)?;
        (
            params.scope().clone(),
            params.signed_headers().to_owned(),
            params.signature().clone(),
            params.date(),
        )
    } else {
        let header = signed.authorization().ok_or(AuthError::AuthorizationHeaderMalformed)?;
        let auth = SigV4Authorization::parse(header)?;
        let text = signed
            .headers()
            .get("x-amz-date")
            .and_then(|value| value.to_str().ok())
            .ok_or(AuthError::AuthorizationHeaderMalformed)?;
        (
            auth.scope().clone(),
            auth.signed_headers().to_owned(),
            auth.signature().clone(),
            AmzDate::parse(text)?,
        )
    };

    // The access key id is not covered by the signature; it is what the secret is looked up by.
    if scope.access_key_id().access_key_id() != EXAMPLE_ACCESS_KEY_ID {
        return Err(AuthError::InvalidAccessKeyId);
    }
    let clock = enforce_clock_skew(&date, now, SkewWindow::DEFAULT)?;
    if presigned {
        enforce_presign_expiry(&view, clock)?;
    }

    let regions = RegionSet::new(["us-east-1"]).expect("a non-empty region set");
    let verified = enforce_scope(&scope, clock, &ExpectedScope::new(SigService::S3, &regions))
        .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
    let set = SignedHeaderSet::parse_and_enforce(&list, signed.headers(), None)?;
    let payload = match signed.headers().get(X_AMZ_CONTENT_SHA256_HEADER_NAME) {
        Some(value) => {
            let text = value.to_str().map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
            PayloadMode::parse(text, TrailerSet::None).map_err(|_| AuthError::AuthorizationHeaderMalformed)?
        }
        None if presigned => PayloadMode::Unsigned,
        None => PayloadMode::Empty,
    };

    let paths = UriPathCandidates::new(signed.path())?;
    let host = host();
    let spec = CanonicalRequestSpec::new(
        signed.method(),
        &paths,
        &raw_query,
        signed.headers(),
        &set,
        &host,
        payload.canonical_payload_token(),
    );
    let spec = if presigned { spec.presigned() } else { spec };
    let material = signing_key(&SecretBytes::new(EXAMPLE_KEY), &verified);
    for candidate in spec.candidates()? {
        let computed = calculate_signature(&material, &candidate.string_to_sign(&date, &scope));
        if presented.ct_verify(&computed).is_ok() {
            return Ok(());
        }
    }
    Err(AuthError::SignatureDoesNotMatch)
}

fn now() -> RequestNow {
    RequestNow::from_unix_seconds(EXAMPLE_NOW)
}

fn sign(path: &str, query: &str) -> SignedRequest {
    let map = headers(&[("content-type", "text/plain")]);
    let host = host();
    let request = SigningRequest::new(&Method::GET, path, query, &map, &host, PayloadMode::Empty, timestamp());
    signer().sign_headers(&request).expect("signable")
}

/// Positive — c-sig-0401: a header-signed request survives the whole public verification path,
/// including the parts a signer never sees: the duplicate rule, the skew window and the scope
/// cross-check.
#[test]
fn c_sig_0401_a_header_signed_request_survives_the_public_verification_path() {
    for (path, query) in [
        ("/", ""),
        ("/bucket", "list-type=2"),
        ("/bucket/key", "prefix=a%20b&x-id=GetObject"),
        ("/bucket/a+b", "prefix=a%2Bb"),
        ("/bucket/%E4%B8%AD%E6%96%87", ""),
        ("/bucket/key", "acl"),
    ] {
        let signed = sign(path, query);
        assert_eq!(verify(&signed, now()), Ok(()), "{path}?{query} must verify");
    }
}

/// Positive — c-sig-0402: a presigned URL survives the same path, expiry reader included, and its
/// target is a URL a client can use verbatim.
#[test]
fn c_sig_0402_a_presigned_url_survives_the_public_verification_path() {
    let map = HeaderMap::new();
    let host = host();
    let request = SigningRequest::new(
        &Method::GET,
        "/bucket/key",
        "versionId=7",
        &map,
        &host,
        PayloadMode::Unsigned,
        timestamp(),
    );
    let signed = signer().presign(&request, 900).expect("signable");
    assert_eq!(verify(&signed, now()), Ok(()));
    assert!(signed.target().starts_with("/bucket/key?versionId=7&X-Amz-Algorithm="));
    assert!(signed.target().contains("&X-Amz-Signature="));
}

/// Positive — c-sig-0403: a session token is signed, not merely attached. It arrives as an
/// `x-amz-*` header, so rule 6 of the signed-header set forces it into the list.
#[test]
fn c_sig_0403_a_session_token_is_covered_by_the_signature() {
    let credentials = SigningCredentials::new(EXAMPLE_ACCESS_KEY_ID, EXAMPLE_KEY)
        .expect("valid")
        .with_session_token(SessionToken::new("FQoGZXIvYXdzE").expect("non-empty"));
    let scope = SigningScope::new(ScopeDate::parse(EXAMPLE_DAY).expect("valid"), "us-east-1", SigService::S3).expect("valid");
    let map = HeaderMap::new();
    let host = host();
    let request = SigningRequest::new(&Method::GET, "/bucket/key", "", &map, &host, PayloadMode::Empty, timestamp());
    let signed = SigV4Signer::new(credentials, scope).sign_headers(&request).expect("signable");
    assert!(signed.headers().contains_key("x-amz-security-token"));
    assert!(
        signed
            .authorization()
            .expect("an Authorization header")
            .contains("SignedHeaders=host;x-amz-date;x-amz-security-token,")
    );
    assert_eq!(verify(&signed, now()), Ok(()));
}

/// Negative — c-sig-0404: swapping the session token after signing is refused. Without rule 6 this
/// would change which identity the request runs as while the signature still verified.
#[test]
fn c_sig_0404_a_swapped_session_token_is_refused() {
    let credentials = SigningCredentials::new(EXAMPLE_ACCESS_KEY_ID, EXAMPLE_KEY)
        .expect("valid")
        .with_session_token(SessionToken::new("FQoGZXIvYXdzE").expect("non-empty"));
    let scope = SigningScope::new(ScopeDate::parse(EXAMPLE_DAY).expect("valid"), "us-east-1", SigService::S3).expect("valid");
    let map = HeaderMap::new();
    let host = host();
    let request = SigningRequest::new(&Method::GET, "/bucket/key", "", &map, &host, PayloadMode::Empty, timestamp());
    let signed = SigV4Signer::new(credentials, scope).sign_headers(&request).expect("signable");
    let swapped = signed
        .tampered(
            &Tamper::new(TamperComponent::CanonicalHeaderValue)
                .with_target("x-amz-security-token")
                .with_new_value("SOMEBODY-ELSES-TOKEN"),
        )
        .expect("tamperable");
    assert_eq!(verify(&swapped, now()), Err(AuthError::SignatureDoesNotMatch));
}

/// Negative — c-sig-0405: injecting an `x-amz-*` header the signature never covered is refused
/// before any comparison, because the header set no longer satisfies rule 6.
#[test]
fn c_sig_0405_an_injected_amz_header_is_refused() {
    let signed = sign("/bucket/key", "");
    let injected = signed
        .tampered(
            &Tamper::new(TamperComponent::CanonicalHeaderValue)
                .with_target("x-amz-copy-source")
                .with_new_value("/other-bucket/other-key"),
        )
        .expect("tamperable");
    assert_eq!(verify(&injected, now()), Err(AuthError::SignatureDoesNotMatch));
}

/// Negative — c-sig-0406: a signature minted for one host is not valid for another spelling of it.
#[test]
fn c_sig_0406_a_signature_is_never_valid_for_a_second_host_spelling() {
    let map = HeaderMap::new();
    for spelling in [
        "other.amazonaws.com",
        "EXAMPLE.AMAZONAWS.COM",
        "example.amazonaws.com.",
        "example.amazonaws.com:443",
    ] {
        let other = RawHost::from_host_header(spelling.as_bytes()).expect("a valid host");
        let request = SigningRequest::new(&Method::GET, "/bucket/key", "", &map, &other, PayloadMode::Empty, timestamp());
        let signed = signer().sign_headers(&request).expect("signable");
        // `verify` canonicalises against `example.amazonaws.com`, so a signature over any other
        // spelling must fail.
        assert_eq!(
            verify(&signed, now()),
            Err(AuthError::SignatureDoesNotMatch),
            "a signature for {spelling} must not verify against example.amazonaws.com"
        );
    }
}

/// Negative — c-sig-0407: `?prefix=a+b` and `?prefix=a%20b` are two URIs and never share a
/// signature. `aws-sigv4` 1.5.1 produces one signature for both.
#[test]
fn c_sig_0407_a_plus_and_a_space_never_share_a_signature() {
    let plus = sign("/bucket/key", "prefix=a%2Bb");
    let space = sign("/bucket/key", "prefix=a%20b");
    assert_eq!(verify(&plus, now()), Ok(()));
    assert_eq!(verify(&space, now()), Ok(()));
    assert_ne!(plus.signature_hex(), space.signature_hex());

    let swapped = plus
        .tampered(
            &Tamper::new(TamperComponent::CanonicalQuery)
                .with_target("prefix")
                .with_new_value("a b"),
        )
        .expect("tamperable");
    assert_eq!(verify(&swapped, now()), Err(AuthError::SignatureDoesNotMatch));
}

/// Negative — c-sig-0408: a signed request outside the skew window is refused by the floor, before
/// the signature is even compared, on the header path as well as the presigned one.
#[test]
fn c_sig_0408_a_stale_signature_is_refused_by_the_skew_window() {
    let signed = sign("/bucket/key", "");
    assert_eq!(
        verify(&signed, RequestNow::from_unix_seconds(EXAMPLE_NOW + 901)),
        Err(AuthError::RequestTimeTooSkewed)
    );
    assert_eq!(
        verify(&signed, RequestNow::from_unix_seconds(EXAMPLE_NOW - 901)),
        Err(AuthError::RequestTimeTooSkewed)
    );
}

/// Negative — c-sig-0409: a presigned URL used after its window is refused, and the ceiling the
/// signer enforces is the verifier's constant rather than a second copy of it.
#[test]
fn c_sig_0409_a_presigned_url_expires() {
    let map = HeaderMap::new();
    let host = host();
    let request = SigningRequest::new(&Method::GET, "/bucket/key", "", &map, &host, PayloadMode::Unsigned, timestamp());
    let signed = signer().presign(&request, 60).expect("signable");
    assert_eq!(verify(&signed, now()), Ok(()));
    assert_eq!(
        verify(&signed, RequestNow::from_unix_seconds(EXAMPLE_NOW + 61)),
        // Past the URL's lifetime but still inside the skew window: expiry is what refuses it.
        Err(AuthError::RequestExpired)
    );
    assert_eq!(
        signer().presign(&request, MAX_PRESIGNED_EXPIRY_SECONDS + 1).err(),
        Some(SignerError::ExpiryOutOfRange)
    );
}

/// Negative — c-sig-0410: every one of the eleven tamper components is refused, described through
/// the public `Tamper` type exactly as `sign.tamper` describes it in the case schema.
#[test]
fn c_sig_0410_every_tamper_component_is_refused_through_the_public_api() {
    let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(b"hello world").into();
    let base = || {
        let map = headers(&[("content-type", "text/plain")]);
        let host = host();
        let request = SigningRequest::new(
            &Method::PUT,
            "/bucket/key",
            "prefix=a&x-id=PutObject",
            &map,
            &host,
            PayloadMode::ExactSha256(digest),
            timestamp(),
        );
        signer().sign_headers(&request).expect("signable")
    };

    let cases: [(&str, Tamper); 11] = [
        ("signature", Tamper::new(TamperComponent::Signature).flip_byte_at(63)),
        ("access_key", Tamper::new(TamperComponent::AccessKey).with_new_value("AKIDNOTREGISTERED")),
        ("scope_date", Tamper::new(TamperComponent::ScopeDate).with_new_value("20150831")),
        ("scope_region", Tamper::new(TamperComponent::ScopeRegion).with_new_value("eu-west-1")),
        ("scope_service", Tamper::new(TamperComponent::ScopeService).with_new_value("sts")),
        (
            "signed_headers_list",
            Tamper::new(TamperComponent::SignedHeadersList).with_new_value("host"),
        ),
        (
            "canonical_query",
            Tamper::new(TamperComponent::CanonicalQuery)
                .with_target("x-id")
                .with_new_value("DeleteObject"),
        ),
        (
            "canonical_path",
            Tamper::new(TamperComponent::CanonicalPath).with_new_value("/bucket/other"),
        ),
        (
            "canonical_header_value",
            Tamper::new(TamperComponent::CanonicalHeaderValue)
                .with_target("content-type")
                .with_new_value("application/xml"),
        ),
        ("payload_hash", Tamper::new(TamperComponent::PayloadHash).flip_byte_at(0)),
        ("date_header", Tamper::new(TamperComponent::DateHeader).with_new_value("20150830T123601Z")),
    ];

    for (label, tamper) in cases {
        let signed = base();
        assert_eq!(verify(&signed, now()), Ok(()), "{label}: the base must verify");
        let tampered = signed
            .tampered(&tamper)
            .unwrap_or_else(|error| panic!("{label}: the tamper must apply, got {error:?}"));
        assert!(verify(&tampered, now()).is_err(), "{label}: must not verify");
    }
}

/// Negative — c-sig-0411: an under-signed request is signable and then refused. This is the
/// complement-of-a-deny-list shape: the signer covers a subset and sends a superset.
#[test]
fn c_sig_0411_under_signing_is_signable_and_then_refused() {
    let map = headers(&[("x-amz-acl", "public-read"), ("content-type", "text/plain")]);
    let host = host();
    let names = [
        HeaderName::from_static("content-type"),
        HeaderName::from_static("host"),
        HeaderName::from_static("x-amz-date"),
    ];
    let request = SigningRequest::new(&Method::PUT, "/bucket/key", "", &map, &host, PayloadMode::Empty, timestamp())
        .with_signed_headers(&names);
    let signed = signer().sign_headers(&request).expect("an under-signing client can sign");
    assert!(!signed.authorization().expect("header").contains("x-amz-acl"));
    assert_eq!(verify(&signed, now()), Err(AuthError::SignatureDoesNotMatch));
}

/// Negative — c-sig-0412: a signed-header list that omits `host` cannot be produced at all. A
/// signature that does not cover the host is valid for every host the gateway answers on, so the
/// completeness rules refuse it on the signing side too.
#[test]
fn c_sig_0412_a_list_without_host_cannot_be_signed() {
    let map = headers(&[("content-type", "text/plain")]);
    let host = host();
    let names = [HeaderName::from_static("content-type"), HeaderName::from_static("x-amz-date")];
    let request = SigningRequest::new(&Method::GET, "/bucket/key", "", &map, &host, PayloadMode::Empty, timestamp())
        .with_signed_headers(&names);
    assert_eq!(
        signer().sign_headers(&request).err(),
        Some(SignerError::Canonical(AuthError::SignatureDoesNotMatch))
    );
}

/// Negative — c-sig-0413: a `content-length` that disagrees with the wire length is refused where
/// it is signed, not where it is read.
#[test]
fn c_sig_0413_a_signed_content_length_must_match_the_wire_length() {
    let map = headers(&[("content-length", "13")]);
    let host = host();
    let request = SigningRequest::new(&Method::PUT, "/bucket/key", "", &map, &host, PayloadMode::Empty, timestamp())
        .with_wire_content_length(14);
    assert_eq!(
        signer().sign_headers(&request).err(),
        Some(SignerError::Canonical(AuthError::SignatureDoesNotMatch))
    );
    let request = SigningRequest::new(&Method::PUT, "/bucket/key", "", &map, &host, PayloadMode::Empty, timestamp())
        .with_wire_content_length(13);
    assert!(signer().sign_headers(&request).is_ok());
}

/// Negative — c-sig-0414: a query that already carries a minted parameter is refused rather than
/// overwritten, because the result would trip the duplicate rule at the floor.
#[test]
fn c_sig_0414_a_query_carrying_a_minted_parameter_is_refused() {
    let map = HeaderMap::new();
    let host = host();
    for existing in [
        "X-Amz-Signature=deadbeef",
        "X-Amz-Credential=x",
        "X-Amz-Date=20150830T123600Z",
        "X-Amz-Expires=60",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "X-Amz-SignedHeaders=host",
        "X-Amz-Security-Token=x",
    ] {
        let request = SigningRequest::new(&Method::GET, "/bucket/key", existing, &map, &host, PayloadMode::Unsigned, timestamp());
        assert_eq!(
            signer().presign(&request, 900).err(),
            Some(SignerError::SigningParameterAlreadyPresent),
            "must refuse a query already carrying {existing}"
        );
    }
}

/// Negative — c-sig-0415: a malformed path or query is refused at signing time with the
/// verification side's own verdict, so a signer cannot mint a request that is unverifiable rather
/// than merely wrong.
#[test]
fn c_sig_0415_a_malformed_target_is_refused_at_signing_time() {
    let map = HeaderMap::new();
    let host = host();
    for path in ["/a%zzb", "/a%2", "/a\nb"] {
        let request = SigningRequest::new(&Method::GET, path, "", &map, &host, PayloadMode::Empty, timestamp());
        assert_eq!(
            signer().sign_headers(&request).err(),
            Some(SignerError::Canonical(AuthError::AuthorizationHeaderMalformed)),
            "must refuse the path {path:?}"
        );
    }
    for query in ["a=1&&b=2", "a=1&a=2", "=novalue", "prefix=%zz"] {
        let request = SigningRequest::new(&Method::GET, "/bucket/key", query, &map, &host, PayloadMode::Empty, timestamp());
        assert_eq!(
            signer().sign_headers(&request).err(),
            Some(SignerError::Canonical(AuthError::AuthorizationHeaderMalformed)),
            "must refuse the query {query:?}"
        );
    }
}

/// Negative — c-sig-0416: two requests differing in exactly one canonical field never share a
/// signature. The loop covers method, path, query and payload token; the host is c-sig-0406's.
#[test]
fn c_sig_0416_one_signature_never_covers_two_requests() {
    let map = HeaderMap::new();
    let host = host();
    let mut seen: Vec<String> = Vec::new();
    let variants: [(Method, &str, &str, PayloadMode); 5] = [
        (Method::GET, "/bucket/key", "prefix=a", PayloadMode::Empty),
        (Method::DELETE, "/bucket/key", "prefix=a", PayloadMode::Empty),
        (Method::GET, "/bucket/kez", "prefix=a", PayloadMode::Empty),
        (Method::GET, "/bucket/key", "prefix=b", PayloadMode::Empty),
        (Method::GET, "/bucket/key", "prefix=a", PayloadMode::Unsigned),
    ];
    for (method, path, query, payload) in variants {
        let request = SigningRequest::new(&method, path, query, &map, &host, payload, timestamp());
        let signed = signer().sign_headers(&request).expect("signable");
        assert!(
            !seen.contains(&signed.signature_hex().to_owned()),
            "{method} {path}?{query} must not repeat an earlier signature"
        );
        seen.push(signed.signature_hex().to_owned());
    }
    assert_eq!(seen.len(), 5);
}
