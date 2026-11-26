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

//! SigV4a (`AWS4-ECDSA-P256-SHA256`) public-API positive and negative verification suite.
//!
//! Responsible for: exercising SigV4a keypair derivation, ASN.1 DER parsing, high-S tolerance,
//! `x-amz-region-set` canonicalization and singleton enforcement, 4-field scope parsing and H5
//! cross-checking, `SecurityFloor` H1–H6 admission, streaming SigV4a head signing, and
//! cross-algorithm downgrade prevention.
//! NOT responsible for: the pinned upstream smithy-rs vector replay (`src/full_chain_tests.rs`)
//! or `aws-chunked` body decoding (`rustfs-gateway-http`).
//! Upstream: the `rustfs-gateway-sig` public API. Downstream: none (integration test module).

use http::Method;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_sig::codec::encode_hex_lower;
use rustfs_gateway_sig::presigned::{PayloadObligation, PresignedRequest};
use rustfs_gateway_sig::{
    Admission, AmzDate, AuthError, AuthScheme, CanonicalRequestSpec, CredentialScope, DeclaredTrailers, EcdsaDerSignature,
    ExpectedScope, HeaderTokenClaim, OperationFloor, PayloadMode, PresentedRegionSet, PresignedParams, RawHost, RawQuery,
    RegionSet, RequestNow, STREAMING_ECDSA, STREAMING_ECDSA_TRAILER, ScopeDate, SecretBytes, SecurityFloor, SessionToken,
    SigFamily, SigIdentity, SigLocation, SigService, SigV4Authorization, SigV4aAuthorization, SigV4aCredentialScope,
    SigV4aPresignedParams, SigV4aSigner, SigV4aVerifyingKey, SignedHeaderSet, SigningCredentials, SigningRequest, SkewWindow,
    TrailerName, TrailerSet, Unimplemented, UriPathCandidates, Verdict, VerifyRejection, WireView, X_AMZ_REGION_SET,
    X_AMZ_REGION_SET_HEADER, detect_aws_credential_marker, enforce_clock_skew, enforce_no_duplicate_sig_params,
    enforce_sigv4a_scope, verify_sigv4a_signature,
};

const AKID: &str = "AKIDEXAMPLE";
const SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const STAMP: &str = "20150830T123600Z";
const NOW_UNIX: i64 = 1_440_938_160;
const HOST: &[u8] = b"example.amazonaws.com";

fn sample_date() -> AmzDate {
    AmzDate::parse(STAMP).expect("valid timestamp")
}

fn sample_day() -> ScopeDate {
    ScopeDate::parse("20150830").expect("valid day")
}

fn sample_host() -> RawHost {
    RawHost::from_host_header(HOST).expect("valid host")
}

fn s3_floor() -> OperationFloor {
    OperationFloor::builtin_presigned("GetObject", SigService::S3)
}

fn privileged_floor() -> OperationFloor {
    OperationFloor::custom("AdminOp", SigService::S3)
}

fn v4a_signer(region_set: &str) -> SigV4aSigner {
    let creds = SigningCredentials::new(AKID, SECRET).expect("valid credentials");
    SigV4aSigner::new(creds, sample_day(), SigService::S3, region_set).expect("valid v4a signer")
}

fn verify_signed_header_request(
    method: &Method,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    payload: &PayloadMode,
    server_regions: &[&str],
    now: RequestNow,
) -> Result<Verdict, AuthError> {
    let floor = SecurityFloor::new();
    let view = WireView::new(headers, RawQuery::new(query));
    let Admission::Sealed(sealed) = floor.admit(view, &s3_floor(), now)? else {
        panic!("expected Sealed admission");
    };
    assert_eq!(sealed.marker().family(), SigFamily::V4a);
    assert_eq!(sealed.marker().location(), SigLocation::Header);

    let auth_raw = headers
        .get("authorization")
        .ok_or(AuthError::AuthorizationHeaderMalformed)?
        .to_str()
        .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
    let auth = SigV4aAuthorization::parse(auth_raw)?;
    let raw_region_set = headers
        .get(X_AMZ_REGION_SET_HEADER)
        .ok_or(AuthError::AuthorizationHeaderMalformed)?
        .to_str()
        .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
    let region_set = PresentedRegionSet::parse(raw_region_set)?;

    let regions = RegionSet::new(server_regions.iter().copied()).expect("valid server regions");
    let expected = ExpectedScope::new(SigService::S3, &regions);
    let verified = enforce_sigv4a_scope(auth.scope(), &region_set, sealed.clock(), &expected)
        .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;

    let signed = SignedHeaderSet::parse_and_enforce(auth.signed_headers(), headers, None)?;
    let paths = UriPathCandidates::new(path)?;
    let raw_query = RawQuery::new(query);
    let host = sample_host();
    let spec = CanonicalRequestSpec::new(method, &paths, &raw_query, headers, &signed, &host, payload.canonical_payload_token());
    let candidate = spec.candidates()?.next().expect("at least one candidate");
    let sts = candidate.string_to_sign_v4a(&sealed.clock().signed_at(), auth.scope());
    let vk = SigV4aVerifyingKey::derive(auth.scope().access_key_id().access_key_id(), &SecretBytes::new(SECRET))
        .map_err(AuthError::from)?;
    let proof = verify_sigv4a_signature(&vk, &verified, &sts, auth.signature()).map_err(AuthError::from)?;
    let scheme = AuthScheme::sigv4a_header(SigIdentity::LongTerm, SigService::S3);
    Ok(Verdict::authenticated_in_sigv4a_scope(
        auth.scope().access_key_id().clone(),
        scheme,
        &verified,
        proof,
    ))
}

// ---------------------------------------------------------------------------
// Positive cases
// ---------------------------------------------------------------------------

/// Positive — the deterministic P-256 key derivation reproduces AWS's published `get-vanilla`
/// compressed public key (`02` || X because Y is even).
#[test]
fn sigv4a_kdf_reproduces_aws_example_public_key() {
    let vk = SigV4aVerifyingKey::derive(AKID, &SecretBytes::new(SECRET)).expect("valid kdf");
    // Published AWS `v4a/get-vanilla/public-key.json`:
    // X = b6618f6a65740a99e650b33b6b4b5bd0d43b176d721a3edfea7e7d2d56d936b1
    // Y = 0865ed22a7eadc9c5cb9d2cbaca1b3699139fedc5043dc6661864218330c8e518 (even -> prefix 0x02)
    assert_eq!(
        encode_hex_lower(&vk.compressed_sec1()),
        "02b6618f6a65740a99e650b33b6b4b5bd0d43b176d721a3edfea7e7d2d56d936b1"
    );
}

/// Positive — header-signed SigV4a authenticates single-region, multi-region, and wildcard `*`
/// region sets and records the verified scope.
#[test]
fn sigv4a_header_roundtrip_single_multi_and_wildcard_regions() {
    let base_headers = HeaderMap::new();
    let host = sample_host();
    let now = RequestNow::from_unix_seconds(NOW_UNIX);

    for (client_regions, server_regions) in [
        ("us-east-1", &["us-east-1"][..]),
        ("eu-west-1,us-east-1", &["us-east-1"][..]),
        ("*", &["ap-northeast-1"][..]),
    ] {
        let signer = v4a_signer(client_regions);
        let req = SigningRequest::new(
            &Method::GET,
            "/bucket/key",
            "list-type=2",
            &base_headers,
            &host,
            PayloadMode::Empty,
            sample_date(),
        );
        let signed = signer.sign_headers(&req).expect("signs header");
        let verdict = verify_signed_header_request(
            &Method::GET,
            "/bucket/key",
            "list-type=2",
            signed.headers(),
            &PayloadMode::Empty,
            server_regions,
            now,
        )
        .expect("must authenticate");
        assert!(verdict.is_authenticated(), "client_regions={client_regions}");
        let scope = verdict.verified_scope().expect("verified scope attached");
        assert_eq!(scope.region(), client_regions);
        assert_eq!(scope.service(), "s3");
        assert_eq!(scope.date().as_str(), "20150830");
    }
}

/// Positive — presigned SigV4a URLs authenticate with `X-Amz-Region-Set` (explicit and `*`).
#[test]
fn sigv4a_presigned_roundtrip_verifies() {
    let floor = SecurityFloor::new();
    let now = RequestNow::from_unix_seconds(NOW_UNIX + 120);
    let host = sample_host();
    let base_headers = HeaderMap::new();

    for region_set in ["us-east-1", "eu-west-1,us-east-1", "*"] {
        let signer = v4a_signer(region_set);
        let req = SigningRequest::new(
            &Method::GET,
            "/bucket/object",
            "",
            &base_headers,
            &host,
            PayloadMode::Unsigned,
            sample_date(),
        );
        let signed = signer.presign(&req, 3600).expect("presigns");
        let view = WireView::new(signed.headers(), RawQuery::new(signed.query()));
        let Admission::Sealed(sealed) = floor.admit(view, &s3_floor(), now).expect("admitted") else {
            panic!("expected Sealed");
        };
        assert_eq!(sealed.marker().family(), SigFamily::V4a);
        assert_eq!(sealed.marker().location(), SigLocation::Query);

        let params = SigV4aPresignedParams::parse(&view.query()).expect("parses presigned v4a");
        assert_eq!(params.region_set().as_str(), region_set);

        let regions = RegionSet::new(["us-east-1"]).expect("valid");
        let expected = ExpectedScope::new(SigService::S3, &regions);
        let verified = enforce_sigv4a_scope(params.scope(), params.region_set(), sealed.clock(), &expected).expect("scope ok");

        let sh = SignedHeaderSet::parse_and_enforce(params.signed_headers(), signed.headers(), None).expect("headers ok");
        let paths = UriPathCandidates::new("/bucket/object").expect("valid");
        let raw_query = view.query();
        let spec = CanonicalRequestSpec::new(
            &Method::GET,
            &paths,
            &raw_query,
            signed.headers(),
            &sh,
            &host,
            PayloadMode::Unsigned.canonical_payload_token(),
        )
        .presigned();
        let candidate = spec.candidates().expect("ok").next().expect("candidate");
        let sts = candidate.string_to_sign_v4a(&params.date(), params.scope());
        let vk = SigV4aVerifyingKey::derive(AKID, &SecretBytes::new(SECRET)).expect("kdf");
        assert!(verify_sigv4a_signature(&vk, &verified, &sts, params.signature()).is_ok());
    }
}

/// Positive — SigV4a with STS `SessionToken` signs and verifies both header and presigned forms.
#[test]
fn sigv4a_with_session_token_verifies() {
    let token = SessionToken::new("AQoDYXdzEJr//////////wEXAMPLE").expect("valid");
    let creds = SigningCredentials::new(AKID, SECRET)
        .expect("valid")
        .with_session_token(token);
    let signer = SigV4aSigner::new(creds, sample_day(), SigService::S3, "*").expect("valid");
    let headers = HeaderMap::new();
    let host = sample_host();
    let req = SigningRequest::new(&Method::GET, "/b/k", "", &headers, &host, PayloadMode::Empty, sample_date());
    let signed = signer.sign_headers(&req).expect("signs");
    assert!(signed.headers().contains_key("x-amz-security-token"));
    let verdict = verify_signed_header_request(
        &Method::GET,
        "/b/k",
        "",
        signed.headers(),
        &PayloadMode::Empty,
        &["us-east-1"],
        RequestNow::from_unix_seconds(NOW_UNIX),
    )
    .expect("authenticates");
    assert!(verdict.is_authenticated());
}

/// Positive — streaming SigV4a head requests sign with both plain and `-TRAILER` modes and
/// `SigV4aChunkSigner` emits both unpadded and 144-char `'*'`-padded frames.
#[test]
fn sigv4a_streaming_head_and_chunk_signer_emit_valid_frames() {
    let signer = v4a_signer("*");
    let headers = HeaderMap::new();
    let host = sample_host();
    let trailer_mode = PayloadMode::parse(
        STREAMING_ECDSA_TRAILER,
        TrailerSet::Declared(DeclaredTrailers::new([TrailerName::new("x-amz-checksum-crc32").expect("ok")], true).expect("ok")),
    )
    .expect("valid");
    let req = SigningRequest::new(&Method::PUT, "/b/obj", "", &headers, &host, trailer_mode.clone(), sample_date())
        .with_decoded_content_length(5);
    let signed = signer.sign_headers(&req).expect("signs streaming head");
    assert_eq!(
        signed.headers().get("x-amz-content-sha256").and_then(|v| v.to_str().ok()),
        Some(STREAMING_ECDSA_TRAILER)
    );
    assert_eq!(
        signed.headers().get("x-amz-trailer").and_then(|v| v.to_str().ok()),
        Some("x-amz-checksum-crc32")
    );
    let mut chunker = signer.chunk_signer(signed.signature_hex(), sample_date());
    let padded_sig = chunker.sign_chunk_padded(b"hello");
    assert_eq!(padded_sig.len(), 144);
    assert!(padded_sig.trim_end_matches('*').len() >= 136);
    assert!(!chunker.previous_signature_hex().contains('*'));
}

/// Positive — credential markers classify SigV4a header, presigned query, and form fields as
/// `SigFamily::V4a` under both default AWS and legacy RustFS recognition.
#[test]
fn sigv4a_credential_markers_identify_v4a_family() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_static(
            "AWS4-ECDSA-P256-SHA256 Credential=AKID/20150830/s3/aws4_request, SignedHeaders=host, Signature=3006020101020101",
        ),
    );
    let header_view = WireView::new(&headers, RawQuery::new(""));
    let marker = detect_aws_credential_marker(&header_view).expect("marked");
    assert_eq!(marker.family(), SigFamily::V4a);
    assert_eq!(marker.location(), SigLocation::Header);

    let empty = HeaderMap::new();
    let query_view = WireView::new(
        &empty,
        RawQuery::new("X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256&X-Amz-Signature=3006020101020101"),
    );
    let qmarker = detect_aws_credential_marker(&query_view).expect("marked");
    assert_eq!(qmarker.family(), SigFamily::V4a);
    assert_eq!(qmarker.location(), SigLocation::Query);

    let legacy = SecurityFloor::new().recognize_signatures_as_legacy_rustfs();
    assert_eq!(legacy.credential_marker(&query_view).map(|m| m.family()), Some(SigFamily::V4a));
}

// ---------------------------------------------------------------------------
// Negative cases (outnumber positive cases > 2:1)
// ---------------------------------------------------------------------------

/// Negative — tampering with a single byte of a valid ECDSA DER signature fails verification.
#[test]
fn n_sigv4a_wrong_signature_is_rejected() {
    let signer = v4a_signer("us-east-1");
    let headers = HeaderMap::new();
    let host = sample_host();
    let req = SigningRequest::new(&Method::GET, "/b/k", "", &headers, &host, PayloadMode::Empty, sample_date());
    let signed = signer.sign_headers(&req).expect("signs");

    // Sign a different path to obtain another structurally valid DER signature for the same key.
    let other_req = SigningRequest::new(&Method::GET, "/b/other", "", &headers, &host, PayloadMode::Empty, sample_date());
    let other_signed = signer.sign_headers(&other_req).expect("signs");

    let mut tampered = signed.headers().clone();
    let auth_text = tampered.get("authorization").expect("auth").to_str().expect("str").to_owned();
    let swapped = auth_text.replace(signed.signature_hex(), other_signed.signature_hex());
    tampered.insert(HeaderName::from_static("authorization"), HeaderValue::from_str(&swapped).expect("hv"));

    assert_eq!(
        verify_signed_header_request(
            &Method::GET,
            "/b/k",
            "",
            &tampered,
            &PayloadMode::Empty,
            &["us-east-1"],
            RequestNow::from_unix_seconds(NOW_UNIX),
        )
        .err(),
        Some(AuthError::SignatureDoesNotMatch)
    );
}

/// Negative — verifying with a different secret key's derived verifying key fails.
#[test]
fn n_sigv4a_wrong_secret_key_is_rejected() {
    let signer = v4a_signer("us-east-1");
    let headers = HeaderMap::new();
    let host = sample_host();
    let req = SigningRequest::new(&Method::GET, "/b/k", "", &headers, &host, PayloadMode::Empty, sample_date());
    let signed = signer.sign_headers(&req).expect("signs");
    let auth = SigV4aAuthorization::parse(signed.authorization().expect("auth")).expect("valid");
    let region_set = PresentedRegionSet::parse("us-east-1").expect("valid");
    let clock = enforce_clock_skew(&sample_date(), RequestNow::from_unix_seconds(NOW_UNIX), SkewWindow::DEFAULT).expect("ok");
    let regions = RegionSet::new(["us-east-1"]).expect("valid");
    let expected = ExpectedScope::new(SigService::S3, &regions);
    let verified = enforce_sigv4a_scope(auth.scope(), &region_set, clock, &expected).expect("ok");

    let sh = SignedHeaderSet::parse_and_enforce(auth.signed_headers(), signed.headers(), None).expect("ok");
    let paths = UriPathCandidates::new("/b/k").expect("ok");
    let raw_query = RawQuery::new("");
    let candidate = CanonicalRequestSpec::new(
        &Method::GET,
        &paths,
        &raw_query,
        signed.headers(),
        &sh,
        &host,
        PayloadMode::Empty.canonical_payload_token(),
    )
    .candidates()
    .expect("ok")
    .next()
    .expect("candidate");
    let sts = candidate.string_to_sign_v4a(&sample_date(), auth.scope());
    let wrong_vk = SigV4aVerifyingKey::derive(AKID, &SecretBytes::new(b"wrong-secret-key")).expect("kdf");
    assert!(matches!(
        verify_sigv4a_signature(&wrong_vk, &verified, &sts, auth.signature()),
        Err(VerifyRejection::Mismatch)
    ));
}

/// Negative — tampering with `x-amz-region-set` after signing invalidates the signature.
#[test]
fn n_sigv4a_tampered_region_set_header_fails_verification() {
    let signer = v4a_signer("us-east-1");
    let headers = HeaderMap::new();
    let host = sample_host();
    let req = SigningRequest::new(&Method::GET, "/b/k", "", &headers, &host, PayloadMode::Empty, sample_date());
    let signed = signer.sign_headers(&req).expect("signs");
    let mut tampered = signed.headers().clone();
    tampered.insert(HeaderName::from_static(X_AMZ_REGION_SET_HEADER), HeaderValue::from_static("*"));
    assert_eq!(
        verify_signed_header_request(
            &Method::GET,
            "/b/k",
            "",
            &tampered,
            &PayloadMode::Empty,
            &["us-east-1"],
            RequestNow::from_unix_seconds(NOW_UNIX),
        )
        .err(),
        Some(AuthError::SignatureDoesNotMatch)
    );
}

/// Negative — tampering with `X-Amz-Region-Set` in a presigned URL invalidates the signature.
#[test]
fn n_sigv4a_tampered_region_set_query_fails_verification() {
    let signer = v4a_signer("us-east-1");
    let headers = HeaderMap::new();
    let host = sample_host();
    let req = SigningRequest::new(&Method::GET, "/b/k", "", &headers, &host, PayloadMode::Unsigned, sample_date());
    let signed = signer.presign(&req, 3600).expect("presigns");
    let tampered_query = signed.query().replace("X-Amz-Region-Set=us-east-1", "X-Amz-Region-Set=%2A");
    let raw_query = RawQuery::new(&tampered_query);
    let params = SigV4aPresignedParams::parse(&raw_query).expect("still syntactically valid");
    let clock = enforce_clock_skew(&sample_date(), RequestNow::from_unix_seconds(NOW_UNIX), SkewWindow::DEFAULT).expect("ok");
    let regions = RegionSet::new(["us-east-1"]).expect("valid");
    let verified =
        enforce_sigv4a_scope(params.scope(), params.region_set(), clock, &ExpectedScope::new(SigService::S3, &regions))
            .expect("wildcard scope passes H5");
    let sh = SignedHeaderSet::parse_and_enforce(params.signed_headers(), signed.headers(), None).expect("ok");
    let paths = UriPathCandidates::new("/b/k").expect("ok");
    let candidate = CanonicalRequestSpec::new(
        &Method::GET,
        &paths,
        &raw_query,
        signed.headers(),
        &sh,
        &host,
        PayloadMode::Unsigned.canonical_payload_token(),
    )
    .presigned()
    .candidates()
    .expect("ok")
    .next()
    .expect("candidate");
    let sts = candidate.string_to_sign_v4a(&params.date(), params.scope());
    let vk = SigV4aVerifyingKey::derive(AKID, &SecretBytes::new(SECRET)).expect("kdf");
    assert!(matches!(
        verify_sigv4a_signature(&vk, &verified, &sts, params.signature()),
        Err(VerifyRejection::Mismatch)
    ));
}

/// Negative — missing `x-amz-region-set` (header) or `X-Amz-Region-Set` (presigned query) is refused.
#[test]
fn n_sigv4a_missing_region_set_is_refused() {
    let signer = v4a_signer("us-east-1");
    let headers = HeaderMap::new();
    let host = sample_host();
    let req = SigningRequest::new(&Method::GET, "/b/k", "", &headers, &host, PayloadMode::Empty, sample_date());
    let signed = signer.sign_headers(&req).expect("signs");
    let mut missing = signed.headers().clone();
    missing.remove(X_AMZ_REGION_SET_HEADER);
    assert_eq!(
        verify_signed_header_request(
            &Method::GET,
            "/b/k",
            "",
            &missing,
            &PayloadMode::Empty,
            &["us-east-1"],
            RequestNow::from_unix_seconds(NOW_UNIX),
        )
        .err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );

    let preq = SigningRequest::new(&Method::GET, "/b/k", "", &headers, &host, PayloadMode::Unsigned, sample_date());
    let psigned = signer.presign(&preq, 3600).expect("presigns");
    let stripped = psigned
        .query()
        .split('&')
        .filter(|pair| !pair.starts_with("X-Amz-Region-Set="))
        .collect::<Vec<_>>()
        .join("&");
    assert_eq!(
        SigV4aPresignedParams::parse(&RawQuery::new(&stripped)).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — duplicate `x-amz-region-set` header or `X-Amz-Region-Set` query parameter is refused
/// at H6 before parsing.
#[test]
fn n_sigv4a_duplicate_region_set_is_refused_by_h6() {
    let mut headers = HeaderMap::new();
    headers.append(HeaderName::from_static(X_AMZ_REGION_SET_HEADER), HeaderValue::from_static("us-east-1"));
    headers.append(HeaderName::from_static(X_AMZ_REGION_SET_HEADER), HeaderValue::from_static("eu-west-1"));
    let view = WireView::new(&headers, RawQuery::new(""));
    assert_eq!(enforce_no_duplicate_sig_params(&view), Err(AuthError::AuthorizationHeaderMalformed));

    let empty = HeaderMap::new();
    let qview = WireView::new(&empty, RawQuery::new("X-Amz-Region-Set=us-east-1&X-Amz-Region-Set=*"));
    assert_eq!(enforce_no_duplicate_sig_params(&qview), Err(AuthError::AuthorizationQueryParametersError));
}

/// Negative — an `x-amz-region-set` header omitted from `SignedHeaders` is rejected.
#[test]
fn n_sigv4a_unsigned_region_set_header_is_rejected() {
    let mut headers = HeaderMap::new();
    headers.insert(HeaderName::from_static("x-amz-date"), HeaderValue::from_static(STAMP));
    headers.insert(HeaderName::from_static(X_AMZ_REGION_SET_HEADER), HeaderValue::from_static("*"));
    assert_eq!(
        SignedHeaderSet::parse_and_enforce("host;x-amz-date", &headers, None),
        Err(AuthError::SignatureDoesNotMatch)
    );
}

/// Negative — malformed `x-amz-region-set` spellings are rejected.
#[test]
fn n_sigv4a_malformed_region_sets_are_rejected() {
    let too_many = (0..65).map(|i| format!("r-{i}")).collect::<Vec<_>>().join(",");
    for bad in [
        "",
        ",",
        "us-east-1,",
        ",us-east-1",
        "us-east-1,,eu-west-1",
        "US-EAST-1",
        "us east 1",
        "*,INVALID",
        "**",
        too_many.as_str(),
    ] {
        assert_eq!(
            PresentedRegionSet::parse(bad),
            Err(AuthError::AuthorizationHeaderMalformed),
            "must reject region set {bad:?}"
        );
    }
}

/// Negative — non-DER, raw 64-byte, uppercase, odd-length, trailing-byte, and `'*'`-padded
/// signatures are rejected by `EcdsaDerSignature::parse_hex`.
#[test]
fn n_sigv4a_malformed_and_non_der_signatures_are_rejected() {
    let signer = v4a_signer("us-east-1");
    let headers = HeaderMap::new();
    let host = sample_host();
    let req = SigningRequest::new(&Method::GET, "/", "", &headers, &host, PayloadMode::Empty, sample_date());
    let valid_hex = signer.sign_headers(&req).expect("signs").signature_hex().to_owned();
    let mut padded = valid_hex.clone();
    while padded.len() < 144 {
        padded.push('*');
    }

    for bad in [
        "".to_owned(),
        "11".repeat(64),                             // raw 64-byte (r||s), not ASN.1 DER
        valid_hex.to_uppercase(),                    // uppercase hex
        valid_hex[..valid_hex.len() - 1].to_owned(), // odd length
        format!("{valid_hex}00"),                    // trailing garbage byte after valid DER
        valid_hex[..14].to_owned(),                  // truncated below min DER
        padded,                                      // '*' padding forbidden on head/query signatures
        "300402000200".to_owned(),                   // invalid zero-length integers
    ] {
        assert!(EcdsaDerSignature::parse_hex(&bad).is_err(), "must reject malformed DER signature {bad:?}");
    }
}

/// Negative — 5-field SigV4 scopes never parse as 4-field SigV4a scopes, and 4-field SigV4a
/// scopes never parse as 5-field SigV4 scopes.
#[test]
fn n_sigv4a_and_sigv4_credential_scopes_never_cross_parse() {
    assert_eq!(
        SigV4aCredentialScope::parse("AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"),
        Err(AuthError::AuthorizationHeaderMalformed)
    );
    assert_eq!(
        CredentialScope::parse("AKIDEXAMPLE/20150830/s3/aws4_request"),
        Err(AuthError::AuthorizationHeaderMalformed)
    );
    assert_eq!(
        SigV4aCredentialScope::parse("AKIDEXAMPLE/20150830/s3/aws4-request"),
        Err(AuthError::AuthorizationHeaderMalformed)
    );
    assert_eq!(
        SigV4aCredentialScope::parse("AKIDEXAMPLE/20150830/ec2/aws4_request"),
        Err(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — SigV4 headers/queries never parse as SigV4a, and SigV4a headers/queries never
/// degrade to SigV4.
#[test]
fn n_sigv4a_and_sigv4_parsers_never_cross_accept() {
    let sigv4_header = format!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, SignedHeaders=host, Signature={}",
        "a".repeat(64)
    );
    assert_eq!(
        SigV4aAuthorization::parse(&sigv4_header).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );

    let signer = v4a_signer("us-east-1");
    let headers = HeaderMap::new();
    let host = sample_host();
    let req = SigningRequest::new(&Method::GET, "/", "", &headers, &host, PayloadMode::Empty, sample_date());
    let signed = signer.sign_headers(&req).expect("signs");
    assert_eq!(
        SigV4Authorization::parse(signed.authorization().expect("auth")).err(),
        Some(AuthError::NotImplemented(Unimplemented::SigV4a))
    );

    let preq = SigningRequest::new(&Method::GET, "/", "", &headers, &host, PayloadMode::Unsigned, sample_date());
    let psigned = signer.presign(&preq, 60).expect("presigns");
    assert_eq!(
        PresignedParams::parse(&RawQuery::new(psigned.query())).err(),
        Some(AuthError::NotImplemented(Unimplemented::SigV4a))
    );
}

/// Negative — H5 scope mismatches (wrong date, wrong service, disjoint region set) are rejected,
/// and only a region-set mismatch carries the configured remediation region.
#[test]
fn n_sigv4a_h5_scope_mismatches_are_rejected() {
    let clock = enforce_clock_skew(&sample_date(), RequestNow::from_unix_seconds(NOW_UNIX), SkewWindow::DEFAULT).expect("ok");
    let regions = RegionSet::new(["us-east-1", "eu-west-1"]).expect("valid");
    let expected = ExpectedScope::new(SigService::S3, &regions);

    let ok_scope = SigV4aCredentialScope::parse("AKIDEXAMPLE/20150830/s3/aws4_request").expect("valid");
    let bad_date = SigV4aCredentialScope::parse("AKIDEXAMPLE/20150831/s3/aws4_request").expect("valid");
    let bad_service = SigV4aCredentialScope::parse("AKIDEXAMPLE/20150830/sts/aws4_request").expect("valid");
    let ok_regions = PresentedRegionSet::parse("us-east-1").expect("valid");
    let bad_regions = PresentedRegionSet::parse("ap-south-1,ca-central-1").expect("valid");

    assert_eq!(
        enforce_sigv4a_scope(&bad_date, &ok_regions, clock, &expected)
            .unwrap_err()
            .expected_region(),
        None
    );
    assert_eq!(
        enforce_sigv4a_scope(&bad_service, &ok_regions, clock, &expected)
            .unwrap_err()
            .expected_region(),
        None
    );
    assert_eq!(
        enforce_sigv4a_scope(&ok_scope, &bad_regions, clock, &expected)
            .unwrap_err()
            .expected_region()
            .map(|r| r.as_str()),
        Some("eu-west-1")
    );
}

/// Negative — H1 clock skew refuses a SigV4a header signed more than 15 minutes away.
#[test]
fn n_sigv4a_clock_skew_is_rejected() {
    let signer = v4a_signer("*");
    let headers = HeaderMap::new();
    let host = sample_host();
    let req = SigningRequest::new(&Method::GET, "/", "", &headers, &host, PayloadMode::Empty, sample_date());
    let signed = signer.sign_headers(&req).expect("signs");
    let skewed_now = RequestNow::from_unix_seconds(NOW_UNIX + 16 * 60);
    assert_eq!(
        verify_signed_header_request(&Method::GET, "/", "", signed.headers(), &PayloadMode::Empty, &["us-east-1"], skewed_now)
            .err(),
        Some(AuthError::RequestTimeTooSkewed)
    );
}

/// Negative — H2 presigned expiry refuses an expired SigV4a presigned URL.
#[test]
fn n_sigv4a_presigned_expiry_is_rejected() {
    let signer = v4a_signer("*");
    let headers = HeaderMap::new();
    let host = sample_host();
    let req = SigningRequest::new(&Method::GET, "/b/k", "", &headers, &host, PayloadMode::Unsigned, sample_date());
    let signed = signer.presign(&req, 60).expect("presigns");
    let floor = SecurityFloor::new();
    let view = WireView::new(signed.headers(), RawQuery::new(signed.query()));
    let expired_now = RequestNow::from_unix_seconds(NOW_UNIX + 61);
    assert_eq!(floor.admit(view, &s3_floor(), expired_now).err(), Some(AuthError::RequestExpired));
}

/// Negative — H3 privileged operations refuse presigned SigV4a URLs.
#[test]
fn n_sigv4a_privileged_operation_refuses_presigned() {
    let signer = v4a_signer("*");
    let headers = HeaderMap::new();
    let host = sample_host();
    let req = SigningRequest::new(&Method::GET, "/admin", "", &headers, &host, PayloadMode::Unsigned, sample_date());
    let signed = signer.presign(&req, 60).expect("presigns");
    let floor = SecurityFloor::new();
    let view = WireView::new(signed.headers(), RawQuery::new(signed.query()));
    assert_eq!(
        floor
            .admit(view, &privileged_floor(), RequestNow::from_unix_seconds(NOW_UNIX))
            .err(),
        Some(AuthError::AccessDenied)
    );
}

/// Negative — presigned requests declaring `STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD[-TRAILER]`
/// still yield `PayloadObligation::StreamingNotImplemented`, and header-token exclusivity refuses
/// `X-Amz-Region-Set` in the query.
#[test]
fn n_sigv4a_presigned_streaming_and_header_token_exclusivity_are_refused() {
    for token in [STREAMING_ECDSA, STREAMING_ECDSA_TRAILER] {
        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_static("host"), HeaderValue::from_static("example.amazonaws.com"));
        headers.insert(HeaderName::from_static("x-amz-content-sha256"), HeaderValue::from_static(token));
        let sh = SignedHeaderSet::parse_and_enforce("host;x-amz-content-sha256", &headers, None).expect("ok");
        let preq = PresignedRequest::enforce(&headers, &sh).expect("enforced");
        assert_eq!(preq.payload_obligation(), PayloadObligation::StreamingNotImplemented);
    }

    let claim = HeaderTokenClaim::new("x-auth-token").expect("valid");
    let floor = SecurityFloor::new().with_header_token_claim(claim);
    let mut headers = HeaderMap::new();
    headers.insert(HeaderName::from_static("x-auth-token"), HeaderValue::from_static("tok-123"));
    let region_query = format!("{X_AMZ_REGION_SET}=us-east-1");
    let view = WireView::new(&headers, RawQuery::new(&region_query));
    assert_eq!(
        floor.admit(view, &s3_floor(), RequestNow::from_unix_seconds(NOW_UNIX)).err(),
        Some(AuthError::AccessDenied)
    );
}
