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

//! The signer's own cases: the round trip, one per tamper component, and the AWS suite.
//!
//! Responsible for: proving that what [`crate::signer`] produces is what [`crate::verifier`]'s
//! primitives accept, that each of the eleven tamper components breaks it in a way that names the
//! component, that the chunk chain is a chain, and that the signer reproduces smithy-rs'
//! `aws-signing-test-suite` vectors in the signing direction.
//! NOT responsible for: anything expressible through the crate's public API alone — that lives in
//! `tests/signer_roundtrip.rs`, which is an external crate and therefore also proves the API is
//! usable from outside.
//! Upstream: every module of this crate. Downstream: none (test-only module).
//!
//! # Why this file is inside `src/`
//!
//! Two of its cases need `pub(crate)` access: the AWS suite is scoped to the placeholder service
//! name `service`, which [`crate::SigService`] deliberately cannot spell, so the string-to-sign is
//! rewritten and re-signed through [`crate::VerifiedScope::from_checked_parts`] — the same
//! workaround `full_chain_tests.rs` already uses, and for the same reason.

use std::path::{Path, PathBuf};

use super::chunked::{hmac_hex, sha256_hex};
use super::*;
use crate::canonical::StringToSign;
use crate::clock::{RequestNow, SkewWindow, enforce_clock_skew};
use crate::codec::decode_hex_lower;
use crate::derive::{VerifiedScope, signing_key};
use crate::mode::{DeclaredTrailers, STREAMING_SIGNED, STREAMING_SIGNED_TRAILER, TrailerName};
use crate::parse::ScopeDate;
use crate::parse::SigV4Authorization;
use crate::scheme::SigService;
use crate::scope::{ExpectedScope, RegionSet, enforce_scope};
use crate::secret::SecretBytes;
use crate::signature::CtBytes;
use sha2::{Digest, Sha256};

/// The published AWS example credential. It authenticates nothing, anywhere.
const EXAMPLE_KEY: &[u8] = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const EXAMPLE_ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
const EXAMPLE_TIMESTAMP: &str = "20150830T123600Z";
const EXAMPLE_DAY: &str = "20150830";
const EXAMPLE_HOST: &[u8] = b"example.amazonaws.com";
/// `20150830T123600Z` in seconds since the Unix epoch.
const EXAMPLE_NOW: i64 = 1_440_938_160;

fn host() -> RawHost {
    RawHost::from_host_header(EXAMPLE_HOST).expect("a valid host")
}

fn timestamp() -> AmzDate {
    AmzDate::parse(EXAMPLE_TIMESTAMP).expect("a valid timestamp")
}

fn scope() -> SigningScope {
    SigningScope::new(ScopeDate::parse(EXAMPLE_DAY).expect("a valid day"), "us-east-1", SigService::S3)
        .expect("a serviceable scope")
}

fn signer() -> SigV4Signer {
    let credentials = SigningCredentials::new(EXAMPLE_ACCESS_KEY_ID, EXAMPLE_KEY).expect("valid credentials");
    SigV4Signer::new(credentials, scope())
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("a test header name");
        map.append(name, value.parse().expect("a test header value"));
    }
    map
}

// ---------------------------------------------------------------------------
// The verification side, assembled from its own public primitives
// ---------------------------------------------------------------------------

/// The payload mode the *verifier* derives, read back off the wire rather than remembered.
///
/// A `payload_hash` tamper is only observable because of this: a helper that reused the mode the
/// signer was given would never notice the header changed.
///
/// The absent-header case depends on the signing location, and [`PayloadMode`] says why: a request
/// with no `x-amz-content-sha256` is [`PayloadMode::Empty`] when it was signed with a header and
/// [`PayloadMode::Unsigned`] when it was presigned, because a presigned URL has no way to carry the
/// digest and its canonical token is `UNSIGNED-PAYLOAD`.
fn payload_mode_of(map: &HeaderMap, location: SigLocation) -> Result<PayloadMode, AuthError> {
    let Some(value) = map.get(X_AMZ_CONTENT_SHA256_HEADER_NAME) else {
        return Ok(match location {
            SigLocation::Query => PayloadMode::Unsigned,
            _ => PayloadMode::Empty,
        });
    };
    let text = value.to_str().map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
    let trailer = match map.get(X_AMZ_TRAILER_HEADER_NAME) {
        Some(list) => {
            let list = list.to_str().map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
            let mut names = Vec::new();
            for name in list.split(',') {
                names.push(TrailerName::new(name).map_err(|_| AuthError::AuthorizationHeaderMalformed)?);
            }
            let declared = DeclaredTrailers::new(names, text == STREAMING_SIGNED_TRAILER)
                .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
            TrailerSet::Declared(declared)
        }
        None => TrailerSet::None,
    };
    PayloadMode::parse(text, trailer).map_err(|_| AuthError::AuthorizationHeaderMalformed)
}

/// The whole verification loop, built only from what this crate exports.
///
/// The credential lookup is modelled rather than skipped, and that is load-bearing: the access key
/// id is **not** covered by a SigV4 signature. The string-to-sign carries `<date>/<region>/<service>/
/// aws4_request` and the four derivation steps carry the same three fields — the key id appears in
/// neither. It is the value a server looks the secret up by, so a `access_key` tamper is refused by
/// the lookup (`InvalidAccessKeyId`) or by the mismatch that follows a different secret, never by
/// the comparison alone. A helper that used one fixed secret regardless of the presented id would
/// report that tamper as verifying, which is how this got noticed.
fn verify(signed: &SignedRequest, secret: &SecretBytes, now: RequestNow) -> Result<(), AuthError> {
    let regions = RegionSet::new(["us-east-1"]).expect("a non-empty region set");
    let expected = ExpectedScope::new(SigService::S3, &regions);
    let host = host();
    let payload = payload_mode_of(signed.headers(), signed.location())?;
    let raw_query = RawQuery::new(signed.query());

    let (presented_scope, signed_list, presented, date, exclusion) = match signed.location() {
        SigLocation::Query => {
            let params = crate::parse::PresignedParams::parse(&raw_query)?;
            (
                params.scope().clone(),
                params.signed_headers().to_owned(),
                params.signature().clone(),
                params.date(),
                QueryExclusion::PresignedSignature,
            )
        }
        _ => {
            let header = signed.authorization().ok_or(AuthError::AuthorizationHeaderMalformed)?;
            let auth = SigV4Authorization::parse(header)?;
            let text = signed
                .headers()
                .get(X_AMZ_DATE_HEADER)
                .and_then(|value| value.to_str().ok())
                .ok_or(AuthError::AuthorizationHeaderMalformed)?;
            (
                auth.scope().clone(),
                auth.signed_headers().to_owned(),
                auth.signature().clone(),
                AmzDate::parse(text)?,
                QueryExclusion::None,
            )
        }
    };

    if presented_scope.access_key_id().access_key_id() != EXAMPLE_ACCESS_KEY_ID {
        return Err(AuthError::InvalidAccessKeyId);
    }
    let clock = enforce_clock_skew(&date, now, SkewWindow::DEFAULT)?;
    let verified = enforce_scope(&presented_scope, clock, &expected).map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
    let set = SignedHeaderSet::parse_and_enforce(&signed_list, signed.headers(), None)?;
    let paths = UriPathCandidates::new(signed.path())?;
    let spec = CanonicalRequestSpec::new(
        signed.method(),
        &paths,
        &raw_query,
        signed.headers(),
        &set,
        &host,
        payload.canonical_payload_token(),
    );
    let spec = match exclusion {
        QueryExclusion::PresignedSignature => spec.presigned(),
        _ => spec,
    };
    let material = signing_key(secret, &verified);
    for candidate in spec.candidates()? {
        let computed = calculate_signature(&material, &candidate.string_to_sign(&date, &presented_scope));
        if presented.ct_verify(&computed).is_ok() {
            return Ok(());
        }
    }
    Err(AuthError::SignatureDoesNotMatch)
}

fn example_secret() -> SecretBytes {
    SecretBytes::new(EXAMPLE_KEY)
}

fn now() -> RequestNow {
    RequestNow::from_unix_seconds(EXAMPLE_NOW)
}

fn sign_get(path: &str, query: &str) -> SignedRequest {
    let map = headers(&[("content-type", "text/plain")]);
    let host = host();
    let request = SigningRequest::new(&Method::GET, path, query, &map, &host, PayloadMode::Empty, timestamp());
    signer().sign_headers(&request).expect("signable")
}

/// A PUT whose body digest is pinned, so every one of the eleven components exists on it —
/// `x-amz-content-sha256` included, which `PayloadMode::Empty` does not mint.
fn sign_put(path: &str, query: &str) -> SignedRequest {
    let digest: [u8; 32] = Sha256::digest(b"hello world").into();
    let map = headers(&[("content-type", "text/plain")]);
    let host = host();
    let request = SigningRequest::new(&Method::PUT, path, query, &map, &host, PayloadMode::ExactSha256(digest), timestamp());
    signer().sign_headers(&request).expect("signable")
}

// ---------------------------------------------------------------------------
// The round trip
// ---------------------------------------------------------------------------

/// Positive — what the signer produces, the verification path accepts, on both signing locations
/// and with every header the signer minted covered by the list it emitted.
#[test]
fn a_signed_request_verifies_through_the_verification_path() {
    let signed = sign_get("/bucket/my key", "prefix=a+b&x-id=GetObject");
    assert_eq!(verify(&signed, &example_secret(), now()), Ok(()));
    let auth = signed.authorization().expect("an Authorization header");
    assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request,"));
    assert!(auth.contains("SignedHeaders=content-type;host;x-amz-date,"));

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
    let presigned = signer().presign(&request, 900).expect("signable");
    assert_eq!(presigned.location(), SigLocation::Query);
    assert_eq!(verify(&presigned, &example_secret(), now()), Ok(()));
}

/// Positive — a presigned URL passes the floor's own expiry reader, so the `X-Amz-Expires` the
/// signer emitted is one the server will actually read back.
#[test]
fn a_presigned_url_satisfies_the_floors_expiry_reader() {
    let map = HeaderMap::new();
    let host = host();
    let request = SigningRequest::new(&Method::GET, "/bucket/key", "", &map, &host, PayloadMode::Unsigned, timestamp());
    let presigned = signer().presign(&request, 3_600).expect("signable");

    let query = RawQuery::new(presigned.query());
    let view = crate::floor::WireView::new(presigned.headers(), query);
    assert!(crate::floor::enforce_no_duplicate_sig_params(&view).is_ok());
    let clock = enforce_clock_skew(&timestamp(), now(), SkewWindow::DEFAULT).expect("inside the window");
    let expiry = crate::floor::enforce_presign_expiry(&view, clock).expect("readable");
    assert_eq!(expiry.expires_in_seconds(), 3_600);
}

// ---------------------------------------------------------------------------
// One negative per tamper component
// ---------------------------------------------------------------------------

/// Negative — every one of the eleven canonical components, tampered with after a correct
/// signature was computed, is refused. One assertion per component, so a regression names the
/// component rather than reporting that something is wrong somewhere.
#[test]
fn every_tamper_component_is_refused_on_a_header_signed_request() {
    let base = || sign_put("/bucket/key", "prefix=a&x-id=PutObject");
    let cases: [(&str, Tamper); 11] = [
        ("signature", Tamper::new(TamperComponent::Signature)),
        ("access_key", Tamper::new(TamperComponent::AccessKey).with_new_value("AKIDNOTTHISONE")),
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
        ("payload_hash", Tamper::new(TamperComponent::PayloadHash)),
        ("date_header", Tamper::new(TamperComponent::DateHeader).with_new_value("20150830T123601Z")),
    ];

    for (label, tamper) in cases {
        let signed = base();
        assert_eq!(verify(&signed, &example_secret(), now()), Ok(()), "{label}: the base must verify");
        let tampered = signed
            .tampered(&tamper)
            .unwrap_or_else(|error| panic!("{label}: the tamper must apply, got {error:?}"));
        assert!(
            verify(&tampered, &example_secret(), now()).is_err(),
            "{label}: a tampered request must not verify"
        );
    }
}

/// Negative — the same eleven components on a presigned URL, where the credential, the signature,
/// the header list and the timestamp all live in the query instead of in a header.
#[test]
fn the_query_borne_components_are_refused_on_a_presigned_url() {
    let map = HeaderMap::new();
    let host = host();
    let base = || {
        let request = SigningRequest::new(
            &Method::GET,
            "/bucket/key",
            "versionId=7",
            &map,
            &host,
            PayloadMode::Unsigned,
            timestamp(),
        );
        signer().presign(&request, 900).expect("signable")
    };
    let cases: [(&str, Tamper); 7] = [
        ("signature", Tamper::new(TamperComponent::Signature)),
        ("access_key", Tamper::new(TamperComponent::AccessKey).with_new_value("AKIDNOTTHISONE")),
        ("scope_region", Tamper::new(TamperComponent::ScopeRegion).with_new_value("eu-west-1")),
        ("scope_service", Tamper::new(TamperComponent::ScopeService).with_new_value("sts")),
        (
            "signed_headers_list",
            Tamper::new(TamperComponent::SignedHeadersList).with_new_value("host;x-amz-date"),
        ),
        (
            "canonical_query",
            Tamper::new(TamperComponent::CanonicalQuery)
                .with_target("versionId")
                .with_new_value("8"),
        ),
        ("date_header", Tamper::new(TamperComponent::DateHeader).with_new_value("20150830T123601Z")),
    ];
    for (label, tamper) in cases {
        let signed = base();
        assert_eq!(verify(&signed, &example_secret(), now()), Ok(()), "{label}: the base must verify");
        let tampered = signed.tampered(&tamper).expect("tamperable");
        assert!(
            verify(&tampered, &example_secret(), now()).is_err(),
            "{label}: a tampered presigned URL must not verify"
        );
    }
}

/// Negative — appending a parameter to somebody else's presigned URL does not work, which is the
/// property `CanonicalRequestSpec::presigned` documents and the one an ignored parameter would
/// break.
#[test]
fn appending_a_parameter_to_a_presigned_url_is_refused() {
    let map = HeaderMap::new();
    let host = host();
    let request = SigningRequest::new(&Method::GET, "/bucket/key", "", &map, &host, PayloadMode::Unsigned, timestamp());
    let signed = signer().presign(&request, 900).expect("signable");
    assert_eq!(verify(&signed, &example_secret(), now()), Ok(()));

    let appended = signed
        .tampered(
            &Tamper::new(TamperComponent::CanonicalQuery)
                .with_target("versionId")
                .with_new_value("7"),
        )
        .expect("tamperable");
    assert!(appended.query().contains("versionId=7"));
    assert!(verify(&appended, &example_secret(), now()).is_err());
}

/// Negative — a tamper description that omits what its component needs is refused rather than
/// silently doing nothing, which would turn a negative case into a vacuous positive one.
#[test]
fn an_incomplete_tamper_description_is_refused() {
    let signed = sign_get("/bucket/key", "prefix=a");
    assert_eq!(
        signed.tampered(&Tamper::new(TamperComponent::CanonicalPath)).err(),
        Some(SignerError::TamperNewValueRequired)
    );
    let signed = sign_get("/bucket/key", "prefix=a");
    assert_eq!(
        signed
            .tampered(&Tamper::new(TamperComponent::CanonicalQuery).with_new_value("x"))
            .err(),
        Some(SignerError::TamperTargetRequired)
    );
}

// ---------------------------------------------------------------------------
// Under-signing, and the streaming invariants
// ---------------------------------------------------------------------------

/// Negative — an explicit list that leaves an `x-amz-*` header uncovered signs, and is then refused
/// by the verifier under rule 6. This is the shape a deny-list-based canonicaliser lets through.
#[test]
fn a_deliberately_under_signed_request_is_refused_by_the_verifier() {
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
    assert!(signed.headers().contains_key("x-amz-acl"), "the header is still sent");
    assert_eq!(
        verify(&signed, &example_secret(), now()),
        Err(AuthError::SignatureDoesNotMatch),
        "an unsigned x-amz-* header must be refused"
    );
}

/// Negative — the decoded-length invariant is enforced at signing time, in both directions, so a
/// signer cannot mint a request the wire layer would have to refuse.
#[test]
fn the_decoded_content_length_invariant_holds_at_signing_time() {
    let map = HeaderMap::new();
    let host = host();
    let streaming = PayloadMode::parse(STREAMING_SIGNED, TrailerSet::None).expect("valid");
    let request = SigningRequest::new(&Method::PUT, "/bucket/key", "", &map, &host, streaming, timestamp());
    assert_eq!(signer().sign_headers(&request).err(), Some(SignerError::DecodedContentLengthRequired));

    let request = SigningRequest::new(&Method::PUT, "/bucket/key", "", &map, &host, PayloadMode::Empty, timestamp())
        .with_decoded_content_length(11);
    assert_eq!(signer().sign_headers(&request).err(), Some(SignerError::DecodedContentLengthNotAllowed));
}

/// Negative — the presigned ceiling is the verification side's constant, and a query that already
/// carries a minted parameter is refused rather than overwritten.
#[test]
fn the_presigned_preconditions_are_refused_at_signing_time() {
    let map = HeaderMap::new();
    let host = host();
    let request = SigningRequest::new(&Method::GET, "/bucket/key", "", &map, &host, PayloadMode::Unsigned, timestamp());
    assert_eq!(signer().presign(&request, 0).err(), Some(SignerError::ExpiryOutOfRange));
    assert_eq!(
        signer().presign(&request, MAX_PRESIGNED_EXPIRY_SECONDS + 1).err(),
        Some(SignerError::ExpiryOutOfRange)
    );
    assert!(signer().presign(&request, MAX_PRESIGNED_EXPIRY_SECONDS).is_ok());

    let request = SigningRequest::new(
        &Method::GET,
        "/bucket/key",
        "X-Amz-Expires=60",
        &map,
        &host,
        PayloadMode::Unsigned,
        timestamp(),
    );
    assert_eq!(signer().presign(&request, 900).err(), Some(SignerError::SigningParameterAlreadyPresent));
}

/// Negative — a scope naming a region the parser refuses cannot be built, so a signer cannot mint
/// a credential the verifier could not read back.
#[test]
fn an_unusable_scope_is_refused_at_construction() {
    let day = ScopeDate::parse(EXAMPLE_DAY).expect("a valid day");
    assert!(SigningScope::new(day, "", SigService::S3).is_err());
    assert!(SigningScope::new(day, "us east 1", SigService::S3).is_err());
    assert!(SigningScope::new(day, &"r".repeat(65), SigService::S3).is_err());
    assert!(SigningCredentials::new("", EXAMPLE_KEY).is_err());
    assert!(SigningCredentials::new("AKID WITH SPACE", EXAMPLE_KEY).is_err());
}

// ---------------------------------------------------------------------------
// The aws-chunked chain
// ---------------------------------------------------------------------------

/// Positive — the seed is the request signature, and each chunk's string-to-sign is the documented
/// five-plus-one-line grammar. Recomputed here from the primitives rather than pinned to a literal,
/// so the assertion survives a change of example credential and still fails on a grammar change.
#[test]
fn the_chunk_chain_follows_the_documented_grammar() {
    let map = HeaderMap::new();
    let host = host();
    let streaming = PayloadMode::parse(STREAMING_SIGNED, TrailerSet::None).expect("valid");
    let request =
        SigningRequest::new(&Method::PUT, "/bucket/key", "", &map, &host, streaming, timestamp()).with_decoded_content_length(11);
    let mut signer = signer();
    let signed = signer.sign_headers(&request).expect("signable");
    assert_eq!(verify(&signed, &example_secret(), now()), Ok(()));

    let mut chain = signer.chunk_signer(&signed).expect("seedable");
    assert_eq!(chain.previous_signature_hex(), signed.signature_hex());

    let seed = signed.signature_hex().to_owned();
    let first = chain.sign_chunk(b"hello world").to_owned();
    let material = signing_key(&example_secret(), &scope().verified());
    let expected = hmac_hex(
        &material,
        format!(
            "{CHUNK_ALGORITHM}\n{EXAMPLE_TIMESTAMP}\n{EXAMPLE_DAY}/us-east-1/s3/aws4_request\n{seed}\n{}\n{}",
            sha256_hex(b""),
            sha256_hex(b"hello world")
        )
        .as_bytes(),
    );
    assert_eq!(first, expected);

    // The final chunk carries no data and is still a link in the chain.
    let last = chain.sign_chunk(b"").to_owned();
    assert_ne!(last, first);
    assert_eq!(chain.previous_signature_hex(), last);
}

/// Negative — the chain is a chain: one byte changed in an early chunk changes that chunk's
/// signature and every signature after it. A per-chunk signature that did not carry the previous
/// one would leave the later links identical, which is chunk reordering.
#[test]
fn a_changed_chunk_invalidates_every_later_link() {
    let map = HeaderMap::new();
    let host = host();
    let streaming = PayloadMode::parse(STREAMING_SIGNED, TrailerSet::None).expect("valid");
    let request =
        SigningRequest::new(&Method::PUT, "/bucket/key", "", &map, &host, streaming, timestamp()).with_decoded_content_length(24);
    let mut signer = signer();
    let signed = signer.sign_headers(&request).expect("signable");

    let run = |signer: &mut SigV4Signer, first: &[u8]| {
        let mut chain = signer.chunk_signer(&signed).expect("seedable");
        let a = chain.sign_chunk(first).to_owned();
        let b = chain.sign_chunk(b"second-slice").to_owned();
        let c = chain.sign_chunk(b"").to_owned();
        (a, b, c)
    };
    let original = run(&mut signer, b"first-slice-");
    let altered = run(&mut signer, b"first-slice!");
    assert_ne!(original.0, altered.0);
    assert_ne!(original.1, altered.1, "the second link must depend on the first");
    assert_ne!(original.2, altered.2, "the final link must depend on every earlier one");
}

/// Positive — a signed frame is `<hex-size>;chunk-signature=<64 hex>\r\n<data>\r\n`, and the
/// trailer block is signed under its own algorithm line.
#[test]
fn a_signed_frame_and_its_trailer_are_shaped_the_way_the_decoder_expects() {
    let map = HeaderMap::new();
    let host = host();
    let names = vec![TrailerName::new("x-amz-checksum-crc32").expect("valid")];
    let declared = DeclaredTrailers::new(names, true).expect("valid");
    let streaming = PayloadMode::parse(STREAMING_SIGNED_TRAILER, TrailerSet::Declared(declared)).expect("valid");
    let request =
        SigningRequest::new(&Method::PUT, "/bucket/key", "", &map, &host, streaming, timestamp()).with_decoded_content_length(11);
    let mut signer = signer();
    let signed = signer.sign_headers(&request).expect("signable");
    assert_eq!(
        signed
            .headers()
            .get(X_AMZ_TRAILER_HEADER_NAME)
            .and_then(|value| value.to_str().ok()),
        Some("x-amz-checksum-crc32")
    );
    assert_eq!(verify(&signed, &example_secret(), now()), Ok(()));

    let mut chain = signer.chunk_signer(&signed).expect("seedable");
    let frame = chain.encode_chunk(b"hello world");
    let text = String::from_utf8(frame).expect("ascii framing around ascii data");
    assert!(text.starts_with("b;chunk-signature="));
    assert!(text.ends_with("hello world\r\n"));

    let trailer = chain.sign_trailer("x-amz-checksum-crc32:AAAAAA==\n").to_owned();
    assert_eq!(trailer.len(), 64);
    assert!(
        trailer
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
}

// ---------------------------------------------------------------------------
// The upstream AWS signing test suite, in the signing direction
// ---------------------------------------------------------------------------

/// The environment variable naming a checkout of the suite's `v4` directory. Same variable, same
/// pinned revision, as `full_chain_tests.rs`; see `SUITE_HOWTO` there for the commands.
const SUITE_DIR_ENV: &str = "S3GATE_AWS_SIGV4_SUITE_DIR";

/// The cases replayed in the signing direction. A subset of the verification runner's list: every
/// case here has a header form the signer can assemble without inventing a header the suite's own
/// signer would not have sent.
const SIGNER_SUITE_CASES: [&str; 10] = [
    "get-vanilla",
    "get-vanilla-query",
    "get-unreserved",
    "get-utf8",
    "get-vanilla-query-order-key-case",
    "get-vanilla-query-unreserved",
    "post-vanilla",
    "post-vanilla-query",
    "post-vanilla-empty-query-value",
    "get-vanilla-empty-query-key",
];

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn context_field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle)? + needle.len();
    let rest = json.get(start..)?.trim_start().strip_prefix(':')?.trim_start();
    let quoted = rest.strip_prefix('"')?;
    let end = quoted.find('"')?;
    Some(quoted[..end].to_owned())
}

fn run_signer_suite_case(dir: &Path, name: &str) {
    let case = dir.join(name);
    let text = read(&case.join("request.txt"));
    let mut lines = text.lines();
    let start = lines.next().expect("a request line");
    let (method_and_target, _version) = start.rsplit_once(' ').expect("a request line with a version");
    let (method, target) = method_and_target.split_once(' ').expect("a method and a target");
    let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));

    let mut host_value: Option<String> = None;
    let mut map = HeaderMap::new();
    let mut names: Vec<HeaderName> = vec![HeaderName::from_static("host")];
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (field, value) = line.split_once(':').expect("a header line");
        let field = field.to_ascii_lowercase();
        if field == "host" {
            host_value = Some(value.to_owned());
            continue;
        }
        let field = HeaderName::from_bytes(field.as_bytes()).expect("a header name");
        map.append(field.clone(), value.parse().expect("a header value"));
        names.push(field);
    }
    names.push(HeaderName::from_static("x-amz-date"));
    names.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    names.dedup();

    let context = read(&case.join("context.json"));
    let region = context_field(&context, "region").expect("a region");
    let service = context_field(&context, "service").expect("a service");

    let host = RawHost::from_host_header(host_value.expect("a Host header").as_bytes()).expect("a valid host");
    let method = Method::from_bytes(method.as_bytes()).expect("a method");
    let request =
        SigningRequest::new(&method, path, query, &map, &host, PayloadMode::Empty, timestamp()).with_signed_headers(&names);
    let credentials = SigningCredentials::new(EXAMPLE_ACCESS_KEY_ID, EXAMPLE_KEY).expect("valid");
    let scope = SigningScope::new(ScopeDate::parse(EXAMPLE_DAY).expect("valid"), &region, SigService::S3).expect("valid");
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&request)
        .unwrap_or_else(|error| panic!("{name}: the suite's own request must be signable, got {error:?}"));

    // Layer one: the canonical request the signer built, byte for byte.
    assert_eq!(
        signed.canonical_request(),
        read(&case.join("header-canonical-request.txt")),
        "{name}: canonical request"
    );

    // Layer two: the string-to-sign. The suite scopes its vectors to the placeholder service name
    // `service`, which `SigService` deliberately cannot spell, so the scope line is rewritten after
    // the signer produced it rather than hand-assembled around it.
    let rewritten = signed.string_to_sign().replace("/s3/", &format!("/{service}/"));
    assert_eq!(rewritten, read(&case.join("header-string-to-sign.txt")), "{name}: string to sign");

    // Layer three: the signature, re-derived under the suite's own service name.
    let suite_scope = VerifiedScope::from_checked_parts(ScopeDate::parse(EXAMPLE_DAY).expect("valid"), &region, &service);
    // Two statements, not one: rule 6 of `scripts/check_ct_eq.sh` greps for a line that names key
    // material and a `String` in the same breath, and `StringToSign` matches its `String` pattern.
    let material = signing_key(&example_secret(), &suite_scope);
    let computed = calculate_signature(&material, &StringToSign::from_text(rewritten));
    let expected = Signature::HmacSha256(CtBytes::from_array(
        decode_hex_lower::<32>(read(&case.join("header-signature.txt")).trim()).expect("64 lowercase hex characters"),
    ));
    assert!(computed.ct_verify(&expected).is_ok(), "{name}: signature");
}

/// Positive — the signer reproduces the upstream suite's canonical request, string-to-sign and
/// signature. Verification already replays these vectors; producing them is the other direction,
/// and a canonicaliser that agreed with itself but not with AWS would pass one and fail the other.
/// Skipped, loudly, when the suite is not checked out.
#[test]
fn the_signer_reproduces_the_aws_signing_suite_vectors() {
    let Some(dir) = std::env::var_os(SUITE_DIR_ENV).map(PathBuf::from) else {
        println!("skipping the AWS signing test suite: set {SUITE_DIR_ENV}; see full_chain_tests.rs SUITE_HOWTO");
        return;
    };
    for name in SIGNER_SUITE_CASES {
        run_signer_suite_case(&dir, name);
    }
}

/// Negative — the suite list may not be quietly emptied, and may not name a case that depends on
/// path normalisation, which S3 does not do.
#[test]
fn the_signer_suite_case_list_is_not_empty_and_names_no_normalising_case() {
    assert!(SIGNER_SUITE_CASES.len() >= 8);
    for name in SIGNER_SUITE_CASES {
        assert!(!name.ends_with("-normalized") || name.ends_with("-unnormalized"), "{name}");
    }
}

/// Positive — a request dated by the HTTP `Date` header carries no `x-amz-date`, its `Date` is the
/// RFC 1123 spelling of the same instant with the right weekday, `Date` is in `SignedHeaders`, and
/// the verification side reads it back to the timestamp it was signed with (rustfs/gateway#809).
#[test]
fn a_request_dated_by_http_date_signs_its_date_header() {
    for (basic, expected) in [
        ("20150830T123600Z", "Sun, 30 Aug 2015 12:36:00 GMT"),
        ("20260914T031656Z", "Mon, 14 Sep 2026 03:16:56 GMT"),
        ("20240229T235959Z", "Thu, 29 Feb 2024 23:59:59 GMT"),
        ("20000101T000000Z", "Sat, 01 Jan 2000 00:00:00 GMT"),
        ("19991231T235959Z", "Fri, 31 Dec 1999 23:59:59 GMT"),
    ] {
        let stamp = AmzDate::parse(basic).expect("a timestamp");
        assert_eq!(super::http_date(&stamp), expected, "{basic}");
        assert_eq!(crate::sig_v2::parse_sigv2_date(expected).as_ref(), Ok(&stamp), "{basic}");
    }
    let headers = HeaderMap::new();
    let host = RawHost::from_host_header(b"example.amazonaws.com").expect("a host");
    let method = Method::GET;
    let request =
        SigningRequest::new(&method, "/bucket", "", &headers, &host, PayloadMode::Empty, timestamp()).dated_by_http_date();
    let signed = signer().sign_headers(&request).expect("signable");
    assert!(signed.headers().get("x-amz-date").is_none());
    assert_eq!(
        signed.headers().get("date").and_then(|value| value.to_str().ok()),
        Some("Sun, 30 Aug 2015 12:36:00 GMT")
    );
    let authorization = signed
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .expect("signed");
    assert!(authorization.contains("SignedHeaders=date;host,"), "{authorization}");
    assert_eq!(super::parse_timestamp(&signed).expect("a timestamp"), timestamp());
}
