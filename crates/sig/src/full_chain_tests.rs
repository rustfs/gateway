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

//! The cases that need the whole chain: canonicalise, derive, sign, compare.
//!
//! Responsible for: `c-sig-0209` (the raw-path fallback verifies a request the first candidate
//! rejects), `c-sig-0237` (two spellings of one query never share a signature), `c-sig-0230` ..
//! `c-sig-0234` and `c-sig-0252` at the signature level, and `c-sig-0212` .. `c-sig-0214` /
//! `c-sig-0258` — the run against smithy-rs' `aws-signing-test-suite` at all three plaintext layers.
//! NOT responsible for: everything expressible without a signing key, which lives in
//! `tests/canonical_request.rs` and `tests/effective_host.rs`.
//! Upstream: every module of this crate. Downstream: none (test-only module).
//!
//! # Why this file is inside `src/` and compiled only under `cfg(test)`
//!
//! [`crate::VerifiedScope`] has no public constructor, on purpose: a scope the client chose must
//! not be able to seed the key derivation, and P2-04 lands the constructor together with the
//! cross-check that earns it. An integration test in `tests/` is an external crate and therefore
//! cannot build one either — which is the guarantee working, not a gap. So the cases that need a
//! signing key live here rather than being bought by widening the type.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use http::Method;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_http::RawHost;
use sha2::{Digest, Sha256};

use crate::canonical::{CanonicalRequestSpec, PathCandidate, StringToSign, UriPathCandidates};
use crate::codec::{decode_hex_lower, encode_hex_lower};
use crate::derive::{VerifiedScope, calculate_signature, signing_key};
use crate::mode::{EMPTY_PAYLOAD_SHA256_HEX, PayloadMode};
use crate::parse::{AmzDate, CredentialScope, ScopeDate};
use crate::query::RawQuery;
use crate::secret::SecretBytes;
use crate::signature::{CtBytes, Signature};
use crate::signed_headers::SignedHeaderSet;
use crate::verdict::AuthError;

/// The published AWS example credential. It authenticates nothing, anywhere.
const EXAMPLE_KEY: &[u8] = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const EXAMPLE_CREDENTIAL: &str = "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request";
const EXAMPLE_TIMESTAMP: &str = "20150830T123600Z";
const EXAMPLE_HOST: &[u8] = b"example.amazonaws.com";

// ---------------------------------------------------------------------------
// A miniature of the P2-04 verification loop
// ---------------------------------------------------------------------------

/// One request, described the way the wire layer will hand it over.
struct Fixture {
    method: Method,
    path: String,
    query: String,
    headers: HeaderMap,
    signed_headers: String,
    host: RawHost,
    payload: PayloadMode,
}

impl Fixture {
    fn get(path: &str, query: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.append(HeaderName::from_static("x-amz-date"), HeaderValue::from_static(EXAMPLE_TIMESTAMP));
        Self {
            method: Method::GET,
            path: path.to_owned(),
            query: query.to_owned(),
            headers,
            signed_headers: "host;x-amz-date".to_owned(),
            host: RawHost::from_host_header(EXAMPLE_HOST).expect("valid host"),
            payload: PayloadMode::Empty,
        }
    }
}

fn scope_for(region: &str, service: &str) -> VerifiedScope {
    VerifiedScope::from_checked_parts(ScopeDate::parse("20150830").expect("valid"), region, service)
}

fn signing_material() -> crate::secret::SigningKey {
    signing_key(&SecretBytes::new(EXAMPLE_KEY), &scope_for("us-east-1", "s3"))
}

/// Signs the candidate at `index`, the way a client that produced that spelling would have.
fn sign_candidate(fixture: &Fixture, index: usize) -> Signature {
    let signed = SignedHeaderSet::parse_and_enforce(&fixture.signed_headers, &fixture.headers, None).expect("valid list");
    let paths = UriPathCandidates::new(&fixture.path).expect("valid path");
    let query = RawQuery::new(&fixture.query);
    let spec = CanonicalRequestSpec::new(
        &fixture.method,
        &paths,
        &query,
        &fixture.headers,
        &signed,
        &fixture.host,
        fixture.payload.canonical_payload_token(),
    );
    let request = spec
        .candidates()
        .expect("canonicalisable")
        .nth(index)
        .expect("the requested candidate exists");
    let date = AmzDate::parse(EXAMPLE_TIMESTAMP).expect("valid");
    let presented = CredentialScope::parse(EXAMPLE_CREDENTIAL).expect("valid");
    calculate_signature(&signing_material(), &request.string_to_sign(&date, &presented))
}

fn sign(fixture: &Fixture) -> Signature {
    sign_candidate(fixture, 0)
}

/// The whole loop: every candidate, a full derivation each time, a constant-time comparison each
/// time, and a rejection only once every candidate has failed.
fn verify(fixture: &Fixture, presented: &Signature) -> Result<PathCandidate, AuthError> {
    let signed = SignedHeaderSet::parse_and_enforce(&fixture.signed_headers, &fixture.headers, None)?;
    let paths = UriPathCandidates::new(&fixture.path)?;
    let query = RawQuery::new(&fixture.query);
    let spec = CanonicalRequestSpec::new(
        &fixture.method,
        &paths,
        &query,
        &fixture.headers,
        &signed,
        &fixture.host,
        fixture.payload.canonical_payload_token(),
    );
    let date = AmzDate::parse(EXAMPLE_TIMESTAMP).expect("valid");
    let presented_scope = CredentialScope::parse(EXAMPLE_CREDENTIAL).expect("valid");
    let key = signing_material();
    for candidate in spec.candidates()? {
        let expected = calculate_signature(&key, &candidate.string_to_sign(&date, &presented_scope));
        if presented.ct_verify(&expected).is_ok() {
            return Ok(candidate.path_candidate());
        }
    }
    Err(AuthError::SignatureDoesNotMatch)
}

/// Positive — c-sig-0209: a proxy that re-spelled the path's escapes does not break verification;
/// the raw candidate is what saves it, and the outcome names which spelling matched (s3s#589).
#[test]
fn c_sig_0209_the_raw_path_fallback_verifies_a_proxy_rewritten_request() {
    let rewritten = Fixture::get("/bucket/my key", "");
    // The client signed the spelling that arrived, which canonicalises to candidate two.
    let signature = sign_candidate(&rewritten, 1);
    assert_eq!(verify(&rewritten, &signature).expect("the fallback must verify it"), PathCandidate::Raw);

    // The ordinary case still resolves on the first candidate, and the first candidate alone.
    let untouched = Fixture::get("/bucket/mykey", "");
    let signature = sign(&untouched);
    assert_eq!(verify(&untouched, &signature).expect("verifies"), PathCandidate::Decoded);
}

/// Negative — c-sig-0237: a signature minted for `?prefix=a%20b` does not verify `?prefix=a%2Bb`,
/// nor the other way round. `aws-sigv4` 1.5.1 produces one signature for both.
#[test]
fn c_sig_0237_a_space_and_a_plus_never_share_a_signature() {
    let space = Fixture::get("/", "prefix=a%20b");
    let plus = Fixture::get("/", "prefix=a%2Bb");
    let space_signature = sign(&space);
    let plus_signature = sign(&plus);

    assert!(verify(&space, &space_signature).is_ok());
    assert!(verify(&plus, &plus_signature).is_ok());
    assert_eq!(verify(&space, &plus_signature), Err(AuthError::SignatureDoesNotMatch));
    assert_eq!(verify(&plus, &space_signature), Err(AuthError::SignatureDoesNotMatch));
}

/// Negative — c-sig-0230 .. c-sig-0234: tampering with any covered field fails the whole chain, not
/// merely the plaintext. One assertion per field: method, path, query, payload token, host.
#[test]
fn c_sig_0230_to_0234_tampering_with_any_covered_field_fails_verification() {
    let original = Fixture::get("/bucket/key", "prefix=a");
    let signature = sign(&original);
    assert!(verify(&original, &signature).is_ok());

    let mut method = Fixture::get("/bucket/key", "prefix=a");
    method.method = Method::DELETE;
    let path = Fixture::get("/bucket/kez", "prefix=a");
    let query = Fixture::get("/bucket/key", "prefix=b");
    let mut payload = Fixture::get("/bucket/key", "prefix=a");
    payload.payload = PayloadMode::Unsigned;
    let mut host = Fixture::get("/bucket/key", "prefix=a");
    host.host = RawHost::from_host_header(b"evil.amazonaws.com").expect("valid");

    for (label, tampered) in [
        ("method", &method),
        ("path", &path),
        ("query", &query),
        ("payload token", &payload),
        ("host", &host),
    ] {
        assert_eq!(
            verify(tampered, &signature),
            Err(AuthError::SignatureDoesNotMatch),
            "tampering with the {label} must fail verification"
        );
    }
}

/// Negative — c-sig-0252 at the signature level: one signature is never valid for two spellings of
/// one host name. This is the property a `canonical host uses the resolver's value` mutant breaks.
#[test]
fn c_sig_0252_one_signature_is_never_valid_for_two_host_spellings() {
    let original = Fixture::get("/", "");
    let signature = sign(&original);
    for spelling in ["EXAMPLE.AMAZONAWS.COM", "example.amazonaws.com.", "example.amazonaws.com:443"] {
        let mut other = Fixture::get("/", "");
        other.host = RawHost::from_host_header(spelling.as_bytes()).expect("valid");
        assert_eq!(
            verify(&other, &signature),
            Err(AuthError::SignatureDoesNotMatch),
            "a signature for example.amazonaws.com must not verify {spelling}"
        );
    }
}

/// Negative — c-sig-0244 at the signature level: an injected, unsigned `x-amz-*` header stops the
/// request before a signature is ever computed.
#[test]
fn c_sig_0244_an_injected_unsigned_amz_header_stops_the_chain() {
    let original = Fixture::get("/bucket/key", "");
    let signature = sign(&original);
    let mut injected = Fixture::get("/bucket/key", "");
    injected.headers.append(
        HeaderName::from_static("x-amz-copy-source"),
        HeaderValue::from_static("/other-bucket/other-key"),
    );
    assert_eq!(verify(&injected, &signature), Err(AuthError::SignatureDoesNotMatch));
}

// ---------------------------------------------------------------------------
// The upstream AWS signing test suite (c-sig-0212 .. c-sig-0214, c-sig-0258)
// ---------------------------------------------------------------------------

/// The environment variable naming a checkout of the suite's `v4` directory.
const SUITE_DIR_ENV: &str = "S3GATE_AWS_SIGV4_SUITE_DIR";

/// How to obtain the suite. It is **invoked, never vendored** (ADR-0001): the sources stay under
/// their own licence, and an upgrade is a one-line revision bump.
///
/// ```text
/// git clone --filter=blob:none --sparse --depth 1 \
///     https://github.com/smithy-lang/smithy-rs.git /tmp/smithy-rs
/// git -C /tmp/smithy-rs sparse-checkout set aws/rust-runtime/aws-sigv4/aws-signing-test-suite
/// export S3GATE_AWS_SIGV4_SUITE_DIR=/tmp/smithy-rs/aws/rust-runtime/aws-sigv4/aws-signing-test-suite/v4
/// export S3GATE_AWS_SIGV4A_SUITE_DIR=/tmp/smithy-rs/aws/rust-runtime/aws-sigv4/aws-signing-test-suite/v4a
/// cargo test -p rustfs-gateway-sig
/// ```
///
/// Revision this was written against: `cb39d6e52459b47fa8881a241ac9f78849f1bc25`.
///
/// The reviewed identity and complete case disposition live in the protected signing-suite lock.
/// The follow-up runner supplies both directories from that exact checkout.
const SUITE_HOWTO: &str = concat!(
    "skipping the AWS signing test suite: set S3GATE_AWS_SIGV4_SUITE_DIR and\n",
    "S3GATE_AWS_SIGV4A_SUITE_DIR to the smithy-rs suite's v4 and v4a directories.\n",
    "See the SUITE_HOWTO constant in crates/sig/src/full_chain_tests.rs for the commands.",
);

/// The cases replayed at all three layers.
///
/// Every entry's expected canonical request is independent of dot-segment collapsing: S3 signs the
/// path it was given, so the suite's `-normalized` variants describe a different service and
/// matching them would be the bug rather than the goal. Two further families are excluded on
/// purpose and are covered as negative controls instead:
///
/// * `double-url-encode` and `double-encode-path` — a non-S3 service encodes the path twice; see
///   `c_sig_0258_the_double_encoding_cases_are_negative_controls_for_s3`;
/// * `post-sts-header-after` — its expectation is that the session token is attached *after*
///   signing, which is a property of a client-side signer rather than of a canonical request.
const SUITE_LOCK: &str = include_str!("../../../spec/third-party/aws-signing-test-suite.lock");

struct SuiteRequest {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: String,
}

fn parse_suite_request(text: &str) -> SuiteRequest {
    let mut lines = text.lines();
    let start = lines.next().expect("a request line");
    // The target is everything between the first and the last space: `get-space-unnormalized`
    // sends a literal space inside the path, which a naive `split(' ')` would truncate.
    let (method_and_target, _version) = start.rsplit_once(' ').expect("a request line with a version");
    let (method, target) = method_and_target.split_once(' ').expect("a method and a target");
    let (method, target) = (method.to_owned(), target.to_owned());
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_owned(), query.to_owned()),
        None => (target, String::new()),
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Obsolete line folding. hyper rejects it outright, so it cannot reach this crate over
            // the wire; the continuation is joined with a space, which is what the collapse rule
            // would produce from the folded form anyway.
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
            continue;
        }
        let (name, value) = line.split_once(':').expect("a header line");
        headers.push((name.to_ascii_lowercase(), value.to_owned()));
    }
    let body = lines.collect::<Vec<_>>().join("\n");
    SuiteRequest {
        method,
        path,
        query,
        headers,
        body,
    }
}

fn lock_array(name: &str) -> Vec<&'static str> {
    let opening = format!("{name} = [\n");
    let (_, rest) = SUITE_LOCK
        .split_once(&opening)
        .unwrap_or_else(|| panic!("protected lock has no {name}"));
    let (body, _) = rest
        .split_once("\n]\n")
        .unwrap_or_else(|| panic!("protected lock has no closing array for {name}"));
    body.lines()
        .map(|line| {
            line.trim()
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix("\","))
                .unwrap_or_else(|| panic!("invalid protected-lock array entry for {name}: {line}"))
        })
        .collect()
}

/// A one-field reader for the suite's context files.
///
/// Deliberately not a JSON parser: this crate takes no serialisation dependency (see `MAP.md` —
/// with `serde` absent from the manifest, no `#[derive(Serialize)]` on key material can reappear),
/// and the files are fixed, machine-generated and tiny.
fn context_field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle)? + needle.len();
    let rest = json.get(start..)?.trim_start().strip_prefix(':')?.trim_start();
    let quoted = rest.strip_prefix('"')?;
    let end = quoted.find('"')?;
    Some(quoted[..end].to_owned())
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn suite_canonical(dir: &Path, name: &str) -> (SuiteRequest, crate::CanonicalRequest, String, String) {
    let case = dir.join(name);
    let request = parse_suite_request(&read(&case.join("request.txt")));
    let context = read(&case.join("context.json"));
    let region = context_field(&context, "region").expect("a region");
    let service = context_field(&context, "service").expect("a service");
    let session = context_field(&context, "token");

    let mut host_value: Option<String> = None;
    let mut headers = HeaderMap::new();
    for (field, value) in &request.headers {
        if field == "host" {
            host_value = Some(value.clone());
            continue;
        }
        let header = HeaderName::from_bytes(field.as_bytes()).expect("a header name");
        headers.append(header, HeaderValue::from_str(value).expect("a header value"));
    }
    headers.append(HeaderName::from_static("x-amz-date"), HeaderValue::from_static(EXAMPLE_TIMESTAMP));
    if let Some(session) = &session {
        headers.append(
            HeaderName::from_static("x-amz-security-token"),
            HeaderValue::from_str(session).expect("a token value"),
        );
    }

    let paths = UriPathCandidates::new(&request.path).expect("a valid path");
    let query = RawQuery::new(&request.query);
    let host = RawHost::from_host_header(host_value.expect("a Host header").as_bytes()).expect("a valid host");
    let method = Method::from_bytes(request.method.as_bytes()).expect("a method");
    let wire_content_length = request
        .headers
        .iter()
        .find(|(field, _)| field == "content-length")
        .map(|(_, value)| value.parse::<u64>().expect("a content length"));
    let payload = if request.body.is_empty() {
        PayloadMode::Empty
    } else {
        let digest: [u8; 32] = Sha256::digest(request.body.as_bytes()).into();
        headers.append(
            HeaderName::from_static("x-amz-content-sha256"),
            HeaderValue::from_str(&encode_hex_lower(&digest)).expect("a payload digest"),
        );
        PayloadMode::ExactSha256(digest)
    };
    let mut names: BTreeSet<String> = headers.keys().map(|field| field.as_str().to_owned()).collect();
    names.insert("host".to_owned());
    let signed_list = names.into_iter().collect::<Vec<_>>().join(";");
    let signed = SignedHeaderSet::parse_and_enforce(&signed_list, &headers, wire_content_length)
        .unwrap_or_else(|_| panic!("{name}: the suite's own header set must satisfy the completeness rules"));
    let spec = CanonicalRequestSpec::new(&method, &paths, &query, &headers, &signed, &host, payload.canonical_payload_token());
    let canonical = spec.candidates().expect("canonicalisable").next().expect("one candidate");
    (request, canonical, region, service)
}

fn run_suite_case(dir: &Path, name: &str) {
    let case = dir.join(name);
    let (_request, canonical, region, service) = suite_canonical(dir, name);

    // Layer one: the canonical request, byte for byte.
    let expected_canonical = read(&case.join("header-canonical-request.txt"));
    assert_eq!(canonical.text(), expected_canonical, "{name}: canonical request");

    // Layer two: the string-to-sign. The suite scopes its vectors to the placeholder service name
    // `service`, which no S3 deployment serves, so the scope line is rewritten after the real
    // method produced it rather than being hand-assembled around it.
    let date = AmzDate::parse(EXAMPLE_TIMESTAMP).expect("valid");
    let presented = CredentialScope::parse(EXAMPLE_CREDENTIAL).expect("valid");
    let produced = canonical.string_to_sign(&date, &presented);
    let string_to_sign = StringToSign::from_text(produced.text().replace("/s3/", &format!("/{service}/")));
    let expected_sts = read(&case.join("header-string-to-sign.txt"));
    assert_eq!(string_to_sign.text(), expected_sts, "{name}: string to sign");

    // Layer three: the signature.
    let key = signing_key(&SecretBytes::new(EXAMPLE_KEY), &scope_for(&region, &service));
    let computed = calculate_signature(&key, &string_to_sign);
    let expected_hex = read(&case.join("header-signature.txt"));
    let expected = Signature::HmacSha256(CtBytes::from_array(
        decode_hex_lower::<32>(expected_hex.trim()).expect("a 64-character lowercase hex signature"),
    ));
    assert!(computed.ct_verify(&expected).is_ok(), "{name}: signature");
}

fn run_s3_path_negative(dir: &Path, name: &str) {
    let case = dir.join(name);
    let (_request, canonical, _region, _service) = suite_canonical(dir, name);
    assert_ne!(
        canonical.text(),
        read(&case.join("header-canonical-request.txt")),
        "{name}: S3 must preserve path spelling"
    );
}

fn run_unsigned_token_negative(dir: &Path) {
    let name = "post-sts-header-after";
    let case = dir.join(name);
    let request = parse_suite_request(&read(&case.join("request.txt")));
    let signed_request = read(&case.join("header-signed-request.txt"));
    let authorization = signed_request
        .lines()
        .find_map(|line| line.strip_prefix("Authorization:"))
        .expect("an authorization header");
    let signed_headers = authorization
        .split_once("SignedHeaders=")
        .and_then(|(_, rest)| rest.split_once(", Signature="))
        .map(|(value, _)| value)
        .expect("a signed-header list");
    let mut headers = HeaderMap::new();
    for (field, value) in request.headers {
        if field != "host" {
            headers.append(
                HeaderName::from_bytes(field.as_bytes()).expect("a header name"),
                HeaderValue::from_str(&value).expect("a header value"),
            );
        }
    }
    let context = read(&case.join("context.json"));
    headers.append(
        HeaderName::from_static("x-amz-security-token"),
        HeaderValue::from_str(&context_field(&context, "token").expect("a session token")).expect("a token value"),
    );
    headers.append(HeaderName::from_static("x-amz-date"), HeaderValue::from_static(EXAMPLE_TIMESTAMP));
    assert_eq!(
        SignedHeaderSet::parse_and_enforce(signed_headers, &headers, None).err(),
        Some(AuthError::SignatureDoesNotMatch),
        "{name}: an unsigned session token must be rejected"
    );
}

fn run_v4a_refusal(dir: &Path, name: &str) {
    let case = dir.join(name);
    let header_request = read(&case.join("header-signed-request.txt"));
    let authorization = header_request
        .lines()
        .find_map(|line| line.strip_prefix("Authorization:"))
        .expect("a SigV4a authorization header");
    assert_eq!(
        crate::SigV4Authorization::parse(authorization).err(),
        Some(AuthError::NotImplemented(crate::Unimplemented::SigV4a)),
        "{name}: header SigV4a must be recognised and refused"
    );
    let query_request = read(&case.join("query-signed-request.txt"));
    let request = parse_suite_request(&query_request);
    assert_eq!(
        crate::PresignedParams::parse(&RawQuery::new(&request.query)).err(),
        Some(AuthError::NotImplemented(crate::Unimplemented::SigV4a)),
        "{name}: query SigV4a must be recognised and refused"
    );
}

/// Positive — c-sig-0212 / c-sig-0213 / c-sig-0214: the upstream suite matches at all three
/// plaintext layers, so a mismatch says *which* layer diverged. Skipped, loudly, when the suite is
/// not checked out.
#[test]
fn c_sig_official_suite() {
    let v4 = std::env::var_os(SUITE_DIR_ENV).map(PathBuf::from);
    let v4a = std::env::var_os("S3GATE_AWS_SIGV4A_SUITE_DIR").map(PathBuf::from);
    let (Some(dir), Some(v4a)) = (v4, v4a) else {
        assert!(
            std::env::var_os(SUITE_DIR_ENV).is_none() && std::env::var_os("S3GATE_AWS_SIGV4A_SUITE_DIR").is_none(),
            "the official-suite runner must provide both v4 and v4a directories"
        );
        println!("{SUITE_HOWTO}");
        return;
    };
    let runnable = lock_array("v4_run_three_layer");
    let negatives = lock_array("v4_s3_negative");
    let v4a_cases = lock_array("v4a_reject_not_implemented");
    assert_eq!((runnable.len(), negatives.len(), v4a_cases.len()), (31, 9, 38));
    for name in runnable {
        run_suite_case(&dir, name);
    }
    for name in negatives
        .iter()
        .copied()
        .filter(|name| !matches!(*name, "double-encode-path" | "double-url-encode" | "post-sts-header-after"))
    {
        run_s3_path_negative(&dir, name);
    }
    run_double_encoding_negative(&dir);
    run_unsigned_token_negative(&dir);
    for name in v4a_cases {
        run_v4a_refusal(&v4a, name);
    }
}

/// Negative — c-sig-0258: the suite's two double-encoding cases describe a **non-S3** service, so
/// matching their expectation would be the bug. S3 encodes the path once (s3s#13).
#[test]
fn c_sig_0258_the_double_encoding_cases_are_negative_controls_for_s3() {
    let Some(dir) = std::env::var_os(SUITE_DIR_ENV).map(PathBuf::from) else {
        return;
    };
    run_double_encoding_negative(&dir);
}

fn run_double_encoding_negative(dir: &Path) {
    let lambda_request = parse_suite_request(&read(&dir.join("double-url-encode/request.txt")));
    let lambda = UriPathCandidates::new(&lambda_request.path).expect("valid");
    assert_eq!(lambda.decoded(), lambda_request.path);
    assert!(!lambda.decoded().contains("%253A"), "S3 must not double-encode");

    let api_request = parse_suite_request(&read(&dir.join("double-encode-path/request.txt")));
    let api_gateway = UriPathCandidates::new(&api_request.path).expect("valid");
    assert_eq!(api_gateway.decoded(), "/test/%40connections/JBDvjfGEIAMCERw%3D");
    assert!(!api_gateway.decoded().contains("%253D"), "S3 must not double-encode");
}

/// Negative — the suite runner must not silently pass on an emptied case list, which is how a
/// conformance suite quietly stops testing anything.
#[test]
fn every_official_case_has_one_disposition() {
    let mut v4 = lock_array("v4_run_three_layer");
    v4.extend(lock_array("v4_s3_negative"));
    v4.sort_unstable();
    assert_eq!(v4, lock_array("v4_cases"));
    assert_eq!(lock_array("v4a_reject_not_implemented"), lock_array("v4a_cases"));
}

/// Positive — the empty-payload digest constant this crate publishes is the real SHA-256.
#[test]
fn the_empty_payload_digest_constant_is_correct() {
    let digest: [u8; 32] = Sha256::digest(b"").into();
    assert_eq!(encode_hex_lower(&digest), EMPTY_PAYLOAD_SHA256_HEX);
}
