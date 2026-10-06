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

//! Shared fixtures for tests of the actual RustFS-profile assembly.
//!
//! Responsible for: command-line setup, explicit canonical signing and response collection.
//! NOT responsible for: production path canonicalization or test assertions.
//! Upstream: the parent test identities and temporary root. Downstream: service test modules.

use super::*;

/// The exact command line an external suite would use, parsed by the launcher's own parser.
pub(super) fn two_identity_options(root: &TestRoot, extra: &[&str]) -> Options {
    let mut arguments = vec![
        "--data".to_owned(),
        root.0.to_string_lossy().into_owned(),
        "--access-key".to_owned(),
        MAIN_KEY.to_owned(),
        "--secret-key".to_owned(),
        MAIN_SECRET.to_owned(),
        "--owner-id".to_owned(),
        MAIN_OWNER.to_owned(),
        "--display-name".to_owned(),
        MAIN_DISPLAY_NAME.to_owned(),
        "--alt-access-key".to_owned(),
        ALT_KEY.to_owned(),
        "--alt-secret-key".to_owned(),
        ALT_SECRET.to_owned(),
        "--alt-owner-id".to_owned(),
        ALT_OWNER.to_owned(),
        "--alt-display-name".to_owned(),
        ALT_OWNER.to_owned(),
    ];
    arguments.extend(extra.iter().map(|argument| (*argument).to_owned()));
    parse_options(arguments).expect("a valid two-identity command line")
}

pub(super) fn assembled(options: &Options) -> (Arc<FsBackend>, S3Service) {
    let backend = Arc::new(open_backend(options).expect("a usable data root"));
    let owners = Arc::new(BucketOwners::default());
    let service = build_service(options, &backend, &owners).expect("a complete assembly");
    (backend, service)
}

/// Signs one request as the named identity, using the same signer any SDK would.
pub(super) fn signed(
    access_key: &str,
    secret_key: &str,
    method: http::Method,
    target: &str,
    body: Bytes,
    extra: &[(&str, &str)],
) -> http::Request<Bytes> {
    signed_in(Some("us-east-1"), access_key, secret_key, method, target, body, extra)
}

/// [`signed`], scoped to `region`; `None` signs with an empty region, as RustFS's replication
/// client does for a bucket target that names none.
pub(super) fn signed_in(
    region: Option<&str>,
    access_key: &str,
    secret_key: &str,
    method: http::Method,
    target: &str,
    body: Bytes,
    extra: &[(&str, &str)],
) -> http::Request<Bytes> {
    signed_to("s3.example.com", region, access_key, secret_key, method, target, body, extra)
}

/// [`signed_in`], sent to `host` rather than `s3.example.com`.
#[allow(clippy::too_many_arguments, reason = "the signing inputs, each one a fixture choice")]
pub(super) fn signed_to(
    host: &str,
    region: Option<&str>,
    access_key: &str,
    secret_key: &str,
    method: http::Method,
    target: &str,
    body: Bytes,
    extra: &[(&str, &str)],
) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_str(host).expect("a valid host"));
    for (name, value) in extra {
        headers.append(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a valid header name"),
            http::HeaderValue::from_str(value).expect("a valid header value"),
        );
    }
    let payload = if (method == http::Method::PUT && target.matches('/').count() >= 2) || !body.is_empty() {
        let digest: [u8; 32] = Sha256::digest(&body).into();
        let payload = PayloadMode::ExactSha256(digest);
        headers.insert(
            http::HeaderName::from_static("x-amz-content-sha256"),
            http::HeaderValue::from_str(payload.canonical_payload_token().as_str()).expect("a digest header"),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(&body.len().to_string()).expect("a content length"),
        );
        payload
    } else {
        // A bodyless request declares the empty body's digest, as every S3 SDK does: legacy RustFS
        // refuses an `s3`-scoped header signature that declares none, and so does the RustFS
        // profile (rustfs/gateway#1130).
        let digest: [u8; 32] = Sha256::digest(&body).into();
        let payload = PayloadMode::ExactSha256(digest);
        headers.insert(
            http::HeaderName::from_static("x-amz-content-sha256"),
            http::HeaderValue::from_str(payload.canonical_payload_token().as_str()).expect("a digest header"),
        );
        payload
    };
    let probe = http::Request::builder()
        .uri("/")
        .header(http::header::HOST, host)
        .body(Bytes::new())
        .expect("a valid host probe");
    let accepted = WireRequest::accept(probe, &Limits::default()).expect("an acceptable host");
    // The assembled service uses the production system clock — `build_service` installs no
    // fixed one — so the request must be stamped now, or every case here would fail on skew
    // rather than on what it is written to measure.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let rendered = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let stamp = AmzDate::parse(&rendered).expect("a valid signing stamp");
    let scope = match region {
        Some(region) => SigningScope::new(stamp.day(), region, SigService::S3).expect("a valid signing scope"),
        None => SigningScope::with_empty_region(stamp.day(), SigService::S3),
    };
    let credentials = SigningCredentials::new(access_key, secret_key.as_bytes()).expect("valid signing credentials");
    let signing = SigningRequest::new(&method, path, query, &headers, accepted.host().raw_for_signing(), payload, stamp)
        .with_wire_content_length(body.len() as u64);
    let mut signer = SigV4Signer::new(credentials, scope);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut request = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(body).expect("a valid signed request")
}

/// Ordinary profile fixtures sign an escaped slash as `/`, as the frozen native probe does
/// (#1315). Keep `signed` strict for tests intentionally choosing a different canonical URI.
pub(super) fn signed_legacy_path(
    access_key: &str,
    secret_key: &str,
    method: http::Method,
    target: &str,
    body: Bytes,
    extra: &[(&str, &str)],
) -> http::Request<Bytes> {
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    let path = path.replace("%2F", "/").replace("%2f", "/");
    let canonical = query.map_or_else(|| path.clone(), |query| format!("{path}?{query}"));
    let mut request = signed(access_key, secret_key, method, &canonical, body, extra);
    *request.uri_mut() = target.parse().expect("the original raw target");
    request
}

pub(super) fn as_main(method: http::Method, target: &str, body: Bytes) -> http::Request<Bytes> {
    signed_legacy_path(MAIN_KEY, MAIN_SECRET, method, target, body, &[])
}

pub(super) fn as_alt(method: http::Method, target: &str, body: Bytes) -> http::Request<Bytes> {
    signed_legacy_path(ALT_KEY, ALT_SECRET, method, target, body, &[])
}

pub(super) async fn exchange(service: &S3Service, request: http::Request<Bytes>) -> WireResponse {
    collect(service.call_bytes(request).await).await.expect("a finite response")
}

pub(super) fn body_of(response: &WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}
