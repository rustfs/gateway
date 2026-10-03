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

//! A buffered write legacy RustFS cannot size, as the RustFS-profile launcher answers it
//! (rustfs/gateway#1173).
//!
//! Responsible for: legacy RustFS's answers to a bucket tag-set write carried by a chunked
//! transfer (signed or presigned) or decoded from aws-chunked framing — each refused, with the
//! stored tag set left as it was — and the controls that a sized write, an aws-chunked upload and a
//! sized batch delete are applied as before.
//! NOT responsible for: the rules' mechanics (`rustfs-gateway`'s `tests/buffered_lengths.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed against a legacy RustFS build (rustfs/rustfs `3268c42e00`): a
//! signed `PutBucketTagging` over a chunked transfer is `411` "missing header: content-length",
//! empty or not; as unsigned aws-chunked framing it is `400 IncompleteBody` under a
//! `Content-Length` and `411` under a chunked transfer; the stored tag set is unchanged each time.

use super::bodyless_body_tests::{Counted, answer};
use super::*;

const TAGGING: &[u8] = b"<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>";
/// [`TAGGING`] as one unsigned aws-chunked chunk with its `x-amz-checksum-crc32` trailer.
const FRAMED_TAGGING: &[u8] =
    b"4b\r\n<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>\r\n0\r\nx-amz-checksum-crc32:5y4GWw==\r\n\r\n";
/// The tag set every case stores first, to show what a refused write left in place.
const KEPT: &[u8] = b"<Tagging><TagSet><Tag><Key>kept</Key><Value>v</Value></Tag></TagSet></Tagging>";

/// Now, in the `x-amz-date` spelling.
fn now_rendered() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp")
}

fn now_stamp() -> AmzDate {
    AmzDate::parse(&now_rendered()).expect("a valid signing stamp")
}

fn raw_host() -> WireRequest<Bytes> {
    let probe = http::Request::builder()
        .uri("/")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid host probe");
    WireRequest::accept(probe, &Limits::default()).expect("an acceptable host")
}

/// A header-signed request head as the main identity, `extra` headers signed too; `length` is
/// sent as `Content-Length` when given and a chunked transfer is declared otherwise.
fn signed_head(
    method: http::Method,
    target: &str,
    extra: &[(&str, &str)],
    payload: PayloadMode,
    length: Option<u64>,
    decoded: Option<u64>,
) -> http::request::Builder {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    for (name, value) in extra {
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a valid header name"),
            http::HeaderValue::from_str(value).expect("a valid header value"),
        );
    }
    let accepted = raw_host();
    let stamp = now_stamp();
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a valid signing scope");
    let credentials = SigningCredentials::new(MAIN_KEY, MAIN_SECRET.as_bytes()).expect("valid signing credentials");
    let mut signing = SigningRequest::new(&method, path, query, &headers, accepted.host().raw_for_signing(), payload, stamp);
    if let Some(length) = length {
        signing = signing.with_wire_content_length(length);
    }
    if let Some(decoded) = decoded {
        signing = signing.with_decoded_content_length(decoded);
    }
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    match length {
        Some(length) => request.header(http::header::CONTENT_LENGTH, length),
        None => request.header(http::header::TRANSFER_ENCODING, "chunked"),
    }
}

/// A header-signed unsigned aws-chunked `PUT` of [`TAGGING`] to `path?query`, under `length`
/// when given and a chunked transfer otherwise.
///
/// Signed by hand, as `body_refusal_tests.rs` signs one: the facade does not name the trailer
/// declaration its signer takes, and this assembly signs the query too.
fn framed_head(path: &str, query: &str, length: Option<u64>) -> http::request::Builder {
    use hmac::{Hmac, KeyInit, Mac};
    let mac = |key: &[u8], data: &[u8]| {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };
    let hex = |bytes: &[u8]| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let stamp = now_rendered();
    let day = &stamp[..8];
    let scope = format!("{day}/us-east-1/s3/aws4_request");
    let token = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
    let headers = [
        ("content-encoding", "aws-chunked".to_owned()),
        ("host", "s3.example.com".to_owned()),
        ("x-amz-content-sha256", token.to_owned()),
        ("x-amz-date", stamp.clone()),
        ("x-amz-decoded-content-length", TAGGING.len().to_string()),
        ("x-amz-trailer", "x-amz-checksum-crc32".to_owned()),
    ];
    let canonical_headers: String = headers.iter().map(|(name, value)| format!("{name}:{value}\n")).collect();
    let signed_names = headers.iter().map(|(name, _)| *name).collect::<Vec<_>>().join(";");
    let canonical_query = if query.is_empty() {
        String::new()
    } else {
        format!("{query}=")
    };
    let canonical = format!("PUT\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_names}\n{token}");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = mac(format!("AWS4{MAIN_SECRET}").as_bytes(), day.as_bytes());
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = mac(&key, part.as_bytes());
    }
    let signature = hex(&mac(&key, string_to_sign.as_bytes()));
    let target = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let mut request = http::Request::builder().method(http::Method::PUT).uri(target).header(
        http::header::AUTHORIZATION,
        format!("AWS4-HMAC-SHA256 Credential={MAIN_KEY}/{scope}, SignedHeaders={signed_names}, Signature={signature}"),
    );
    for (name, value) in &headers {
        request = request.header(*name, value.as_str());
    }
    match length {
        Some(length) => request.header(http::header::CONTENT_LENGTH, length),
        None => request.header(http::header::TRANSFER_ENCODING, "chunked"),
    }
}

fn send(request: http::request::Builder, bytes: &'static [u8]) -> (http::Request<Counted>, Arc<AtomicU64>) {
    let (body, polled) = Counted::new(Bytes::from_static(bytes));
    (request.body(body).expect("a valid request"), polled)
}

/// A service with bucket `lengths` holding the [`KEPT`] tag set.
async fn with_kept_tags(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/lengths", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let kept = exchange(&service, as_main(http::Method::PUT, "/lengths?tagging", Bytes::from_static(KEPT))).await;
    assert_eq!(kept.status(), 200, "{}", body_of(&kept));
    service
}

/// The stored tag set still holds [`KEPT`] and not [`TAGGING`].
async fn assert_tags_kept(service: &S3Service) {
    let tags = exchange(service, as_main(http::Method::GET, "/lengths?tagging", Bytes::new())).await;
    let body = body_of(&tags);
    assert_eq!(tags.status(), 200, "{body}");
    assert!(
        body.contains("<Key>kept</Key>") && !body.contains("<Key>a</Key>"),
        "the refused tag set was stored: {body}"
    );
}

fn code(response: &WireResponse) -> String {
    body_of(response)
        .split("<Code>")
        .nth(1)
        .and_then(|rest| rest.split("</Code>").next())
        .unwrap_or_default()
        .to_owned()
}

/// Positive — a signed tag-set write over a chunked transfer is `411` before it is read, and the
/// stored tag set is unchanged.
#[tokio::test]
async fn a_chunked_transfer_of_a_signed_buffered_write_is_length_required() {
    let root = TestRoot::new();
    let service = with_kept_tags(&root).await;
    for bytes in [TAGGING, b"".as_slice()] {
        let (request, polled) = send(
            signed_head(http::Method::PUT, "/lengths?tagging", &[], PayloadMode::Unsigned, None, None),
            bytes,
        );
        let response = answer(&service, request).await;
        assert_eq!(response.status(), 411, "{}", body_of(&response));
        assert!(body_of(&response).contains("missing header: content-length"), "{}", body_of(&response));
        assert_eq!(polled.load(Ordering::SeqCst), 0, "the body was read before the refusal");
    }
    assert_tags_kept(&service).await;
}

/// Positive — a tag-set write decoded from aws-chunked framing under a `Content-Length` is
/// `400 IncompleteBody`, and the stored tag set is unchanged.
#[tokio::test]
async fn an_aws_chunked_buffered_write_under_a_length_is_incomplete() {
    let root = TestRoot::new();
    let service = with_kept_tags(&root).await;
    let (request, _polled) = send(framed_head("/lengths", "tagging", Some(FRAMED_TAGGING.len() as u64)), FRAMED_TAGGING);
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 400, "{}", body_of(&response));
    assert_eq!(code(&response), "IncompleteBody");
    assert_tags_kept(&service).await;
}

/// Positive — the same write under a chunked transfer is `411`, and the stored tag set is
/// unchanged.
#[tokio::test]
async fn an_aws_chunked_buffered_write_without_a_length_is_length_required() {
    let root = TestRoot::new();
    let service = with_kept_tags(&root).await;
    let (request, _polled) = send(framed_head("/lengths", "tagging", None), FRAMED_TAGGING);
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 411, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("You must provide the Content-Length HTTP header."),
        "{}",
        body_of(&response)
    );
    assert_tags_kept(&service).await;
}

/// Negative — a tag-set write under a `Content-Length` is applied as before.
#[tokio::test]
async fn n_a_sized_buffered_write_is_applied() {
    let root = TestRoot::new();
    let service = with_kept_tags(&root).await;
    let (request, polled) = send(
        signed_head(
            http::Method::PUT,
            "/lengths?tagging",
            &[],
            PayloadMode::Unsigned,
            Some(TAGGING.len() as u64),
            None,
        ),
        TAGGING,
    );
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    assert_eq!(polled.load(Ordering::SeqCst), TAGGING.len() as u64);
    let tags = exchange(&service, as_main(http::Method::GET, "/lengths?tagging", Bytes::new())).await;
    assert!(body_of(&tags).contains("<Key>a</Key>"), "the write was not applied: {}", body_of(&tags));
}

/// Negative — an upload decoded from aws-chunked framing is stored whole, as before.
#[tokio::test]
async fn n_an_aws_chunked_upload_is_stored() {
    let root = TestRoot::new();
    let service = with_kept_tags(&root).await;
    let (request, _polled) = send(framed_head("/lengths/object", "", Some(FRAMED_TAGGING.len() as u64)), FRAMED_TAGGING);
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    let stored = exchange(&service, as_main(http::Method::GET, "/lengths/object", Bytes::new())).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    assert_eq!(stored.body().as_ref(), TAGGING, "the upload was not stored whole");
}

/// Negative — a batch delete under a `Content-Length` deletes as before.
#[tokio::test]
async fn n_a_sized_batch_delete_deletes() {
    let root = TestRoot::new();
    let service = with_kept_tags(&root).await;
    let stored = exchange(&service, as_main(http::Method::PUT, "/lengths/gone", Bytes::from_static(b"x"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    let delete: &'static [u8] = b"<Delete><Object><Key>gone</Key></Object></Delete>";
    let (request, _polled) = send(
        signed_head(
            http::Method::POST,
            "/lengths?delete",
            &[],
            PayloadMode::Unsigned,
            Some(delete.len() as u64),
            None,
        ),
        delete,
    );
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    let gone = exchange(&service, as_main(http::Method::GET, "/lengths/gone", Bytes::new())).await;
    assert_eq!(gone.status(), 404, "the batch delete left the object");
}

/// Negative — a batch delete over a chunked transfer is `411` and deletes nothing.
#[tokio::test]
async fn n_a_chunked_transfer_of_a_batch_delete_deletes_nothing() {
    let root = TestRoot::new();
    let service = with_kept_tags(&root).await;
    let stored = exchange(&service, as_main(http::Method::PUT, "/lengths/kept", Bytes::from_static(b"x"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    let (request, _polled) = send(
        signed_head(http::Method::POST, "/lengths?delete", &[], PayloadMode::Unsigned, None, None),
        b"<Delete><Object><Key>kept</Key></Object></Delete>",
    );
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 411, "{}", body_of(&response));
    let kept = exchange(&service, as_main(http::Method::GET, "/lengths/kept", Bytes::new())).await;
    assert_eq!(kept.status(), 200, "a refused batch delete deleted the object");
}

/// A presigned `PUT` target to `target` over `UNSIGNED-PAYLOAD`, signed now by the main identity.
fn presigned(target: &str) -> String {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let accepted = raw_host();
    let stamp = now_stamp();
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a valid signing scope");
    let credentials = SigningCredentials::new(MAIN_KEY, MAIN_SECRET.as_bytes()).expect("valid signing credentials");
    let signing = SigningRequest::new(
        &http::Method::PUT,
        path,
        query,
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Unsigned,
        stamp,
    );
    SigV4Signer::new(credentials, scope)
        .presign(&signing, 300)
        .expect("a presignable request")
        .target()
}

/// Positive — a presigned tag-set write declaring no digest demands no length of its signature, so
/// it is read, and then refused `411` for arriving without one; the stored tag set is unchanged.
#[tokio::test]
async fn a_lengthless_presigned_buffered_write_is_length_required_once_read() {
    let root = TestRoot::new();
    let service = with_kept_tags(&root).await;
    let request = http::Request::builder()
        .method(http::Method::PUT)
        .uri(presigned("/lengths?tagging"))
        .header(http::header::HOST, "s3.example.com")
        .header(http::header::TRANSFER_ENCODING, "chunked");
    let (request, polled) = send(request, TAGGING);
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 411, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("You must provide the Content-Length HTTP header."),
        "{}",
        body_of(&response)
    );
    assert_eq!(polled.load(Ordering::SeqCst), TAGGING.len() as u64, "legacy RustFS reads it first");
    assert_tags_kept(&service).await;
}
