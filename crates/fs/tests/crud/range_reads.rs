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

//! Signed production-service evidence that ranged reads serve a window rather than the object.
//!
//! Responsible for: the `Range` boundaries a real client sends — a leading window, a suffix, an
//! open-ended tail, a window past the end, a single byte, an unsatisfiable range, a multi-range
//! request, an unreadable header, `If-Range` in both directions, the `partNumber` conflict, and the
//! same window on `HEAD` and on an explicit version.
//! NOT responsible for: deciding range semantics. Every expectation below is what
//! `rustfs_gateway::evaluate_range` answers; this file proves the backend asks it and puts the
//! answer on the wire.
//! Upstream: the shared CRUD service fixture. Downstream: the crate verification gate.

use super::*;

/// Ten bytes, so that every boundary below is readable by eye: `bytes=6-` is `"6789"`.
const BODY: &[u8] = b"0123456789";

async fn put(service: &S3Service, bucket: &str, key: &str, body: &'static [u8]) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::PUT, &format!("/{bucket}/{key}"), Bytes::from_static(body))).await
}

/// A signed request carrying one extra header, which is what puts `Range` inside the signature.
async fn get_with(service: &S3Service, target: &str, extra: &[(&'static str, &str)]) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    for (name, value) in extra {
        headers.insert(
            http::HeaderName::from_static(name),
            http::HeaderValue::from_str(value).expect("an ASCII fixture header"),
        );
    }
    exchange(service, signed_with_headers(http::Method::GET, target, Bytes::new(), headers)).await
}

async fn head_with(service: &S3Service, target: &str, extra: &[(&'static str, &str)]) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    for (name, value) in extra {
        headers.insert(
            http::HeaderName::from_static(name),
            http::HeaderValue::from_str(value).expect("an ASCII fixture header"),
        );
    }
    exchange(service, signed_with_headers(http::Method::HEAD, target, Bytes::new(), headers)).await
}

fn text<'a>(response: &'a rustfs_gateway::WireResponse, name: &str) -> Option<&'a str> {
    header(response, name).and_then(|value| value.to_str().ok())
}

async fn ranged_object(root: &TestRoot, bucket: &str, key: &str) -> S3Service {
    let (_backend, service) = service(root);
    create_bucket(&service, bucket).await;
    assert_eq!(put(&service, bucket, key, BODY).await.status(), 200);
    service
}

/// Positive — the leading window a resuming client asks for is the window it gets.
///
/// This is rustfs/gateway#626 in one exchange: the backend answered `200` and all ten bytes, so a
/// client that trusts `Content-Length` and stops reading received the wrong bytes with no error.
#[tokio::test]
async fn a_leading_range_is_served_as_partial_content() {
    let root = TestRoot::new();
    let service = ranged_object(&root, "range-lead", "object.bin").await;
    let response = get_with(&service, "/range-lead/object.bin", &[("range", "bytes=0-3")]).await;
    assert_eq!(response.status(), 206, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(text(&response, "content-range"), Some("bytes 0-3/10"));
    assert_eq!(text(&response, "content-length"), Some("4"));
    assert_eq!(text(&response, "accept-ranges"), Some("bytes"));
    assert_eq!(response.body().as_ref(), b"0123".as_slice());
}

/// Positive — a suffix range counts from the end, and the `Content-Range` reports where it landed.
#[tokio::test]
async fn a_suffix_range_is_counted_from_the_end() {
    let root = TestRoot::new();
    let service = ranged_object(&root, "range-suffix", "object.bin").await;
    let response = get_with(&service, "/range-suffix/object.bin", &[("range", "bytes=-4")]).await;
    assert_eq!(response.status(), 206, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(text(&response, "content-range"), Some("bytes 6-9/10"));
    assert_eq!(response.body().as_ref(), b"6789".as_slice());
}

/// Positive — an open-ended range runs to the last byte, which is how restic reads a pack tail.
#[tokio::test]
async fn an_open_ended_range_runs_to_the_last_byte() {
    let root = TestRoot::new();
    let service = ranged_object(&root, "range-open", "object.bin").await;
    let response = get_with(&service, "/range-open/object.bin", &[("range", "bytes=6-")]).await;
    assert_eq!(response.status(), 206, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(text(&response, "content-range"), Some("bytes 6-9/10"));
    assert_eq!(response.body().as_ref(), b"6789".as_slice());
}

/// Negative — a range whose last byte is past the end is clamped, not refused.
///
/// The pair with the unsatisfiable case below is the point: "past the end" and "starts past the
/// end" are two different answers, and a backend that returned `416` for both would fail every
/// client that asks for a fixed-size window at an unknown offset.
#[tokio::test]
async fn n_a_range_running_past_the_end_is_clamped_to_the_object() {
    let root = TestRoot::new();
    let service = ranged_object(&root, "range-past", "object.bin").await;
    let response = get_with(&service, "/range-past/object.bin", &[("range", "bytes=6-999")]).await;
    assert_eq!(response.status(), 206, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(text(&response, "content-range"), Some("bytes 6-9/10"));
    assert_eq!(text(&response, "content-length"), Some("4"));
    assert_eq!(response.body().as_ref(), b"6789".as_slice());
}

/// Negative — a single-byte range is one byte, not zero and not two.
///
/// `end - start + 1` is the arithmetic a ranged read gets wrong most often, and only a window of
/// length one can tell the inclusive spelling from the exclusive one.
#[tokio::test]
async fn n_a_single_byte_range_serves_exactly_one_byte() {
    let root = TestRoot::new();
    let service = ranged_object(&root, "range-one", "object.bin").await;
    let response = get_with(&service, "/range-one/object.bin", &[("range", "bytes=0-0")]).await;
    assert_eq!(response.status(), 206, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(text(&response, "content-range"), Some("bytes 0-0/10"));
    assert_eq!(text(&response, "content-length"), Some("1"));
    assert_eq!(response.body().as_ref(), b"0".as_slice());
}

/// Negative — a range that starts past the end is `416`, with the object's real size on the wire.
///
/// Both halves are asserted: the `Content-Range: bytes */10` RFC 9110 §14.4 requires on a `416`,
/// and the two S3 document elements a client reads to decide what to ask for next.
#[tokio::test]
async fn n_a_range_starting_past_the_end_is_unsatisfiable() {
    let root = TestRoot::new();
    let service = ranged_object(&root, "range-over", "object.bin").await;
    let response = get_with(&service, "/range-over/object.bin", &[("range", "bytes=10-20")]).await;
    assert_eq!(response.status(), 416, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(text(&response, "content-range"), Some("bytes */10"));
    let body = String::from_utf8_lossy(response.body()).into_owned();
    assert_eq!(element(response.body(), "Code").as_deref(), Some("InvalidRange"), "{body}");
    assert_eq!(element(response.body(), "ActualObjectSize").as_deref(), Some("10"), "{body}");
    assert_eq!(element(response.body(), "RangeRequested").as_deref(), Some("bytes=10-20"), "{body}");
}

/// Negative — a multi-range request is answered with the whole object and a `200`.
///
/// S3 does not implement `multipart/byteranges`: `RangeDecision::Whole` is what the exported
/// contract answers for a multi-range header, and a backend that served only the first span would
/// hand a client bytes it never asked for under a status that claims they are the whole object.
#[tokio::test]
async fn n_a_multi_range_request_is_answered_whole() {
    let root = TestRoot::new();
    let service = ranged_object(&root, "range-multi", "object.bin").await;
    let response = get_with(&service, "/range-multi/object.bin", &[("range", "bytes=0-1,4-5")]).await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(text(&response, "content-range"), None);
    assert_eq!(response.body().as_ref(), BODY);
}

/// Negative — a `Range` this server cannot read is ignored, not refused.
#[tokio::test]
async fn n_an_unreadable_range_unit_serves_the_whole_object() {
    let root = TestRoot::new();
    let service = ranged_object(&root, "range-junk", "object.bin").await;
    let response = get_with(&service, "/range-junk/object.bin", &[("range", "pages=1-2")]).await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(text(&response, "content-range"), None);
    assert_eq!(response.body().as_ref(), BODY);
}

/// Negative — `If-Range` decides the range in both directions.
///
/// A backend whose `If-Range` was stuck on either answer satisfies half of this test and fails the
/// other half, which is the only reason both halves are here: a stale validator must drop the range
/// and serve the whole representation, and a current one must honour it.
#[tokio::test]
async fn n_if_range_drops_the_range_only_when_the_validator_is_stale() {
    let root = TestRoot::new();
    let service = ranged_object(&root, "range-ifrange", "object.bin").await;
    let current = text(&get_with(&service, "/range-ifrange/object.bin", &[]).await, "etag")
        .expect("an entity tag")
        .to_owned();

    let honoured = get_with(
        &service,
        "/range-ifrange/object.bin",
        &[("range", "bytes=0-3"), ("if-range", current.as_str())],
    )
    .await;
    assert_eq!(honoured.status(), 206, "{}", String::from_utf8_lossy(honoured.body()));
    assert_eq!(honoured.body().as_ref(), b"0123".as_slice());

    let stale = get_with(
        &service,
        "/range-ifrange/object.bin",
        &[("range", "bytes=0-3"), ("if-range", "\"00000000000000000000000000000000\"")],
    )
    .await;
    assert_eq!(stale.status(), 200, "{}", String::from_utf8_lossy(stale.body()));
    assert_eq!(stale.body().as_ref(), BODY);
    assert_eq!(text(&stale, "content-range"), None);
}

/// Negative — `Range` and `partNumber` together select bytes twice and are refused.
#[tokio::test]
async fn n_range_and_part_number_together_are_refused() {
    let root = TestRoot::new();
    let service = ranged_object(&root, "range-conflict", "object.bin").await;
    let response = get_with(&service, "/range-conflict/object.bin?partNumber=1", &[("range", "bytes=0-3")]).await;
    assert_eq!(response.status(), 400, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(element(response.body(), "Code").as_deref(), Some("InvalidRequest"));
}

/// Negative — `HEAD` reports the window it would have served and sends no body.
///
/// A `HEAD` that answered `200` and the object's full length would tell a client resuming a
/// download that the server has no ranged read, and the client would start again from zero.
#[tokio::test]
async fn n_head_reports_the_window_without_a_body() {
    let root = TestRoot::new();
    let service = ranged_object(&root, "range-head", "object.bin").await;
    let response = head_with(&service, "/range-head/object.bin", &[("range", "bytes=2-5")]).await;
    assert_eq!(response.status(), 206, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(text(&response, "content-range"), Some("bytes 2-5/10"));
    assert_eq!(text(&response, "content-length"), Some("4"));
    assert!(response.body().is_empty(), "a HEAD carries no body");
}

/// Negative — a `HEAD` whose range cannot be satisfied is `416` too, not `200`.
#[tokio::test]
async fn n_head_refuses_an_unsatisfiable_range() {
    let root = TestRoot::new();
    let service = ranged_object(&root, "range-head-over", "object.bin").await;
    let response = head_with(&service, "/range-head-over/object.bin", &[("range", "bytes=99-")]).await;
    assert_eq!(response.status(), 416);
    assert_eq!(text(&response, "content-range"), Some("bytes */10"));
}

/// Negative — the window applies to an explicitly selected version, not only to the current object.
///
/// `GetObject` has two return paths in this backend — a stored version record and a plain object
/// file — and a range honoured on one of them is a range ignored on the other. The version path is
/// the one a client reaches after any `PUT` into a versioned bucket, which is most of them.
#[tokio::test]
async fn n_a_ranged_read_of_an_explicit_version_serves_the_window() {
    let root = TestRoot::new();
    let (_backend, service) = service(&root);
    create_bucket(&service, "range-version").await;
    let document = Bytes::from_static(
        b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>",
    );
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static("content-md5"),
        http::HeaderValue::from_static("QQFYoy/mRYV9PGZUfFi0Bw=="),
    );
    assert_eq!(
        exchange(
            &service,
            signed_with_headers(http::Method::PUT, "/range-version?versioning", document, headers)
        )
        .await
        .status(),
        200
    );
    let stored = put(&service, "range-version", "object.bin", BODY).await;
    assert_eq!(stored.status(), 200);
    let version = text(&stored, "x-amz-version-id").expect("a version id").to_owned();

    let response = get_with(
        &service,
        &format!("/range-version/object.bin?versionId={version}"),
        &[("range", "bytes=3-5")],
    )
    .await;
    assert_eq!(response.status(), 206, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(text(&response, "content-range"), Some("bytes 3-5/10"));
    assert_eq!(response.body().as_ref(), b"345".as_slice());
}
