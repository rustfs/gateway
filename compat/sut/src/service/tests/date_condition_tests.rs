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

//! Conditional dates as the RustFS-profile launcher reads them (rustfs/backlog#1677, ruling R14).
//!
//! Responsible for: a copy-source date condition RustFS cannot read being `400 InvalidArgument`
//! quoting the value, a repeated one `400 InvalidRequest`, both with nothing copied — no object,
//! no part — and a date RustFS does read (`+1994` as the year included) being served; the same
//! refusal for `If-Modified-Since` on GetObject and HeadObject; and the refusal coming after
//! authentication, where legacy RustFS answers it.
//! NOT responsible for: the grammar (`rustfs_gateway_core::codec::strict_date` unit tests, and
//! its differential against legacy RustFS in `crates/goldens`), or the core default, which ignores
//! an unreadable date (`crates/core/tests/tolerant_conditions.rs`, `q-cond-0050`,
//! `q-copy-source-date-0159`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed on a legacy RustFS build for all four operations: `Invalid Date`, an
//! RFC 850 date and an asctime date are `400 InvalidArgument` `invalid header: <name>: "<value>"`;
//! two field lines are `400 InvalidRequest` `duplicate header: <name>`; `+1994` and an empty value
//! are served.

use super::*;

const MODIFIED_SINCE: &str = "x-amz-copy-source-if-modified-since";
const UNMODIFIED_SINCE: &str = "x-amz-copy-source-if-unmodified-since";

async fn served(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    for (target, body) in [("/dates", ""), ("/dates/src", "source")] {
        let made = exchange(&service, as_main(http::Method::PUT, target, Bytes::from_static(body.as_bytes()))).await;
        assert_eq!(made.status(), 200, "{target}: {}", body_of(&made));
    }
    service
}

async fn send(service: &S3Service, method: http::Method, target: &str, extra: &[(&str, &str)]) -> WireResponse {
    exchange(service, signed(MAIN_KEY, MAIN_SECRET, method, target, Bytes::new(), extra)).await
}

async fn copy(service: &S3Service, destination: &str, extra: &[(&str, &str)]) -> WireResponse {
    let mut headers = vec![("x-amz-copy-source", "/dates/src")];
    headers.extend_from_slice(extra);
    send(service, http::Method::PUT, destination, &headers).await
}

fn element(response: &WireResponse, name: &str) -> Option<String> {
    let body = body_of(response);
    let open = format!("<{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&format!("</{name}>"))? + start;
    Some(body[start..end].to_owned())
}

/// The code and the message, with the XML text escapes a message can carry undone.
fn refusal(response: &WireResponse) -> (u16, Option<String>, Option<String>) {
    let message = element(response, "Message").map(|text| text.replace("&quot;", "\"").replace("&amp;", "&"));
    (response.status().as_u16(), element(response, "Code"), message)
}

fn invalid_argument(header: &str, value: &str) -> (u16, Option<String>, Option<String>) {
    (
        400,
        Some("InvalidArgument".to_owned()),
        Some(format!("invalid header: {header}: \"{value}\"")),
    )
}

async fn destination_status(service: &S3Service, target: &str) -> u16 {
    exchange(service, as_main(http::Method::HEAD, target, Bytes::new()))
        .await
        .status()
        .as_u16()
}

/// Negative — minio-js's `Invalid Date`, an RFC 850 date and an asctime date in either copy-source
/// date header are legacy RustFS's `400 InvalidArgument`, and nothing is copied.
#[tokio::test]
async fn n_an_unreadable_copy_source_date_is_refused_and_copies_nothing() {
    let root = TestRoot::new();
    let service = served(&root).await;

    for header in [MODIFIED_SINCE, UNMODIFIED_SINCE] {
        for value in ["Invalid Date", "Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994"] {
            let refused = copy(&service, "/dates/dst", &[(header, value)]).await;
            assert_eq!(refusal(&refused), invalid_argument(header, value), "{header}: {value}");
            assert_eq!(destination_status(&service, "/dates/dst").await, 404, "{header}: {value}");
        }
    }
}

/// Negative — the same for UploadPartCopy: refused, and no part is stored under the upload.
#[tokio::test]
async fn n_an_unreadable_copy_source_date_stores_no_part() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let created = send(&service, http::Method::POST, "/dates/mpu?uploads", &[]).await;
    let upload = element(&created, "UploadId").expect("an upload id");

    let target = format!("/dates/mpu?partNumber=1&uploadId={upload}");
    let refused = copy(&service, &target, &[(MODIFIED_SINCE, "Invalid Date")]).await;
    assert_eq!(refusal(&refused), invalid_argument(MODIFIED_SINCE, "Invalid Date"));
    let parts = send(&service, http::Method::GET, &format!("/dates/mpu?uploadId={upload}"), &[]).await;
    assert_eq!(parts.status(), 200, "{}", body_of(&parts));
    assert!(!body_of(&parts).contains("<Part>"), "{}", body_of(&parts));
}

/// Negative — two field lines are legacy RustFS's `400 InvalidRequest`, whatever they hold.
#[tokio::test]
async fn n_a_repeated_copy_source_date_is_refused_and_copies_nothing() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let date = "Sun, 06 Nov 1994 08:49:37 GMT";

    let refused = copy(&service, "/dates/dst", &[(MODIFIED_SINCE, date), (MODIFIED_SINCE, date)]).await;
    assert_eq!(
        refusal(&refused),
        (
            400,
            Some("InvalidRequest".to_owned()),
            Some(format!("duplicate header: {MODIFIED_SINCE}"))
        )
    );
    assert_eq!(destination_status(&service, "/dates/dst").await, 404);
}

/// Negative — `If-Modified-Since` on a read is refused the same way; HEAD answers the status alone.
#[tokio::test]
async fn n_an_unreadable_read_condition_is_refused() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let get = send(&service, http::Method::GET, "/dates/src", &[("if-modified-since", "Invalid Date")]).await;
    assert_eq!(refusal(&get), invalid_argument("if-modified-since", "Invalid Date"));
    let head = send(&service, http::Method::HEAD, "/dates/src", &[("if-unmodified-since", "Invalid Date")]).await;
    assert_eq!(head.status(), 400);
    assert!(head.body().is_empty());
}

/// Negative — a forged signature is still answered first: the date is read after authentication,
/// as legacy RustFS reads it after verifying the signature.
#[tokio::test]
async fn n_the_date_is_read_after_authentication() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let forged = signed(
        MAIN_KEY,
        "not-the-secret",
        http::Method::PUT,
        "/dates/dst",
        Bytes::new(),
        &[("x-amz-copy-source", "/dates/src"), (MODIFIED_SINCE, "Invalid Date")],
    );
    let refused = exchange(&service, forged).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    assert_eq!(element(&refused, "Code").as_deref(), Some("SignatureDoesNotMatch"));
}

/// Positive — a date RustFS reads is served: the fixed spelling, a signed year, and an empty value.
#[tokio::test]
async fn a_readable_or_empty_copy_source_date_is_served() {
    let root = TestRoot::new();
    let service = served(&root).await;

    for value in ["Sun, 06 Nov 1994 08:49:37 GMT", "Sun, 06 Nov +1994 08:49:37 GMT", ""] {
        let copied = copy(&service, "/dates/dst", &[(MODIFIED_SINCE, value)]).await;
        assert_eq!(copied.status(), 200, "{value:?}: {}", body_of(&copied));
    }
    let read = send(
        &service,
        http::Method::GET,
        "/dates/src",
        &[("if-modified-since", "Sun, 06 Nov 1994 08:49:37 GMT")],
    )
    .await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
}

/// Positive — a signed year is the instant RustFS reads, not an ignored condition: on the reference
/// backend, which evaluates it, `+1994` as the unmodified-since date is a `412` for a source written
/// today, as `1994` is.
#[tokio::test]
async fn a_signed_year_is_evaluated_as_its_instant() {
    let root = TestRoot::new();
    let service = served(&root).await;

    for value in ["Sun, 06 Nov 1994 08:49:37 GMT", "Sun, 06 Nov +1994 08:49:37 GMT"] {
        let refused = copy(&service, "/dates/dst", &[(UNMODIFIED_SINCE, value)]).await;
        assert_eq!(refused.status(), 412, "{value}: {}", body_of(&refused));
    }
    assert_eq!(destination_status(&service, "/dates/dst").await, 404);
}
