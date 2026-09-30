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

//! An optional header whose one line is empty, through a whole service (rustfs/gateway#1087).
//!
//! Responsible for: `ServiceBuilder::read_empty_headers_as_absent` serving what legacy RustFS
//! serves — an empty expected bucket owner, `Content-MD5`, SDK checksum algorithm, SSE header or
//! timestamp reaching the handler as absent, with the raw line still in the handler's context —
//! while the default assembly refuses each before any handler exactly as before, and a value is
//! still checked under the switch.
//! NOT responsible for: the codec reading (`rustfs-gateway-core`'s codec tests), the arbitration
//! (`rustfs-gateway-http`'s `checksum_empty_headers`), or the census over every operation (the
//! difftest seam diff).
//! Upstream: `S3Service` with a recording handler. Downstream: none.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::BodyExt;
use rustfs_gateway::{
    BoxFuture, BucketOwnerError, BucketOwnerSource, Handler, HandlerError, HandlerResult, Req, Resp, S3Service, dto,
};
use rustfs_gateway_types::BucketName;

use crate::support;

const OWNER: &str = "111122223333";

/// Every bucket belongs to [`OWNER`].
struct Owner;

impl BucketOwnerSource for Owner {
    fn owner<'a>(&'a self, _bucket: &'a BucketName) -> BoxFuture<'a, Result<Arc<str>, BucketOwnerError>> {
        Box::pin(async { Ok(Arc::from(OWNER)) })
    }
}

/// What the handler was handed: the members an empty line would otherwise set, and whether the
/// raw line reached its context.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Handed {
    expected_owner: Option<String>,
    storage_class: Option<String>,
    server_side_encryption: Option<String>,
    retain_until: bool,
    raw_owner_line: Option<String>,
}

type Records = Arc<Mutex<Vec<Handed>>>;

struct Backend(Records);

impl Handler<dto::PutObject> for Backend {
    async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        let raw_owner_line = request
            .context()
            .headers()
            .iter_raw()
            .find(|(name, _)| name.as_str() == "x-amz-expected-bucket-owner")
            .map(|(_, value)| String::from_utf8_lossy(value.as_bytes()).into_owned());
        let input = request.into_input();
        // The body is read to its end, as every storing handler must, so its verdict is the one
        // the service answers with.
        if let Some(body) = input.body {
            let mut body = body.into_body();
            while let Some(frame) = body.frame().await {
                frame.map_err(|_| HandlerError::internal_error("the request body stream failed"))?;
            }
        }
        self.0.lock().expect("the record is never poisoned").push(Handed {
            expected_owner: input.expected_bucket_owner,
            storage_class: input.storage_class.map(|class| class.as_str().to_owned()),
            server_side_encryption: input.server_side_encryption.map(|sse| sse.as_str().to_owned()),
            retain_until: input.object_lock_retain_until_date.is_some(),
            raw_owner_line,
        });
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}

fn service(empty_absent: bool) -> (S3Service, Records) {
    let records = Records::default();
    let mut builder = support::wired_at_signed_time().bucket_owner_source(Owner);
    if empty_absent {
        builder = builder.read_empty_headers_as_absent();
    }
    let service = builder
        .register::<dto::PutObject, _>(Arc::new(Backend(Arc::clone(&records))))
        .build()
        .expect("a complete assembly");
    (service, records)
}

async fn put(service: &S3Service, headers: &[(&str, &str)]) -> (http::StatusCode, String) {
    let headers = [&[("content-length", "5")], headers].concat();
    let request =
        support::signed_target_with_body_and_headers(http::Method::PUT, "/bucket/key", &headers, Bytes::from_static(b"hello"));
    support::exchange(service, request).await
}

/// Every empty header the census found the gateway refusing before its handler, one class each.
const EMPTY: [&str; 6] = [
    "x-amz-expected-bucket-owner",
    "content-md5",
    "x-amz-sdk-checksum-algorithm",
    "x-amz-server-side-encryption",
    "x-amz-object-lock-retain-until-date",
    "x-amz-storage-class",
];

/// Positive — under the switch each empty header is served, and the handler is handed nothing for
/// it; the raw line still reaches the handler's context.
#[tokio::test]
async fn under_the_switch_an_empty_header_is_served_as_absent() {
    let (service, backend) = service(true);
    for name in EMPTY {
        let (status, body) = put(&service, &[(name, "")]).await;
        assert_eq!(status, http::StatusCode::OK, "{name}: {body}");
    }
    let handed = backend.lock().expect("the record is never poisoned").clone();
    assert_eq!(handed.len(), EMPTY.len());
    for (name, handed) in EMPTY.iter().zip(&handed) {
        let expected = Handed {
            raw_owner_line: (*name == "x-amz-expected-bucket-owner").then(String::new),
            ..Handed::default()
        };
        assert_eq!(handed, &expected, "{name}");
    }
}

/// Negative — the default assembly refuses every one of them before its handler, as before.
#[tokio::test]
async fn n_by_default_an_empty_header_is_refused_before_the_handler() {
    let (service, backend) = service(false);
    for name in EMPTY {
        let (status, body) = put(&service, &[(name, "")]).await;
        if name == "x-amz-storage-class" {
            // An open enumeration: the default hands it over as an empty value.
            assert_eq!(status, http::StatusCode::OK, "{name}: {body}");
            continue;
        }
        assert!(status.is_client_error(), "{name}: {status} {body}");
    }
    let handed = backend.lock().expect("the record is never poisoned").clone();
    assert_eq!(handed.len(), 1);
    assert_eq!(handed[0].storage_class.as_deref(), Some(""));
}

/// Negative — under the switch a value is still checked: another owner is `403 AccessDenied`, the
/// right one is served, and a malformed digest is still refused.
#[tokio::test]
async fn n_under_the_switch_a_value_is_still_checked() {
    let (service, backend) = service(true);
    let (status, _) = put(&service, &[("x-amz-expected-bucket-owner", "999999999999")]).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN);
    let (status, body) = put(&service, &[("x-amz-expected-bucket-owner", OWNER)]).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let (status, _) = put(&service, &[("content-md5", "not base64")]).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST);
    let handed = backend.lock().expect("the record is never poisoned").clone();
    assert_eq!(handed.len(), 1);
    assert_eq!(handed[0].expected_owner.as_deref(), Some(OWNER));
}
