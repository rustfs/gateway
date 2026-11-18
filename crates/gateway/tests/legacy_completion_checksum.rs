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

//! A `CompleteMultipartUpload` that declares a checksum type beside a checksum value, through a
//! whole service (rustfs/gateway#1349).
//!
//! Responsible for: the contradicting pair (`x-amz-checksum-type: COMPOSITE` beside a full-object
//! `x-amz-checksum-crc32`) reaching the handler under
//! `ServiceBuilder::read_checksums_as_legacy_rustfs`, as legacy RustFS lets it reach its own, with
//! the handler seeing the value and the type exactly as sent; the same pair refused before any
//! handler runs off the switch; and a value that cannot be read still refused under it.
//! NOT responsible for: the arbitration (`rustfs-gateway-http`) or the answer a backend gives the
//! pair (`rustfs-gateway-fs`).
//! Upstream: `S3Service` with a recording `CompleteMultipartUpload` handler. Downstream: none.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::{Handler, HandlerResult, Req, Resp, S3Service, ServiceBuilder, dto};

use crate::support;

/// What the handler was handed: the checksum value and type, as text.
type Seen = (Option<String>, Option<String>);

/// Records every input handed to `CompleteMultipartUpload`, so "the handler ran" is a measurement.
struct Recording(Mutex<Vec<Seen>>);

impl Handler<dto::CompleteMultipartUpload> for Recording {
    fn call(
        &self,
        request: Req<dto::CompleteMultipartUpload>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::CompleteMultipartUpload>> + Send {
        let input = request.into_input();
        let seen = (
            input.checksum_spec.as_ref().map(|spec| spec.render_base64().to_owned()),
            input.checksum_type.as_ref().map(|kind| format!("{kind:?}")),
        );
        self.0.lock().expect("an unpoisoned lock").push(seen);
        async { Ok(Resp::new(Default::default())) }
    }
}

const COMPLETION: &str = "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Part><PartNumber>1</PartNumber><ETag>\"5d41402abc4b2a76b9719d911017c592\"</ETag></Part></CompleteMultipartUpload>";
/// A well-formed full-object CRC-32: no `-N` suffix.
const CRC32: (&str, &str) = ("x-amz-checksum-crc32", "J8WdGg==");
const COMPOSITE: (&str, &str) = ("x-amz-checksum-type", "COMPOSITE");
const FULL_OBJECT: (&str, &str) = ("x-amz-checksum-type", "FULL_OBJECT");

fn service(configure: impl FnOnce(ServiceBuilder) -> ServiceBuilder) -> (S3Service, Arc<Recording>) {
    let backend = Arc::new(Recording(Mutex::new(Vec::new())));
    let service = configure(support::wired_at_signed_time())
        .register::<dto::CompleteMultipartUpload, _>(Arc::clone(&backend))
        .build()
        .expect("a complete assembly");
    (service, backend)
}

/// The RustFS profile's checksum switches.
fn legacy(builder: ServiceBuilder) -> ServiceBuilder {
    builder
        .read_checksums_as_legacy_rustfs()
        .answer_checksum_failures_with_bad_digest()
}

async fn complete(service: &S3Service, headers: &[(&str, &str)]) -> (u16, Option<String>) {
    let request = support::signed_target_with_body_and_headers(
        http::Method::POST,
        "/bucket/key?uploadId=upload-1",
        headers,
        Bytes::from_static(COMPLETION.as_bytes()),
    );
    let (status, body) = support::exchange(service, request).await;
    (status.as_u16(), support::element_text(&body, "Code").map(str::to_owned))
}

fn seen(backend: &Recording) -> Vec<Seen> {
    backend.0.lock().expect("an unpoisoned lock").clone()
}

/// Positive — under the switch the contradicting pair reaches the handler, which is handed the
/// value and the type exactly as sent and reconciles them itself.
#[tokio::test]
async fn under_the_switch_the_contradicting_pair_reaches_the_handler_as_sent() {
    let (service, backend) = service(legacy);
    assert_eq!(complete(&service, &[CRC32, COMPOSITE]).await, (200, None));
    assert_eq!(
        seen(&backend),
        vec![(Some("J8WdGg==".to_owned()), Some("ChecksumType(\"COMPOSITE\")".to_owned()))]
    );
}

/// Negative — off the switch the same pair is refused and no handler runs: `InvalidRequest` by
/// default, `BadDigest` with only the RustFS codes.
#[tokio::test]
async fn n_off_the_switch_the_contradicting_pair_reaches_no_handler() {
    let (service_default, default) = service(|builder| builder);
    let by_default = complete(&service_default, &[CRC32, COMPOSITE]).await;
    assert_eq!(by_default, (400, Some("InvalidRequest".to_owned())));
    let (service_codes, codes) = service(ServiceBuilder::answer_checksum_failures_with_bad_digest);
    assert_eq!(complete(&service_codes, &[CRC32, COMPOSITE]).await, (400, Some("BadDigest".to_owned())));
    assert!(seen(&default).is_empty() && seen(&codes).is_empty());
}

/// Negative — a value that cannot be read as the algorithm's is still refused before any handler
/// runs under the switch, with or without a type beside it.
#[tokio::test]
async fn n_under_the_switch_an_unreadable_value_reaches_no_handler() {
    let (service, backend) = service(legacy);
    for headers in [
        &[("x-amz-checksum-crc32", "!!")][..],
        &[("x-amz-checksum-crc32", "!!"), COMPOSITE][..],
    ] {
        assert_eq!(complete(&service, headers).await, (400, Some("BadDigest".to_owned())), "{headers:?}");
    }
    assert!(seen(&backend).is_empty());
}

/// Negative — two value headers of different algorithms are still refused under the switch.
#[tokio::test]
async fn n_under_the_switch_two_value_headers_reach_no_handler() {
    let (service, backend) = service(legacy);
    let both = [
        CRC32,
        ("x-amz-checksum-sha256", "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="),
    ];
    assert_eq!(complete(&service, &both).await.0, 400);
    assert!(seen(&backend).is_empty());
}

/// Positive — the agreeing spellings reach the handler under the switch and off it: a full-object
/// type, and no type.
#[tokio::test]
async fn the_agreeing_spellings_reach_the_handler_under_the_switch_and_off_it() {
    for configure in [legacy as fn(ServiceBuilder) -> ServiceBuilder, |builder| builder] {
        let (service, backend) = service(configure);
        assert_eq!(complete(&service, &[CRC32, FULL_OBJECT]).await, (200, None));
        assert_eq!(complete(&service, &[CRC32]).await, (200, None));
        assert_eq!(seen(&backend).len(), 2);
    }
}
