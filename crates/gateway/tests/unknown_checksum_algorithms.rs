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

//! A checksum header naming an unknown algorithm, through a whole service: refused by default,
//! ignored under `ServiceBuilder::ignore_unknown_checksum_algorithms` (rustfs/backlog#1677).
//!
//! Responsible for: the default assembly refusing an `x-amz-checksum-<name>` no algorithm answers
//! to, and an `x-amz-sdk-checksum-algorithm` naming none, before any handler runs; the switch
//! handing both to the handler; an ignored header standing in for no required integrity check;
//! and, under the switch, a known checksum or `Content-MD5` beside the unknown header that does not
//! match the body still reaching no handler.
//! NOT responsible for: the arbitration itself (`rustfs-gateway-http`'s
//! `tests/checksum_unknown_algorithms.rs`) or what a RustFS backend stores (`compat/sut`).
//! Upstream: `S3Service` with a counting buffered-body backend. Downstream: none.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use rustfs_gateway::{Handler, HandlerResult, Req, Resp, S3Service, ServiceBuilder, dto};

use crate::support;

/// Counts the requests that reached a handler, so "no handler ran" is a measurement.
struct Counting(Arc<AtomicUsize>);

impl Handler<dto::PutObjectTagging> for Counting {
    fn call(
        &self,
        _request: Req<dto::PutObjectTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObjectTagging>> + Send {
        self.0.fetch_add(1, Ordering::SeqCst);
        async { Ok(Resp::new(Default::default())) }
    }
}

const TAGGING: &str = "<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>";
/// The base64 CRC32 of `wrong`, which is not the CRC32 of [`TAGGING`].
const WRONG_CRC32: &str = "J8WdGg==";
/// The base64 MD5 of `wrong`, which is not the MD5 of [`TAGGING`].
const WRONG_MD5: &str = "K9opmNmw7hl9oUKgRH9nJQ==";

/// The two forms of an unknown algorithm.
const UNKNOWN: [(&str, &str); 2] = [
    ("x-amz-checksum-blake3", "DUoRhQ=="),
    ("x-amz-sdk-checksum-algorithm", "BLAKE3"),
];

fn service(configure: impl FnOnce(ServiceBuilder) -> ServiceBuilder) -> (S3Service, Arc<AtomicUsize>) {
    let reached = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Counting(Arc::clone(&reached)));
    let service = configure(support::wired_at_signed_time())
        .register::<dto::PutObjectTagging, _>(backend)
        .build()
        .expect("a complete assembly");
    (service, reached)
}

async fn tag(service: &S3Service, headers: &[(&str, &str)]) -> (u16, Option<String>) {
    let request = support::signed_target_with_body_and_headers(
        http::Method::PUT,
        "/bucket/key?tagging",
        headers,
        Bytes::from_static(TAGGING.as_bytes()),
    );
    let (status, body) = support::exchange(service, request).await;
    (status.as_u16(), support::element_text(&body, "Code").map(str::to_owned))
}

/// Negative — by default both forms are `400 InvalidRequest`, and no handler runs.
#[tokio::test]
async fn n_by_default_an_unknown_checksum_algorithm_reaches_no_handler() {
    let (service, reached) = service(|builder| builder);
    for pair in UNKNOWN {
        assert_eq!(tag(&service, &[pair]).await, (400, Some("InvalidRequest".to_owned())), "{pair:?}");
    }
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// The RustFS profile's pair: unknown algorithms ignored, and no write required to carry a check.
fn rustfs_profile(builder: ServiceBuilder) -> ServiceBuilder {
    builder.ignore_unknown_checksum_algorithms().accept_all_checksum_omissions()
}

/// Positive — under the switch, with the profile's omission waiver, both forms reach the handler.
#[tokio::test]
async fn under_the_switch_an_unknown_checksum_algorithm_reaches_the_handler() {
    let (service, reached) = service(rustfs_profile);
    for pair in UNKNOWN {
        assert_eq!(tag(&service, &[pair]).await, (200, None), "{pair:?}");
    }
    assert_eq!(reached.load(Ordering::SeqCst), UNKNOWN.len());
}

/// Negative — an ignored header claims nothing: under the switch alone, a write that must carry an
/// integrity check and carries only an unknown algorithm is refused as carrying none.
#[tokio::test]
async fn n_under_the_switch_an_ignored_header_is_no_integrity_check() {
    let (service, reached) = service(ServiceBuilder::ignore_unknown_checksum_algorithms);
    for pair in UNKNOWN {
        assert_eq!(tag(&service, &[pair]).await, (400, Some("InvalidRequest".to_owned())), "{pair:?}");
    }
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Negative — under the switch a known checksum or a `Content-MD5` beside the unknown header is
/// still compared: one that does not match the body reaches no handler.
#[tokio::test]
async fn n_under_the_switch_a_mismatched_claim_beside_it_reaches_no_handler() {
    let (service, reached) = service(rustfs_profile);
    for pair in UNKNOWN {
        let crc = tag(&service, &[pair, ("x-amz-checksum-crc32", WRONG_CRC32)]).await;
        assert_eq!(crc, (400, Some("XAmzContentChecksumMismatch".to_owned())), "{pair:?}");
        let md5 = tag(&service, &[pair, ("content-md5", WRONG_MD5)]).await;
        assert_eq!(md5, (400, Some("BadDigest".to_owned())), "{pair:?}");
    }
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}
