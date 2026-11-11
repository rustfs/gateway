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

//! When the STS body digest counts as a signed body (rustfs/gateway#1587).
//!
//! Responsible for: `Authentication::signs_its_body` after a rejected STS-digest comparison, and
//! after a successful plain comparison that followed one, so a fallback cannot inherit it.
//! NOT responsible for: the positive path through an assembled service, which
//! `crates/gateway/tests/dialect_claims_signed_body.rs` pins.
//! Upstream: `super`. Downstream: Cargo's test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http::{HeaderMap, HeaderValue, Method};
use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_http::RawHost;
use rustfs_gateway_sig::{Admission, OperationFloor, PayloadMode, RawQuery, RequestNow, SecurityFloor, SigService, WireView};
use sha2::{Digest as _, Sha256};

use super::super::{Authentication, Authenticator, RegionSet, SigV4Authenticator};
use crate::ext::credentials::{Credentials, StaticCredentials};
use crate::gate::{BodyTimeouts, StsBodyReader};
use crate::render::S3Error;

/// 2015-08-30T12:36:00Z, the instant the head is dated at.
const NOW: i64 = 1_440_938_160;
const STAMP: &str = "20150830T123600Z";

/// A body reader that answers the digest of a fixed body and counts how often it was asked.
struct Body(AtomicUsize);

impl StsBodyReader for Body {
    fn digest(&self, _timeouts: BodyTimeouts) -> BoxFuture<'_, Result<[u8; 32], S3Error>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(Sha256::digest(b"Action=AssumeRole").into()) })
    }
}

fn legacy(secret: &[u8]) -> SigV4Authenticator {
    SigV4Authenticator::new(
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", secret).expect("valid"))),
        RegionSet::new(["us-east-1"]).expect("non-empty"),
    )
    .accept_legacy_rustfs_signing_services()
}

/// An `sts`-scoped header credential with no payload header and a signature that matches nothing.
fn head() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("s3.example.com"));
    headers.insert("x-amz-date", HeaderValue::from_static(STAMP));
    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/sts/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature={}",
            "0".repeat(64)
        ))
        .expect("a header value"),
    );
    headers
}

/// Negative — a comparison that digested the STS body and was rejected leaves the body unsigned,
/// though the digest was computed; so does the same rejection asked a second time.
#[tokio::test]
async fn n_a_rejected_sts_digest_comparison_signs_no_body() {
    let headers = head();
    let floor = OperationFloor::builtin("acme:Form", SigService::Sts);
    let admitted = SecurityFloor::new()
        .admit(WireView::new(&headers, RawQuery::new("")), &floor, RequestNow::from_unix_seconds(NOW))
        .expect("a well-formed header credential is admitted");
    let Admission::Sealed(sealed) = admitted else { panic!("an AWS header credential is sealed") };
    let host = RawHost::from_host_header(b"s3.example.com").expect("valid host");
    let payload = PayloadMode::Empty;
    let body = Body(AtomicUsize::new(0));
    let request = Authentication::new(&sealed, &Method::PUT, "/example/admin/v1/form", &host, &payload, Some(17))
        .with_sts_body_reader(Some(&body), BodyTimeouts::S3);
    for attempt in 0..2 {
        let outcome = legacy(b"secret").authenticate(&request).await.expect("an answer");
        assert!(
            !outcome.verdict().is_authenticated(),
            "attempt {attempt}: the forged signature is refused"
        );
        assert!(!request.signs_its_body(), "attempt {attempt}: a refused comparison signs no body");
    }
    assert_eq!(body.0.load(Ordering::SeqCst), 2, "the STS body digest was computed each time");
}
