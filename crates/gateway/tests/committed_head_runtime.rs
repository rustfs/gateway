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

//! The runtime boundary between a frozen committed head and its terminal encoded output.
//!
//! Responsible for: proving an operation header is available before work completes and that a
//! terminal encoder cannot add or change one after commitment. NOT responsible for: header-name
//! admission, keep-alive timing, or socket ownership.
//! Upstream: generated `CopyObject` codec and `S3Service`. Downstream: no production code.

use std::sync::Arc;

use http::{HeaderMap, HeaderValue};
use rustfs_gateway::{
    ErrorCode, Handler, HandlerResult, HeadPart, Req, Resp, S3Service,
    dto::{CopyObject, CopyObjectOutput},
};
use tokio::sync::Notify;

use crate::support;

const VERSION_HEADER: &str = "x-amz-version-id";

struct FrozenHeadBackend {
    head_version: Option<&'static str>,
    output_version: Option<&'static str>,
    release: Arc<Notify>,
}

impl Handler<CopyObject> for FrozenHeadBackend {
    async fn call(&self, _request: Req<CopyObject>) -> HandlerResult<CopyObject> {
        let mut headers = HeaderMap::new();
        if let Some(version) = self.head_version {
            headers.insert(VERSION_HEADER, HeaderValue::from_static(version));
        }
        let head = HeadPart::new(headers).expect("a generated CopyObject response header");
        let output_version = self.output_version.map(str::to_owned);
        let release = Arc::clone(&self.release);
        Ok(Resp::commit(
            head,
            Box::pin(async move {
                release.notified().await;
                Ok(CopyObjectOutput {
                    version_id: output_version,
                    ..CopyObjectOutput::default()
                })
            }),
        ))
    }
}

fn service(head_version: Option<&'static str>, output_version: Option<&'static str>) -> (S3Service, Arc<Notify>) {
    let release = Arc::new(Notify::new());
    let backend = Arc::new(FrozenHeadBackend {
        head_version,
        output_version,
        release: Arc::clone(&release),
    });
    let service = support::wired_at_signed_time()
        .register::<CopyObject, _>(backend)
        .build()
        .expect("a complete assembly");
    (service, release)
}

/// Positive — an operation header leaves with the head while the terminal output is still blocked.
#[tokio::test]
async fn a_frozen_operation_header_is_visible_before_committed_work_finishes() {
    let (service, release) = service(Some("version-one"), Some("version-one"));
    let response = service.call_bytes(support::copy_commit_request()).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get(VERSION_HEADER), Some(&HeaderValue::from_static("version-one")));

    release.notify_one();
    let collected = rustfs_gateway::collect(response).await.expect("the committed body collects");
    let body = String::from_utf8(collected.body().to_vec()).expect("UTF-8 XML");
    assert!(body.contains("<CopyObjectResult"), "{body}");
    assert!(!body.contains("<Error>"), "{body}");
}

/// Negative — an operation header that appears only in the terminal output is a committed error.
#[tokio::test]
async fn a_terminal_output_cannot_add_a_header_missing_from_the_frozen_head() {
    let (service, release) = service(None, Some("version-one"));
    let response = service.call_bytes(support::copy_commit_request()).await;
    assert!(!response.headers().contains_key(VERSION_HEADER));

    release.notify_one();
    let collected = rustfs_gateway::collect(response).await.expect("the committed error collects");
    let body = String::from_utf8(collected.body().to_vec()).expect("UTF-8 XML");
    assert!(body.contains(&format!("<Code>{}</Code>", ErrorCode::INTERNAL_ERROR.as_str())), "{body}");
    assert!(!body.contains("<CopyObjectResult"), "{body}");
}

/// Negative — a terminal output cannot replace a value the client already received.
#[tokio::test]
async fn a_terminal_output_cannot_change_a_frozen_header() {
    let (service, release) = service(Some("version-one"), Some("version-two"));
    let response = service.call_bytes(support::copy_commit_request()).await;
    assert_eq!(response.headers().get(VERSION_HEADER), Some(&HeaderValue::from_static("version-one")));

    release.notify_one();
    let collected = rustfs_gateway::collect(response).await.expect("the committed error collects");
    assert_eq!(
        collected
            .headers()
            .iter()
            .find(|(name, _)| name == VERSION_HEADER)
            .map(|(_, value)| value),
        Some(&HeaderValue::from_static("version-one"))
    );
    let body = String::from_utf8(collected.body().to_vec()).expect("UTF-8 XML");
    assert!(body.contains(&format!("<Code>{}</Code>", ErrorCode::INTERNAL_ERROR.as_str())), "{body}");
    assert!(!body.contains("version-two"), "{body}");
}
