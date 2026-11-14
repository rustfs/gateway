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

//! Current RustFS 304 object facts through the assembled service.
//! Responsible for: preserving the seven measured fields after final response preparation.
//! NOT responsible for: precondition evaluation or the strict ETag grammar.
//! Upstream: the legacy refusal adapter and service builder. Downstream: nothing.

use crate::support;
use rustfs_gateway::{
    ETag, ErrorCode, Handler, HandlerErrorContext, HandlerResult, LegacyRustfsFacts, LegacyRustfsRefusal, Req,
    dto::{GetObject, HeadObject},
};
use std::sync::Arc;

struct Stored;

fn refusal() -> rustfs_gateway::HandlerError {
    HandlerErrorContext::legacy_rustfs(
        LegacyRustfsRefusal::new(
            ErrorCode::NOT_MODIFIED,
            None,
            LegacyRustfsFacts {
                etag: Some(ETag::new("abc").expect("fixture ETag")),
                last_modified: Some(1794631776),
                cache_control: Some("max-age=7".into()),
                content_location: Some("/snapshot".into()),
                expires: Some("opaque stored expiry".into()),
                vary: Some("Origin, Accept-Encoding".into()),
                version_id: Some("7d28d1ef-53da-43de-a447-7f0cd0dc1cf3".into()),
                ..Default::default()
            },
        )
        .expect("valid stored 304 facts"),
    )
    .into()
}

impl Handler<GetObject> for Stored {
    async fn call(&self, _: Req<GetObject>) -> HandlerResult<GetObject> {
        Err(refusal())
    }
}
impl Handler<HeadObject> for Stored {
    async fn call(&self, _: Req<HeadObject>) -> HandlerResult<HeadObject> {
        Err(refusal())
    }
}

#[tokio::test]
async fn current_object_facts_survive_final_service_preparation() {
    let service = support::wired_at_signed_time()
        .answer_not_modified_with_legacy_rustfs_headers()
        .register::<GetObject, _>(Arc::new(Stored))
        .register::<HeadObject, _>(Arc::new(Stored))
        .build()
        .expect("complete fixture assembly");
    for method in [http::Method::GET, http::Method::HEAD] {
        for uri in ["/bucket/key", "/bucket/key?versionId=7d28d1ef-53da-43de-a447-7f0cd0dc1cf3"] {
            let response = support::exchange_wire(&service, support::signed_with(method.clone(), uri, &[])).await;
            assert_eq!(response.status(), http::StatusCode::NOT_MODIFIED);
            assert!(response.body().is_empty());
            let mut actual: Vec<_> = response
                .headers()
                .iter()
                .filter(|(name, _)| !matches!(name.as_str(), "date" | "server" | "x-amz-request-id" | "x-amz-id-2"))
                .map(|(name, value)| (name.as_str(), value.as_bytes()))
                .collect();
            actual.sort_unstable();
            assert_eq!(
                actual,
                vec![
                    ("cache-control", &b"max-age=7"[..]),
                    ("content-location", &b"/snapshot"[..]),
                    ("etag", &b"\"abc\""[..]),
                    ("expires", &b"opaque stored expiry"[..]),
                    ("last-modified", &b"Sat, 14 Nov 2026 04:49:36 GMT"[..]),
                    ("vary", &b"Origin, Accept-Encoding"[..]),
                    ("x-amz-version-id", &b"7d28d1ef-53da-43de-a447-7f0cd0dc1cf3"[..]),
                ]
            );
        }
    }
}
