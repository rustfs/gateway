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

//! A declared `aws-chunked` `Content-Encoding` over a plain body, stored by the RustFS-profile
//! launcher as legacy RustFS stores it (rustfs/gateway#1203, s3-tests
//! `test_object_content_encoding_aws_chunked`).
//!
//! Responsible for: proving the served assembly normalizes the stored value — `gzip, aws-chunked`
//! answers `gzip`, `aws-chunked` answers no header — where the gateway itself leaves an unframed
//! body's declared value alone.
//! NOT responsible for: every spelling and write path, which
//! `crates/fs/tests/crud/content_encoding.rs` pins against the backend alone.
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, measured on a legacy RustFS build (rustfs/rustfs `528a36814`): the same two
//! writes answer `Content-Encoding: gzip` and none.

use super::*;

fn content_encoding(response: &WireResponse) -> Option<String> {
    response.headers().iter().find_map(|(name, value)| {
        (name.as_str() == "content-encoding").then(|| value.to_str().expect("an ASCII header").to_owned())
    })
}

/// Positive — the declared token is dropped from the stored value, and a value holding nothing
/// else is not stored at all.
#[tokio::test]
async fn a_declared_aws_chunked_member_is_not_stored() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/encoded", Bytes::new()))
            .await
            .status(),
        200
    );
    for (key, declared, expected) in [("gzip", "gzip, aws-chunked", Some("gzip")), ("bare", "aws-chunked", None)] {
        let target = format!("/encoded/{key}");
        let request = signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            &target,
            Bytes::from_static(b"plain body"),
            &[("content-encoding", declared)],
        );
        let stored = exchange(&service, request).await;
        assert_eq!(stored.status(), 200, "{key}: {}", body_of(&stored));
        let head = exchange(&service, as_main(http::Method::HEAD, &target, Bytes::new())).await;
        assert_eq!(head.status(), 200, "{key}");
        assert_eq!(content_encoding(&head).as_deref(), expected, "{key}");
    }
}
