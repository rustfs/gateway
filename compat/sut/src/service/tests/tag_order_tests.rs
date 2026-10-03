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

//! An object's tag set answered in key order by the RustFS-profile launcher, as legacy RustFS
//! answers it (rustfs/gateway#1000, s3-tests `test_put_obj_with_tags`).
//!
//! Responsible for: proving the served assembly sorts — `x-amz-tagging: foo=bar&bar` reads back
//! `bar` then `foo`.
//! NOT responsible for: every write path and what the order leaves alone, which
//! `crates/fs/tests/crud/tag_order.rs` pins against the backend alone.
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, measured on a legacy RustFS build (rustfs/rustfs `528a36814`): the same
//! write reads back `[bar, foo]`.

use super::*;

/// Positive — the header's written order is not the answer's.
#[tokio::test]
async fn header_tags_are_answered_in_key_order() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/ordered", Bytes::new()))
            .await
            .status(),
        200
    );
    let tagged = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/ordered/key",
        Bytes::from_static(b"body"),
        &[("x-amz-tagging", "foo=bar&bar")],
    );
    let stored = exchange(&service, tagged).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));

    let read = exchange(&service, as_main(http::Method::GET, "/ordered/key?tagging", Bytes::new())).await;
    let body = body_of(&read);
    assert_eq!(read.status(), 200, "{body}");
    let bar = body.find("<Key>bar</Key>").expect("the bare key is listed");
    let foo = body.find("<Key>foo</Key>").expect("foo is listed");
    assert!(bar < foo, "{body}");
}
