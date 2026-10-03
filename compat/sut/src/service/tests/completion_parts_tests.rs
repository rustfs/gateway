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

//! A completion naming a part number twice, answered by the RustFS-profile launcher as legacy
//! RustFS answers it (rustfs/gateway#1002, s3-tests `test_multipart_resend_first_finishes_last`).
//!
//! Responsible for: proving the served assembly normalizes a completion's part list — part 1
//! uploaded twice and named twice, stale tag first, completes with its last upload.
//! NOT responsible for: the rest of the rule, which `crates/fs/tests/crud/completion_parts.rs` pins
//! against the backend alone.
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, measured on a legacy RustFS build (rustfs/rustfs `528a36814`): the same
//! completion is `200` and the object holds the second upload.

use super::*;

fn header_text(response: &WireResponse, name: &str) -> String {
    response
        .headers()
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == name).then(|| value.to_str().ok()).flatten())
        .expect("the header is answered")
        .to_owned()
}

/// Positive — the stale first entry is dropped unread, and the part's last upload is the object.
#[tokio::test]
async fn a_resent_part_named_twice_completes_with_its_last_upload() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/resent", Bytes::new()))
            .await
            .status(),
        200
    );
    let created = body_of(&exchange(&service, as_main(http::Method::POST, "/resent/key?uploads", Bytes::new())).await);
    let start = created.find("<UploadId>").expect("an upload id") + "<UploadId>".len();
    let end = created[start..].find("</UploadId>").expect("an upload id") + start;
    let upload = created[start..end].to_owned();
    let part = format!("/resent/key?partNumber=1&uploadId={upload}");
    let first = exchange(&service, as_main(http::Method::PUT, &part, Bytes::from_static(b"B-first"))).await;
    let second = exchange(&service, as_main(http::Method::PUT, &part, Bytes::from_static(b"A-second"))).await;
    let (stale, current) = (header_text(&first, "etag"), header_text(&second, "etag"));

    let document = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{stale}</ETag></Part><Part><PartNumber>1</PartNumber><ETag>{current}</ETag></Part></CompleteMultipartUpload>"
    );
    let completed = exchange(
        &service,
        as_main(http::Method::POST, &format!("/resent/key?uploadId={upload}"), Bytes::from(document)),
    )
    .await;
    assert_eq!(completed.status(), 200, "{}", body_of(&completed));
    let read = exchange(&service, as_main(http::Method::GET, "/resent/key", Bytes::new())).await;
    assert_eq!(read.body().as_ref(), b"A-second");
}
