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

//! The RustFS-profile request matrix: requests whose bucket and key each stack must hand its
//! handler identically once the gateway fronts RustFS, and exactly which registered differences
//! each may still produce.
//!
//! Responsible for: the rows diffed under [`crate::Profile::Rustfs`] — the gateway's RustFS
//! profile against the legacy stack configured as RustFS main configures it — grouped by the
//! addressing rule each row pins: the slash rule (rustfs/gateway#1101) so far.
//! NOT responsible for: judging the rows (`tests/rustfs_profile.rs`), or the generic matrix
//! (`requests.rs`), whose rows compare both stacks' defaults.
//! Upstream: the library's request type. Downstream: tests.

use http::Method;

use super::RequestRow;
use crate::RawRequest;

fn row(name: &'static str, request: RawRequest, expect: &'static [&'static str]) -> RequestRow {
    RequestRow { name, request, expect }
}

const COMPLETE_BODY: &[u8] =
    b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"e1\"</ETag></Part></CompleteMultipartUpload>";

/// Every RustFS-profile row.
#[must_use]
pub(super) fn rows() -> Vec<RequestRow> {
    slash_rule()
}

/// The legacy slash rule: a key that starts with `/` reaches the handler folded, every other key
/// as sent, for every operation that names a key in its path. Legacy RustFS hands its storage
/// `key` for `/bkt//key` and `dir//key` for `/bkt/dir//key`; each row holds the gateway to that.
fn slash_rule() -> Vec<RequestRow> {
    let long_folded = format!("/bkt//{}", "k".repeat(1024));
    vec![
        row("rustfs-slash-get-rooted", RawRequest::get("/bkt//key"), &[]),
        row("rustfs-slash-get-rooted-run", RawRequest::get("/bkt///dir//key"), &[]),
        row("rustfs-slash-get-interior", RawRequest::get("/bkt/dir//key"), &[]),
        row("rustfs-slash-get-encoded-rooted", RawRequest::get("/bkt/%2F%2Fkey"), &[]),
        row("rustfs-slash-get-trailing-run", RawRequest::get("/bkt//dir//"), &[]),
        row("rustfs-slash-get-only-slashes", RawRequest::get("/bkt//"), &[]),
        row("rustfs-slash-get-folded-at-limit", RawRequest::get(&long_folded), &[]),
        row("rustfs-slash-put-rooted", RawRequest::put("/bkt//key", b"folded"), &[]),
        row("rustfs-slash-put-interior", RawRequest::put("/bkt/a//b", b"kept"), &[]),
        row("rustfs-slash-head-rooted", RawRequest::head("/bkt//key"), &[]),
        row("rustfs-slash-delete-rooted", RawRequest::delete("/bkt///key"), &[]),
        row(
            "rustfs-slash-copy-destination-rooted",
            RawRequest::new(Method::PUT, "/bkt//dst").header("x-amz-copy-source", "src/k"),
            &[],
        ),
        row("rustfs-slash-create-mpu-rooted", RawRequest::new(Method::POST, "/bkt//key?uploads"), &[]),
        row(
            "rustfs-slash-upload-part-rooted",
            RawRequest::put("/bkt//key?partNumber=1&uploadId=u", b"part"),
            &[],
        ),
        row(
            "rustfs-slash-complete-rooted",
            RawRequest::post("/bkt//key?uploadId=u", COMPLETE_BODY),
            &[],
        ),
        row("rustfs-slash-abort-rooted", RawRequest::delete("/bkt//key?uploadId=u"), &[]),
        row(
            "rustfs-slash-list-parts-rooted",
            RawRequest::get("/bkt//key?uploadId=u"),
            &["kd-decode-0010"],
        ),
        row("rustfs-slash-tagging-rooted", RawRequest::get("/bkt//key?tagging"), &["kd-decode-0029"]),
    ]
}
