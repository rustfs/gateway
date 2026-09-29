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
//! addressing rule each row pins: the slash rule (rustfs/gateway#1101) and the key floor
//! (rustfs/gateway#1107).
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
    let mut rows = slash_rule();
    rows.extend(key_floor());
    rows
}

/// Every key shape the legacy key floor pins, as the label after `/bkt/` and the key legacy RustFS
/// hands its storage for it: first the keys legacy RustFS stored and served (`PUT` 200 and `GET`
/// 200 on a legacy build), then the keys its storage refused after authorization.
#[cfg(test)]
pub(crate) const KEY_SHAPES: [(&str, &str); 23] = [
    ("a%01b", "a\u{1}b"),
    ("a%09b", "a\tb"),
    ("a%0Bb", "a\u{b}b"),
    ("a%1Fb", "a\u{1f}b"),
    ("a%7Fb", "a\u{7f}b"),
    ("a%C2%85b", "a\u{85}b"),
    ("a%252Fb", "a%2Fb"),
    ("a%255Cb", "a%5Cb"),
    ("a%252e%252e", "a%2e%2e"),
    ("%5Cx", "\\x"),
    ("%5C%5Cserver%5Cshare", "\\\\server\\share"),
    ("C:%5Cx", "C:\\x"),
    ("c:/x", "c:/x"),
    ("a%zzb", "a%zzb"),
    ("a%", "a%"),
    ("a/../b", "a/../b"),
    ("../b", "../b"),
    ("a/..", "a/.."),
    ("a/./b", "a/./b"),
    ("a%5C..%5Cb", "a\\..\\b"),
    ("a/%20../b", "a/ ../b"),
    ("a%0Ab", "a\nb"),
    ("a%0Db", "a\rb"),
];

/// One operation that names its key in the path: a name, the request for one target, and the
/// register ids its diff produces whatever the key is (`ListParts`' page-size default, and the
/// tagging operations, which the diff routes but does not project).
#[cfg(test)]
pub(crate) type KeyOperation = (&'static str, fn(&str) -> RawRequest, &'static [&'static str]);

/// Every operation that names its key in the path (see [`KeyOperation`]).
#[cfg(test)]
pub(crate) fn key_operations() -> [KeyOperation; 12] {
    [
        ("GetObject", |target| RawRequest::get(target), &[]),
        ("HeadObject", |target| RawRequest::head(target), &[]),
        ("PutObject", |target| RawRequest::put(target, b"body"), &[]),
        ("DeleteObject", |target| RawRequest::delete(target), &[]),
        (
            "CopyObject",
            |target| RawRequest::new(Method::PUT, target).header("x-amz-copy-source", "src/k"),
            &[],
        ),
        (
            "CreateMultipartUpload",
            |target| RawRequest::new(Method::POST, &format!("{target}?uploads")),
            &[],
        ),
        (
            "UploadPart",
            |target| RawRequest::put(&format!("{target}?partNumber=1&uploadId=u"), b"part"),
            &[],
        ),
        (
            "CompleteMultipartUpload",
            |target| RawRequest::post(&format!("{target}?uploadId=u"), COMPLETE_BODY),
            &[],
        ),
        ("AbortMultipartUpload", |target| RawRequest::delete(&format!("{target}?uploadId=u")), &[]),
        (
            "ListParts",
            |target| RawRequest::get(&format!("{target}?uploadId=u")),
            &["kd-decode-0010"],
        ),
        (
            "GetObjectTagging",
            |target| RawRequest::get(&format!("{target}?tagging")),
            &["kd-decode-0029"],
        ),
        (
            "PutObjectTagging",
            |target| RawRequest::put(&format!("{target}?tagging"), b"<Tagging><TagSet></TagSet></Tagging>"),
            &["kd-decode-0029"],
        ),
    ]
}

/// The legacy key floor: each key shape reaches the handler as the bytes legacy RustFS hands its
/// storage (rows for `GetObject`; `tests/rustfs_profile.rs` crosses every shape with every
/// operation), and the two keys an `ObjectKey` cannot represent are refused.
fn key_floor() -> Vec<RequestRow> {
    let at_limit = format!("/bkt/{}", "k".repeat(1024));
    let over_limit = format!("/bkt/{}", "k".repeat(1025));
    vec![
        row("rustfs-key-control-01", RawRequest::get("/bkt/a%01b"), &[]),
        row("rustfs-key-control-tab", RawRequest::get("/bkt/a%09b"), &[]),
        row("rustfs-key-control-del", RawRequest::get("/bkt/a%7Fb"), &[]),
        row("rustfs-key-control-c1", RawRequest::get("/bkt/a%C2%85b"), &[]),
        row("rustfs-key-control-lf", RawRequest::get("/bkt/a%0Ab"), &[]),
        row("rustfs-key-control-cr", RawRequest::get("/bkt/a%0Db"), &[]),
        row("rustfs-key-literal-slash-escape", RawRequest::get("/bkt/a%252Fb"), &[]),
        row("rustfs-key-literal-backslash-escape", RawRequest::get("/bkt/a%255Cb"), &[]),
        row("rustfs-key-literal-dotdot-escape", RawRequest::get("/bkt/a%252e%252e"), &[]),
        row("rustfs-key-invalid-escape", RawRequest::get("/bkt/a%zzb"), &[]),
        row("rustfs-key-backslash-rooted", RawRequest::get("/bkt/%5Cx"), &[]),
        row("rustfs-key-unc", RawRequest::get("/bkt/%5C%5Cserver%5Cshare"), &[]),
        row("rustfs-key-drive", RawRequest::get("/bkt/C:%5Cx"), &[]),
        row("rustfs-key-drive-slash", RawRequest::get("/bkt/c:/x"), &[]),
        row("rustfs-key-dotdot", RawRequest::get("/bkt/a/../b"), &[]),
        row("rustfs-key-dotdot-leading", RawRequest::get("/bkt/../b"), &[]),
        row("rustfs-key-dot", RawRequest::get("/bkt/a/./b"), &[]),
        row("rustfs-key-dotdot-backslash", RawRequest::get("/bkt/a%5C..%5Cb"), &[]),
        row("rustfs-key-at-limit", RawRequest::get(&at_limit), &[]),
        row("rustfs-key-over-limit", RawRequest::get(&over_limit), &["kd-decode-0082"]),
        row("rustfs-key-nul", RawRequest::get("/bkt/a%00b"), &["kd-decode-0081"]),
    ]
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
