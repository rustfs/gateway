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
//! addressing rule each row pins: the slash rule (rustfs/gateway#1101), the key floor
//! (rustfs/gateway#1107) and the path addressing (rustfs/gateway#1115).
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
    rows.extend(addressing());
    rows.extend(selection());
    rows
}

/// Legacy RustFS's operation selection: an `x-id` named once is the operation, and two operation
/// keys select the first in legacy RustFS's order. Only operations both stacks register here; an
/// `x-id` refused with a body is pinned by the core and gateway cases, since the legacy stack names
/// the declared operation back in its sentence (rd-err-0009).
fn selection() -> Vec<RequestRow> {
    vec![
        row("rustfs-select-location-over-versioning", RawRequest::get("/bkt?versioning&location"), &[]),
        row(
            "rustfs-select-versions-over-v2",
            RawRequest::get("/bkt?list-type=2&versions"),
            &["kd-decode-0008"],
        ),
        row(
            "rustfs-select-uploads-over-versions",
            RawRequest::get("/bkt?versions&uploads"),
            &["kd-decode-0009"],
        ),
        row(
            "rustfs-select-x-id-over-a-key",
            RawRequest::get("/bkt?location&x-id=GetBucketVersioning"),
            &[],
        ),
        row(
            "rustfs-select-x-id-v2",
            RawRequest::get("/bkt?x-id=ListObjectsV2"),
            &["kd-decode-0006", "kd-decode-0007"],
        ),
        row(
            "rustfs-select-x-id-uploads",
            RawRequest::get("/bkt?x-id=ListMultipartUploads"),
            &["kd-decode-0009"],
        ),
        row(
            "rustfs-select-x-id-get-over-upload-id",
            RawRequest::get("/bkt/src?uploadId=u&x-id=GetObject"),
            &[],
        ),
        row(
            "rustfs-select-x-id-put-over-a-part",
            RawRequest::put("/bkt/src?partNumber=1&uploadId=u&x-id=PutObject", b"part"),
            &[],
        ),
        row(
            "rustfs-select-x-id-delete-over-upload-id",
            RawRequest::delete("/bkt/src?uploadId=u&x-id=DeleteObject"),
            &[],
        ),
        row(
            "rustfs-select-uploads-over-upload-id",
            RawRequest::post("/bkt/src?uploadId=u&uploads", b""),
            &[],
        ),
        row("rustfs-select-x-id-head", RawRequest::head("/bkt?x-id=ListBuckets"), &[]),
    ]
}

/// Legacy RustFS's path addressing: the path decoded as a whole and split at its first decoded
/// `/`, the bucket held to legacy RustFS's rules, and every refusal made before routing.
fn addressing() -> Vec<RequestRow> {
    vec![
        row("rustfs-addr-escaped-separator-get", RawRequest::get("/bkt%2Fsrc"), &[]),
        row("rustfs-addr-escaped-separator-head", RawRequest::head("/bkt%2Fsrc"), &[]),
        row("rustfs-addr-escaped-separator-put", RawRequest::put("/bkt%2Fsrc", b"escaped"), &[]),
        row("rustfs-addr-escaped-separator-delete", RawRequest::delete("/bkt%2Fsrc"), &[]),
        row("rustfs-addr-escaped-separator-list", RawRequest::get("/bkt%2F"), &["kd-decode-0005"]),
        row("rustfs-addr-escaped-separator-folded", RawRequest::get("/bkt%2F%2Fsrc"), &[]),
        row("rustfs-addr-escaped-label", RawRequest::get("/b%6Bt/src"), &[]),
        row("rustfs-addr-reserved-prefix", RawRequest::get("/sthree-x/k"), &[]),
        row("rustfs-addr-reserved-alias-suffix", RawRequest::get("/abc-s3alias/k"), &[]),
        row("rustfs-addr-reserved-express-suffix", RawRequest::get("/abc--x-s3/k"), &[]),
        row("rustfs-addr-reserved-olap-suffix", RawRequest::get("/abc--ol-s3/k"), &[]),
        row("rustfs-addr-leading-zero-quad", RawRequest::get("/01.2.3.4/k"), &[]),
        row("rustfs-addr-address", RawRequest::get("/1.2.3.4/k"), &["kd-decode-0024"]),
        row("rustfs-addr-punycode", RawRequest::get("/xn--abc/k"), &["kd-decode-0024"]),
        row("rustfs-addr-bad-bucket", RawRequest::get("/Bad_Bucket/k"), &["kd-decode-0024"]),
        row(
            "rustfs-addr-bad-bucket-unrouted",
            RawRequest::new(Method::PATCH, "/Bad_Bucket/k"),
            &["kd-decode-0024"],
        ),
        row("rustfs-addr-empty-bucket", RawRequest::get("//bkt"), &["kd-decode-0024"]),
        row("rustfs-addr-empty-bucket-object", RawRequest::get("//bkt/src"), &["kd-decode-0024"]),
        row("rustfs-addr-empty-bucket-run", RawRequest::get("///"), &["kd-decode-0024"]),
        row("rustfs-addr-empty-bucket-escaped", RawRequest::get("/%2Fbkt/src"), &["kd-decode-0024"]),
        row("rustfs-addr-undecodable-key", RawRequest::get("/bkt/a%FFb"), &[]),
        row("rustfs-addr-undecodable-before-bucket", RawRequest::get("/Bad_Bucket/a%FFb"), &[]),
        row(
            "rustfs-addr-copy-source-reserved-bucket",
            RawRequest::put("/bkt/dst", b"").header("x-amz-copy-source", "sthree-x/src"),
            &[],
        ),
        row(
            "rustfs-addr-copy-source-question-mark",
            RawRequest::put("/bkt/dst", b"").header("x-amz-copy-source", "bkt/src?partNumber=1"),
            &[],
        ),
        row(
            "rustfs-addr-copy-source-version-after-question-mark",
            RawRequest::put("/bkt/dst", b"").header("x-amz-copy-source", "bkt/a?b?versionId=v1"),
            &[],
        ),
    ]
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
