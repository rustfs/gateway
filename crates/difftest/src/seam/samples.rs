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

//! The seam decode diff's rows and its register.
//!
//! Responsible for: the raw requests the seam diff sends ([`seam_rows`]), each with what it must
//! show; [`SEAM_FINDINGS`], every difference between what the two stacks hand the RustFS app
//! layer, classified; and [`UNREACHED_PATHS`], every legacy input member no row can make both
//! stacks hand over, with the reason.
//! NOT responsible for: sending (`mod.rs`) or judging (`tests/seam.rs`).
//! Upstream: none. Downstream: `tests/seam.rs`.

use http::Method;

use crate::request::RawRequest;

mod configs;
mod findings;
mod objects;
mod reads;

/// What a finding means for what RustFS does and stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SeamClass {
    /// A divergence already ruled in the request-divergence register, by id.
    Ruled(&'static str),
    /// The gateway fills the model's default where the legacy decoder leaves the member unset, and
    /// every RustFS read of the member substitutes that same default.
    Synthesized,
    /// The same information in another shape (one joined list element on one side, several on the
    /// other), and every RustFS read normalises both to the same answer.
    Reshaped,
    /// The same information in another spelling, which RustFS normalises to the same stored value.
    Normalized,
    /// A member only the legacy decoder reads, which RustFS never reads.
    DroppedUnread,
    /// A member only the legacy decoder reads; RustFS reads the raw header instead, and the request
    /// context hands every header line over unchanged.
    DroppedCarriedByHeaders,
    /// A member only the legacy decoder reads, which RustFS reads: a lossy spot. The evidence names
    /// the RustFS read and the issue that owns the fix.
    DroppedRead,
    /// Both stacks hand the member over, with values RustFS stores or acts on differently: a lossy
    /// spot. The evidence names the RustFS read and the issue that owns the fix.
    Lossy,
    /// A value the legacy decoder refuses and the gateway hands over, where RustFS then acts on the
    /// raw header: a lossy spot. The evidence names the RustFS read and the issue that owns the fix.
    LegacyStricter,
    /// A member the gateway decodes and no legacy input holds; the seam refuses it by name instead
    /// of dropping it.
    FailClosed,
}

/// One classified difference between what the two stacks hand the RustFS app layer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SeamFinding {
    /// `sd-<nnnn>`.
    pub(crate) id: &'static str,
    /// The operation.
    pub(crate) operation: &'static str,
    /// The legacy input member path the census names (list indices dropped), or for
    /// [`SeamClass::FailClosed`] the member the conversion refuses, or for
    /// [`SeamClass::LegacyStricter`] the header the legacy decoder refuses.
    pub(crate) path: &'static str,
    /// What it means.
    pub(crate) class: SeamClass,
    /// RustFS main `file:line` evidence (rustfs/rustfs `1e7065101d`), and the owning issue when
    /// the class needs one.
    pub(crate) evidence: &'static str,
}

const fn finding(
    id: &'static str,
    operation: &'static str,
    path: &'static str,
    class: SeamClass,
    evidence: &'static str,
) -> SeamFinding {
    SeamFinding {
        id,
        operation,
        path,
        class,
        evidence,
    }
}

/// Every classified difference.
pub(crate) const SEAM_FINDINGS: &[SeamFinding] = &[
    finding(
        "sd-0001",
        "PutObject",
        "checksum_algorithm",
        SeamClass::Ruled("rd-put-0002"),
        "RustFS reads it only to pick a trailer checksum to echo (rustfs/src/app/object/put.rs:1374-1378), and the seam refuses \
         declared trailers",
    ),
    finding(
        "sd-0002",
        "PutObject",
        "version_id",
        SeamClass::Ruled("rd-put-0007"),
        "the RustFS profile routes ?versionId= to the replication dialect's replica write, which carries it",
    ),
    finding(
        "sd-0003",
        "CopyObject",
        "version_id",
        SeamClass::DroppedRead,
        "MinIO ?versionId= names the new version (rustfs/src/app/object/copy.rs:176, :325-333; storage/options.rs:385-410); \
         owner rustfs/gateway#1076",
    ),
    finding(
        "sd-0004",
        "CreateMultipartUpload",
        "version_id",
        SeamClass::DroppedRead,
        "MinIO ?versionId= names the version the upload completes into (rustfs/src/app/multipart_usecase.rs:961, :1106); \
         owner rustfs/gateway#1076",
    ),
    finding(
        "sd-0005",
        "DeleteBucket",
        "force_delete",
        SeamClass::DroppedCarriedByHeaders,
        "RustFS reads x-rustfs-force-delete then x-minio-force-delete from the request headers \
         (rustfs/src/app/bucket_usecase.rs:1457; crates/utils/src/http/header_compat.rs:139-154)",
    ),
    finding(
        "sd-0006",
        "DeleteBucket",
        "x-minio-force-delete",
        SeamClass::LegacyStricter,
        "the legacy decoder admits only true/True/false/False and one line; RustFS's own parse also takes 1, t, TRUE, on, \
         enabled (crates/utils/src/string.rs:42-47) and force-deletes a non-empty bucket (rustfs/src/app/bucket_usecase.rs:1457-1480); \
         owner rustfs/gateway#1076",
    ),
    finding(
        "sd-0007",
        "CopyObject",
        "annotation_directive",
        SeamClass::DroppedUnread,
        "no RustFS read: the copy body destructures its input without it (rustfs/src/app/object/copy.rs:185-205)",
    ),
    finding(
        "sd-0008",
        "DeleteObjects",
        "delete.objects[].e_tag",
        SeamClass::DroppedUnread,
        "RustFS reads only key and version_id of each identifier (rustfs/src/app/object/delete.rs:511-530)",
    ),
    finding(
        "sd-0009",
        "DeleteObjects",
        "delete.objects[].last_modified_time",
        SeamClass::DroppedUnread,
        "RustFS reads only key and version_id of each identifier (rustfs/src/app/object/delete.rs:511-530)",
    ),
    finding(
        "sd-0010",
        "DeleteObjects",
        "delete.objects[].size",
        SeamClass::DroppedUnread,
        "RustFS reads only key and version_id of each identifier (rustfs/src/app/object/delete.rs:511-530)",
    ),
    finding(
        "sd-0011",
        "CreateBucket",
        "bucket_namespace",
        SeamClass::DroppedUnread,
        "RustFS reads only the bucket name and the object-lock flag (rustfs/src/app/bucket_usecase.rs:1380-1385)",
    ),
    finding(
        "sd-0012",
        "CreateBucket",
        "create_bucket_configuration.bucket",
        SeamClass::DroppedUnread,
        "RustFS reads only the bucket name and the object-lock flag (rustfs/src/app/bucket_usecase.rs:1380-1385)",
    ),
    finding(
        "sd-0013",
        "CreateBucket",
        "create_bucket_configuration.location",
        SeamClass::DroppedUnread,
        "RustFS reads only the bucket name and the object-lock flag (rustfs/src/app/bucket_usecase.rs:1380-1385)",
    ),
    finding(
        "sd-0014",
        "CreateBucket",
        "create_bucket_configuration.tags",
        SeamClass::DroppedUnread,
        "RustFS reads only the bucket name and the object-lock flag (rustfs/src/app/bucket_usecase.rs:1380-1385)",
    ),
    finding(
        "sd-0015",
        "GetObjectAttributes",
        "object_attributes",
        SeamClass::Reshaped,
        "RustFS splits every element on ',' and compares case-insensitively (rustfs/src/app/object/get.rs:4490-4497)",
    ),
    finding("sd-0016", "PutObject", "object_lock_event_hold", SeamClass::FailClosed, EVENT_HOLD),
    finding(
        "sd-0017",
        "PutObject",
        "object_lock_event_hold_duration_days",
        SeamClass::FailClosed,
        EVENT_HOLD,
    ),
    finding(
        "sd-0018",
        "PutObject",
        "object_lock_event_hold_duration_years",
        SeamClass::FailClosed,
        EVENT_HOLD,
    ),
    finding("sd-0019", "CopyObject", "object_lock_event_hold", SeamClass::FailClosed, EVENT_HOLD),
    finding(
        "sd-0020",
        "CopyObject",
        "object_lock_event_hold_duration_days",
        SeamClass::FailClosed,
        EVENT_HOLD,
    ),
    finding(
        "sd-0021",
        "CopyObject",
        "object_lock_event_hold_duration_years",
        SeamClass::FailClosed,
        EVENT_HOLD,
    ),
    finding(
        "sd-0022",
        "CreateMultipartUpload",
        "object_lock_event_hold",
        SeamClass::FailClosed,
        EVENT_HOLD,
    ),
    finding(
        "sd-0023",
        "CreateMultipartUpload",
        "object_lock_event_hold_duration_days",
        SeamClass::FailClosed,
        EVENT_HOLD,
    ),
    finding(
        "sd-0024",
        "CreateMultipartUpload",
        "object_lock_event_hold_duration_years",
        SeamClass::FailClosed,
        EVENT_HOLD,
    ),
    finding(
        "sd-0025",
        "ListObjects",
        "max_keys",
        SeamClass::Synthesized,
        "the model default 1000; RustFS maps V1 onto V2 unchanged and reads max_keys.unwrap_or(S3_MAX_KEYS = 1000) \
         (rustfs/src/storage/s3_api/bucket.rs:33, :161; rustfs/src/app/bucket_usecase.rs:3114)",
    ),
    finding(
        "sd-0026",
        "ListObjectsV2",
        "max_keys",
        SeamClass::Synthesized,
        "the model default 1000; RustFS reads max_keys.unwrap_or(S3_MAX_KEYS = 1000) (rustfs/src/storage/s3_api/bucket.rs:33, :161)",
    ),
    finding(
        "sd-0027",
        "ListObjectsV2",
        "fetch_owner",
        SeamClass::Synthesized,
        "the model default false; RustFS reads fetch_owner.unwrap_or_default() (rustfs/src/app/bucket_usecase.rs:2884, :2898, :2910)",
    ),
    finding(
        "sd-0028",
        "ListObjectVersions",
        "max_keys",
        SeamClass::Synthesized,
        "the model default 1000; RustFS reads max_keys.unwrap_or(S3_MAX_KEYS = 1000) (rustfs/src/storage/s3_api/bucket.rs:33, :132)",
    ),
    finding(
        "sd-0029",
        "ListMultipartUploads",
        "max_uploads",
        SeamClass::Synthesized,
        "the model default 1000; RustFS substitutes MAX_MULTIPART_UPLOADS_LIST = 1000 for none (rustfs/src/storage/s3_api/multipart.rs:24, :138-150)",
    ),
    finding(
        "sd-0030",
        "ListParts",
        "max_parts",
        SeamClass::Synthesized,
        "the model default 1000; RustFS substitutes 1000 for none (rustfs/src/storage/s3_api/multipart.rs:102-113)",
    ),
    finding(
        "sd-0031",
        "ListBuckets",
        "max_buckets",
        SeamClass::Synthesized,
        "the model default 10000; RustFS never reads the ListBuckets input (rustfs/src/storage/ecfs.rs:1264-1268; \
         rustfs/src/app/bucket_usecase.rs:1564-1597)",
    ),
    finding(
        "sd-0032",
        "PutObject",
        "content_type",
        SeamClass::Lossy,
        "an empty Content-Type is absent to the legacy decoder (kd-decode-0074) and an empty value through the seam; RustFS \
         stores the input value and skips the raw header (rustfs/src/app/object/put.rs:840-874; storage/options.rs:807-850), \
         so it would store an empty content type where legacy stores the one detected from the key; owner rustfs/gateway#1076",
    ),
    finding(
        "sd-0033",
        "PutObject",
        "content_encoding",
        SeamClass::Normalized,
        "the gateway strips aws-chunked (kd-decode-0075); RustFS strips it too and re-applies the raw header after the input \
         (rustfs/src/storage/options.rs:668-681, :830-839), so both store the same value",
    ),
    finding(
        "sd-0034",
        "UploadPart",
        "checksum_algorithm",
        SeamClass::Ruled("rd-put-0002"),
        "RustFS reads it only to pick a trailer checksum to echo (rustfs/src/app/multipart_usecase.rs:1449-1470), and the \
         seam refuses declared trailers",
    ),
    finding(
        "sd-0035",
        "DeleteObjects",
        "checksum_algorithm",
        SeamClass::Ruled("rd-put-0002"),
        "no RustFS read (rustfs/src/app/object/delete.rs:455-470 takes the bucket and the delete list)",
    ),
    finding(
        "sd-0036",
        "PutBucketVersioning",
        "checksum_algorithm",
        SeamClass::Ruled("rd-put-0002"),
        "no RustFS read of the member in the bucket use case (rustfs/src/app/bucket_usecase.rs)",
    ),
];

const EVENT_HOLD: &str = "no legacy input holds an Object Lock event hold and RustFS stores none (rd-put-0009)";

/// Legacy input members no row makes both stacks hand over, with the reason: (operation, path,
/// reason). A path under a listed one is covered by it.
pub(crate) const UNREACHED_PATHS: &[(&str, &str, &str)] = &[];

/// What one row must show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Expect {
    /// Both stacks hand the app layer the same input and body.
    Identical,
    /// Both handlers are reached and the inputs differ at exactly the paths these findings name.
    Differs(&'static [&'static str]),
    /// The gateway handler is reached and the seam refuses the member this finding names, where
    /// the legacy stack hands the value over.
    FailsClosed(&'static str),
    /// The legacy decoder refuses what the gateway hands over, as this finding says.
    LegacyRefuses(&'static str),
}

/// One raw request and what it must show.
#[derive(Clone, Debug)]
pub(crate) struct SeamRow {
    /// A unique name.
    pub(crate) name: &'static str,
    /// The request.
    pub(crate) request: RawRequest,
    /// What it must show.
    pub(crate) expect: Expect,
}

pub(super) fn row(name: &'static str, request: RawRequest, expect: Expect) -> SeamRow {
    SeamRow { name, request, expect }
}

/// The base64 MD5 of `body`, as `Content-MD5` spells it.
pub(super) fn content_md5(body: &[u8]) -> String {
    checksum_value(rustfs_gateway_types::ChecksumAlgorithm::Md5, body)
}

/// The base64 digest of `body` under `algorithm`, as its `x-amz-checksum-*` header spells it.
pub(super) fn checksum_value(algorithm: rustfs_gateway_types::ChecksumAlgorithm, body: &[u8]) -> String {
    let mut digest = algorithm.checksummer();
    digest.update(body);
    rustfs_gateway_types::ChecksumSpec::from_digest(algorithm, &digest.finalize())
        .map(|spec| spec.render_base64().to_owned())
        .unwrap_or_else(|_| unreachable!("a digest is always its algorithm's width"))
}

/// `request`, whose body is `body`, naming `algorithm` in both algorithm headers (one per stack,
/// `kd-decode-0001`) and carrying the body's checksum under it.
pub(super) fn checked(
    request: RawRequest,
    algorithm: rustfs_gateway_types::ChecksumAlgorithm,
    name: &str,
    body: &[u8],
) -> RawRequest {
    request
        .header("x-amz-sdk-checksum-algorithm", name)
        .header("x-amz-checksum-algorithm", name)
        .header(algorithm.header_name(), &checksum_value(algorithm, body))
}

/// A request carrying the XML document `body`, with its exact length and `Content-MD5`.
pub(crate) fn document(method: Method, target: &str, body: &str) -> RawRequest {
    RawRequest::with_body(method, target, body.as_bytes()).header("content-md5", &content_md5(body.as_bytes()))
}

/// Every row.
pub(crate) fn seam_rows() -> Vec<SeamRow> {
    let mut rows = Vec::new();
    rows.extend(objects::rows());
    rows.extend(configs::rows());
    rows.extend(reads::rows());
    rows.extend(findings::rows());
    rows
}
