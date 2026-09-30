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

pub(in crate::seam) mod configs;
mod findings;
mod objects;
pub(crate) mod omitted;
mod reads;
mod trailers;

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
    /// A member both stacks hand over in different shapes, which RustFS never reads.
    Unread,
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
    /// [`SeamClass::FailClosed`] the member the conversion refuses.
    pub(crate) path: &'static str,
    /// What it means.
    pub(crate) class: SeamClass,
    /// RustFS main `file:line` evidence (rustfs/rustfs `1e7065101d`).
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
        "sd-0002",
        "PutObject",
        "version_id",
        SeamClass::Ruled("rd-put-0007"),
        "the RustFS profile routes ?versionId= to the replication dialect's replica write, which carries it",
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
        "sd-0033",
        "PutObject",
        "content_encoding",
        SeamClass::Normalized,
        "the gateway strips aws-chunked (kd-decode-0075); RustFS strips it too and re-applies the raw header after the input \
         (rustfs/src/storage/options.rs:668-681, :830-839), so both store the same value",
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
    finding(
        "sd-0037",
        "ListObjects",
        "optional_object_attributes",
        SeamClass::Unread,
        "the legacy decoder keeps one element per header line, an empty line included; RustFS never reads the member \\
         (it only builds inputs without it: rustfs/src/app/bucket_list_through.rs:824; app/metadata_route.rs:718, :736)",
    ),
    finding(
        "sd-0038",
        "ListObjectsV2",
        "optional_object_attributes",
        SeamClass::Unread,
        "the legacy decoder keeps one element per header line, an empty line included; RustFS never reads the member \\
         (it only builds inputs without it: rustfs/src/app/bucket_list_through.rs:824; app/metadata_route.rs:718, :736)",
    ),
    finding(
        "sd-0039",
        "ListObjectVersions",
        "optional_object_attributes",
        SeamClass::Unread,
        "the legacy decoder keeps one element per header line, an empty line included; RustFS never reads the member \\
         (it only builds inputs without it: rustfs/src/app/bucket_list_through.rs:824; app/metadata_route.rs:718, :736)",
    ),
    finding(
        "sd-0040",
        "PutObjectLockConfiguration",
        "default_event_hold",
        SeamClass::FailClosed,
        "no legacy input holds a default event hold (the legacy decoder refuses the element as MalformedXML) and RustFS \
         stores none (rd-put-0009)",
    ),
    finding(
        "sd-0041",
        "PutObjectRetention",
        "event_hold",
        SeamClass::FailClosed,
        "the legacy decoder skips the element and hands RustFS the retention without it, so RustFS would apply no hold \
         the caller asked for (rd-put-0009)",
    ),
    finding(
        "sd-0042",
        "PutObjectRetention",
        "event_hold_duration",
        SeamClass::FailClosed,
        "as sd-0041, for the hold's duration (rd-put-0009)",
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
    /// The gateway handler is reached and the seam refuses the member this finding names; the
    /// legacy stack hands the request over without the value, or refuses it itself.
    FailsClosed(&'static str),
    /// The legacy decoder refuses the request, and the seam refuses the member only the legacy
    /// decoder reads, named here, with the legacy decoder's status and code: no RustFS body is
    /// handed the request on either stack.
    BothRefuse(&'static str),
    /// Both stacks refuse the request before any handler, so no RustFS body is handed it. Which
    /// code each answers is the decode diff's to compare, not this one's.
    NeitherHandsOver,
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
    rows.extend(omitted::rows());
    rows.extend(trailers::rows());
    rows
}
