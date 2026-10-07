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

//! Legacy RustFS's operation selection (rustfs/gateway#1127): which operation a request names when
//! its query carries `x-id`, or more than one operation key.
//!
//! Responsible for: [`Selection`], the choice a [`crate::Router`] is built with, and
//! [`legacy_rustfs_selection`], the operation legacy RustFS selects for a request outside every
//! dialect claim — from its method, its target, the keys its query names, the `list-type`,
//! `select-type` and `x-id` values, and three headers — and, ahead of all of that, the eight
//! S3-shaped extension routes its admin router claims by one query discriminator
//! ([`EXTENSIONS`], rustfs/backlog#2753).
//! NOT responsible for: the operation's own parameter checks (`crate::registry`), dialect claims
//! (asked first, by the router), the extension operations themselves (the `rustfs` dialect
//! declares them as S3-table rows; a table without them refuses the request `501` by name), the
//! name of the bucket or key, or anything after selection.
//! Upstream: `super::selector`'s request parts. Downstream: `crate::dispatch::Router::dispatch`.
//!
//! # What legacy RustFS does, measured on a legacy build
//!
//! Before its S3 service reads anything, RustFS's admin router claims a request whose method,
//! target and one query discriminator name an extension route — `PUT /bkt?replication-reset`,
//! `GET /bkt?replication-metrics=2`, `GET /bkt/obj?lambdaArn=…`, `GET /?events=…` — whatever
//! else the query names, `x-id` included; the discriminators are tried in [`EXTENSIONS`]' order.
//! Then an `x-id` named exactly once is the operation, among the operations of the request's
//! method and target, whatever else the query names: `GET /bkt?x-id=GetBucketVersioning&acl` is
//! GetBucketVersioning, and `PUT /bkt/obj?x-id=PutObjectTagging` stores tags rather than an
//! object. An `x-id` named twice, naming no operation, or naming one of another method or target
//! is `400 InvalidRequest`. Without it, the first present key in a fixed order per method and
//! target wins — the order in [`partition`] — and a request none of them names is the method and
//! target's plain operation (`ListObjects`, `GetObject`, `PutObject`, ...), or `501` where there
//! is none. A browser-form `POST` is read by neither rule: to a bucket it is `PostObject`, and
//! anywhere else it is left to the route table, as legacy RustFS's own form path is.

use http::Method;
use rustfs_gateway_types::decode_once;

use super::selector::{RouteRequestParts, TargetKind};
use Cond::{First, Header, Key, NoHeader, NoKey, Value};

/// How a router chooses the operation a request outside every dialect claim names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Selection {
    /// The route table's own precedences, for every deployment but one fronting RustFS.
    #[default]
    Table,
    /// Legacy RustFS's order, `x-id` first ([`legacy_rustfs_selection`]).
    ///
    /// Legacy-compat (rustfs/backlog#2684): legacy RustFS lets an `x-id` override every operation
    /// key in the query and orders the keys by its own table, so a request naming two operations
    /// is one of them only by that accident of order, and a signed `x-id` can turn a write into
    /// another write. Kept so a RustFS client's request reaches the operation it reaches today; the
    /// intended future behaviour is [`Selection::Table`], with a query naming two operations
    /// refused rather than resolved.
    RustfsLegacy,
}

impl Selection {
    /// A short, stable label for a start-up report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::RustfsLegacy => "rustfs-legacy",
        }
    }
}

/// The operation legacy RustFS selects, or what it answers instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacySelection {
    /// The operation selected, by its S3 name.
    Selected(&'static str),
    /// No operation: legacy RustFS answers `501 NotImplemented`.
    Unknown,
    /// An `x-id` named more than once, or naming no operation of the request's method and target:
    /// legacy RustFS answers `400 InvalidRequest`.
    Undeclared,
    /// A browser-form `POST` legacy RustFS does not route by its query: the route table decides.
    Table,
}

/// One condition a candidate operation needs.
#[derive(Clone, Copy, Debug)]
enum Cond {
    /// The query names the key, with any value.
    Key(&'static str),
    /// The query does not name the key.
    NoKey(&'static str),
    /// The query names the key exactly once, and its value, decoded, is this text.
    Value(&'static str, &'static str),
    /// The query's first value for the key, still encoded, is this text: RustFS's extension
    /// discriminators read the first pair and ignore a repeat, and the dialect's S3-table rows
    /// compare the encoded value as every `QueryEquals` row does, so both selections agree.
    First(&'static str, &'static str),
    /// The header is present.
    Header(&'static str),
    /// The header is absent.
    NoHeader(&'static str),
}

/// An operation and every condition it needs.
#[derive(Clone, Copy, Debug)]
struct Candidate {
    op: &'static str,
    when: &'static [Cond],
}

const fn when(op: &'static str, when: &'static [Cond]) -> Candidate {
    Candidate { op, when }
}

/// Every operation of one method and target, in legacy RustFS's order.
#[derive(Clone, Copy, Debug)]
struct Partition {
    /// Tried in order; the first whose conditions all hold is the operation.
    candidates: &'static [Candidate],
    /// The operation when no candidate holds, if there is one.
    otherwise: Option<&'static str>,
}

/// One extension route RustFS's admin router claims ahead of its S3 service: a method, a target,
/// one discriminating condition, and the `rustfs` dialect's operation for it.
#[derive(Clone, Debug)]
struct Extension {
    method: Method,
    target: TargetKind,
    when: Cond,
    op: &'static str,
}

const fn extension(method: Method, target: TargetKind, when: Cond, op: &'static str) -> Extension {
    Extension {
        method,
        target,
        when,
        op,
    }
}

/// RustFS's eight S3-shaped extension routes, in the order its router tries them
/// (rustfs/backlog#2753): the replication discriminators, then object lambda, then the two
/// notification listeners. Each names the `rustfs` dialect's operation, declared there as an
/// S3-table row with the same selector; the two are pinned to agree by that crate's tests.
const EXTENSIONS: &[Extension] = &[
    extension(
        Method::PUT,
        TargetKind::Bucket,
        First("replication-reset", ""),
        "rustfs:ResetBucketReplication",
    ),
    extension(
        Method::GET,
        TargetKind::Bucket,
        First("replication-reset-status", ""),
        "rustfs:GetReplicationResetStatus",
    ),
    extension(
        Method::GET,
        TargetKind::Bucket,
        First("replication-metrics", "2"),
        "rustfs:GetReplicationMetricsV2",
    ),
    extension(
        Method::GET,
        TargetKind::Bucket,
        First("replication-metrics", ""),
        "rustfs:GetReplicationMetrics",
    ),
    extension(Method::GET, TargetKind::Bucket, First("replication-check", ""), "rustfs:CheckReplication"),
    extension(Method::GET, TargetKind::Object, Key("lambdaArn"), "rustfs:InvokeObjectLambda"),
    extension(Method::GET, TargetKind::Service, Key("events"), "rustfs:ListenNotification"),
    extension(Method::GET, TargetKind::Bucket, Key("events"), "rustfs:ListenBucketNotification"),
];

const COPY_SOURCE: &str = "x-amz-copy-source";

const GET_SERVICE: Partition = Partition {
    candidates: &[when("ListDirectoryBuckets", &[Value("x-id", "ListDirectoryBuckets")])],
    otherwise: Some("ListBuckets"),
};

const GET_BUCKET: Partition = Partition {
    candidates: &[
        when("GetBucketAnalyticsConfiguration", &[Key("analytics"), Key("id")]),
        when("GetBucketIntelligentTieringConfiguration", &[Key("intelligent-tiering"), Key("id")]),
        when("GetBucketInventoryConfiguration", &[Key("inventory"), Key("id")]),
        when("GetBucketMetricsConfiguration", &[Key("metrics"), Key("id")]),
        when("CreateSession", &[Key("session")]),
        when("GetBucketAbac", &[Key("abac")]),
        when("GetBucketAccelerateConfiguration", &[Key("accelerate")]),
        when("GetBucketAcl", &[Key("acl")]),
        when("GetBucketCors", &[Key("cors")]),
        when("GetBucketEncryption", &[Key("encryption")]),
        when("GetBucketLifecycleConfiguration", &[Key("lifecycle")]),
        when("GetBucketLocation", &[Key("location")]),
        when("GetBucketLogging", &[Key("logging")]),
        when("GetBucketMetadataConfiguration", &[Key("metadataConfiguration")]),
        when("GetBucketMetadataTableConfiguration", &[Key("metadataTable")]),
        when("GetBucketNotificationConfiguration", &[Key("notification")]),
        when("GetBucketOwnershipControls", &[Key("ownershipControls")]),
        when("GetBucketPolicy", &[Key("policy")]),
        when("GetBucketPolicyStatus", &[Key("policyStatus")]),
        when("GetBucketReplication", &[Key("replication")]),
        when("GetBucketRequestPayment", &[Key("requestPayment")]),
        when("GetBucketTagging", &[Key("tagging")]),
        when("GetBucketVersioning", &[Key("versioning")]),
        when("GetBucketWebsite", &[Key("website")]),
        when("GetObjectLockConfiguration", &[Key("object-lock")]),
        when("GetPublicAccessBlock", &[Key("publicAccessBlock")]),
        when("ListBucketAnalyticsConfigurations", &[Key("analytics"), NoKey("id")]),
        when("ListBucketIntelligentTieringConfigurations", &[Key("intelligent-tiering"), NoKey("id")]),
        when("ListBucketInventoryConfigurations", &[Key("inventory"), NoKey("id")]),
        when("ListBucketMetricsConfigurations", &[Key("metrics"), NoKey("id")]),
        when("ListMultipartUploads", &[Key("uploads")]),
        when("ListObjectVersions", &[Key("versions")]),
        when("ListObjectsV2", &[Value("list-type", "2")]),
    ],
    otherwise: Some("ListObjects"),
};

const GET_OBJECT: Partition = Partition {
    candidates: &[
        when("GetObjectAnnotation", &[Key("annotation"), Key("annotationName")]),
        when("GetObjectAttributes", &[Key("attributes")]),
        when("GetObjectAcl", &[Key("acl")]),
        when("GetObjectLegalHold", &[Key("legal-hold")]),
        when("GetObjectRetention", &[Key("retention")]),
        when("GetObjectTagging", &[Key("tagging")]),
        when("GetObjectTorrent", &[Key("torrent")]),
        when("ListObjectAnnotations", &[Key("annotation"), NoKey("annotationName")]),
        when("ListParts", &[Key("uploadId")]),
    ],
    otherwise: Some("GetObject"),
};

const HEAD_BUCKET: Partition = Partition {
    candidates: &[],
    otherwise: Some("HeadBucket"),
};

const HEAD_OBJECT: Partition = Partition {
    candidates: &[],
    otherwise: Some("HeadObject"),
};

const POST_BUCKET: Partition = Partition {
    candidates: &[
        when("CreateBucketMetadataConfiguration", &[Key("metadataConfiguration")]),
        when("CreateBucketMetadataTableConfiguration", &[Key("metadataTable")]),
        when("DeleteObjects", &[Key("delete")]),
        when("WriteGetObjectResponse", &[Header("x-amz-request-route"), Header("x-amz-request-token")]),
    ],
    otherwise: None,
};

const POST_OBJECT: Partition = Partition {
    candidates: &[
        when("SelectObjectContent", &[Key("select"), Value("select-type", "2")]),
        when("CreateMultipartUpload", &[Key("uploads")]),
        when("RestoreObject", &[Key("restore")]),
        when("CompleteMultipartUpload", &[Key("uploadId")]),
    ],
    otherwise: None,
};

const PUT_BUCKET: Partition = Partition {
    candidates: &[
        when("PutBucketAnalyticsConfiguration", &[Key("analytics")]),
        when("PutBucketIntelligentTieringConfiguration", &[Key("intelligent-tiering")]),
        when("PutBucketInventoryConfiguration", &[Key("inventory")]),
        when("PutBucketMetricsConfiguration", &[Key("metrics")]),
        when("PutBucketAbac", &[Key("abac")]),
        when("PutBucketAccelerateConfiguration", &[Key("accelerate")]),
        when("PutBucketAcl", &[Key("acl")]),
        when("PutBucketCors", &[Key("cors")]),
        when("PutBucketEncryption", &[Key("encryption")]),
        when("PutBucketLifecycleConfiguration", &[Key("lifecycle")]),
        when("PutBucketLogging", &[Key("logging")]),
        when("PutBucketNotificationConfiguration", &[Key("notification")]),
        when("PutBucketOwnershipControls", &[Key("ownershipControls")]),
        when("PutBucketPolicy", &[Key("policy")]),
        when("PutBucketReplication", &[Key("replication")]),
        when("PutBucketRequestPayment", &[Key("requestPayment")]),
        when("PutBucketTagging", &[Key("tagging")]),
        when("PutBucketVersioning", &[Key("versioning")]),
        when("PutBucketWebsite", &[Key("website")]),
        when("PutObjectLockConfiguration", &[Key("object-lock")]),
        when("PutPublicAccessBlock", &[Key("publicAccessBlock")]),
        when("UpdateBucketMetadataAnnotationTableConfiguration", &[Key("metadataAnnotationTable")]),
        when("UpdateBucketMetadataInventoryTableConfiguration", &[Key("metadataInventoryTable")]),
        when("UpdateBucketMetadataJournalTableConfiguration", &[Key("metadataJournalTable")]),
    ],
    otherwise: Some("CreateBucket"),
};

const PUT_OBJECT: Partition = Partition {
    candidates: &[
        when("PutObjectAnnotation", &[Key("annotation")]),
        when("RenameObject", &[Key("renameObject")]),
        when("PutObjectAcl", &[Key("acl")]),
        when("PutObjectLegalHold", &[Key("legal-hold")]),
        when("PutObjectRetention", &[Key("retention")]),
        when("PutObjectTagging", &[Key("tagging")]),
        when("UpdateObjectEncryption", &[Key("encryption")]),
        when("UploadPartCopy", &[Key("partNumber"), Key("uploadId"), Header(COPY_SOURCE)]),
        when("UploadPart", &[Key("partNumber"), Key("uploadId"), NoHeader(COPY_SOURCE)]),
        // A copy source names CopyObject unless the query names both halves of a part.
        when("CopyObject", &[Header(COPY_SOURCE), NoKey("partNumber")]),
        when("CopyObject", &[Header(COPY_SOURCE), NoKey("uploadId")]),
    ],
    otherwise: Some("PutObject"),
};

const DELETE_BUCKET: Partition = Partition {
    candidates: &[
        when("DeleteBucketAnalyticsConfiguration", &[Key("analytics")]),
        when("DeleteBucketIntelligentTieringConfiguration", &[Key("intelligent-tiering")]),
        when("DeleteBucketInventoryConfiguration", &[Key("inventory")]),
        when("DeleteBucketMetricsConfiguration", &[Key("metrics")]),
        when("DeleteBucketCors", &[Key("cors")]),
        when("DeleteBucketEncryption", &[Key("encryption")]),
        when("DeleteBucketLifecycle", &[Key("lifecycle")]),
        when("DeleteBucketMetadataConfiguration", &[Key("metadataConfiguration")]),
        when("DeleteBucketMetadataTableConfiguration", &[Key("metadataTable")]),
        when("DeleteBucketOwnershipControls", &[Key("ownershipControls")]),
        when("DeleteBucketPolicy", &[Key("policy")]),
        when("DeleteBucketReplication", &[Key("replication")]),
        when("DeleteBucketTagging", &[Key("tagging")]),
        when("DeleteBucketWebsite", &[Key("website")]),
        when("DeletePublicAccessBlock", &[Key("publicAccessBlock")]),
    ],
    otherwise: Some("DeleteBucket"),
};

const DELETE_OBJECT: Partition = Partition {
    candidates: &[
        when("DeleteObjectAnnotation", &[Key("annotation")]),
        when("DeleteObjectTagging", &[Key("tagging")]),
        when("AbortMultipartUpload", &[Key("uploadId")]),
    ],
    otherwise: Some("DeleteObject"),
};

/// The operations of one method and target, in legacy RustFS's order; `None` where legacy RustFS
/// defines none (a `PUT`, `POST`, `DELETE` or `HEAD` of `/`, and every other method).
fn partition(parts: &RouteRequestParts<'_>) -> Option<&'static Partition> {
    let method = parts.method;
    Some(match parts.target {
        TargetKind::Service if *method == Method::GET => &GET_SERVICE,
        TargetKind::Bucket if *method == Method::GET => &GET_BUCKET,
        TargetKind::Object if *method == Method::GET => &GET_OBJECT,
        TargetKind::Bucket if *method == Method::HEAD => &HEAD_BUCKET,
        TargetKind::Object if *method == Method::HEAD => &HEAD_OBJECT,
        TargetKind::Bucket if *method == Method::POST => &POST_BUCKET,
        TargetKind::Object if *method == Method::POST => &POST_OBJECT,
        TargetKind::Bucket if *method == Method::PUT => &PUT_BUCKET,
        TargetKind::Object if *method == Method::PUT => &PUT_OBJECT,
        TargetKind::Bucket if *method == Method::DELETE => &DELETE_BUCKET,
        TargetKind::Object if *method == Method::DELETE => &DELETE_OBJECT,
        _ => return None,
    })
}

/// Whether one condition holds.
fn holds(cond: Cond, parts: &RouteRequestParts<'_>) -> bool {
    match cond {
        Key(key) => parts.query.contains(key),
        NoKey(key) => !parts.query.contains(key),
        Value(key, expected) => parts.query.count(key) == 1 && parts.query.get(key).is_some_and(|raw| spells(raw, expected)),
        First(key, expected) => parts.query.get(key) == Some(expected),
        Header(name) => has_header(parts, name),
        NoHeader(name) => !has_header(parts, name),
    }
}

fn has_header(parts: &RouteRequestParts<'_>, name: &str) -> bool {
    parts.headers.iter_raw().any(|(header, _)| header.as_str() == name)
}

/// Whether a query value, decoded once, is `expected`. A value that does not decode is not it.
fn spells(raw: &str, expected: &str) -> bool {
    decode_once(raw).is_ok_and(|decoded| decoded == expected)
}

/// Whether the request is a browser-form upload: a `POST` whose one `Content-Type` is
/// `multipart/form-data`, parameters aside.
fn is_form_post(parts: &RouteRequestParts<'_>) -> bool {
    if *parts.method != http::Method::POST {
        return false;
    }
    let mut types = parts
        .headers
        .iter_raw()
        .filter(|(header, _)| *header == http::header::CONTENT_TYPE);
    let (Some((_, value)), None) = (types.next(), types.next()) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let media = value.split(';').next().unwrap_or_default().trim();
    media.eq_ignore_ascii_case("multipart/form-data")
}

/// The operation legacy RustFS selects for a request outside every dialect claim, or what it
/// answers instead: see the module documentation for the rules and where they were measured.
#[must_use]
pub fn legacy_rustfs_selection(parts: &RouteRequestParts<'_>) -> LegacySelection {
    if let Some(extension) = EXTENSIONS
        .iter()
        .find(|extension| *parts.method == extension.method && parts.target == extension.target && holds(extension.when, parts))
    {
        return LegacySelection::Selected(extension.op);
    }
    if is_form_post(parts) {
        return match parts.target {
            TargetKind::Bucket => LegacySelection::Selected("PostObject"),
            TargetKind::Service => LegacySelection::Unknown,
            TargetKind::Object => LegacySelection::Table,
        };
    }
    let partition = partition(parts);
    match parts.query.count("x-id") {
        0 => {}
        1 => {
            let declared = parts.query.get("x-id").and_then(|raw| decode_once(raw).ok());
            // The set an `x-id` is read against is every operation of the method and target.
            return match (partition, declared) {
                (Some(partition), Some(name)) => partition
                    .candidates
                    .iter()
                    .map(|candidate| candidate.op)
                    .chain(partition.otherwise)
                    .find(|op| *op == name)
                    .map_or(LegacySelection::Undeclared, LegacySelection::Selected),
                _ => LegacySelection::Undeclared,
            };
        }
        _ => return LegacySelection::Undeclared,
    }
    let Some(partition) = partition else {
        return LegacySelection::Unknown;
    };
    partition
        .candidates
        .iter()
        .find(|candidate| candidate.when.iter().all(|cond| holds(*cond, parts)))
        .map(|candidate| candidate.op)
        .or(partition.otherwise)
        .map_or(LegacySelection::Unknown, LegacySelection::Selected)
}

#[cfg(test)]
#[path = "tests/legacy_rustfs.rs"]
mod tests;
