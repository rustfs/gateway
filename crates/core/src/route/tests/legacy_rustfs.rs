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

//! Legacy RustFS's operation selection (rustfs/gateway#1127), pinned to its answers.
//!
//! Responsible for: pinning [`super::legacy_rustfs_selection`] to legacy RustFS's operation for
//! every row measured on a legacy build and to its order among two operation keys, and pinning a
//! [`crate::Router`] built with [`Selection::RustfsLegacy`] to dispatch by it outside every claim.
//! NOT responsible for: the gateway pipeline around the router (`rustfs-gateway`'s own cases).
//! Upstream: the parent module. Downstream: nothing; this is a leaf test module.

use super::*;
use crate::route::RequestShape;
use crate::route::selector::{HostClass, TargetKind};
use http::Method;

/// The selection for `method target?query` with `headers`, the path shaped to the target.
fn select(method: Method, target: TargetKind, query: &str, headers: &[(&str, &str)]) -> LegacySelection {
    let path = match target {
        TargetKind::Service => "/",
        TargetKind::Bucket => "/bkt",
        TargetKind::Object => "/bkt/obj",
    };
    let shape = RequestShape {
        method,
        path: path.to_owned(),
        target,
        host_class: HostClass::Standard,
        arn_form: None,
        query: query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((key, value)) => (key.to_owned(), value.to_owned()),
                None => (pair.to_owned(), String::new()),
            })
            .collect(),
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
    };
    #[allow(clippy::expect_used, reason = "every fixture here is a request the wire accepts")]
    let materialised = shape.materialise().expect("an acceptable request");
    legacy_rustfs_selection(&materialised.parts())
}

fn op(name: &'static str) -> LegacySelection {
    LegacySelection::Selected(name)
}

// ---------------------------------------------------------------------------
// Positive: legacy RustFS's answers, measured on a legacy build.
// ---------------------------------------------------------------------------

/// Two operation keys: the first in legacy RustFS's order wins.
#[test]
fn two_operation_keys_select_the_first_in_legacy_order() {
    let bucket = |query| select(Method::GET, TargetKind::Bucket, query, &[]);
    assert_eq!(bucket("acl&versioning"), op("GetBucketAcl"));
    assert_eq!(bucket("versioning&acl"), op("GetBucketAcl"), "order in the query does not matter");
    assert_eq!(bucket("encryption&acl"), op("GetBucketAcl"));
    assert_eq!(bucket("location&policy"), op("GetBucketLocation"));
    assert_eq!(bucket("versioning&location"), op("GetBucketLocation"));
    assert_eq!(bucket("lifecycle&location"), op("GetBucketLifecycleConfiguration"));
    assert_eq!(bucket("object-lock&website"), op("GetBucketWebsite"));
    assert_eq!(bucket("uploads&versions"), op("ListMultipartUploads"));
    assert_eq!(bucket("list-type=2&versions"), op("ListObjectVersions"));
    let object = |method, query| select(method, TargetKind::Object, query, &[]);
    assert_eq!(object(Method::GET, "tagging&acl"), op("GetObjectAcl"));
    assert_eq!(object(Method::GET, "uploadId=u&tagging"), op("GetObjectTagging"));
    assert_eq!(object(Method::GET, "attributes&acl"), op("GetObjectAttributes"));
    assert_eq!(object(Method::PUT, "tagging&partNumber=1&uploadId=u"), op("PutObjectTagging"));
    assert_eq!(object(Method::PUT, "tagging&acl"), op("PutObjectAcl"));
    assert_eq!(object(Method::DELETE, "tagging&uploadId=u"), op("DeleteObjectTagging"));
    assert_eq!(object(Method::POST, "uploadId=u&uploads"), op("CreateMultipartUpload"));
}

/// An `x-id` named once is the operation, whatever else the query names.
#[test]
fn an_x_id_named_once_is_the_operation() {
    assert_eq!(
        select(Method::GET, TargetKind::Bucket, "x-id=GetBucketVersioning&acl", &[]),
        op("GetBucketVersioning")
    );
    assert_eq!(select(Method::GET, TargetKind::Bucket, "x-id=GetBucketAcl", &[]), op("GetBucketAcl"));
    assert_eq!(select(Method::GET, TargetKind::Bucket, "x-id=ListObjectsV2", &[]), op("ListObjectsV2"));
    assert_eq!(
        select(Method::GET, TargetKind::Object, "x-id=GetObjectTagging", &[]),
        op("GetObjectTagging")
    );
    assert_eq!(select(Method::GET, TargetKind::Object, "x-id=ListParts", &[]), op("ListParts"));
    assert_eq!(
        select(Method::PUT, TargetKind::Object, "x-id=PutObjectTagging", &[]),
        op("PutObjectTagging")
    );
    assert_eq!(
        select(Method::DELETE, TargetKind::Object, "x-id=AbortMultipartUpload", &[]),
        op("AbortMultipartUpload")
    );
    assert_eq!(
        select(Method::GET, TargetKind::Service, "x-id=ListDirectoryBuckets", &[]),
        op("ListDirectoryBuckets")
    );
    assert_eq!(select(Method::HEAD, TargetKind::Object, "x-id=HeadObject", &[]), op("HeadObject"));
    assert_eq!(
        select(Method::GET, TargetKind::Bucket, "x-id=Get%42ucketAcl", &[]),
        op("GetBucketAcl"),
        "the value is read decoded"
    );
}

/// What an SDK sends — an `x-id` its own keys agree with — selects the same operation.
#[test]
fn an_sdk_request_selects_the_operation_it_names() {
    let copy = [("x-amz-copy-source", "src/obj")];
    assert_eq!(select(Method::GET, TargetKind::Object, "x-id=GetObject", &[]), op("GetObject"));
    assert_eq!(select(Method::PUT, TargetKind::Object, "x-id=PutObject", &[]), op("PutObject"));
    assert_eq!(select(Method::PUT, TargetKind::Object, "x-id=CopyObject", &copy), op("CopyObject"));
    assert_eq!(
        select(Method::PUT, TargetKind::Object, "partNumber=1&uploadId=u&x-id=UploadPart", &[]),
        op("UploadPart")
    );
    assert_eq!(
        select(Method::PUT, TargetKind::Object, "partNumber=1&uploadId=u&x-id=UploadPartCopy", &copy),
        op("UploadPartCopy")
    );
    assert_eq!(
        select(Method::POST, TargetKind::Bucket, "delete&x-id=DeleteObjects", &[]),
        op("DeleteObjects")
    );
}

/// The plain operation of each method and target, and the header-selected ones.
#[test]
fn a_request_naming_no_key_is_the_plain_operation() {
    assert_eq!(select(Method::GET, TargetKind::Service, "", &[]), op("ListBuckets"));
    assert_eq!(select(Method::GET, TargetKind::Bucket, "prefix=a", &[]), op("ListObjects"));
    assert_eq!(select(Method::GET, TargetKind::Object, "versionId=v", &[]), op("GetObject"));
    assert_eq!(select(Method::HEAD, TargetKind::Bucket, "acl", &[]), op("HeadBucket"));
    assert_eq!(select(Method::HEAD, TargetKind::Object, "tagging", &[]), op("HeadObject"));
    assert_eq!(select(Method::PUT, TargetKind::Bucket, "", &[]), op("CreateBucket"));
    assert_eq!(select(Method::PUT, TargetKind::Object, "partNumber=1", &[]), op("PutObject"));
    assert_eq!(select(Method::DELETE, TargetKind::Bucket, "acl", &[]), op("DeleteBucket"));
    assert_eq!(select(Method::DELETE, TargetKind::Object, "versionId=v", &[]), op("DeleteObject"));
    let copy = [("x-amz-copy-source", "src/obj")];
    assert_eq!(select(Method::PUT, TargetKind::Object, "", &copy), op("CopyObject"));
    assert_eq!(select(Method::PUT, TargetKind::Object, "partNumber=1", &copy), op("CopyObject"));
    assert_eq!(
        select(Method::PUT, TargetKind::Object, "partNumber=1&uploadId=u", &copy),
        op("UploadPartCopy")
    );
    assert_eq!(
        select(Method::PUT, TargetKind::Object, "tagging&partNumber=1&uploadId=u", &copy),
        op("PutObjectTagging")
    );
    let route = [("x-amz-request-route", "r"), ("x-amz-request-token", "t")];
    assert_eq!(select(Method::POST, TargetKind::Bucket, "", &route), op("WriteGetObjectResponse"));
}

/// The configuration and annotation keys that also need `id` or `annotationName`.
#[test]
fn a_key_that_needs_a_second_one_selects_by_it() {
    let bucket = |query| select(Method::GET, TargetKind::Bucket, query, &[]);
    assert_eq!(bucket("analytics&id=1"), op("GetBucketAnalyticsConfiguration"));
    assert_eq!(bucket("analytics"), op("ListBucketAnalyticsConfigurations"));
    assert_eq!(bucket("metrics&id=1&acl"), op("GetBucketMetricsConfiguration"));
    assert_eq!(bucket("metrics&acl"), op("GetBucketAcl"), "the listing comes after every Get");
    let object = |query| select(Method::GET, TargetKind::Object, query, &[]);
    assert_eq!(object("annotation&annotationName=a"), op("GetObjectAnnotation"));
    assert_eq!(object("annotation"), op("ListObjectAnnotations"));
    assert_eq!(object("annotationName=a"), op("GetObject"));
    let post = |query| select(Method::POST, TargetKind::Object, query, &[]);
    assert_eq!(post("select&select-type=2&uploads"), op("SelectObjectContent"));
    assert_eq!(post("select&uploads"), op("CreateMultipartUpload"));
    assert_eq!(post("select-type=2&restore"), op("RestoreObject"));
}

/// RustFS's eight S3-shaped extension routes (rustfs/backlog#2753): its admin router claims each
/// by method, target and one query discriminator before its S3 service reads anything else, so
/// every one is ahead of every operation key and of `x-id`, and `replication-metrics` splits on
/// its value.
#[test]
fn an_extension_discriminator_selects_the_dialect_operation_ahead_of_every_key() {
    let bucket = |query| select(Method::GET, TargetKind::Bucket, query, &[]);
    assert_eq!(
        select(Method::PUT, TargetKind::Bucket, "replication-reset", &[]),
        op("rustfs:ResetBucketReplication")
    );
    assert_eq!(bucket("replication-reset-status"), op("rustfs:GetReplicationResetStatus"));
    assert_eq!(bucket("replication-metrics=2"), op("rustfs:GetReplicationMetricsV2"));
    assert_eq!(bucket("replication-metrics"), op("rustfs:GetReplicationMetrics"));
    assert_eq!(bucket("replication-metrics="), op("rustfs:GetReplicationMetrics"));
    assert_eq!(bucket("replication-check"), op("rustfs:CheckReplication"));
    assert_eq!(bucket("replication-check="), op("rustfs:CheckReplication"));
    assert_eq!(
        select(Method::GET, TargetKind::Object, "lambdaArn=arn", &[]),
        op("rustfs:InvokeObjectLambda")
    );
    assert_eq!(select(Method::GET, TargetKind::Service, "events=x", &[]), op("rustfs:ListenNotification"));
    assert_eq!(bucket("events"), op("rustfs:ListenBucketNotification"));
    // Ahead of every operation key, of `x-id`, and of each other in RustFS's order.
    assert_eq!(bucket("acl&events"), op("rustfs:ListenBucketNotification"));
    assert_eq!(bucket("replication&replication-check"), op("rustfs:CheckReplication"));
    assert_eq!(bucket("x-id=ListObjects&replication-check"), op("rustfs:CheckReplication"));
    assert_eq!(bucket("x-id=GetBucketAcl&events"), op("rustfs:ListenBucketNotification"));
    assert_eq!(
        select(Method::PUT, TargetKind::Bucket, "x-id=CreateBucket&replication-reset", &[]),
        op("rustfs:ResetBucketReplication")
    );
    assert_eq!(
        bucket("replication-check&replication-reset-status"),
        op("rustfs:GetReplicationResetStatus")
    );
    assert_eq!(bucket("replication-check&replication-metrics=2"), op("rustfs:GetReplicationMetricsV2"));
    assert_eq!(bucket("events&replication-check"), op("rustfs:CheckReplication"));
    assert_eq!(
        select(Method::GET, TargetKind::Service, "x-id=ListBuckets&events", &[]),
        op("rustfs:ListenNotification")
    );
}

/// Negative — a discriminator with the wrong value, method or target is no extension route: the
/// request is whatever its keys name, as on RustFS, whose router reads the first value of the key
/// still encoded and takes nothing a later value says.
#[test]
fn n_an_extension_near_miss_is_the_ordinary_operation() {
    let bucket = |query| select(Method::GET, TargetKind::Bucket, query, &[]);
    assert_eq!(bucket("replication-check=1"), op("ListObjects"));
    assert_eq!(bucket("replication-check=%20"), op("ListObjects"));
    assert_eq!(bucket("replication-metrics=3"), op("ListObjects"));
    assert_eq!(bucket("replication-metrics=%32"), op("ListObjects"));
    assert_eq!(bucket("replication-reset"), op("ListObjects"));
    assert_eq!(bucket("Replication-Check"), op("ListObjects"));
    assert_eq!(bucket("replication-check=1&replication-check"), op("ListObjects"));
    assert_eq!(bucket("lambdaArn=arn"), op("ListObjects"));
    assert_eq!(bucket("acl&lambdaArn=arn"), op("GetBucketAcl"));
    assert_eq!(select(Method::PUT, TargetKind::Bucket, "events", &[]), op("CreateBucket"));
    assert_eq!(select(Method::PUT, TargetKind::Bucket, "replication-check", &[]), op("CreateBucket"));
    assert_eq!(select(Method::PUT, TargetKind::Bucket, "replication-reset=1", &[]), op("CreateBucket"));
    assert_eq!(select(Method::PUT, TargetKind::Object, "replication-reset", &[]), op("PutObject"));
    assert_eq!(select(Method::GET, TargetKind::Object, "replication-check", &[]), op("GetObject"));
    assert_eq!(select(Method::GET, TargetKind::Object, "events", &[]), op("GetObject"));
    assert_eq!(select(Method::GET, TargetKind::Service, "lambdaArn=arn", &[]), op("ListBuckets"));
    assert_eq!(select(Method::GET, TargetKind::Service, "replication-check", &[]), op("ListBuckets"));
    assert_eq!(select(Method::HEAD, TargetKind::Bucket, "events", &[]), op("HeadBucket"));
    assert_eq!(select(Method::DELETE, TargetKind::Bucket, "events", &[]), op("DeleteBucket"));
    assert_eq!(select(Method::POST, TargetKind::Bucket, "events", &[]), LegacySelection::Unknown);
    // Naming an extension operation by `x-id` names nothing: legacy RustFS's `x-id` set is its
    // S3 operations.
    assert_eq!(bucket("x-id=rustfs:CheckReplication"), LegacySelection::Undeclared);
    assert_eq!(bucket("x-id=ListenBucketNotification"), LegacySelection::Undeclared);
}

/// A browser-form upload to a bucket is PostObject, whatever its query names.
#[test]
fn a_form_post_to_a_bucket_is_post_object() {
    let form = [("content-type", "multipart/form-data; boundary=x")];
    assert_eq!(select(Method::POST, TargetKind::Bucket, "", &form), op("PostObject"));
    assert_eq!(
        select(Method::POST, TargetKind::Bucket, "delete&x-id=DeleteObjects", &form),
        op("PostObject")
    );
    assert_eq!(select(Method::POST, TargetKind::Service, "", &form), LegacySelection::Unknown);
    assert_eq!(select(Method::POST, TargetKind::Object, "uploads", &form), LegacySelection::Table);
    let other = [("content-type", "application/xml")];
    assert_eq!(select(Method::POST, TargetKind::Bucket, "delete", &other), op("DeleteObjects"));
}

// ---------------------------------------------------------------------------
// Negative: what legacy RustFS refuses, and the order no other rule may change.
// ---------------------------------------------------------------------------

/// An `x-id` named twice, naming no operation, or naming one of another method or target.
#[test]
fn n_an_undeclared_x_id_is_refused() {
    for (method, target, query) in [
        (Method::GET, TargetKind::Bucket, "x-id=GetObject"),
        (Method::GET, TargetKind::Bucket, "x-id=NoSuchOp"),
        (Method::GET, TargetKind::Bucket, "x-id=getbucketacl"),
        (Method::GET, TargetKind::Bucket, "x-id="),
        (Method::GET, TargetKind::Bucket, "x-id=a&x-id=b"),
        (Method::GET, TargetKind::Bucket, "x-id=ListObjects&x-id=ListObjects"),
        (Method::GET, TargetKind::Service, "x-id=ListObjects"),
        (Method::HEAD, TargetKind::Bucket, "x-id=ListBuckets"),
        (Method::PUT, TargetKind::Service, "x-id=CreateBucket"),
        (Method::POST, TargetKind::Bucket, "x-id=PutObject"),
        (Method::DELETE, TargetKind::Object, "x-id=DeleteBucket"),
        (Method::PATCH, TargetKind::Object, "x-id=GetObject"),
        (Method::GET, TargetKind::Bucket, "x-id=%FF"),
    ] {
        assert_eq!(
            select(method.clone(), target, query, &[]),
            LegacySelection::Undeclared,
            "{method} {target:?} {query}"
        );
    }
}

/// A method and target legacy RustFS defines no operation for.
#[test]
fn n_a_shape_with_no_operation_is_unknown() {
    for (method, target) in [
        (Method::PUT, TargetKind::Service),
        (Method::DELETE, TargetKind::Service),
        (Method::HEAD, TargetKind::Service),
        (Method::POST, TargetKind::Service),
        (Method::PATCH, TargetKind::Bucket),
        (Method::OPTIONS, TargetKind::Object),
    ] {
        assert_eq!(select(method.clone(), target, "", &[]), LegacySelection::Unknown, "{method} {target:?}");
    }
    assert_eq!(select(Method::POST, TargetKind::Bucket, "", &[]), LegacySelection::Unknown);
    assert_eq!(select(Method::POST, TargetKind::Object, "", &[]), LegacySelection::Unknown);
    let one_header = [("x-amz-request-route", "r")];
    assert_eq!(select(Method::POST, TargetKind::Bucket, "", &one_header), LegacySelection::Unknown);
}

/// Every candidate beats every later one of its method and target: the order, pinned pairwise.
#[test]
fn n_no_later_candidate_beats_an_earlier_one() {
    for (method, target, partition) in [
        (Method::GET, TargetKind::Bucket, &GET_BUCKET),
        (Method::GET, TargetKind::Object, &GET_OBJECT),
        (Method::PUT, TargetKind::Bucket, &PUT_BUCKET),
        (Method::DELETE, TargetKind::Bucket, &DELETE_BUCKET),
        (Method::DELETE, TargetKind::Object, &DELETE_OBJECT),
        (Method::POST, TargetKind::Bucket, &POST_BUCKET),
        (Method::POST, TargetKind::Object, &POST_OBJECT),
    ] {
        let simple: Vec<(&str, &str)> = partition
            .candidates
            .iter()
            .filter_map(|candidate| match candidate.when {
                [Key(key)] => Some((candidate.op, *key)),
                _ => None,
            })
            .collect();
        for (index, (earlier, earlier_key)) in simple.iter().enumerate() {
            for (_, later_key) in simple.iter().skip(index + 1) {
                assert_eq!(
                    select(method.clone(), target, &format!("{later_key}&{earlier_key}"), &[]),
                    op(earlier),
                    "{method} {target:?} {later_key}&{earlier_key}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The router: a legacy selection is what `dispatch` routes by, outside every claim.
// ---------------------------------------------------------------------------

/// A router over the generated table with nothing registered, so every routed request is refused
/// `501` naming the operation it was routed to.
fn router(selection: Selection) -> crate::Router {
    #[allow(clippy::expect_used, reason = "the generated table always builds")]
    let router = crate::Router::from_generated(crate::registry::Registry::new()).expect("the generated table");
    router.selecting(selection)
}

/// The operation a router routed `method target?query` to, or the code it refused with.
fn routed(router: &crate::Router, method: Method, target: TargetKind, query: &str) -> Result<&'static str, String> {
    let path = match target {
        TargetKind::Service => "/",
        TargetKind::Bucket => "/bkt",
        TargetKind::Object => "/bkt/obj",
    };
    let shape = RequestShape {
        method,
        path: path.to_owned(),
        target,
        host_class: HostClass::Standard,
        arn_form: None,
        query: query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((key, value)) => (key.to_owned(), value.to_owned()),
                None => (pair.to_owned(), String::new()),
            })
            .collect(),
        headers: Vec::new(),
    };
    #[allow(clippy::expect_used, reason = "every fixture here is a request the wire accepts")]
    let materialised = shape.materialise().expect("an acceptable request");
    match router.dispatch(&materialised.parts()) {
        Ok(dispatch) => Ok(dispatch.entry.op_name),
        Err(error) => error.operation().ok_or_else(|| error.code().as_str().to_owned()),
    }
}

/// The router dispatches by the legacy order and by `x-id`, naming the operation it chose.
#[test]
fn a_legacy_router_dispatches_by_the_legacy_selection() {
    let legacy = router(Selection::RustfsLegacy);
    assert_eq!(routed(&legacy, Method::GET, TargetKind::Bucket, "acl&versioning"), Ok("GetBucketAcl"));
    assert_eq!(
        routed(&legacy, Method::PUT, TargetKind::Object, "x-id=PutObjectTagging"),
        Ok("PutObjectTagging")
    );
    assert_eq!(
        routed(&legacy, Method::DELETE, TargetKind::Object, "tagging&uploadId=u"),
        Ok("DeleteObjectTagging")
    );
    assert_eq!(routed(&legacy, Method::GET, TargetKind::Bucket, ""), Ok("ListObjects"));
}

/// Negative — an undeclared `x-id` is `400 InvalidRequest` naming no operation; an operation the
/// table does not define is `501` naming it; a shape with none is `501` naming none.
#[test]
fn n_a_legacy_router_refuses_what_legacy_rustfs_refuses() {
    let legacy = router(Selection::RustfsLegacy);
    assert_eq!(
        routed(&legacy, Method::GET, TargetKind::Bucket, "x-id=NoSuchOp"),
        Err("InvalidRequest".to_owned())
    );
    assert_eq!(
        routed(&legacy, Method::GET, TargetKind::Bucket, "x-id=a&x-id=b"),
        Err("InvalidRequest".to_owned())
    );
    assert_eq!(
        routed(&legacy, Method::PUT, TargetKind::Bucket, "analytics"),
        Ok("PutBucketAnalyticsConfiguration"),
        "an operation the table does not define is still the one refused"
    );
    assert_eq!(routed(&legacy, Method::PUT, TargetKind::Service, ""), Err("NotImplemented".to_owned()));
    // An extension route names the dialect's operation; a table without the dialect refuses it by
    // that name rather than serving the S3 operation legacy RustFS never reaches.
    assert_eq!(
        routed(&legacy, Method::GET, TargetKind::Bucket, "replication-check"),
        Ok("rustfs:CheckReplication")
    );
    assert_eq!(
        routed(&legacy, Method::GET, TargetKind::Service, "events"),
        Ok("rustfs:ListenNotification")
    );
}

/// Negative — the default router is untouched: its own precedences, and `x-id` ignored.
#[test]
fn n_the_table_router_is_unchanged() {
    let table = router(Selection::Table);
    assert_eq!(table.selection(), Selection::Table);
    assert_eq!(
        routed(&table, Method::GET, TargetKind::Bucket, "acl&versioning"),
        Ok("GetBucketVersioning")
    );
    assert_eq!(routed(&table, Method::PUT, TargetKind::Object, "x-id=PutObjectTagging"), Ok("PutObject"));
    assert_eq!(routed(&table, Method::GET, TargetKind::Bucket, "x-id=NoSuchOp"), Ok("ListObjects"));
    assert_eq!(routed(&table, Method::GET, TargetKind::Bucket, "replication-check"), Ok("ListObjects"));
}
