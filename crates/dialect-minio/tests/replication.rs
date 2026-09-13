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

//! `minio:PutObjectReplica` below the service: routing, the two actions it owes, its floor, and
//! its codec.
//!
//! Responsible for: the routing matrix with and without the dialect installed, the authorisation
//! a replica write requires, the floor that refuses a presigned replica, and the codec —
//! `PutObject`'s plus `versionId`. NOT responsible for: the exchange with a real authorizer
//! (`crates/gateway/tests/replica_put.rs`) or the agreement with s3s (`rd-put-0007` in the goldens
//! register). Upstream: this crate and `rustfs-gateway-core`. Downstream: nothing.

use http::Request;
use rustfs_gateway_core::DerivedResourceSet as _;
use rustfs_gateway_core::ResourceRef;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::op::{Operation, ResourceShape};
use rustfs_gateway_core::registry::RouterBuilder;
use rustfs_gateway_core::route::{HostClass, RouteRequestParts, TargetKind};
use rustfs_gateway_dialect_minio::replication::NAME;
use rustfs_gateway_dialect_minio::{PutObjectReplica, PutObjectReplicaInput, replication_dialect};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto::PutObject;

const TARGET: &str = "/photos/a.png";
const VERSION: &str = "0190b7a1-6d4e-7c3a-9f00-0123456789ab";

fn accepted(method: &str, target: &str, headers: &[(&str, &str)]) -> WireRequest<()> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(()).expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

/// The operation `method target` reaches on an object, with or without the dialect installed.
fn routed(installed: bool, method: &str, target: &str, headers: &[(&str, &str)]) -> Option<&'static str> {
    let wire = accepted(method, target, headers);
    let mut builder = RouterBuilder::new();
    if installed {
        builder = builder.dialect(&replication_dialect().expect("the record and the declaration agree"));
    }
    let router = builder
        .build()
        .expect("the table builds with the replica row and its one declared overlap");
    let parts = RouteRequestParts {
        method: wire.method(),
        path: wire.raw_path().as_str(),
        target: TargetKind::Object,
        host_class: HostClass::Standard,
        arn_form: None,
        query: wire.query(),
        headers: wire.headers(),
        host_named_bucket: false,
    };
    router.resolve(&parts).map(|entry| entry.op_name)
}

fn versioned(target: &str) -> String {
    format!("{target}?versionId={VERSION}")
}

fn decode(target: &str, headers: &[(&str, &str)]) -> Result<PutObjectReplicaInput, String> {
    let wire = accepted("PUT", target, headers);
    let view = MetaView::of(&wire, TargetKind::Object).expect("view");
    PutObjectReplica::decode(&view, RequestBody::None).map_err(|error| error.code().as_str().to_owned())
}

// ── routing ───────────────────────────────────────────────────────────────────────────────────

/// Positive — the replica write is reachable once a deployment installs the dialect.
#[test]
fn a_put_naming_a_version_reaches_the_replica_write_once_the_dialect_is_installed() {
    assert_eq!(routed(true, "PUT", &versioned(TARGET), &[]), Some(NAME));
}

/// Negative — the dialect is off unless installed: the query stays an ignored key on `PutObject`.
#[test]
fn n_without_the_dialect_a_put_naming_a_version_is_an_ordinary_put_object() {
    assert_eq!(routed(false, "PUT", &versioned(TARGET), &[]), Some("PutObject"));
}

/// Negative — installing the dialect does not move an ordinary write.
#[test]
fn n_with_the_dialect_a_put_naming_no_version_is_an_ordinary_put_object() {
    assert_eq!(routed(true, "PUT", TARGET, &[]), Some("PutObject"));
}

/// Negative — every sub-resource `PUT` that may also carry a `versionId` keeps its own operation.
#[test]
fn n_a_sub_resource_put_naming_a_version_keeps_its_own_operation() {
    for (query, operation) in [
        ("tagging", "PutObjectTagging"),
        ("acl", "PutObjectAcl"),
        ("retention", "PutObjectRetention"),
        ("legal-hold", "PutObjectLegalHold"),
        ("partNumber=1&uploadId=u1", "UploadPart"),
        ("renameObject", "RenameObject"),
        ("annotation", "PutObjectAnnotation"),
        ("encryption", "UpdateObjectEncryption"),
    ] {
        let target = format!("{TARGET}?{query}&versionId={VERSION}");
        assert_eq!(routed(true, "PUT", &target, &[]), Some(operation), "{target}");
    }
}

/// Negative — a copy that names a version is a copy; the replica row never reads a copy source.
#[test]
fn n_a_copy_naming_a_version_is_still_a_copy() {
    let headers = [("x-amz-copy-source", "/source/a.png")];
    assert_eq!(routed(true, "PUT", &versioned(TARGET), &headers), Some("CopyObject"));
}

/// Negative — only `PUT` is a write; a versioned read is untouched.
#[test]
fn n_a_read_naming_a_version_is_still_a_read() {
    assert_eq!(routed(true, "GET", &versioned(TARGET), &[]), Some("GetObject"));
}

// ── authorisation ─────────────────────────────────────────────────────────────────────────────

/// Negative — the route action is replication, not an ordinary write: holding `s3:PutObject`
/// alone never reaches the decoder.
#[test]
fn n_a_replica_write_is_authorised_as_replication() {
    let auth = PutObjectReplica::spec()
        .auth
        .expect("an operation nobody can authorise does not register");
    assert_eq!(auth.action, "s3:ReplicateObject");
    assert_eq!(auth.resource, ResourceShape::Object);
}

/// Negative — replication alone is not a licence to write: the key is also checked for
/// `s3:PutObject`, unversioned, before the handler runs.
#[test]
fn n_a_replica_write_also_owes_put_object_on_the_key_it_writes() {
    let input = decode(&versioned(TARGET), &[("content-length", "0")]).expect("decodes");
    let resources = PutObjectReplica::derive_resources(&input).expect("a key always derives");
    let mut seen = Vec::new();
    resources.visit(&mut |resource| match resource {
        ResourceRef::Object {
            action,
            bucket,
            key,
            version_id,
            ..
        } => seen.push((action, bucket.is_none(), key.as_str().to_owned(), version_id.map(str::to_owned))),
        other => panic!("a replica write derives an object resource, not {other:?}"),
    });
    assert_eq!(seen, [("s3:PutObject", true, "a.png".to_owned(), None)]);
}

/// Negative — a presigned URL cannot carry a chosen version id, and nobody anonymous can.
#[test]
fn n_a_replica_write_is_header_signed_only() {
    let floor = PutObjectReplica::floor();
    assert!(floor.privileged());
    assert!(!floor.allowed_schemes().allows_presigned());
    assert!(!floor.allowed_schemes().allows_anonymous());
}

// ── the codec ─────────────────────────────────────────────────────────────────────────────────

/// Positive — the version id travels beside every `PutObject` member, decoded by `PutObject`.
#[test]
fn the_replica_codec_carries_the_version_id_beside_the_put_object_input() {
    let headers = [
        ("content-length", "0"),
        ("content-type", "image/png"),
        ("x-amz-meta-origin", "source"),
    ];
    let input = decode(&versioned(TARGET), &headers).expect("decodes");
    assert_eq!(input.version_id, VERSION);
    assert_eq!(input.object.bucket.as_str(), "photos");
    assert_eq!(input.object.key.as_str(), "a.png");
    assert_eq!(input.object.content_type.as_deref(), Some("image/png"));
    assert_eq!(input.object.metadata.get("origin").map(String::as_str), Some("source"));
}

/// Negative — the value is percent-decoded once, not twice.
#[test]
fn n_the_version_id_is_percent_decoded_exactly_once() {
    let input = decode(&format!("{TARGET}?versionId=a%252Bb"), &[("content-length", "0")]).expect("decodes");
    assert_eq!(input.version_id, "a%2Bb");
}

/// Negative — an empty value names no version and is refused, never read as "mint one".
#[test]
fn n_an_empty_version_id_is_refused() {
    assert_eq!(
        decode(&format!("{TARGET}?versionId="), &[("content-length", "0")])
            .err()
            .as_deref(),
        Some("InvalidArgument")
    );
}

/// Negative — the codec does not invent a version for a request the row would never route.
#[test]
fn n_a_request_without_the_query_is_refused_by_the_codec() {
    assert_eq!(decode(TARGET, &[("content-length", "0")]).err().as_deref(), Some("InvalidRequest"));
}

/// Negative — `PutObject`'s own refusals still apply to a replica write.
#[test]
fn n_a_replica_write_keeps_put_objects_refusals() {
    assert_eq!(decode(&versioned(TARGET), &[]).err().as_deref(), Some("MissingContentLength"));
}

/// Negative — the body is handed over live, exactly as `PutObject`'s is, never buffered.
#[test]
fn n_the_replica_body_is_handed_over_as_put_objects_is() {
    assert_eq!(PutObjectReplica::REQUEST_BODY, <PutObject as OperationCodec>::REQUEST_BODY);
}
