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

//! The MinIO bucket-configuration extensions RustFS reads: the same bytes decoded by the gateway
//! and converted through the generated seam, and decoded by the pinned legacy stack's service
//! (built with MinIO support, as RustFS builds it), compared at the configuration the RustFS body
//! is handed.
//!
//! Responsible for: `ExpiryUpdatedAt`, `DelMarkerExpiration` and `ExpiredObjectAllVersions` on
//! PutBucketLifecycleConfiguration, `DeleteReplication` on PutBucketReplication, and
//! `ExcludedPrefixes` / `ExcludeFolders` on PutBucketVersioning — each handed over alike, each
//! absent alike when the document omits it, and a malformed value refused by both stacks — and
//! the read half of the round trip: a configuration RustFS answers through the seam and the
//! gateway's encoder decodes back to exactly what RustFS stored. The tests carry their ruling ids;
//! the register's guard refuses one without.
//! NOT responsible for: persistence (the `dto_bridge` tests), or the RustFS behaviour the members
//! drive.
//! Upstream: the harness, the generated `s3s_0_17_0` seam. Downstream: the request-divergence
//! register.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway_core::codec::{EncodedResponse, MetaView, OperationCodec, RequestBody, ResponseBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

use super::put_object::md5_base64;
use super::s3s::{Body as LegacyBody, S3, S3Request, S3Response, S3Result, service::S3ServiceBuilder};
use super::seam::generated::ops::{
    get_bucket_lifecycle_configuration, get_bucket_replication, put_bucket_lifecycle_configuration, put_bucket_replication,
    put_bucket_versioning,
};
use super::{HOST, block_on, oracle};

/// A request body and its `Content-MD5`: all three writes require one.
type Body<'a> = (&'a [u8], &'a str);

const LIFECYCLE: Body = (
    b"<LifecycleConfiguration><ExpiryUpdatedAt>2026-08-30T12:34:56.123Z</ExpiryUpdatedAt><Rule><ID>r</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>30</Days><ExpiredObjectAllVersions>true</ExpiredObjectAllVersions></Expiration><DelMarkerExpiration><Days>7</Days></DelMarkerExpiration></Rule></LifecycleConfiguration>",
    "ArUafdYSGJGTiAcTF9X1IA==",
);
const LIFECYCLE_PLAIN: Body = (
    b"<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>",
    "MA07QgaP7C/5BEsU9yNEuw==",
);
const LIFECYCLE_BAD_DAYS: Body = (
    b"<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><DelMarkerExpiration><Days>soon</Days></DelMarkerExpiration></Rule></LifecycleConfiguration>",
    "wa5awKiSwPOXj1EFfRCO7g==",
);
const LIFECYCLE_BAD_ALL_VERSIONS: Body = (
    b"<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>30</Days><ExpiredObjectAllVersions>maybe</ExpiredObjectAllVersions></Expiration></Rule></LifecycleConfiguration>",
    "4AuS+kCa5VDjoYVKw0WWmg==",
);
const REPLICATION: Body = (
    b"<ReplicationConfiguration><Role>arn:aws:iam::1:role/r</Role><Rule><ID>r</ID><Status>Enabled</Status><Priority>1</Priority><DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication><DeleteReplication><Status>Enabled</Status></DeleteReplication><Filter><Prefix></Prefix></Filter><Destination><Bucket>arn:aws:s3:::dst</Bucket></Destination></Rule></ReplicationConfiguration>",
    "/gu9x+0VOW0/agdv/3nmZA==",
);
const REPLICATION_PLAIN: Body = (
    b"<ReplicationConfiguration><Role>arn:aws:iam::1:role/r</Role><Rule><ID>r</ID><Status>Enabled</Status><Priority>1</Priority><DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication><Filter><Prefix></Prefix></Filter><Destination><Bucket>arn:aws:s3:::dst</Bucket></Destination></Rule></ReplicationConfiguration>",
    "nlVNDaiuzstkVyrAhAxtgQ==",
);
const REPLICATION_NO_STATUS: Body = (
    b"<ReplicationConfiguration><Role>arn:aws:iam::1:role/r</Role><Rule><ID>r</ID><Status>Enabled</Status><Priority>1</Priority><DeleteReplication></DeleteReplication><Filter><Prefix></Prefix></Filter><Destination><Bucket>arn:aws:s3:::dst</Bucket></Destination></Rule></ReplicationConfiguration>",
    "NUfZM77qGNTWsvS3kNwd0A==",
);
const VERSIONING: Body = (
    b"<VersioningConfiguration><Status>Enabled</Status><ExcludedPrefixes><Prefix>tmp/</Prefix></ExcludedPrefixes><ExcludedPrefixes><Prefix>cache/</Prefix></ExcludedPrefixes><ExcludeFolders>true</ExcludeFolders></VersioningConfiguration>",
    "ovN+75efMfYczOfJLEt4TQ==",
);
const VERSIONING_PLAIN: Body = (
    b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    "8qj8HSeDu3APPMQZVG06WQ==",
);
const VERSIONING_BAD_FOLDERS: Body = (
    b"<VersioningConfiguration><Status>Enabled</Status><ExcludeFolders>maybe</ExcludeFolders></VersioningConfiguration>",
    "4igZoe+OMr1amLENezDJSw==",
);

fn head(query: &str, (body, md5): Body<'_>) -> http::request::Builder {
    http::Request::builder()
        .method("PUT")
        .uri(format!("http://{HOST}/photos?{query}"))
        .header("host", HOST)
        .header("content-md5", md5)
        .header("content-length", body.len().to_string())
}

/// The input the generated decoder reads, or its error code.
fn decode<O: OperationCodec>(query: &str, body: Body<'_>) -> Result<O::Input, String> {
    let request = head(query, body).body(()).map_err(|error| format!("fixture head: {error}"))?;
    let wire = WireRequest::accept(request, &Limits::default()).map_err(|error| format!("wire refusal: {error:?}"))?;
    let view = MetaView::of(&wire, TargetKind::Bucket).map_err(|error| error.code().as_str().to_owned())?;
    O::decode(&view, RequestBody::Buffered(Bytes::copy_from_slice(body.0))).map_err(|error| error.code().as_str().to_owned())
}

/// The lifecycle configuration the gateway hands the RustFS body: decoded, then converted through
/// the seam.
fn lifecycle_handed(body: Body<'_>) -> Result<Option<oracle::BucketLifecycleConfiguration>, String> {
    let input = decode::<dto::PutBucketLifecycleConfiguration>("lifecycle", body)?;
    let converted = put_bucket_lifecycle_configuration::input_to_s3s(input).map_err(|error| error.to_string())?;
    Ok(converted.lifecycle_configuration)
}

fn replication_handed(body: Body<'_>) -> Result<oracle::ReplicationConfiguration, String> {
    let input = decode::<dto::PutBucketReplication>("replication", body)?;
    let converted = put_bucket_replication::input_to_s3s(input).map_err(|error| error.to_string())?;
    Ok(converted.replication_configuration)
}

/// The configuration the gateway hands the RustFS body, in the legacy stack's `Debug` spelling.
fn gateway_lifecycle(body: Body<'_>) -> Result<String, String> {
    Ok(format!("{:?}", lifecycle_handed(body)?))
}

fn gateway_replication(body: Body<'_>) -> Result<String, String> {
    Ok(format!("{:?}", replication_handed(body)?))
}

fn gateway_versioning(body: Body<'_>) -> Result<String, String> {
    let input = decode::<dto::PutBucketVersioning>("versioning", body)?;
    let converted = put_bucket_versioning::input_to_s3s(input).map_err(|error| error.to_string())?;
    Ok(format!("{:?}", converted.versioning_configuration))
}

/// A legacy-stack backend whose three configuration writes record the configuration they are handed.
struct RecordingS3 {
    handed: Arc<Mutex<Option<String>>>,
}

type Answer<T> = Pin<Box<dyn Future<Output = S3Result<S3Response<T>>> + Send + 'static>>;

impl RecordingS3 {
    fn record<T: Default + Send + 'static>(&self, handed: String) -> Answer<T> {
        if let Ok(mut slot) = self.handed.lock() {
            *slot = Some(handed);
        }
        Box::pin(async { Ok(S3Response::new(T::default())) })
    }
}

impl S3 for RecordingS3 {
    // The pinned trait is declared with `#[async_trait]`; these are the signatures that attribute
    // expands a `&self` method to, as in the PutObject harness.
    fn put_bucket_lifecycle_configuration<'life0, 'future>(
        &'life0 self,
        request: S3Request<oracle::PutBucketLifecycleConfigurationInput>,
    ) -> Answer<oracle::PutBucketLifecycleConfigurationOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record(format!("{:?}", request.input.lifecycle_configuration))
    }

    fn put_bucket_replication<'life0, 'future>(
        &'life0 self,
        request: S3Request<oracle::PutBucketReplicationInput>,
    ) -> Answer<oracle::PutBucketReplicationOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record(format!("{:?}", request.input.replication_configuration))
    }

    fn put_bucket_versioning<'life0, 'future>(
        &'life0 self,
        request: S3Request<oracle::PutBucketVersioningInput>,
    ) -> Answer<oracle::PutBucketVersioningOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record(format!("{:?}", request.input.versioning_configuration))
    }
}

/// The configuration the legacy stack's service hands its handler, or the `<Code>` it refused with.
fn legacy(query: &str, body: Body<'_>) -> Result<String, String> {
    let handed = Arc::new(Mutex::new(None));
    let service = S3ServiceBuilder::new(RecordingS3 {
        handed: Arc::clone(&handed),
    })
    .build();
    let request = head(query, body)
        .body(LegacyBody::from(Bytes::copy_from_slice(body.0)))
        .map_err(|error| format!("fixture head: {error}"))?;
    let response = block_on(service.call(request)).map_err(|error| format!("legacy service: {error:?}"))?;
    let (_, mut answer) = response.into_parts();
    let answer = block_on(answer.store_all_limited(1 << 20)).map_err(|error| format!("legacy answer: {error}"))?;
    let recorded = handed.lock().map_err(|_| "the recording slot is poisoned".to_owned())?.take();
    recorded.ok_or_else(|| {
        let text = String::from_utf8_lossy(&answer).into_owned();
        text.split_once("<Code>")
            .and_then(|(_, rest)| rest.split_once("</Code>"))
            .map_or(text.clone(), |(code, _)| code.to_owned())
    })
}

/// Both stacks refuse a malformed value of each member before any handler runs.
fn refused_by_both(query: &str, body: Body<'_>, gateway: fn(Body<'_>) -> Result<String, String>) {
    let gateway = gateway(body);
    let legacy = legacy(query, body);
    assert!(gateway.is_err(), "the gateway handed over {gateway:?}");
    assert!(legacy.is_err(), "the legacy stack handed over {legacy:?}");
}

// ── controls ──────────────────────────────────────────────────────────────────────────────────

/// A document without the extensions is handed over alike too: the members are absent on both.
#[test]
fn n_a_document_without_the_minio_members_is_handed_over_alike() {
    for (query, body, gateway) in [
        ("lifecycle", LIFECYCLE_PLAIN, gateway_lifecycle as fn(Body<'_>) -> Result<String, String>),
        ("replication", REPLICATION_PLAIN, gateway_replication),
        ("versioning", VERSIONING_PLAIN, gateway_versioning),
    ] {
        let handed = gateway(body).expect("the gateway hands the document over");
        assert_eq!(Ok(handed.clone()), legacy(query, body), "{query}");
        // The legacy `Debug` leaves an absent member out, so a named member is a present one.
        for member in [
            "expiry_updated_at",
            "del_marker_expiration",
            "expired_object_all_versions",
            "delete_replication",
            "exclude",
        ] {
            assert!(!handed.contains(member), "{query}: {member} in {handed}");
        }
    }
}

#[test]
fn n_a_malformed_minio_member_is_refused_by_both_stacks() {
    refused_by_both("lifecycle", LIFECYCLE_BAD_DAYS, gateway_lifecycle);
    refused_by_both("lifecycle", LIFECYCLE_BAD_ALL_VERSIONS, gateway_lifecycle);
    refused_by_both("replication", REPLICATION_NO_STATUS, gateway_replication);
    refused_by_both("versioning", VERSIONING_BAD_FOLDERS, gateway_versioning);
}

// ── named divergences (rd-cfg) ────────────────────────────────────────────────────────────────

/// Ruling: `rd-cfg-0002`
#[test]
fn a_lifecycle_expiry_updated_at_is_handed_over_by_both_stacks() {
    let handed = gateway_lifecycle(LIFECYCLE).expect("the gateway hands the document over");
    assert!(handed.contains("expiry_updated_at: Timestamp(2026-08-30 12:34:56.123"), "{handed}");
    assert_eq!(Ok(handed), legacy("lifecycle", LIFECYCLE));
}

/// Ruling: `rd-cfg-0003`
#[test]
fn a_lifecycle_del_marker_expiration_is_handed_over_by_both_stacks() {
    let handed = gateway_lifecycle(LIFECYCLE).expect("the gateway hands the document over");
    assert!(handed.contains("del_marker_expiration: DelMarkerExpiration { days: 7"), "{handed}");
    assert_eq!(Ok(handed), legacy("lifecycle", LIFECYCLE));
}

/// Ruling: `rd-cfg-0004`
#[test]
fn a_lifecycle_expired_object_all_versions_is_handed_over_by_both_stacks() {
    let handed = gateway_lifecycle(LIFECYCLE).expect("the gateway hands the document over");
    assert!(handed.contains("expired_object_all_versions: true"), "{handed}");
    assert_eq!(Ok(handed), legacy("lifecycle", LIFECYCLE));
}

/// Ruling: `rd-cfg-0005`
#[test]
fn a_replication_delete_replication_is_handed_over_by_both_stacks() {
    let handed = gateway_replication(REPLICATION).expect("the gateway hands the document over");
    assert!(
        handed.contains("delete_replication: DeleteReplication { status: DeleteReplicationStatus(\"Enabled\")"),
        "{handed}"
    );
    assert_eq!(Ok(handed), legacy("replication", REPLICATION));
}

/// Ruling: `rd-cfg-0006`
#[test]
fn versioning_excluded_prefixes_and_folders_are_handed_over_by_both_stacks() {
    let handed = gateway_versioning(VERSIONING).expect("the gateway hands the document over");
    assert!(handed.contains("exclude_folders: true"), "{handed}");
    assert!(
        handed.contains("[ExcludedPrefix { prefix: \"tmp/\", .. }, ExcludedPrefix { prefix: \"cache/\", .. }]"),
        "{handed}"
    );
    assert_eq!(Ok(handed), legacy("versioning", VERSIONING));
}

// ── the read half of the round trip (ADR-0033) ────────────────────────────────────────────────

/// The document the gateway answers a bucket-configuration read with, for an output RustFS built.
fn answered<O: OperationCodec>(query: &str, output: O::Output) -> String {
    let head = http::Request::builder()
        .method("GET")
        .uri(format!("http://{HOST}/photos?{query}"))
        .header("host", HOST)
        .body(())
        .expect("a fixture head");
    let wire = WireRequest::accept(head, &Limits::default()).expect("an accepted fixture head");
    let view = MetaView::of(&wire, TargetKind::Bucket).expect("bucket metadata");
    let encoded: EncodedResponse = O::encode(output, &view, 200).expect("the gateway encodes the configuration");
    match encoded.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes).expect("a UTF-8 document"),
        other => panic!("a bucket configuration is a complete document, not {other:?}"),
    }
}

/// A lifecycle configuration RustFS stored, answered through the seam and the gateway's encoder,
/// and the rules the gateway hands RustFS when that answer is written back.
fn lifecycle_read_and_rewritten(body: Body<'_>) -> (Vec<oracle::LifecycleRule>, String, Vec<oracle::LifecycleRule>) {
    let stored = lifecycle_handed(body)
        .expect("the gateway hands the document over")
        .expect("a document with a rule is a configuration");
    let output = get_bucket_lifecycle_configuration::output_from_s3s(oracle::GetBucketLifecycleConfigurationOutput {
        rules: Some(stored.rules.clone()),
        ..Default::default()
    })
    .expect("the seam carries the stored rules");
    let document = answered::<dto::GetBucketLifecycleConfiguration>("lifecycle", output);
    let md5 = md5_base64(document.as_bytes());
    let rewritten = lifecycle_handed((document.as_bytes(), &md5))
        .expect("the gateway reads its own answer")
        .expect("the answer is a configuration");
    (stored.rules, document, rewritten.rules)
}

/// As [`lifecycle_read_and_rewritten`], for a replication configuration.
fn replication_read_and_rewritten(
    body: Body<'_>,
) -> (oracle::ReplicationConfiguration, String, oracle::ReplicationConfiguration) {
    let stored = replication_handed(body).expect("the gateway hands the document over");
    let output = get_bucket_replication::output_from_s3s(oracle::GetBucketReplicationOutput {
        replication_configuration: Some(stored.clone()),
    })
    .expect("the seam carries the stored configuration");
    let document = answered::<dto::GetBucketReplication>("replication", output);
    let md5 = md5_base64(document.as_bytes());
    let rewritten = replication_handed((document.as_bytes(), &md5)).expect("the gateway reads its own answer");
    (stored, document, rewritten)
}

/// Positive — a lifecycle configuration RustFS stored with MinIO's rule members is answered with
/// them, and writing the answer back hands RustFS exactly the rules it stored, so neither a
/// client's read-modify-write through the gateway nor a rollback to legacy loses one. The legacy
/// read (its `GetBucketLifecycleConfigurationOutput`) carries no `ExpiryUpdatedAt`, so there is
/// none to round-trip.
#[test]
fn a_stored_lifecycle_keeps_the_minio_rule_members_through_a_read_and_a_rewrite() {
    let (stored, document, rewritten) = lifecycle_read_and_rewritten(LIFECYCLE);
    assert!(
        document.contains("<DelMarkerExpiration><Days>7</Days></DelMarkerExpiration>"),
        "{document}"
    );
    assert!(
        document.contains("<ExpiredObjectAllVersions>true</ExpiredObjectAllVersions>"),
        "{document}"
    );
    assert_eq!(rewritten, stored, "{document}");
}

/// Positive — as above for MinIO's `DeleteReplication` on a replication rule.
#[test]
fn a_stored_replication_keeps_the_minio_rule_member_through_a_read_and_a_rewrite() {
    let (stored, document, rewritten) = replication_read_and_rewritten(REPLICATION);
    assert!(
        document.contains("<DeleteReplication><Status>Enabled</Status></DeleteReplication>"),
        "{document}"
    );
    assert_eq!(rewritten, stored, "{document}");
}

/// Negative — a stored configuration without the members is answered without them, and its
/// rewrite gains none: the read half invents nothing RustFS did not store.
#[test]
fn n_a_stored_configuration_without_the_minio_members_is_answered_and_rewritten_without_them() {
    let (stored, document, rewritten) = lifecycle_read_and_rewritten(LIFECYCLE_PLAIN);
    for element in ["DelMarkerExpiration", "ExpiredObjectAllVersions", "ExpiryUpdatedAt"] {
        assert!(!document.contains(element), "{element} in {document}");
    }
    assert_eq!(rewritten, stored, "{document}");

    let (stored, document, rewritten) = replication_read_and_rewritten(REPLICATION_PLAIN);
    assert!(!document.contains("DeleteReplication>"), "{document}");
    assert_eq!(rewritten, stored, "{document}");
}
