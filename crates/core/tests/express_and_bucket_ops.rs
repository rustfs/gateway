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

//! Route, parameter, security-floor, redaction, and XML codec contracts for `CreateSession`,
//! the 18 promoted bucket subresource write/delete operations, and `PutBucketPolicy` `204`.
//!
//! Responsible for: proving every newly promoted operation routes accurately without leaking into
//! `CreateBucket`, `DeleteBucket`, `ListObjects`, or `DeleteObjects`; verifying `c-param-1001`
//! `400 InvalidArgument` for all 8 keyed-by-`id` write/delete operations; verifying fail-closed
//! union decoding (`AnalyticsFilter`, `MetricsFilter`) and AWS wire XML root checks for
//! `UpdateBucketMetadata*TableConfiguration`; and proving `SessionCredentials` and
//! `MetadataTableEncryptionConfiguration` redact sensitive fields in `Debug`.
//! NOT responsible for: full HTTP pipeline authentication (`crates/gateway`) or security-floor
//! unit details (`crates/sig`).
//! Upstream: `rustfs-gateway-core`, `rustfs-gateway-types`, `support`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::{Request, StatusCode};
use rustfs_gateway_core::codec::response::ResponseBody;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::dispatch::{NOT_REGISTERED_MESSAGE, Router};
use rustfs_gateway_core::op::{Operation, ResourceShape};
use rustfs_gateway_core::registry::{HandlerDeadlineClass, OperationSpec, Registry};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{HeaderTokenClaim, SecurityFloor, SigService};
use rustfs_gateway_types::{ErrorCode, Timestamp, dto};

use crate::support::Req;

fn accepted(method: &str, target: &str, headers: &[(&str, &str)]) -> WireRequest<()> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(()).expect("valid fixture request");
    WireRequest::accept(request, &Limits::default()).expect("acceptable fixture request")
}

fn body_text(response: rustfs_gateway_core::codec::response::EncodedResponse) -> String {
    match response.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes.to_vec()).expect("UTF-8 XML"),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("expected complete response body"),
    }
}

fn register_promoted_specs() -> Registry {
    let mut registry = Registry::new();
    let specs: [&'static OperationSpec; 19] = [
        <dto::CreateSession as Operation>::spec(),
        <dto::PutBucketOwnershipControls as Operation>::spec(),
        <dto::DeleteBucketOwnershipControls as Operation>::spec(),
        <dto::PutBucketAbac as Operation>::spec(),
        <dto::PutBucketIntelligentTieringConfiguration as Operation>::spec(),
        <dto::DeleteBucketIntelligentTieringConfiguration as Operation>::spec(),
        <dto::PutBucketAnalyticsConfiguration as Operation>::spec(),
        <dto::DeleteBucketAnalyticsConfiguration as Operation>::spec(),
        <dto::PutBucketInventoryConfiguration as Operation>::spec(),
        <dto::DeleteBucketInventoryConfiguration as Operation>::spec(),
        <dto::PutBucketMetricsConfiguration as Operation>::spec(),
        <dto::DeleteBucketMetricsConfiguration as Operation>::spec(),
        <dto::CreateBucketMetadataConfiguration as Operation>::spec(),
        <dto::CreateBucketMetadataTableConfiguration as Operation>::spec(),
        <dto::DeleteBucketMetadataConfiguration as Operation>::spec(),
        <dto::DeleteBucketMetadataTableConfiguration as Operation>::spec(),
        <dto::UpdateBucketMetadataAnnotationTableConfiguration as Operation>::spec(),
        <dto::UpdateBucketMetadataInventoryTableConfiguration as Operation>::spec(),
        <dto::UpdateBucketMetadataJournalTableConfiguration as Operation>::spec(),
    ];
    for spec in specs {
        registry.register(spec).expect("promoted op spec is registrable");
    }
    registry
}

// ── negative ───────────────────────────────────────────────────────────────────────────────────

/// Negative — c-param-1001: all 8 keyed-by-`id` bucket configuration writes and deletes must
/// route to their own operation and fail with `400 InvalidArgument` when `id` is missing, never
/// `501 NotImplemented` and never falling through to `CreateBucket` / `DeleteBucket`.
#[test]
fn n_all_eight_keyed_bucket_ops_return_400_invalid_argument_when_id_is_missing() {
    let router = Router::from_generated(register_promoted_specs()).expect("generated table builds");
    for (line, expected_op) in [
        ("PUT /bucket?intelligent-tiering", "PutBucketIntelligentTieringConfiguration"),
        ("DELETE /bucket?intelligent-tiering", "DeleteBucketIntelligentTieringConfiguration"),
        ("PUT /bucket?analytics", "PutBucketAnalyticsConfiguration"),
        ("DELETE /bucket?analytics", "DeleteBucketAnalyticsConfiguration"),
        ("PUT /bucket?inventory", "PutBucketInventoryConfiguration"),
        ("DELETE /bucket?inventory", "DeleteBucketInventoryConfiguration"),
        ("PUT /bucket?metrics", "PutBucketMetricsConfiguration"),
        ("DELETE /bucket?metrics", "DeleteBucketMetricsConfiguration"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("missing `id` must be refused");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{line}");
        assert_ne!(error.status(), StatusCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(*error.code(), ErrorCode::INVALID_ARGUMENT, "{line}");
        assert_eq!(error.message(), "The required parameter 'id' is missing", "{line}");
        assert_eq!(error.operation(), Some(expected_op), "{line}");
    }
}

/// Negative — when a backend only registers the generic bucket neighbours (`CreateBucket`,
/// `DeleteBucket`, `ListObjects`, `DeleteObjects`), all 19 promoted operations still refuse by
/// name (`501 NOT_REGISTERED_MESSAGE`) rather than mutating or listing the bucket.
#[test]
fn n_unregistered_promoted_ops_refuse_by_name_never_hitting_neighbours() {
    let mut registry = Registry::new();
    for spec in [
        <dto::CreateBucket as Operation>::spec(),
        <dto::DeleteBucket as Operation>::spec(),
        <dto::ListObjects as Operation>::spec(),
        <dto::DeleteObjects as Operation>::spec(),
    ] {
        registry.register(spec).expect("neighbour spec is registrable");
    }
    let router = Router::from_generated(registry).expect("generated table builds");

    for (line, expected_op) in [
        ("GET /bucket?session", "CreateSession"),
        ("PUT /bucket?ownershipControls", "PutBucketOwnershipControls"),
        ("DELETE /bucket?ownershipControls", "DeleteBucketOwnershipControls"),
        ("PUT /bucket?abac", "PutBucketAbac"),
        ("PUT /bucket?intelligent-tiering&id=c1", "PutBucketIntelligentTieringConfiguration"),
        ("DELETE /bucket?intelligent-tiering&id=c1", "DeleteBucketIntelligentTieringConfiguration"),
        ("PUT /bucket?analytics&id=c1", "PutBucketAnalyticsConfiguration"),
        ("DELETE /bucket?analytics&id=c1", "DeleteBucketAnalyticsConfiguration"),
        ("PUT /bucket?inventory&id=c1", "PutBucketInventoryConfiguration"),
        ("DELETE /bucket?inventory&id=c1", "DeleteBucketInventoryConfiguration"),
        ("PUT /bucket?metrics&id=c1", "PutBucketMetricsConfiguration"),
        ("DELETE /bucket?metrics&id=c1", "DeleteBucketMetricsConfiguration"),
        ("POST /bucket?metadataConfiguration", "CreateBucketMetadataConfiguration"),
        ("POST /bucket?metadataTable", "CreateBucketMetadataTableConfiguration"),
        ("DELETE /bucket?metadataConfiguration", "DeleteBucketMetadataConfiguration"),
        ("DELETE /bucket?metadataTable", "DeleteBucketMetadataTableConfiguration"),
        ("PUT /bucket?metadataAnnotationTable", "UpdateBucketMetadataAnnotationTableConfiguration"),
        ("PUT /bucket?metadataInventoryTable", "UpdateBucketMetadataInventoryTableConfiguration"),
        ("PUT /bucket?metadataJournalTable", "UpdateBucketMetadataJournalTableConfiguration"),
    ] {
        let error = router
            .dispatch(&Req::new(line).parts())
            .expect_err("unregistered promoted op must refuse");
        assert_eq!(error.status(), StatusCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(*error.code(), ErrorCode::NOT_IMPLEMENTED, "{line}");
        assert_eq!(error.message(), NOT_REGISTERED_MESSAGE, "{line}");
        assert_eq!(error.operation(), Some(expected_op), "{line}");
    }
}

/// Negative — `CreateSession` floor is privileged, requires SigV4 under `s3express`, refuses S3
/// Express session-token auth, and refuses host header-token auth (ADR-0054).
#[test]
fn n_create_session_floor_is_privileged_and_refuses_session_and_header_tokens() {
    let floor = <dto::CreateSession as Operation>::floor();
    assert!(floor.privileged());
    assert!(floor.requires_sigv4_under_every_policy());
    assert!(floor.refuses_s3_express_session_auth());
    assert_eq!(floor.service(), SigService::S3Express);
    assert!(!floor.allowed_schemes().allows_presigned());
    assert!(!floor.allowed_schemes().allows_anonymous());

    let claim = HeaderTokenClaim::new("x-auth-token").expect("valid claim");
    let security = SecurityFloor::new().with_header_token_claim(claim);
    assert!(!security.admits_header_token(floor));
}

/// Negative — `SessionCredentials` redacts `secret_access_key` and `session_token` in `Debug`.
#[test]
fn n_session_credentials_debug_redacts_secret_and_session_token() {
    let creds = dto::SessionCredentials {
        access_key_id: "ASIAIOSFODNN7EXAMPLE".to_owned(),
        secret_access_key: "SUPER_SECRET_KEY_SENTINEL".to_owned(),
        session_token: "SUPER_SESSION_TOKEN_SENTINEL".to_owned(),
        expiration: Timestamp::from_secs(1_767_323_045),
    };
    let rendered = format!("{creds:?} {creds:#?}");
    assert!(rendered.contains("ASIAIOSFODNN7EXAMPLE"), "{rendered}");
    assert!(!rendered.contains("SUPER_SECRET_KEY_SENTINEL"), "{rendered}");
    assert!(!rendered.contains("SUPER_SESSION_TOKEN_SENTINEL"), "{rendered}");
}

/// Negative — `MetadataTableEncryptionConfiguration` redacts `kms_key_arn` in `Debug`.
#[test]
fn n_metadata_encryption_debug_redacts_kms_key_arn() {
    let enc = dto::MetadataTableEncryptionConfiguration {
        sse_algorithm: dto::SseAlgorithm::AWS_KMS,
        kms_key_arn: Some("arn:aws:kms:us-east-1:111122223333:key/secret-key-id".to_owned()),
    };
    let rendered = format!("{enc:?} {enc:#?}");
    assert!(!rendered.contains("secret-key-id"), "{rendered}");
}

/// Negative — request-side union decoding for `AnalyticsFilter` and `MetricsFilter` fails closed
/// on empty unions, multiple variants, and unknown child elements.
#[test]
fn n_analytics_and_metrics_union_filter_fail_closed_on_empty_multiple_and_unknown_variants() {
    let analytics_req = accepted("PUT", "/bucket?analytics&id=a1", &[]);
    let analytics_view = MetaView::of(&analytics_req, TargetKind::Bucket).expect("view");
    for bad_xml in [
        "<AnalyticsConfiguration><Id>a1</Id><Filter></Filter><StorageClassAnalysis/></AnalyticsConfiguration>",
        "<AnalyticsConfiguration><Id>a1</Id><Filter><Prefix>p/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></Filter><StorageClassAnalysis/></AnalyticsConfiguration>",
        "<AnalyticsConfiguration><Id>a1</Id><Filter><UnknownVariant>x</UnknownVariant></Filter><StorageClassAnalysis/></AnalyticsConfiguration>",
    ] {
        let error = dto::PutBucketAnalyticsConfiguration::decode(
            &analytics_view,
            RequestBody::Buffered(Bytes::copy_from_slice(bad_xml.as_bytes())),
        )
        .expect_err("malformed AnalyticsFilter union must fail closed");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{bad_xml}: {error}");
        assert_eq!(error.code(), &ErrorCode::MALFORMED_XML, "{bad_xml}: {error}");
    }

    let metrics_req = accepted("PUT", "/bucket?metrics&id=m1", &[]);
    let metrics_view = MetaView::of(&metrics_req, TargetKind::Bucket).expect("view");
    for bad_xml in [
        "<MetricsConfiguration><Id>m1</Id><Filter></Filter></MetricsConfiguration>",
        "<MetricsConfiguration><Id>m1</Id><Filter><Prefix>p/</Prefix><AccessPointArn>arn:aws:s3:us-east-1:1:accesspoint/ap</AccessPointArn></Filter></MetricsConfiguration>",
        "<MetricsConfiguration><Id>m1</Id><Filter><Bogus>1</Bogus></Filter></MetricsConfiguration>",
    ] {
        let error = dto::PutBucketMetricsConfiguration::decode(
            &metrics_view,
            RequestBody::Buffered(Bytes::copy_from_slice(bad_xml.as_bytes())),
        )
        .expect_err("malformed MetricsFilter union must fail closed");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{bad_xml}: {error}");
        assert_eq!(error.code(), &ErrorCode::MALFORMED_XML, "{bad_xml}: {error}");
    }
}

/// Negative — the three `UpdateBucketMetadata*TableConfiguration` codecs reject the Smithy
/// `*Updates` shape names and arbitrary wrong root elements; only the AWS wire root elements
/// (`AnnotationTableConfiguration`, `InventoryTableConfiguration`, `JournalTableConfiguration`)
/// decode.
#[test]
fn n_metadata_table_updates_reject_smithy_updates_root_names() {
    let ann_req = accepted("PUT", "/bucket?metadataAnnotationTable", &[]);
    let ann_view = MetaView::of(&ann_req, TargetKind::Bucket).expect("view");
    let err = dto::UpdateBucketMetadataAnnotationTableConfiguration::decode(
        &ann_view,
        RequestBody::Buffered(Bytes::from_static(
            b"<AnnotationTableConfigurationUpdates><ConfigurationState>ENABLED</ConfigurationState></AnnotationTableConfigurationUpdates>",
        )),
    )
    .expect_err("Smithy shape name must not be accepted as wire root");
    assert_eq!(err.code(), &ErrorCode::MALFORMED_XML);

    let inv_req = accepted("PUT", "/bucket?metadataInventoryTable", &[]);
    let inv_view = MetaView::of(&inv_req, TargetKind::Bucket).expect("view");
    let err = dto::UpdateBucketMetadataInventoryTableConfiguration::decode(
        &inv_view,
        RequestBody::Buffered(Bytes::from_static(
            b"<InventoryTableConfigurationUpdates><ConfigurationState>ENABLED</ConfigurationState></InventoryTableConfigurationUpdates>",
        )),
    )
    .expect_err("Smithy shape name must not be accepted as wire root");
    assert_eq!(err.code(), &ErrorCode::MALFORMED_XML);

    let jrn_req = accepted("PUT", "/bucket?metadataJournalTable", &[]);
    let jrn_view = MetaView::of(&jrn_req, TargetKind::Bucket).expect("view");
    let err = dto::UpdateBucketMetadataJournalTableConfiguration::decode(
        &jrn_view,
        RequestBody::Buffered(Bytes::from_static(
            b"<JournalTableConfigurationUpdates><RecordExpiration><Expiration>DISABLED</Expiration></RecordExpiration></JournalTableConfigurationUpdates>",
        )),
    )
    .expect_err("Smithy shape name must not be accepted as wire root");
    assert_eq!(err.code(), &ErrorCode::MALFORMED_XML);
}

/// Negative — promoted XML-body write codecs refuse empty bodies and missing required members.
#[test]
fn n_promoted_write_codecs_refuse_empty_or_incomplete_xml() {
    let ow_req = accepted("PUT", "/bucket?ownershipControls", &[]);
    let ow_view = MetaView::of(&ow_req, TargetKind::Bucket).expect("view");
    assert_eq!(
        dto::PutBucketOwnershipControls::decode(&ow_view, RequestBody::Buffered(Bytes::new()))
            .expect_err("empty body")
            .code(),
        &ErrorCode::MALFORMED_XML
    );

    let abac_req = accepted("PUT", "/bucket?abac", &[]);
    let abac_view = MetaView::of(&abac_req, TargetKind::Bucket).expect("view");
    assert_eq!(
        dto::PutBucketAbac::decode(&abac_view, RequestBody::Buffered(Bytes::from_static(b"<Wrong/>")))
            .expect_err("wrong root")
            .code(),
        &ErrorCode::MALFORMED_XML
    );

    let it_req = accepted("PUT", "/bucket?intelligent-tiering&id=t1", &[]);
    let it_view = MetaView::of(&it_req, TargetKind::Bucket).expect("view");
    assert_eq!(
        dto::PutBucketIntelligentTieringConfiguration::decode(
            &it_view,
            RequestBody::Buffered(Bytes::from_static(
                b"<IntelligentTieringConfiguration><Id>t1</Id></IntelligentTieringConfiguration>"
            )),
        )
        .expect_err("missing required Status")
        .code(),
        &ErrorCode::MALFORMED_XML
    );

    let inv_req = accepted("PUT", "/bucket?inventory&id=i1", &[]);
    let inv_view = MetaView::of(&inv_req, TargetKind::Bucket).expect("view");
    assert_eq!(
        dto::PutBucketInventoryConfiguration::decode(
            &inv_view,
            RequestBody::Buffered(Bytes::from_static(b"<InventoryConfiguration><Id>i1</Id></InventoryConfiguration>")),
        )
        .expect_err("missing required InventoryConfiguration fields")
        .code(),
        &ErrorCode::MALFORMED_XML
    );

    let meta_req = accepted("POST", "/bucket?metadataConfiguration", &[]);
    let meta_view = MetaView::of(&meta_req, TargetKind::Bucket).expect("view");
    assert_eq!(
        dto::CreateBucketMetadataConfiguration::decode(
            &meta_view,
            RequestBody::Buffered(Bytes::from_static(b"<MetadataConfiguration/>")),
        )
        .expect_err("missing required JournalTableConfiguration")
        .code(),
        &ErrorCode::MALFORMED_XML
    );

    let table_req = accepted("POST", "/bucket?metadataTable", &[]);
    let table_view = MetaView::of(&table_req, TargetKind::Bucket).expect("view");
    assert_eq!(
        dto::CreateBucketMetadataTableConfiguration::decode(
            &table_view,
            RequestBody::Buffered(Bytes::from_static(b"<MetadataTableConfiguration/>")),
        )
        .expect_err("missing required S3TablesDestination")
        .code(),
        &ErrorCode::MALFORMED_XML
    );
}

/// Negative — `PutBucketPolicy` and every promoted DELETE operation declare `204 No Content`,
/// never `200 OK`.
#[test]
fn n_put_bucket_policy_and_promoted_deletes_declare_204_not_200() {
    let specs: [(&str, &'static OperationSpec); 8] = [
        ("PutBucketPolicy", <dto::PutBucketPolicy as Operation>::spec()),
        ("DeleteBucketOwnershipControls", <dto::DeleteBucketOwnershipControls as Operation>::spec()),
        (
            "DeleteBucketIntelligentTieringConfiguration",
            <dto::DeleteBucketIntelligentTieringConfiguration as Operation>::spec(),
        ),
        (
            "DeleteBucketAnalyticsConfiguration",
            <dto::DeleteBucketAnalyticsConfiguration as Operation>::spec(),
        ),
        (
            "DeleteBucketInventoryConfiguration",
            <dto::DeleteBucketInventoryConfiguration as Operation>::spec(),
        ),
        (
            "DeleteBucketMetricsConfiguration",
            <dto::DeleteBucketMetricsConfiguration as Operation>::spec(),
        ),
        (
            "DeleteBucketMetadataConfiguration",
            <dto::DeleteBucketMetadataConfiguration as Operation>::spec(),
        ),
        (
            "DeleteBucketMetadataTableConfiguration",
            <dto::DeleteBucketMetadataTableConfiguration as Operation>::spec(),
        ),
    ];
    for (name, spec) in specs {
        assert_eq!(spec.success_status, 204, "{name}");
        assert_ne!(spec.success_status, 200, "{name}");
    }
}

/// Negative — decoding a keyed DELETE directly without `id` still fails with `400 InvalidArgument`.
#[test]
fn n_keyed_delete_codec_refuses_missing_id_query_parameter() {
    let req = accepted("DELETE", "/bucket?metrics", &[]);
    let view = MetaView::of(&req, TargetKind::Bucket).expect("view");
    let err = dto::DeleteBucketMetricsConfiguration::decode(&view, RequestBody::None).expect_err("missing id");
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    assert_eq!(err.code(), &ErrorCode::INVALID_ARGUMENT);
}

// ── positive ───────────────────────────────────────────────────────────────────────────────────

/// Positive — `CreateSession` decodes `x-amz-create-session-mode` and SSE headers, and encodes
/// `<CreateSessionResult><Credentials>...</Credentials></CreateSessionResult>` plus SSE headers.
#[test]
fn create_session_codec_decodes_headers_and_encodes_xml_and_sse_headers() {
    let req = accepted(
        "GET",
        "/dir-bucket?session",
        &[
            ("x-amz-create-session-mode", "ReadOnly"),
            ("x-amz-server-side-encryption", "aws:kms"),
            ("x-amz-server-side-encryption-aws-kms-key-id", "arn:aws:kms:us-east-1:1:key/k1"),
            ("x-amz-server-side-encryption-context", "e30="),
            ("x-amz-server-side-encryption-bucket-key-enabled", "true"),
        ],
    );
    let view = MetaView::of(&req, TargetKind::Bucket).expect("view");
    let input = dto::CreateSession::decode(&view, RequestBody::None).expect("decodes");
    assert_eq!(input.bucket.as_str(), "dir-bucket");
    assert_eq!(input.session_mode, Some(dto::SessionMode::READONLY));
    assert_eq!(input.server_side_encryption, Some(dto::ServerSideEncryption::AWS_KMS));
    assert_eq!(input.ssekms_key_id.as_deref(), Some("arn:aws:kms:us-east-1:1:key/k1"));
    assert_eq!(input.ssekms_encryption_context.as_deref(), Some("e30="));
    assert_eq!(input.bucket_key_enabled, Some(true));

    let output = dto::CreateSessionOutput {
        server_side_encryption: Some(dto::ServerSideEncryption::AWS_KMS),
        ssekms_key_id: Some("arn:aws:kms:us-east-1:1:key/k1".to_owned()),
        ssekms_encryption_context: Some("e30=".to_owned()),
        bucket_key_enabled: Some(true),
        credentials: dto::SessionCredentials {
            access_key_id: "ASIAIOSFODNN7EXAMPLE".to_owned(),
            secret_access_key: "secret-value".to_owned(),
            session_token: "express-token-value".to_owned(),
            expiration: Timestamp::from_secs(1_767_323_045),
        },
    };
    let encoded = dto::CreateSession::encode(output, &view, 200).expect("encodes");
    assert_eq!(encoded.status, 200);
    assert!(
        encoded
            .headers
            .iter()
            .any(|(k, v)| k == "x-amz-server-side-encryption" && v == "aws:kms")
    );
    assert!(
        encoded
            .headers
            .iter()
            .any(|(k, v)| k == "x-amz-server-side-encryption-bucket-key-enabled" && v == "true")
    );
    let xml = body_text(encoded);
    assert!(xml.contains("<CreateSessionResult"), "{xml}");
    assert!(xml.contains("<Credentials>"), "{xml}");
    assert!(xml.contains("<AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>"), "{xml}");
    assert!(xml.contains("<SecretAccessKey>secret-value</SecretAccessKey>"), "{xml}");
    assert!(xml.contains("<SessionToken>express-token-value</SessionToken>"), "{xml}");
    assert!(xml.contains("<Expiration>2026-01-02T03:04:05.000Z</Expiration>"), "{xml}");
}

/// Positive — all 19 newly promoted operations dispatch when registered, carry their AWS IAM
/// action on `ResourceShape::Bucket`, and classify into `HandlerDeadlineClass::Standard`.
#[test]
fn all_19_promoted_ops_dispatch_and_declare_iam_actions_and_standard_deadlines() {
    let router = Router::from_generated(register_promoted_specs()).expect("generated table builds");
    let cases: [(&str, &str, &str); 19] = [
        ("GET /bucket?session", "CreateSession", "s3express:CreateSession"),
        (
            "PUT /bucket?ownershipControls",
            "PutBucketOwnershipControls",
            "s3:PutBucketOwnershipControls",
        ),
        (
            "DELETE /bucket?ownershipControls",
            "DeleteBucketOwnershipControls",
            "s3:PutBucketOwnershipControls",
        ),
        ("PUT /bucket?abac", "PutBucketAbac", "s3:PutBucketAbac"),
        (
            "PUT /bucket?intelligent-tiering&id=it1",
            "PutBucketIntelligentTieringConfiguration",
            "s3:PutIntelligentTieringConfiguration",
        ),
        (
            "DELETE /bucket?intelligent-tiering&id=it1",
            "DeleteBucketIntelligentTieringConfiguration",
            "s3:PutIntelligentTieringConfiguration",
        ),
        (
            "PUT /bucket?analytics&id=a1",
            "PutBucketAnalyticsConfiguration",
            "s3:PutAnalyticsConfiguration",
        ),
        (
            "DELETE /bucket?analytics&id=a1",
            "DeleteBucketAnalyticsConfiguration",
            "s3:PutAnalyticsConfiguration",
        ),
        (
            "PUT /bucket?inventory&id=i1",
            "PutBucketInventoryConfiguration",
            "s3:PutInventoryConfiguration",
        ),
        (
            "DELETE /bucket?inventory&id=i1",
            "DeleteBucketInventoryConfiguration",
            "s3:PutInventoryConfiguration",
        ),
        ("PUT /bucket?metrics&id=m1", "PutBucketMetricsConfiguration", "s3:PutMetricsConfiguration"),
        (
            "DELETE /bucket?metrics&id=m1",
            "DeleteBucketMetricsConfiguration",
            "s3:PutMetricsConfiguration",
        ),
        (
            "POST /bucket?metadataConfiguration",
            "CreateBucketMetadataConfiguration",
            "s3:CreateBucketMetadataTableConfiguration",
        ),
        (
            "POST /bucket?metadataTable",
            "CreateBucketMetadataTableConfiguration",
            "s3:CreateBucketMetadataTableConfiguration",
        ),
        (
            "DELETE /bucket?metadataConfiguration",
            "DeleteBucketMetadataConfiguration",
            "s3:DeleteBucketMetadataTableConfiguration",
        ),
        (
            "DELETE /bucket?metadataTable",
            "DeleteBucketMetadataTableConfiguration",
            "s3:DeleteBucketMetadataTableConfiguration",
        ),
        (
            "PUT /bucket?metadataAnnotationTable",
            "UpdateBucketMetadataAnnotationTableConfiguration",
            "s3:UpdateBucketMetadataAnnotationTableConfiguration",
        ),
        (
            "PUT /bucket?metadataInventoryTable",
            "UpdateBucketMetadataInventoryTableConfiguration",
            "s3:UpdateBucketMetadataInventoryTableConfiguration",
        ),
        (
            "PUT /bucket?metadataJournalTable",
            "UpdateBucketMetadataJournalTableConfiguration",
            "s3:UpdateBucketMetadataJournalTableConfiguration",
        ),
    ];
    for (line, expected_op, expected_action) in cases {
        let dispatch = router
            .dispatch(&Req::new(line).parts())
            .unwrap_or_else(|e| panic!("{line} failed: {e}"));
        assert_eq!(dispatch.entry.op_name, expected_op, "{line}");
        let auth = dispatch.spec.auth.as_ref().expect("auth requirement");
        assert_eq!(auth.action, expected_action, "{expected_op}");
        assert_eq!(auth.resource, ResourceShape::Bucket, "{expected_op}");
        assert_eq!(dispatch.spec.deadline_class(), Some(HandlerDeadlineClass::Standard), "{expected_op}");
    }
}

/// Positive — `PutBucketAnalyticsConfiguration` and `PutBucketMetricsConfiguration` decode each
/// union variant (`Prefix`, `Tag`, `AccessPointArn`, `And`).
#[test]
fn analytics_and_metrics_put_decode_valid_union_filters() {
    let a_req = accepted("PUT", "/bucket?analytics&id=a1", &[]);
    let a_view = MetaView::of(&a_req, TargetKind::Bucket).expect("view");
    let a_xml = r#"<AnalyticsConfiguration><Id>a1</Id><Filter><And><Prefix>logs/</Prefix><Tag><Key>env</Key><Value>prod</Value></Tag></And></Filter><StorageClassAnalysis/></AnalyticsConfiguration>"#;
    let a_in = dto::PutBucketAnalyticsConfiguration::decode(&a_view, RequestBody::Buffered(Bytes::from_static(a_xml.as_bytes())))
        .expect("decodes AnalyticsFilter::And");
    assert_eq!(a_in.id, "a1");
    assert!(matches!(a_in.analytics_configuration.filter, Some(dto::AnalyticsFilter::And(_))));

    let m_req = accepted("PUT", "/bucket?metrics&id=m1", &[]);
    let m_view = MetaView::of(&m_req, TargetKind::Bucket).expect("view");
    let m_xml = r#"<MetricsConfiguration><Id>m1</Id><Filter><AccessPointArn>arn:aws:s3:us-east-1:111122223333:accesspoint/ap</AccessPointArn></Filter></MetricsConfiguration>"#;
    let m_in = dto::PutBucketMetricsConfiguration::decode(&m_view, RequestBody::Buffered(Bytes::from_static(m_xml.as_bytes())))
        .expect("decodes MetricsFilter::AccessPointArn");
    assert_eq!(m_in.id, "m1");
    assert!(matches!(m_in.metrics_configuration.filter, Some(dto::MetricsFilter::AccessPointArn(_))));
}

/// Positive — all 5 S3 Metadata create/update codecs decode valid AWS wire XML documents.
#[test]
fn metadata_create_and_update_codecs_decode_aws_wire_xml_roots() {
    let c2_req = accepted("POST", "/bucket?metadataConfiguration", &[]);
    let c2_view = MetaView::of(&c2_req, TargetKind::Bucket).expect("view");
    let c2_xml = r#"<MetadataConfiguration><JournalTableConfiguration><RecordExpiration><Expiration>ENABLED</Expiration><Days>7</Days></RecordExpiration></JournalTableConfiguration></MetadataConfiguration>"#;
    let c2 =
        dto::CreateBucketMetadataConfiguration::decode(&c2_view, RequestBody::Buffered(Bytes::from_static(c2_xml.as_bytes())))
            .expect("decodes V2 create");
    assert_eq!(c2.metadata_configuration.journal_table_configuration.record_expiration.days, Some(7));

    let c1_req = accepted("POST", "/bucket?metadataTable", &[]);
    let c1_view = MetaView::of(&c1_req, TargetKind::Bucket).expect("view");
    let c1_xml = r#"<MetadataTableConfiguration><S3TablesDestination><TableBucketArn>arn:aws:s3tables:us-east-1:1:bucket/b</TableBucketArn><TableName>tbl</TableName></S3TablesDestination></MetadataTableConfiguration>"#;
    let c1 = dto::CreateBucketMetadataTableConfiguration::decode(
        &c1_view,
        RequestBody::Buffered(Bytes::from_static(c1_xml.as_bytes())),
    )
    .expect("decodes V1 create");
    assert_eq!(c1.metadata_table_configuration.s3tables_destination.table_name, "tbl");

    let ann_req = accepted("PUT", "/bucket?metadataAnnotationTable", &[]);
    let ann_view = MetaView::of(&ann_req, TargetKind::Bucket).expect("view");
    let ann_xml =
        r#"<AnnotationTableConfiguration><ConfigurationState>ENABLED</ConfigurationState></AnnotationTableConfiguration>"#;
    let ann = dto::UpdateBucketMetadataAnnotationTableConfiguration::decode(
        &ann_view,
        RequestBody::Buffered(Bytes::from_static(ann_xml.as_bytes())),
    )
    .expect("decodes annotation table update");
    assert_eq!(ann.annotation_table_configuration.configuration_state, dto::ConfigurationState::ENABLED);

    let inv_req = accepted("PUT", "/bucket?metadataInventoryTable", &[]);
    let inv_view = MetaView::of(&inv_req, TargetKind::Bucket).expect("view");
    let inv_xml =
        r#"<InventoryTableConfiguration><ConfigurationState>DISABLED</ConfigurationState></InventoryTableConfiguration>"#;
    let inv = dto::UpdateBucketMetadataInventoryTableConfiguration::decode(
        &inv_view,
        RequestBody::Buffered(Bytes::from_static(inv_xml.as_bytes())),
    )
    .expect("decodes inventory table update");
    assert_eq!(inv.inventory_table_configuration.configuration_state, dto::ConfigurationState::DISABLED);

    let jrn_req = accepted("PUT", "/bucket?metadataJournalTable", &[]);
    let jrn_view = MetaView::of(&jrn_req, TargetKind::Bucket).expect("view");
    let jrn_xml = r#"<JournalTableConfiguration><RecordExpiration><Expiration>ENABLED</Expiration><Days>14</Days></RecordExpiration></JournalTableConfiguration>"#;
    let jrn = dto::UpdateBucketMetadataJournalTableConfiguration::decode(
        &jrn_view,
        RequestBody::Buffered(Bytes::from_static(jrn_xml.as_bytes())),
    )
    .expect("decodes journal table update");
    assert_eq!(jrn.journal_table_configuration.record_expiration.days, Some(14));
}

/// Positive — OwnershipControls, ABAC, IntelligentTiering, and Inventory PUT codecs decode valid XML.
#[test]
fn ownership_controls_abac_intelligent_tiering_and_inventory_put_decode_valid_xml() {
    let ow_req = accepted("PUT", "/bucket?ownershipControls", &[]);
    let ow_view = MetaView::of(&ow_req, TargetKind::Bucket).expect("view");
    let ow_xml = r#"<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>"#;
    let ow = dto::PutBucketOwnershipControls::decode(&ow_view, RequestBody::Buffered(Bytes::from_static(ow_xml.as_bytes())))
        .expect("decodes ownership controls");
    assert_eq!(ow.ownership_controls.rules.len(), 1);
    assert_eq!(ow.ownership_controls.rules[0].object_ownership, dto::ObjectOwnership::BUCKETOWNERENFORCED);

    let abac_req = accepted("PUT", "/bucket?abac", &[]);
    let abac_view = MetaView::of(&abac_req, TargetKind::Bucket).expect("view");
    let abac_xml = r#"<AbacStatus><Status>Enabled</Status></AbacStatus>"#;
    let abac = dto::PutBucketAbac::decode(&abac_view, RequestBody::Buffered(Bytes::from_static(abac_xml.as_bytes())))
        .expect("decodes ABAC");
    assert_eq!(abac.abac_status.status, Some(dto::Status::ENABLED));

    let it_req = accepted("PUT", "/bucket?intelligent-tiering&id=tier1", &[]);
    let it_view = MetaView::of(&it_req, TargetKind::Bucket).expect("view");
    let it_xml = r#"<IntelligentTieringConfiguration><Id>tier1</Id><Status>Enabled</Status><Tiering><Days>90</Days><AccessTier>ARCHIVE_ACCESS</AccessTier></Tiering></IntelligentTieringConfiguration>"#;
    let it = dto::PutBucketIntelligentTieringConfiguration::decode(
        &it_view,
        RequestBody::Buffered(Bytes::from_static(it_xml.as_bytes())),
    )
    .expect("decodes intelligent tiering");
    assert_eq!(it.id, "tier1");
    assert_eq!(it.intelligent_tiering_configuration.tierings[0].days, 90);

    let inv_req = accepted("PUT", "/bucket?inventory&id=inv1", &[]);
    let inv_view = MetaView::of(&inv_req, TargetKind::Bucket).expect("view");
    let inv_xml = r#"<InventoryConfiguration><Destination><S3BucketDestination><Bucket>dest-bucket</Bucket><Format>CSV</Format></S3BucketDestination></Destination><IsEnabled>true</IsEnabled><Id>inv1</Id><IncludedObjectVersions>All</IncludedObjectVersions><Schedule><Frequency>Daily</Frequency></Schedule></InventoryConfiguration>"#;
    let inv =
        dto::PutBucketInventoryConfiguration::decode(&inv_view, RequestBody::Buffered(Bytes::from_static(inv_xml.as_bytes())))
            .expect("decodes inventory");
    assert_eq!(inv.id, "inv1");
    assert!(inv.inventory_configuration.is_enabled);
}
