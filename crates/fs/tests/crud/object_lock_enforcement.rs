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

//! Signed production-service evidence for Object Lock deletion enforcement, governance bypass
//! authorization, bulk deletion, multipart propagation, lifecycle protection, corrupt authority,
//! and concurrent lock/delete races (rustfs/gateway#1512).
//!
//! Responsible for: COMPLIANCE immutability, GOVERNANCE bypass intent/permission/wire-header
//! binding, legal-hold precedence, DeleteObjects per-key failures, multipart initiation lock
//! durability, lifecycle noncurrent retention, corrupt/symlink fail-closed behavior, and
//! linearizable concurrent lock-vs-delete races.
//! NOT responsible for: bucket configuration and readback matrix (`object_lock.rs`).
//! Upstream: `super` (`object_lock`) and the shared CRUD fixture. Downstream: crate verification.

use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Decision, InputAuthzRequest, InputDecisions, Next, OpLayer, RequestContext,
};

use super::super::*;
use super::{
    AFTER_FUTURE_SECS, FUTURE_ISO, LATER_ISO, SHORTER_ISO, create_locked_bucket, delete_with, error_code, header_map,
    legal_hold_xml, lock_config_xml, post_xml, put_object_with, put_xml, retention_xml, service_at, text, version_of,
};

struct DenyBypassAuthorizer;

impl Authorizer for DenyBypassAuthorizer {
    fn authorize_route<'a>(&'a self, _context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        let decision = if request.action == "s3:BypassGovernanceRetention" {
            Decision::Deny
        } else {
            Decision::Allow
        };
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decision = |req: &AuthzRequest<'_>| {
            if req.action == "s3:BypassGovernanceRetention" {
                Decision::Deny
            } else {
                Decision::Allow
            }
        };
        let stage = decision(request.route());
        let decisions = request.decide_all(stage, decision);
        Box::pin(async move { decisions })
    }
}

struct ForgeDeleteBypassLayer;

impl OpLayer<dto::DeleteObject> for ForgeDeleteBypassLayer {
    fn wrap<'a>(
        &'a self,
        mut request: Req<dto::DeleteObject>,
        next: Next<'a, dto::DeleteObject>,
    ) -> BoxFuture<'a, rustfs_gateway::HandlerResult<dto::DeleteObject>> {
        request.input_mut().bypass_governance_retention = Some(true);
        Box::pin(next.run(request))
    }
}

struct ForgeRetentionBypassLayer;

impl OpLayer<dto::PutObjectRetention> for ForgeRetentionBypassLayer {
    fn wrap<'a>(
        &'a self,
        mut request: Req<dto::PutObjectRetention>,
        next: Next<'a, dto::PutObjectRetention>,
    ) -> BoxFuture<'a, rustfs_gateway::HandlerResult<dto::PutObjectRetention>> {
        request.input_mut().bypass_governance_retention = Some(true);
        Box::pin(next.run(request))
    }
}

fn custom_service(root: &TestRoot, deny_bypass: bool, forge_bypass_layers: bool) -> (Arc<FsBackend>, S3Service) {
    let backend = Arc::new(
        FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS))).expect("usable root"),
    );
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials")));
    let base = rustfs_gateway::ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("region")))
        .clock_with_skew_ack(
            FixedClock::at_unix_seconds(SIGNED_AT_SECONDS),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        );
    let base = if deny_bypass {
        base.authorizer(DenyBypassAuthorizer)
    } else {
        base.authorizer(allow_when(|_| true))
    };
    let builder = backend.register_crud(base);
    let builder =
        backend.register_object_lock(backend.register_cors(backend.register_encryption(backend.register_policy(
            backend.register_acl(backend.register_tagging(
                backend.register_lifecycle(
                    backend.register_listing(backend.register_versioning(backend.register_multipart(builder))),
                ),
            )),
        ))));
    let builder = if forge_bypass_layers {
        builder
            .op_layer::<dto::DeleteObject, _>(ForgeDeleteBypassLayer)
            .op_layer::<dto::PutObjectRetention, _>(ForgeRetentionBypassLayer)
    } else {
        builder
    };
    let service = builder.build().expect("assembled service");
    (backend, service)
}

async fn status_of(svc: &S3Service, method: http::Method, target: &str) -> u16 {
    exchange(svc, signed(method, target, Bytes::new())).await.status().as_u16()
}

/// Positive — authorized GOVERNANCE bypass, expired retention, and released legal hold permit
/// explicit version deletion and governance shortening/clearing.
#[tokio::test]
async fn governance_bypass_expired_retention_and_released_hold_permit_explicit_deletion() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_locked_bucket(&svc, "release").await;

    let gov = put_object_with(
        &svc,
        "/release/gov",
        b"gov",
        &[
            ("x-amz-object-lock-mode", "GOVERNANCE"),
            ("x-amz-object-lock-retain-until-date", FUTURE_ISO),
        ],
    )
    .await;
    let v_gov = version_of(&gov);
    let shortened = put_xml(
        &svc,
        &format!("/release/gov?retention&versionId={v_gov}"),
        &retention_xml("GOVERNANCE", SHORTER_ISO),
        &[("x-amz-bypass-governance-retention", "True")],
    )
    .await;
    assert_eq!(shortened.status(), 200, "{}", text(&shortened));
    let cleared = put_xml(
        &svc,
        &format!("/release/gov?retention&versionId={v_gov}"),
        "<Retention></Retention>",
        &[("x-amz-bypass-governance-retention", "true")],
    )
    .await;
    assert_eq!(cleared.status(), 200, "{}", text(&cleared));
    let ret_gone = exchange(
        &svc,
        signed(http::Method::GET, &format!("/release/gov?retention&versionId={v_gov}"), Bytes::new()),
    )
    .await;
    assert_eq!(ret_gone.status(), 404);
    assert_eq!(error_code(&ret_gone).as_deref(), Some("NoSuchObjectLockConfiguration"));
    assert_eq!(
        delete_with(&svc, &format!("/release/gov?versionId={v_gov}"), &[])
            .await
            .status(),
        204
    );

    let gov2 = put_object_with(
        &svc,
        "/release/gov2",
        b"gov2",
        &[
            ("x-amz-object-lock-mode", "GOVERNANCE"),
            ("x-amz-object-lock-retain-until-date", FUTURE_ISO),
        ],
    )
    .await;
    let v_gov2 = version_of(&gov2);
    let del_bypass = delete_with(
        &svc,
        &format!("/release/gov2?versionId={v_gov2}"),
        &[("x-amz-bypass-governance-retention", "true")],
    )
    .await;
    assert_eq!(del_bypass.status(), 204, "{}", text(&del_bypass));

    let held = put_object_with(&svc, "/release/held", b"held", &[("x-amz-object-lock-legal-hold", "ON")]).await;
    let v_held = version_of(&held);
    assert_eq!(
        put_xml(&svc, &format!("/release/held?legal-hold&versionId={v_held}"), &legal_hold_xml("OFF"), &[])
            .await
            .status(),
        200
    );
    assert_eq!(
        delete_with(&svc, &format!("/release/held?versionId={v_held}"), &[])
            .await
            .status(),
        204
    );

    let comp = put_object_with(
        &svc,
        "/release/comp",
        b"comp",
        &[
            ("x-amz-object-lock-mode", "COMPLIANCE"),
            ("x-amz-object-lock-retain-until-date", FUTURE_ISO),
        ],
    )
    .await;
    let v_comp = version_of(&comp);
    let (_, later_svc) = service_at(&root, AFTER_FUTURE_SECS);
    assert_eq!(
        delete_with(&later_svc, &format!("/release/comp?versionId={v_comp}"), &[])
            .await
            .status(),
        204
    );
}

/// Positive — creating a delete marker or writing a newer version leaves the earlier protected
/// version readable and still protected, while the delete marker itself can be deleted.
#[tokio::test]
async fn new_version_and_delete_marker_preserve_earlier_protected_version() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_locked_bucket(&svc, "markers").await;
    let v1_resp = put_object_with(
        &svc,
        "/markers/key",
        b"locked-v1",
        &[
            ("x-amz-object-lock-mode", "COMPLIANCE"),
            ("x-amz-object-lock-retain-until-date", FUTURE_ISO),
        ],
    )
    .await;
    let v1 = version_of(&v1_resp);

    let dm = delete_with(&svc, "/markers/key", &[]).await;
    assert_eq!(dm.status(), 204, "{}", text(&dm));
    assert_eq!(header(&dm, "x-amz-delete-marker").and_then(|v| v.to_str().ok()), Some("true"));
    let dm_ver = version_of(&dm);

    let read_v1 = exchange(&svc, signed(http::Method::GET, &format!("/markers/key?versionId={v1}"), Bytes::new())).await;
    assert_eq!(read_v1.status(), 200);
    assert_eq!(read_v1.body().as_ref(), b"locked-v1");

    assert_eq!(
        delete_with(&svc, &format!("/markers/key?versionId={dm_ver}"), &[])
            .await
            .status(),
        204
    );
    assert_eq!(delete_with(&svc, &format!("/markers/key?versionId={v1}"), &[]).await.status(), 403);
}

/// Negative — COMPLIANCE retention refuses deletion, shortening, mode downgrade, and clearing even
/// with governance bypass, and survives restart.
#[tokio::test]
async fn n_compliance_blocks_deletion_shortening_downgrade_and_clearing_even_with_bypass() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_locked_bucket(&svc, "compliance").await;
    let obj = put_object_with(
        &svc,
        "/compliance/doc",
        b"immutable",
        &[
            ("x-amz-object-lock-mode", "COMPLIANCE"),
            ("x-amz-object-lock-retain-until-date", FUTURE_ISO),
        ],
    )
    .await;
    let v = version_of(&obj);

    let (_, reopened) = service(&root);
    for bypass in [&[][..], &[("x-amz-bypass-governance-retention", "true")][..]] {
        let del = delete_with(&reopened, &format!("/compliance/doc?versionId={v}"), bypass).await;
        assert_eq!(del.status(), 403, "{}", text(&del));
        assert_eq!(error_code(&del).as_deref(), Some("AccessDenied"));

        let shorten = put_xml(
            &reopened,
            &format!("/compliance/doc?retention&versionId={v}"),
            &retention_xml("COMPLIANCE", SHORTER_ISO),
            bypass,
        )
        .await;
        assert_eq!(shorten.status(), 403, "{}", text(&shorten));

        let downgrade = put_xml(
            &reopened,
            &format!("/compliance/doc?retention&versionId={v}"),
            &retention_xml("GOVERNANCE", LATER_ISO),
            bypass,
        )
        .await;
        assert_eq!(downgrade.status(), 403, "{}", text(&downgrade));

        let clear = put_xml(
            &reopened,
            &format!("/compliance/doc?retention&versionId={v}"),
            "<Retention></Retention>",
            bypass,
        )
        .await;
        assert_eq!(clear.status(), 403, "{}", text(&clear));
    }

    let extend = put_xml(
        &reopened,
        &format!("/compliance/doc?retention&versionId={v}"),
        &retention_xml("COMPLIANCE", LATER_ISO),
        &[],
    )
    .await;
    assert_eq!(extend.status(), 200, "{}", text(&extend));
    let read = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/compliance/doc?versionId={v}"), Bytes::new()),
    )
    .await;
    assert_eq!(read.status(), 200);
    assert_eq!(read.body().as_ref(), b"immutable");
}

/// Negative — GOVERNANCE blocks deletion, shortening, and clearing without bypass while permitting
/// extension and upgrade to COMPLIANCE.
#[tokio::test]
async fn n_governance_blocks_deletion_shortening_and_clearing_without_bypass() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_locked_bucket(&svc, "governance").await;
    let obj = put_object_with(
        &svc,
        "/governance/doc",
        b"gov-bytes",
        &[
            ("x-amz-object-lock-mode", "GOVERNANCE"),
            ("x-amz-object-lock-retain-until-date", FUTURE_ISO),
        ],
    )
    .await;
    let v = version_of(&obj);

    assert_eq!(
        delete_with(&svc, &format!("/governance/doc?versionId={v}"), &[])
            .await
            .status(),
        403
    );
    assert_eq!(
        put_xml(
            &svc,
            &format!("/governance/doc?retention&versionId={v}"),
            &retention_xml("GOVERNANCE", SHORTER_ISO),
            &[]
        )
        .await
        .status(),
        403
    );
    assert_eq!(
        put_xml(&svc, &format!("/governance/doc?retention&versionId={v}"), "<Retention></Retention>", &[])
            .await
            .status(),
        403
    );

    assert_eq!(
        put_xml(
            &svc,
            &format!("/governance/doc?retention&versionId={v}"),
            &retention_xml("COMPLIANCE", LATER_ISO),
            &[]
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        delete_with(
            &svc,
            &format!("/governance/doc?versionId={v}"),
            &[("x-amz-bypass-governance-retention", "true")]
        )
        .await
        .status(),
        403
    );
}

/// Negative — governance bypass fails when `s3:BypassGovernanceRetention` is denied OR when a
/// post-authorization layer mutates `Req::input_mut` without an accepted wire bypass header.
#[tokio::test]
async fn n_governance_bypass_requires_permission_and_immutable_wire_header() {
    let root = TestRoot::new();
    let (_, setup_svc) = service(&root);
    create_locked_bucket(&setup_svc, "authz").await;
    let obj = put_object_with(
        &setup_svc,
        "/authz/doc",
        b"protected",
        &[
            ("x-amz-object-lock-mode", "GOVERNANCE"),
            ("x-amz-object-lock-retain-until-date", FUTURE_ISO),
        ],
    )
    .await;
    let v = version_of(&obj);

    let (_, denied_svc) = custom_service(&root, true, false);
    let del_denied = delete_with(
        &denied_svc,
        &format!("/authz/doc?versionId={v}"),
        &[("x-amz-bypass-governance-retention", "true")],
    )
    .await;
    assert_eq!(del_denied.status(), 403, "{}", text(&del_denied));
    let ret_denied = put_xml(
        &denied_svc,
        &format!("/authz/doc?retention&versionId={v}"),
        &retention_xml("GOVERNANCE", SHORTER_ISO),
        &[("x-amz-bypass-governance-retention", "true")],
    )
    .await;
    assert_eq!(ret_denied.status(), 403, "{}", text(&ret_denied));

    let (_, forged_svc) = custom_service(&root, false, true);
    let del_forged = delete_with(&forged_svc, &format!("/authz/doc?versionId={v}"), &[]).await;
    assert_eq!(del_forged.status(), 403, "forged delete bypass must fail: {}", text(&del_forged));
    let ret_forged = put_xml(
        &forged_svc,
        &format!("/authz/doc?retention&versionId={v}"),
        &retention_xml("GOVERNANCE", SHORTER_ISO),
        &[],
    )
    .await;
    assert_eq!(ret_forged.status(), 403, "forged retention bypass must fail: {}", text(&ret_forged));

    let still_there = exchange(&setup_svc, signed(http::Method::GET, &format!("/authz/doc?versionId={v}"), Bytes::new())).await;
    assert_eq!(still_there.status(), 200);
    assert_eq!(still_there.body().as_ref(), b"protected");
}

/// Negative — LegalHold=ON prevents deletion without bypass, with bypass, and even after
/// retention expires across restart.
#[tokio::test]
async fn n_legal_hold_blocks_deletion_regardless_of_bypass_or_retention_expiry() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_locked_bucket(&svc, "hold").await;
    let obj = put_object_with(
        &svc,
        "/hold/doc",
        b"court-hold",
        &[
            ("x-amz-object-lock-mode", "GOVERNANCE"),
            ("x-amz-object-lock-retain-until-date", FUTURE_ISO),
            ("x-amz-object-lock-legal-hold", "ON"),
        ],
    )
    .await;
    let v = version_of(&obj);

    let (_, later_svc) = service_at(&root, AFTER_FUTURE_SECS);
    for bypass in [&[][..], &[("x-amz-bypass-governance-retention", "true")][..]] {
        let del = delete_with(&later_svc, &format!("/hold/doc?versionId={v}"), bypass).await;
        assert_eq!(del.status(), 403, "{}", text(&del));
        assert_eq!(error_code(&del).as_deref(), Some("AccessDenied"));
    }
    let read = exchange(&later_svc, signed(http::Method::GET, &format!("/hold/doc?versionId={v}"), Bytes::new())).await;
    assert_eq!(read.status(), 200);
    assert_eq!(read.body().as_ref(), b"court-hold");
}

/// Negative — DeleteObjects reports per-key AccessDenied for protected versions while deleting
/// unprotected versions in the same batch, and refuses batch governance bypass with 501.
#[tokio::test]
async fn n_bulk_delete_reports_protected_per_key_errors_and_refuses_batch_bypass() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_locked_bucket(&svc, "bulk").await;
    let v_free = version_of(&put_object_with(&svc, "/bulk/free", b"free", &[]).await);
    let v_gov = version_of(
        &put_object_with(
            &svc,
            "/bulk/gov",
            b"gov",
            &[
                ("x-amz-object-lock-mode", "GOVERNANCE"),
                ("x-amz-object-lock-retain-until-date", FUTURE_ISO),
            ],
        )
        .await,
    );
    let v_comp = version_of(
        &put_object_with(
            &svc,
            "/bulk/comp",
            b"comp",
            &[
                ("x-amz-object-lock-mode", "COMPLIANCE"),
                ("x-amz-object-lock-retain-until-date", FUTURE_ISO),
            ],
        )
        .await,
    );
    let v_hold = version_of(&put_object_with(&svc, "/bulk/hold", b"hold", &[("x-amz-object-lock-legal-hold", "ON")]).await);

    let body = format!(
        "<Delete><Object><Key>free</Key><VersionId>{v_free}</VersionId></Object><Object><Key>gov</Key><VersionId>{v_gov}</VersionId></Object><Object><Key>comp</Key><VersionId>{v_comp}</VersionId></Object><Object><Key>hold</Key><VersionId>{v_hold}</VersionId></Object></Delete>"
    );

    let bypass_batch = post_xml(&svc, "/bulk?delete", &body, &[("x-amz-bypass-governance-retention", "true")]).await;
    assert_eq!(bypass_batch.status(), 501, "{}", text(&bypass_batch));
    assert_eq!(
        exchange(&svc, signed(http::Method::HEAD, &format!("/bulk/free?versionId={v_free}"), Bytes::new()))
            .await
            .status(),
        200
    );

    let batch = post_xml(&svc, "/bulk?delete", &body, &[]).await;
    assert_eq!(batch.status(), 200, "{}", text(&batch));
    let xml = text(&batch);
    assert!(xml.contains("<Deleted><Key>free</Key>"), "{xml}");
    assert_eq!(xml.matches("<Code>AccessDenied</Code>").count(), 3, "{xml}");
    assert_eq!(
        exchange(&svc, signed(http::Method::HEAD, &format!("/bulk/free?versionId={v_free}"), Bytes::new()))
            .await
            .status(),
        404
    );
    for (k, v) in [("gov", v_gov), ("comp", v_comp), ("hold", v_hold)] {
        assert_eq!(
            exchange(&svc, signed(http::Method::HEAD, &format!("/bulk/{k}?versionId={v}"), Bytes::new()))
                .await
                .status(),
            200,
            "{k} must survive batch delete"
        );
    }
}

/// Negative — multipart initiation lock headers fail closed on unlocked buckets and survive restart
/// through completion on locked buckets, protecting the published version.
#[tokio::test]
async fn n_multipart_initiation_lock_persists_through_completion_and_protects_version() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_bucket(&svc, "mpu-unlocked").await;
    let refused = exchange(
        &svc,
        signed_with_headers(
            http::Method::POST,
            "/mpu-unlocked/k?uploads",
            Bytes::new(),
            header_map(&[("x-amz-object-lock-legal-hold", "ON")]),
        ),
    )
    .await;
    assert_eq!(refused.status(), 400, "{}", text(&refused));
    assert_eq!(error_code(&refused).as_deref(), Some("InvalidRequest"));

    create_locked_bucket(&svc, "mpu-locked").await;
    let init = exchange(
        &svc,
        signed_with_headers(
            http::Method::POST,
            "/mpu-locked/k?uploads",
            Bytes::new(),
            header_map(&[
                ("x-amz-object-lock-mode", "COMPLIANCE"),
                ("x-amz-object-lock-retain-until-date", FUTURE_ISO),
                ("x-amz-object-lock-legal-hold", "ON"),
            ]),
        ),
    )
    .await;
    assert_eq!(init.status(), 200, "{}", text(&init));
    let upload_id = element(init.body(), "UploadId").expect("upload id");

    let (_, reopened) = service(&root);
    let part = exchange(
        &reopened,
        signed(
            http::Method::PUT,
            &format!("/mpu-locked/k?partNumber=1&uploadId={upload_id}"),
            Bytes::from_static(b"mpu-payload"),
        ),
    )
    .await;
    let etag = header(&part, "etag").expect("etag").to_str().expect("ascii").to_owned();
    let complete_xml =
        format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>");
    let done = exchange(
        &reopened,
        signed(
            http::Method::POST,
            &format!("/mpu-locked/k?uploadId={upload_id}"),
            Bytes::from(complete_xml),
        ),
    )
    .await;
    assert_eq!(done.status(), 200, "{}", text(&done));
    let ver = version_of(&done);

    assert_eq!(
        delete_with(
            &reopened,
            &format!("/mpu-locked/k?versionId={ver}"),
            &[("x-amz-bypass-governance-retention", "true")]
        )
        .await
        .status(),
        403
    );
    let ret = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/mpu-locked/k?retention&versionId={ver}"), Bytes::new()),
    )
    .await;
    assert_eq!(element(ret.body(), "Mode").as_deref(), Some("COMPLIANCE"));
    let hold = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/mpu-locked/k?legal-hold&versionId={ver}"), Bytes::new()),
    )
    .await;
    assert_eq!(element(hold.body(), "Status").as_deref(), Some("ON"));
}

/// Negative — lifecycle expiration preserves protected versions while expiring unprotected
/// noncurrent versions and placing a delete marker over the current version.
#[tokio::test]
async fn n_lifecycle_expiration_preserves_locked_current_and_noncurrent_versions() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_locked_bucket(&svc, "lc-lock").await;
    let v_free = version_of(&put_object_with(&svc, "/lc-lock/k", b"free", &[]).await);
    let v_gov = version_of(
        &put_object_with(
            &svc,
            "/lc-lock/k",
            b"gov",
            &[
                ("x-amz-object-lock-mode", "GOVERNANCE"),
                ("x-amz-object-lock-retain-until-date", FUTURE_ISO),
            ],
        )
        .await,
    );
    let v_hold = version_of(&put_object_with(&svc, "/lc-lock/k", b"hold", &[("x-amz-object-lock-legal-hold", "ON")]).await);

    let lc_xml = "<LifecycleConfiguration><Rule><ID>expire-all</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>";
    assert_eq!(put_xml(&svc, "/lc-lock?lifecycle", lc_xml, &[]).await.status(), 200);

    let (later_backend, later_svc) = service_at(&root, SIGNED_AT_SECONDS + 5 * 86_400);
    let expired_current = later_backend.expire_lifecycle_once().await.expect("lifecycle sweep");
    assert_eq!(expired_current, 1);

    assert_eq!(
        status_of(&later_svc, http::Method::HEAD, &format!("/lc-lock/k?versionId={v_free}")).await,
        404
    );
    assert_eq!(
        status_of(&later_svc, http::Method::GET, &format!("/lc-lock/k?versionId={v_gov}")).await,
        200
    );
    assert_eq!(
        status_of(&later_svc, http::Method::GET, &format!("/lc-lock/k?versionId={v_hold}")).await,
        200
    );
}

/// Negative — corrupt or symlinked bucket `object-lock` authority fails closed across lock reads,
/// lock writes, versioning updates, and object publication.
#[tokio::test]
async fn n_corrupt_or_symlink_object_lock_config_fails_closed() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_locked_bucket(&svc, "corrupt").await;
    let bucket_dir = root.0.join(format!("b-{}", hex::encode("corrupt")));
    let lock_file = bucket_dir.join("object-lock");
    assert!(lock_file.is_file(), "object-lock file must exist on disk");

    std::fs::write(&lock_file, b"<ObjectLockConfiguration>corrupt").expect("corrupt file");
    assert_eq!(status_of(&svc, http::Method::GET, "/corrupt?object-lock").await, 500);
    assert_eq!(
        put_xml(&svc, "/corrupt?object-lock", &lock_config_xml(None), &[])
            .await
            .status(),
        500
    );
    assert_eq!(
        super::super::multipart_versioning::set_versioning(&svc, "corrupt", "Suspended")
            .await
            .status(),
        500
    );
    assert_eq!(put_object_with(&svc, "/corrupt/doc", b"x", &[]).await.status(), 500);

    std::fs::write(&lock_file, b"<ObjectLockConfiguration/>").expect("missing ObjectLockEnabled");
    assert_eq!(status_of(&svc, http::Method::GET, "/corrupt?object-lock").await, 500);
    assert_eq!(put_object_with(&svc, "/corrupt/doc", b"x", &[]).await.status(), 500);

    #[cfg(unix)]
    {
        let decoy = root.0.join("decoy-lock");
        std::fs::write(&decoy, b"<ObjectLockConfiguration/>").expect("decoy");
        std::fs::remove_file(&lock_file).expect("remove corrupt");
        std::os::unix::fs::symlink(&decoy, &lock_file).expect("symlink");
        assert_eq!(status_of(&svc, http::Method::GET, "/corrupt?object-lock").await, 400);
        assert_eq!(put_object_with(&svc, "/corrupt/doc", b"x", &[]).await.status(), 400);
        let _ = std::fs::remove_file(&lock_file);
        let _ = std::fs::remove_file(&decoy);
    }
}

/// Negative — racing `PutObjectLegalHold(ON)` against explicit `DeleteObject` under the shared
/// version lock is strictly linearizable: a version whose hold succeeded is never deleted.
#[tokio::test]
async fn n_concurrent_lock_update_and_delete_race_never_deletes_protected_version() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    let svc = Arc::new(svc);
    create_locked_bucket(&svc, "race").await;
    for i in 0..16 {
        let key = format!("k{i}");
        let v = version_of(&put_object_with(&svc, &format!("/race/{key}"), b"race-data", &[]).await);
        let svc_hold = Arc::clone(&svc);
        let svc_del = Arc::clone(&svc);
        let k_hold = key.clone();
        let k_del = key.clone();
        let v_hold = v.clone();
        let v_del = v.clone();
        let (hold_res, del_res) = tokio::join!(
            tokio::spawn(async move {
                put_xml(
                    &svc_hold,
                    &format!("/race/{k_hold}?legal-hold&versionId={v_hold}"),
                    &legal_hold_xml("ON"),
                    &[],
                )
                .await
            }),
            tokio::spawn(async move { delete_with(&svc_del, &format!("/race/{k_del}?versionId={v_del}"), &[]).await }),
        );
        let hold_status = hold_res.expect("hold task").status().as_u16();
        let del_status = del_res.expect("del task").status().as_u16();
        match (hold_status, del_status) {
            (200, 403) => {
                assert_eq!(
                    exchange(&svc, signed(http::Method::GET, &format!("/race/{key}?versionId={v}"), Bytes::new()))
                        .await
                        .body()
                        .as_ref(),
                    b"race-data"
                );
            }
            (404, 204) => {
                assert_eq!(
                    exchange(&svc, signed(http::Method::HEAD, &format!("/race/{key}?versionId={v}"), Bytes::new()))
                        .await
                        .status(),
                    404
                );
            }
            other => panic!("non-linearizable race outcome on {key}: (hold, del) = {other:?}"),
        }
    }
}
