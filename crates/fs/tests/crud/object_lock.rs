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

//! Signed production-service evidence for bucket Object Lock configuration, default retention,
//! exact-version retention/legal-hold readback, and validation in `rustfs-gateway-fs`
//! (rustfs/gateway#1512).
//!
//! Responsible for: lock-enabled bucket creation coupled with irreversible versioning, default
//! retention across PUT/COPY/multipart, exact-version readback and restart persistence, distinct
//! unconfigured/missing error codes, and malformed/unsupported lock document refusals.
//! NOT responsible for: deletion/bypass/lifecycle/race enforcement (`object_lock_enforcement.rs`)
//! or external conformance fixture provisioning (`rustfs/gateway#1418`).
//! Upstream: the shared CRUD service fixture. Downstream: the crate verification gate.

#[path = "object_lock_enforcement.rs"]
mod enforcement;

use md5::{Digest as _, Md5};
use rustfs_gateway::{ChecksumAlgorithm, ChecksumSpec};

use super::*;

pub(super) const FUTURE_ISO: &str = "2030-01-01T00:00:00.000Z";
pub(super) const LATER_ISO: &str = "2031-01-01T00:00:00.000Z";
pub(super) const SHORTER_ISO: &str = "2028-01-01T00:00:00.000Z";
pub(super) const PAST_ISO: &str = "2020-01-01T00:00:00.000Z";
pub(super) const AFTER_FUTURE_SECS: i64 = 1_900_000_000;

pub(super) fn text(response: &rustfs_gateway::WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

pub(super) fn md5_b64(body: &[u8]) -> String {
    let digest = Md5::digest(body);
    ChecksumSpec::from_digest(ChecksumAlgorithm::Md5, &digest)
        .expect("md5 checksum")
        .render_base64()
        .to_owned()
}

pub(super) fn header_map(pairs: &[(&str, &str)]) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    for (name, value) in pairs {
        map.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            http::HeaderValue::from_str(value).expect("header value"),
        );
    }
    map
}

pub(super) fn version_of(response: &rustfs_gateway::WireResponse) -> String {
    header(response, "x-amz-version-id")
        .expect("x-amz-version-id header")
        .to_str()
        .expect("ASCII version id")
        .to_owned()
}

pub(super) fn error_code(response: &rustfs_gateway::WireResponse) -> Option<String> {
    element(response.body(), "Code")
}

pub(super) async fn create_locked_bucket(service: &S3Service, bucket: &str) -> rustfs_gateway::WireResponse {
    exchange(
        service,
        signed_with_headers(
            http::Method::PUT,
            &format!("/{bucket}"),
            Bytes::new(),
            header_map(&[("x-amz-bucket-object-lock-enabled", "true")]),
        ),
    )
    .await
}

pub(super) async fn put_xml(
    service: &S3Service,
    target: &str,
    xml: &str,
    extra: &[(&str, &str)],
) -> rustfs_gateway::WireResponse {
    let body = Bytes::from(xml.as_bytes().to_vec());
    let md5 = md5_b64(&body);
    let mut map = header_map(extra);
    map.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/xml"));
    map.insert("content-md5", http::HeaderValue::from_str(&md5).expect("md5 header"));
    exchange(service, signed_with_headers(http::Method::PUT, target, body, map)).await
}

pub(super) async fn post_xml(
    service: &S3Service,
    target: &str,
    xml: &str,
    extra: &[(&str, &str)],
) -> rustfs_gateway::WireResponse {
    let body = Bytes::from(xml.as_bytes().to_vec());
    let md5 = md5_b64(&body);
    let mut map = header_map(extra);
    map.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/xml"));
    map.insert("content-md5", http::HeaderValue::from_str(&md5).expect("md5 header"));
    exchange(service, signed_with_headers(http::Method::POST, target, body, map)).await
}

pub(super) async fn put_object_with(
    service: &S3Service,
    target: &str,
    body: &'static [u8],
    extra: &[(&str, &str)],
) -> rustfs_gateway::WireResponse {
    exchange(
        service,
        signed_with_headers(http::Method::PUT, target, Bytes::from_static(body), header_map(extra)),
    )
    .await
}

pub(super) async fn delete_with(service: &S3Service, target: &str, extra: &[(&str, &str)]) -> rustfs_gateway::WireResponse {
    exchange(
        service,
        signed_with_headers(http::Method::DELETE, target, Bytes::new(), header_map(extra)),
    )
    .await
}

pub(super) fn service_at(root: &TestRoot, clock_secs: i64) -> (Arc<FsBackend>, S3Service) {
    let backend =
        Arc::new(FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(clock_secs))).expect("open root"));
    service_with_backend(backend)
}

pub(super) fn retention_xml(mode: &str, until: &str) -> String {
    format!("<Retention><Mode>{mode}</Mode><RetainUntilDate>{until}</RetainUntilDate></Retention>")
}

pub(super) fn legal_hold_xml(status: &str) -> String {
    format!("<LegalHold><Status>{status}</Status></LegalHold>")
}

pub(super) fn lock_config_xml(rule: Option<(&str, &str, i32)>) -> String {
    match rule {
        None => "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>".to_owned(),
        Some((mode, unit, value)) => format!(
            "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>{mode}</Mode><{unit}>{value}</{unit}></DefaultRetention></Rule></ObjectLockConfiguration>"
        ),
    }
}

/// Positive — creating a lock-enabled bucket atomically enables Object Lock and versioning,
/// survives restart, and deleting the empty bucket leaves no stale lock configuration behind.
#[tokio::test]
async fn locked_bucket_creation_enables_lock_and_versioning_across_restart() {
    let root = TestRoot::new();
    let (backend, svc) = service(&root);
    for op in [
        "GetObjectLockConfiguration",
        "PutObjectLockConfiguration",
        "GetObjectRetention",
        "PutObjectRetention",
        "GetObjectLegalHold",
        "PutObjectLegalHold",
    ] {
        assert!(
            backend.supported_operations().any(|name| name == op),
            "supported_operations must register {op}"
        );
    }
    let created = create_locked_bucket(&svc, "locked-bkt").await;
    assert_eq!(created.status(), 200, "{}", text(&created));
    drop(svc);
    drop(backend);

    let (_, reopened) = service(&root);
    let ver = exchange(&reopened, signed(http::Method::GET, "/locked-bkt?versioning", Bytes::new())).await;
    assert_eq!(ver.status(), 200, "{}", text(&ver));
    assert_eq!(element(ver.body(), "Status").as_deref(), Some("Enabled"));

    let cfg = exchange(&reopened, signed(http::Method::GET, "/locked-bkt?object-lock", Bytes::new())).await;
    assert_eq!(cfg.status(), 200, "{}", text(&cfg));
    assert_eq!(element(cfg.body(), "ObjectLockEnabled").as_deref(), Some("Enabled"));

    let deleted = exchange(&reopened, signed(http::Method::DELETE, "/locked-bkt", Bytes::new())).await;
    assert_eq!(deleted.status(), 204, "{}", text(&deleted));

    create_bucket(&reopened, "locked-bkt").await;
    let recreated_cfg = exchange(&reopened, signed(http::Method::GET, "/locked-bkt?object-lock", Bytes::new())).await;
    assert_eq!(recreated_cfg.status(), 404, "{}", text(&recreated_cfg));
    assert_eq!(error_code(&recreated_cfg).as_deref(), Some("ObjectLockConfigurationNotFoundError"));
}

/// Positive — default retention (`Days` and `Years`) survives restart and applies to PUT, COPY,
/// and multipart completion when explicit retention is omitted, while COPY never inherits source
/// lock and explicit retention overrides the bucket default.
#[tokio::test]
async fn default_retention_days_and_years_apply_across_put_copy_multipart_and_restart() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_locked_bucket(&svc, "defaults").await;
    let put_days = put_xml(&svc, "/defaults?object-lock", &lock_config_xml(Some(("GOVERNANCE", "Days", 10))), &[]).await;
    assert_eq!(put_days.status(), 200, "{}", text(&put_days));

    let (_, reopened) = service(&root);
    let cfg = exchange(&reopened, signed(http::Method::GET, "/defaults?object-lock", Bytes::new())).await;
    assert_eq!(cfg.status(), 200, "{}", text(&cfg));
    assert_eq!(element(cfg.body(), "Mode").as_deref(), Some("GOVERNANCE"));
    assert_eq!(element(cfg.body(), "Days").as_deref(), Some("10"));

    let put_default = put_object_with(&reopened, "/defaults/a", b"alpha", &[]).await;
    assert_eq!(put_default.status(), 200, "{}", text(&put_default));
    let v_a = version_of(&put_default);
    let ret_a = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/defaults/a?retention&versionId={v_a}"), Bytes::new()),
    )
    .await;
    assert_eq!(ret_a.status(), 200, "{}", text(&ret_a));
    assert_eq!(element(ret_a.body(), "Mode").as_deref(), Some("GOVERNANCE"));
    assert_eq!(element(ret_a.body(), "RetainUntilDate").as_deref(), Some("2026-01-12T03:04:05.000Z"));

    let put_explicit = put_object_with(
        &reopened,
        "/defaults/explicit",
        b"beta",
        &[
            ("x-amz-object-lock-mode", "COMPLIANCE"),
            ("x-amz-object-lock-retain-until-date", FUTURE_ISO),
            ("x-amz-object-lock-legal-hold", "ON"),
        ],
    )
    .await;
    assert_eq!(put_explicit.status(), 200, "{}", text(&put_explicit));
    let ret_exp = exchange(&reopened, signed(http::Method::GET, "/defaults/explicit?retention", Bytes::new())).await;
    assert_eq!(element(ret_exp.body(), "Mode").as_deref(), Some("COMPLIANCE"));
    assert_eq!(element(ret_exp.body(), "RetainUntilDate").as_deref(), Some(FUTURE_ISO));

    let put_years = put_xml(
        &reopened,
        "/defaults?object-lock",
        &lock_config_xml(Some(("COMPLIANCE", "Years", 1))),
        &[],
    )
    .await;
    assert_eq!(put_years.status(), 200, "{}", text(&put_years));
    let copied = put_object_with(&reopened, "/defaults/copied", b"", &[("x-amz-copy-source", "/defaults/explicit")]).await;
    assert_eq!(copied.status(), 200, "{}", text(&copied));
    let ret_copy = exchange(&reopened, signed(http::Method::GET, "/defaults/copied?retention", Bytes::new())).await;
    assert_eq!(element(ret_copy.body(), "Mode").as_deref(), Some("COMPLIANCE"));
    assert_eq!(element(ret_copy.body(), "RetainUntilDate").as_deref(), Some("2027-01-02T03:04:05.000Z"));
    let hold_copy = exchange(&reopened, signed(http::Method::GET, "/defaults/copied?legal-hold", Bytes::new())).await;
    assert_eq!(hold_copy.status(), 404, "COPY must not inherit source legal hold: {}", text(&hold_copy));
    assert_eq!(error_code(&hold_copy).as_deref(), Some("NoSuchObjectLockConfiguration"));

    let init = exchange(&reopened, signed(http::Method::POST, "/defaults/mpu?uploads", Bytes::new())).await;
    assert_eq!(init.status(), 200, "{}", text(&init));
    let upload_id = element(init.body(), "UploadId").expect("upload id");
    let part = exchange(
        &reopened,
        signed(
            http::Method::PUT,
            &format!("/defaults/mpu?partNumber=1&uploadId={upload_id}"),
            Bytes::from_static(b"part-bytes"),
        ),
    )
    .await;
    assert_eq!(part.status(), 200);
    let part_etag = header(&part, "etag").expect("etag").to_str().expect("ascii").to_owned();
    let complete_body = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{part_etag}</ETag></Part></CompleteMultipartUpload>"
    );
    let completed = exchange(
        &reopened,
        signed(
            http::Method::POST,
            &format!("/defaults/mpu?uploadId={upload_id}"),
            Bytes::from(complete_body),
        ),
    )
    .await;
    assert_eq!(completed.status(), 200, "{}", text(&completed));
    let ret_mpu = exchange(&reopened, signed(http::Method::GET, "/defaults/mpu?retention", Bytes::new())).await;
    assert_eq!(ret_mpu.status(), 200, "{}", text(&ret_mpu));
    assert_eq!(element(ret_mpu.body(), "Mode").as_deref(), Some("COMPLIANCE"));
    assert_eq!(element(ret_mpu.body(), "RetainUntilDate").as_deref(), Some("2027-01-02T03:04:05.000Z"));
}

/// Positive — explicit retention and legal hold stay isolated per exact version, preserve object
/// bytes/ETag, distinguish `OFF` from never-held `404`, and survive restart.
#[tokio::test]
async fn explicit_retention_and_legal_hold_isolate_exact_versions_and_survive_restart() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_locked_bucket(&svc, "versions").await;
    let first = put_object_with(&svc, "/versions/doc", b"first-bytes", &[]).await;
    assert_eq!(first.status(), 200);
    let v1 = version_of(&first);
    let etag1 = header(&first, "etag").expect("etag").to_str().expect("ascii").to_owned();

    let set_ret = put_xml(
        &svc,
        &format!("/versions/doc?retention&versionId={v1}"),
        &retention_xml("COMPLIANCE", "2030-01-01T00:00:00.250Z"),
        &[],
    )
    .await;
    assert_eq!(set_ret.status(), 200, "{}", text(&set_ret));
    let set_hold = put_xml(&svc, &format!("/versions/doc?legal-hold&versionId={v1}"), &legal_hold_xml("ON"), &[]).await;
    assert_eq!(set_hold.status(), 200, "{}", text(&set_hold));

    let second = put_object_with(&svc, "/versions/doc", b"second-bytes", &[]).await;
    assert_eq!(second.status(), 200);
    let v2 = version_of(&second);

    let (_, reopened) = service(&root);
    let get_v1 = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/versions/doc?versionId={v1}"), Bytes::new()),
    )
    .await;
    assert_eq!(get_v1.body().as_ref(), b"first-bytes");
    assert_eq!(header(&get_v1, "etag").and_then(|v| v.to_str().ok()), Some(etag1.as_str()));

    let r1 = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/versions/doc?retention&versionId={v1}"), Bytes::new()),
    )
    .await;
    assert_eq!(r1.status(), 200, "{}", text(&r1));
    assert_eq!(element(r1.body(), "Mode").as_deref(), Some("COMPLIANCE"));
    assert_eq!(element(r1.body(), "RetainUntilDate").as_deref(), Some("2030-01-01T00:00:00.250Z"));
    let h1 = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/versions/doc?legal-hold&versionId={v1}"), Bytes::new()),
    )
    .await;
    assert_eq!(element(h1.body(), "Status").as_deref(), Some("ON"));

    let r2 = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/versions/doc?retention&versionId={v2}"), Bytes::new()),
    )
    .await;
    assert_eq!(r2.status(), 404);
    assert_eq!(error_code(&r2).as_deref(), Some("NoSuchObjectLockConfiguration"));
    let h2 = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/versions/doc?legal-hold&versionId={v2}"), Bytes::new()),
    )
    .await;
    assert_eq!(h2.status(), 404);
    assert_eq!(error_code(&h2).as_deref(), Some("NoSuchObjectLockConfiguration"));

    let lift = put_xml(
        &reopened,
        &format!("/versions/doc?legal-hold&versionId={v1}"),
        &legal_hold_xml("OFF"),
        &[],
    )
    .await;
    assert_eq!(lift.status(), 200, "{}", text(&lift));
    let h1_off = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/versions/doc?legal-hold&versionId={v1}"), Bytes::new()),
    )
    .await;
    assert_eq!(h1_off.status(), 200, "{}", text(&h1_off));
    assert_eq!(element(h1_off.body(), "Status").as_deref(), Some("OFF"));
    let r1_still = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/versions/doc?retention&versionId={v1}"), Bytes::new()),
    )
    .await;
    assert_eq!(element(r1_still.body(), "Mode").as_deref(), Some("COMPLIANCE"));
}

/// Negative — CreateBucket with object-lock-enabled on an existing bucket fails 409 without
/// enabling Object Lock or mutating versioning.
#[tokio::test]
async fn n_creating_locked_bucket_over_existing_bucket_fails_without_enabling_lock() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_bucket(&svc, "existing").await;
    let resp = create_locked_bucket(&svc, "existing").await;
    assert_eq!(resp.status(), 409, "{}", text(&resp));
    assert_eq!(error_code(&resp).as_deref(), Some("BucketAlreadyOwnedByYou"));
    let cfg = exchange(&svc, signed(http::Method::GET, "/existing?object-lock", Bytes::new())).await;
    assert_eq!(cfg.status(), 404);
    assert_eq!(error_code(&cfg).as_deref(), Some("ObjectLockConfigurationNotFoundError"));
    let ver = exchange(&svc, signed(http::Method::GET, "/existing?versioning", Bytes::new())).await;
    assert!(element(ver.body(), "Status").is_none());
}

/// Negative — PutObjectLockConfiguration fails closed with InvalidBucketState on unversioned,
/// suspended, or exclusion-bearing buckets, and succeeds once versioning is cleanly enabled.
#[tokio::test]
async fn n_enabling_lock_on_unversioned_suspended_or_excluded_bucket_is_refused() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_bucket(&svc, "never-ver").await;
    let r1 = put_xml(&svc, "/never-ver?object-lock", &lock_config_xml(None), &[]).await;
    assert_eq!(r1.status(), 409, "{}", text(&r1));
    assert_eq!(error_code(&r1).as_deref(), Some("InvalidBucketState"));

    create_bucket(&svc, "susp-ver").await;
    assert_eq!(
        super::multipart_versioning::set_versioning(&svc, "susp-ver", "Enabled")
            .await
            .status(),
        200
    );
    assert_eq!(
        super::multipart_versioning::set_versioning(&svc, "susp-ver", "Suspended")
            .await
            .status(),
        200
    );
    let r2 = put_xml(&svc, "/susp-ver?object-lock", &lock_config_xml(None), &[]).await;
    assert_eq!(r2.status(), 409, "{}", text(&r2));
    assert_eq!(error_code(&r2).as_deref(), Some("InvalidBucketState"));

    create_bucket(&svc, "excl-ver").await;
    let excl_xml =
        "<VersioningConfiguration><Status>Enabled</Status><ExcludeFolders>true</ExcludeFolders></VersioningConfiguration>";
    let set_excl = put_xml(&svc, "/excl-ver?versioning", excl_xml, &[]).await;
    assert_eq!(set_excl.status(), 200, "{}", text(&set_excl));
    let r3 = put_xml(&svc, "/excl-ver?object-lock", &lock_config_xml(None), &[]).await;
    assert_eq!(r3.status(), 409, "{}", text(&r3));
    assert_eq!(error_code(&r3).as_deref(), Some("InvalidBucketState"));

    create_bucket(&svc, "clean-ver").await;
    assert_eq!(
        super::multipart_versioning::set_versioning(&svc, "clean-ver", "Enabled")
            .await
            .status(),
        200
    );
    let ok = put_xml(&svc, "/clean-ver?object-lock", &lock_config_xml(None), &[]).await;
    assert_eq!(ok.status(), 200, "{}", text(&ok));
}

/// Negative — an Object-Lock-enabled bucket refuses versioning suspension and versioning exclusions
/// while still permitting idempotent `Enabled`.
#[tokio::test]
async fn n_locked_bucket_refuses_versioning_suspension_and_exclusions() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_locked_bucket(&svc, "irreversible").await;

    let suspend = super::multipart_versioning::set_versioning(&svc, "irreversible", "Suspended").await;
    assert_eq!(suspend.status(), 409, "{}", text(&suspend));
    assert_eq!(error_code(&suspend).as_deref(), Some("InvalidBucketState"));

    for bad_xml in [
        "<VersioningConfiguration><Status>Enabled</Status><ExcludeFolders>true</ExcludeFolders></VersioningConfiguration>",
        "<VersioningConfiguration><Status>Enabled</Status><ExcludedPrefixes><Prefix>tmp/</Prefix></ExcludedPrefixes></VersioningConfiguration>",
    ] {
        let resp = put_xml(&svc, "/irreversible?versioning", bad_xml, &[]).await;
        assert_eq!(resp.status(), 409, "{}", text(&resp));
        assert_eq!(error_code(&resp).as_deref(), Some("InvalidBucketState"));
    }

    assert_eq!(
        super::multipart_versioning::set_versioning(&svc, "irreversible", "Enabled")
            .await
            .status(),
        200
    );
    let ver = exchange(&svc, signed(http::Method::GET, "/irreversible?versioning", Bytes::new())).await;
    assert_eq!(element(ver.body(), "Status").as_deref(), Some("Enabled"));
}

/// Negative — missing bucket, unlocked bucket, never-configured object, missing version, and
/// delete marker each return their distinct pinned S3 error code.
#[tokio::test]
async fn n_missing_and_unlocked_reads_and_writes_preserve_distinct_error_codes() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);

    let no_bkt = exchange(&svc, signed(http::Method::GET, "/missing?object-lock", Bytes::new())).await;
    assert_eq!(no_bkt.status(), 404);
    assert_eq!(error_code(&no_bkt).as_deref(), Some("NoSuchBucket"));

    create_bucket(&svc, "plain").await;
    assert_eq!(put_object_with(&svc, "/plain/obj", b"x", &[]).await.status(), 200);
    let unlocked_cfg = exchange(&svc, signed(http::Method::GET, "/plain?object-lock", Bytes::new())).await;
    assert_eq!(unlocked_cfg.status(), 404);
    assert_eq!(error_code(&unlocked_cfg).as_deref(), Some("ObjectLockConfigurationNotFoundError"));

    for (method, target, body) in [
        (http::Method::GET, "/plain/obj?retention", String::new()),
        (http::Method::GET, "/plain/obj?legal-hold", String::new()),
        (http::Method::PUT, "/plain/obj?retention", retention_xml("GOVERNANCE", FUTURE_ISO)),
        (http::Method::PUT, "/plain/obj?legal-hold", legal_hold_xml("ON")),
    ] {
        let resp = if method == http::Method::PUT {
            put_xml(&svc, target, &body, &[]).await
        } else {
            exchange(&svc, signed(method, target, Bytes::new())).await
        };
        assert_eq!(resp.status(), 400, "{target}: {}", text(&resp));
        assert_eq!(error_code(&resp).as_deref(), Some("InvalidRequest"), "{target}");
    }

    create_locked_bucket(&svc, "locked").await;
    assert_eq!(put_object_with(&svc, "/locked/obj", b"x", &[]).await.status(), 200);
    let no_ver = exchange(&svc, signed(http::Method::GET, "/locked/obj?retention&versionId=nope", Bytes::new())).await;
    assert_eq!(no_ver.status(), 404);
    assert_eq!(error_code(&no_ver).as_deref(), Some("NoSuchVersion"));
    let no_ver_put = put_xml(&svc, "/locked/obj?legal-hold&versionId=nope", &legal_hold_xml("ON"), &[]).await;
    assert_eq!(no_ver_put.status(), 404);
    assert_eq!(error_code(&no_ver_put).as_deref(), Some("NoSuchVersion"));

    let dm = delete_with(&svc, "/locked/obj", &[]).await;
    let dm_ver = version_of(&dm);
    for (method, target, body) in [
        (http::Method::GET, format!("/locked/obj?retention&versionId={dm_ver}"), String::new()),
        (http::Method::GET, format!("/locked/obj?legal-hold&versionId={dm_ver}"), String::new()),
        (
            http::Method::PUT,
            format!("/locked/obj?retention&versionId={dm_ver}"),
            retention_xml("GOVERNANCE", FUTURE_ISO),
        ),
        (
            http::Method::PUT,
            format!("/locked/obj?legal-hold&versionId={dm_ver}"),
            legal_hold_xml("ON"),
        ),
    ] {
        let resp = if method == http::Method::PUT {
            put_xml(&svc, &target, &body, &[]).await
        } else {
            exchange(&svc, signed(method, &target, Bytes::new())).await
        };
        assert_eq!(resp.status(), 405, "{target}: {}", text(&resp));
        assert_eq!(error_code(&resp).as_deref(), Some("MethodNotAllowed"), "{target}");
    }
}

/// Negative — malformed lock documents, past retain-until dates, partial retentions, and
/// unsupported EventHold members fail closed without altering stored state.
#[tokio::test]
async fn n_malformed_and_unsupported_lock_documents_leave_stored_state_unchanged() {
    let root = TestRoot::new();
    let (_, svc) = service(&root);
    create_locked_bucket(&svc, "validate").await;
    assert_eq!(
        put_xml(&svc, "/validate?object-lock", &lock_config_xml(Some(("GOVERNANCE", "Days", 5))), &[])
            .await
            .status(),
        200
    );

    for (xml, expected_code) in [
        (
            "<ObjectLockConfiguration><ObjectLockEnabled>Disabled</ObjectLockEnabled></ObjectLockConfiguration>",
            "MalformedXML",
        ),
        (
            "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days><Years>1</Years></DefaultRetention></Rule></ObjectLockConfiguration>",
            "MalformedXML",
        ),
        (
            "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>0</Days></DefaultRetention></Rule></ObjectLockConfiguration>",
            "InvalidArgument",
        ),
        (
            "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days><DefaultEventHold>ON</DefaultEventHold></DefaultRetention></Rule></ObjectLockConfiguration>",
            "NotImplemented",
        ),
    ] {
        let resp = put_xml(&svc, "/validate?object-lock", xml, &[]).await;
        assert_eq!(error_code(&resp).as_deref(), Some(expected_code), "{xml}: {}", text(&resp));
    }
    let cfg = exchange(&svc, signed(http::Method::GET, "/validate?object-lock", Bytes::new())).await;
    assert_eq!(element(cfg.body(), "Days").as_deref(), Some("5"));

    let obj = put_object_with(&svc, "/validate/doc", b"v", &[]).await;
    let ver = version_of(&obj);
    for (xml, expected_code) in [
        (retention_xml("ARCHIVE", FUTURE_ISO), "MalformedXML"),
        (retention_xml("GOVERNANCE", PAST_ISO), "InvalidArgument"),
        ("<Retention><Mode>GOVERNANCE</Mode></Retention>".to_owned(), "MalformedXML"),
        ("<Retention><RetainUntilDate>2030-01-01T00:00:00Z</RetainUntilDate></Retention>".to_owned(), "MalformedXML"),
        (
            "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-01T00:00:00Z</RetainUntilDate><EventHold>ON</EventHold></Retention>".to_owned(),
            "NotImplemented",
        ),
    ] {
        let resp = put_xml(&svc, &format!("/validate/doc?retention&versionId={ver}"), &xml, &[]).await;
        assert_eq!(error_code(&resp).as_deref(), Some(expected_code), "{xml}: {}", text(&resp));
    }
    let bad_hold = put_xml(&svc, &format!("/validate/doc?legal-hold&versionId={ver}"), &legal_hold_xml("on"), &[]).await;
    assert_eq!(error_code(&bad_hold).as_deref(), Some("MalformedXML"));
}
