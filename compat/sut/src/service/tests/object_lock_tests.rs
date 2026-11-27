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

//! End-to-end Object Lock coverage through `compat-sut`'s full `build_service` assembly
//! (rustfs/gateway#1512).
//!
//! Responsible for: verifying that `compat-sut` registers all six Object Lock handlers, enforces
//! bucket ownership and policy authorization alongside governance bypass, and supports the full
//! create -> lock -> refuse-delete -> release -> cleanup lifecycle.
//! NOT responsible for: exhaustive unit/storage-edge testing (`crates/fs/tests/crud/object_lock*.rs`).
//! Upstream: `super::build_service` and `rustfs-gateway-fs`. Downstream: `compat-sut` test gate.

use super::*;

fn content_md5(bytes: &[u8]) -> String {
    let mut hasher = rustfs_gateway::ChecksumAlgorithm::Md5.checksummer();
    hasher.update(bytes);
    rustfs_gateway::ChecksumSpec::from_digest(rustfs_gateway::ChecksumAlgorithm::Md5, &hasher.finalize())
        .expect("md5 checksum")
        .render_base64()
        .to_owned()
}

fn version_id(response: &WireResponse) -> String {
    response
        .headers()
        .iter()
        .find(|(name, _)| name.as_str().eq_ignore_ascii_case("x-amz-version-id"))
        .expect("x-amz-version-id")
        .1
        .to_str()
        .expect("ascii version id")
        .to_owned()
}

/// Positive + negative — full Object Lock lifecycle through `compat-sut` including owner access,
/// non-owner denial, protected delete refusal, legal-hold release, authorized governance bypass,
/// and clean bucket deletion.
#[tokio::test]
async fn object_lock_lifecycle_and_owner_isolation_through_compat_sut() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);

    let created = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            "/sut-lock",
            Bytes::new(),
            &[("x-amz-bucket-object-lock-enabled", "true")],
        ),
    )
    .await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));

    let cfg = exchange(&service, as_main(http::Method::GET, "/sut-lock?object-lock", Bytes::new())).await;
    assert_eq!(cfg.status(), 200, "{}", body_of(&cfg));
    assert!(body_of(&cfg).contains("<ObjectLockEnabled>Enabled</ObjectLockEnabled>"));

    let put = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            "/sut-lock/obj",
            Bytes::from_static(b"locked-payload"),
            &[
                ("x-amz-object-lock-mode", "GOVERNANCE"),
                ("x-amz-object-lock-retain-until-date", "2099-01-01T00:00:00.000Z"),
                ("x-amz-object-lock-legal-hold", "ON"),
            ],
        ),
    )
    .await;
    assert_eq!(put.status(), 200, "{}", body_of(&put));
    let ver = version_id(&put);

    // Non-owner cannot inspect or mutate lock state.
    let alt_get = exchange(
        &service,
        as_alt(http::Method::GET, &format!("/sut-lock/obj?retention&versionId={ver}"), Bytes::new()),
    )
    .await;
    assert_eq!(alt_get.status(), 403, "{}", body_of(&alt_get));

    // Protected version resists delete without bypass and with bypass while legal hold is ON.
    let del_plain = exchange(
        &service,
        as_main(http::Method::DELETE, &format!("/sut-lock/obj?versionId={ver}"), Bytes::new()),
    )
    .await;
    assert_eq!(del_plain.status(), 403, "{}", body_of(&del_plain));

    let del_while_held = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::DELETE,
            &format!("/sut-lock/obj?versionId={ver}"),
            Bytes::new(),
            &[("x-amz-bypass-governance-retention", "true")],
        ),
    )
    .await;
    assert_eq!(del_while_held.status(), 403, "{}", body_of(&del_while_held));

    // Release legal hold, then authorized owner governance bypass deletes the version cleanly.
    let off_xml = b"<LegalHold><Status>OFF</Status></LegalHold>";
    let off_md5 = content_md5(off_xml);
    let release = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            &format!("/sut-lock/obj?legal-hold&versionId={ver}"),
            Bytes::from_static(off_xml),
            &[("content-type", "application/xml"), ("content-md5", &off_md5)],
        ),
    )
    .await;
    assert_eq!(release.status(), 200, "{}", body_of(&release));

    let del_bypass = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::DELETE,
            &format!("/sut-lock/obj?versionId={ver}"),
            Bytes::new(),
            &[("x-amz-bypass-governance-retention", "true")],
        ),
    )
    .await;
    assert_eq!(del_bypass.status(), 204, "{}", body_of(&del_bypass));

    let del_bkt = exchange(&service, as_main(http::Method::DELETE, "/sut-lock", Bytes::new())).await;
    assert_eq!(del_bkt.status(), 204, "{}", body_of(&del_bkt));
}

/// Negative — a bucket policy granting `s3:DeleteObjectVersion` without
/// `s3:BypassGovernanceRetention` denies a non-owner's governance-bypass delete.
#[tokio::test]
async fn n_policy_without_bypass_permission_denies_governance_bypass_delete() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);

    assert_eq!(
        exchange(
            &service,
            signed(
                MAIN_KEY,
                MAIN_SECRET,
                http::Method::PUT,
                "/policy-lock",
                Bytes::new(),
                &[("x-amz-bucket-object-lock-enabled", "true")],
            ),
        )
        .await
        .status(),
        200
    );
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["s3:DeleteObjectVersion"],"Resource":["arn:aws:s3:::policy-lock/*"]}]}"#;
    let put_policy = exchange(
        &service,
        as_main(http::Method::PUT, "/policy-lock?policy", Bytes::from_static(policy.as_bytes())),
    )
    .await;
    assert_eq!(put_policy.status(), 204, "{}", body_of(&put_policy));

    let put = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            "/policy-lock/doc",
            Bytes::from_static(b"data"),
            &[
                ("x-amz-object-lock-mode", "GOVERNANCE"),
                ("x-amz-object-lock-retain-until-date", "2099-01-01T00:00:00.000Z"),
            ],
        ),
    )
    .await;
    assert_eq!(put.status(), 200, "{}", body_of(&put));
    let ver = version_id(&put);

    let denied = exchange(
        &service,
        signed(
            ALT_KEY,
            ALT_SECRET,
            http::Method::DELETE,
            &format!("/policy-lock/doc?versionId={ver}"),
            Bytes::new(),
            &[("x-amz-bypass-governance-retention", "true")],
        ),
    )
    .await;
    assert_eq!(denied.status(), 403, "{}", body_of(&denied));
    assert!(body_of(&denied).contains("AccessDenied"), "{}", body_of(&denied));
}

/// Negative — a creation the backend refused leaves no owner record behind, so the same
/// identity may still create the bucket properly afterwards; the record follows the creation
/// and not the admission (rustfs/gateway#811).
#[tokio::test]
async fn n_a_refused_creation_records_no_owner() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let owners = Arc::new(BucketOwners::default());
    let backend = Arc::new(open_backend(&options).expect("a usable data root"));
    let service = build_service(&options, &backend, &owners).expect("a complete service");

    // Pre-seed the bucket dir without an owner record so PolicyAuthorizer/TakenNames admit it and
    // FsBackend refuses `object-lock-enabled: true` over an existing bucket (`409`).
    let existing = root.0.join("b-756e6d616465");
    for subdir in ["objects", "uploads", "versions"] {
        std::fs::create_dir_all(existing.join(subdir)).expect("seed bucket");
    }
    let refused = exchange(
        &service,
        signed(
            ALT_KEY,
            ALT_SECRET,
            http::Method::PUT,
            "/unmade",
            Bytes::new(),
            &[("x-amz-bucket-object-lock-enabled", "true")],
        ),
    )
    .await;
    assert_eq!(refused.status(), 409, "{}", body_of(&refused));
    {
        use rustfs_gateway::BucketOwnerSource as _;
        let name = rustfs_gateway::BucketName::new("unmade").expect("a valid bucket name");
        assert!(owners.owner(&name).await.is_err(), "a refused creation must not be recorded");
    }
    std::fs::remove_dir_all(&existing).expect("remove seeded dir");
    assert_eq!(
        exchange(&service, as_alt(http::Method::PUT, "/unmade", Bytes::new()))
            .await
            .status(),
        200
    );
}
