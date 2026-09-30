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

//! A request naming one object version, authorised as legacy RustFS authorises it, through the
//! served RustFS-profile assembly and a stored bucket policy.
//!
//! Responsible for: the second identity, allowed by the bucket policy, reading and deleting a
//! named version only with the version action, as legacy RustFS asks it (GHSA-3ppv,
//! `rustfs/src/storage/access.rs:1029-1056`, `:2423`, `:2705-2707` on rustfs/rustfs
//! `d60dfbb826`), with what a refused delete leaves in storage; and the `HEAD` and tag reads of a
//! named version legacy RustFS still authorises with the unversioned action (`:2839`, `:2787`).
//! NOT responsible for: the question the gateway asks (the gateway's runtime suite) or the policy
//! grammar (`rustfs_gateway_fs::policy::evaluate`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

const BUCKET: &str = "versioned-policy";
const ENABLED: &[u8] = b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";

/// A policy letting the second identity perform `actions` on every object of the bucket.
fn alt_may(actions: &[&str]) -> String {
    let actions = actions
        .iter()
        .map(|action| format!("\"{action}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":["{ALT_OWNER}"]}},"Action":[{actions}],"Resource":"arn:aws:s3:::{BUCKET}/*"}}]}}"#
    )
}

/// Stores `document` as the bucket policy, as the owner.
async fn allow_alt(service: &S3Service, actions: &[&str]) {
    let document = alt_may(actions);
    let written = exchange(
        service,
        as_main(http::Method::PUT, &format!("/{BUCKET}?policy"), Bytes::from(document.into_bytes())),
    )
    .await;
    assert_eq!(written.status(), 204, "{}", body_of(&written));
}

/// A versioned bucket holding two versions of `k`, `first` then `second`; answers the first's id.
async fn two_versions(service: &S3Service) -> String {
    let made = exchange(service, as_main(http::Method::PUT, &format!("/{BUCKET}"), Bytes::new())).await;
    assert_eq!(made.status(), 200, "{}", body_of(&made));
    let enabled = exchange(
        service,
        as_main(http::Method::PUT, &format!("/{BUCKET}?versioning"), Bytes::from_static(ENABLED)),
    )
    .await;
    assert_eq!(enabled.status(), 200, "{}", body_of(&enabled));
    let first = exchange(service, as_main(http::Method::PUT, &format!("/{BUCKET}/k"), Bytes::from_static(b"first"))).await;
    assert_eq!(first.status(), 200, "{}", body_of(&first));
    let second = exchange(
        service,
        as_main(http::Method::PUT, &format!("/{BUCKET}/k"), Bytes::from_static(b"second")),
    )
    .await;
    assert_eq!(second.status(), 200, "{}", body_of(&second));
    let version = first.header("x-amz-version-id").expect("a version id").to_owned();
    assert_ne!(Some(version.as_str()), second.header("x-amz-version-id"));
    version
}

/// What the owner reads of the named version: its status and bytes.
async fn owner_reads(service: &S3Service, version: &str) -> (u16, String) {
    let read = exchange(
        service,
        as_main(http::Method::GET, &format!("/{BUCKET}/k?versionId={version}"), Bytes::new()),
    )
    .await;
    (read.status().as_u16(), body_of(&read))
}

/// Negative, then the grant — `s3:GetObject` reads the current object and not a named version;
/// `s3:GetObjectVersion` reads the version.
#[tokio::test]
async fn a_named_version_is_read_only_with_the_version_action() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let version = two_versions(&service).await;
    let named = format!("/{BUCKET}/k?versionId={version}");

    allow_alt(&service, &["s3:GetObject"]).await;
    let refused = exchange(&service, as_alt(http::Method::GET, &named, Bytes::new())).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    assert!(body_of(&refused).contains("<Code>AccessDenied</Code>"));
    assert!(!body_of(&refused).contains("first"), "no byte of the version is disclosed");
    let current = exchange(&service, as_alt(http::Method::GET, &format!("/{BUCKET}/k"), Bytes::new())).await;
    assert_eq!(current.status(), 200, "{}", body_of(&current));
    assert_eq!(body_of(&current), "second");

    allow_alt(&service, &["s3:GetObject", "s3:GetObjectVersion"]).await;
    let read = exchange(&service, as_alt(http::Method::GET, &named, Bytes::new())).await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    assert_eq!(body_of(&read), "first");
}

/// Negative — `s3:DeleteObject` does not remove a named version, and the refused delete leaves the
/// version stored byte for byte; `s3:DeleteObjectVersion` removes it.
#[tokio::test]
async fn a_named_version_is_deleted_only_with_the_version_delete_action() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let version = two_versions(&service).await;
    let named = format!("/{BUCKET}/k?versionId={version}");

    allow_alt(&service, &["s3:DeleteObject"]).await;
    let refused = exchange(&service, as_alt(http::Method::DELETE, &named, Bytes::new())).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    assert_eq!(owner_reads(&service, &version).await, (200, "first".to_owned()));
    let listed = exchange(&service, as_main(http::Method::GET, &format!("/{BUCKET}?versions"), Bytes::new())).await;
    assert_eq!(listed.status(), 200, "{}", body_of(&listed));
    assert!(body_of(&listed).contains(&format!("<VersionId>{version}</VersionId>")));
    assert!(!body_of(&listed).contains("<DeleteMarker>"), "the refused delete wrote no marker");

    allow_alt(&service, &["s3:DeleteObjectVersion"]).await;
    let deleted = exchange(&service, as_alt(http::Method::DELETE, &named, Bytes::new())).await;
    assert_eq!(deleted.status(), 204, "{}", body_of(&deleted));
    let (status, _) = owner_reads(&service, &version).await;
    assert_eq!(status, 404);
    let current = exchange(&service, as_main(http::Method::GET, &format!("/{BUCKET}/k"), Bytes::new())).await;
    assert_eq!(body_of(&current), "second", "only the named version went");
}

/// Negative — the version delete action does not delete the current object: no delete marker.
#[tokio::test]
async fn n_the_version_delete_action_writes_no_delete_marker() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    two_versions(&service).await;

    allow_alt(&service, &["s3:DeleteObjectVersion"]).await;
    let refused = exchange(&service, as_alt(http::Method::DELETE, &format!("/{BUCKET}/k"), Bytes::new())).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    let current = exchange(&service, as_main(http::Method::GET, &format!("/{BUCKET}/k"), Bytes::new())).await;
    assert_eq!(current.status(), 200, "{}", body_of(&current));
    assert_eq!(body_of(&current), "second");
}

/// Positive — as on legacy RustFS, a `HEAD` and a tag read naming a version are authorised with the
/// unversioned action; the version action alone reaches neither.
#[tokio::test]
async fn a_named_version_head_and_tag_read_keep_the_unversioned_action() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let version = two_versions(&service).await;
    let head = format!("/{BUCKET}/k?versionId={version}");
    let tags = format!("/{BUCKET}/k?tagging&versionId={version}");

    allow_alt(&service, &["s3:GetObjectVersion", "s3:GetObjectVersionTagging"]).await;
    assert_eq!(
        exchange(&service, as_alt(http::Method::HEAD, &head, Bytes::new()))
            .await
            .status(),
        403
    );
    assert_eq!(
        exchange(&service, as_alt(http::Method::GET, &tags, Bytes::new()))
            .await
            .status(),
        403
    );

    allow_alt(&service, &["s3:GetObject", "s3:GetObjectTagging"]).await;
    let headed = exchange(&service, as_alt(http::Method::HEAD, &head, Bytes::new())).await;
    assert_eq!(headed.status(), 200);
    assert_eq!(headed.header("content-length"), Some("5"), "the named version's length");
    let tagged = exchange(&service, as_alt(http::Method::GET, &tags, Bytes::new())).await;
    assert_eq!(tagged.status(), 200, "{}", body_of(&tagged));
}
